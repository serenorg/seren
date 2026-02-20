use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CommandContext;
use crate::OutputFormat;
use crate::output;

// --- Constants ---

const GITHUB_API_BASE: &str = "https://api.github.com/repos/serenorg/seren-skills";
const GITHUB_TARBALL_URL: &str =
    "https://github.com/serenorg/seren-skills/archive/refs/heads/main.tar.gz";
const INDEX_CACHE_SECONDS: i64 = 3600; // 1 hour
const INDEX_FILE_NAME: &str = ".index.json";

const AGENT_DIRS: &[(&str, &str)] = &[
    ("Claude Code", ".claude/skills"),
    ("Codex", ".agents/skills"),
    ("Cursor", ".cursor/skills"),
    ("Gemini", ".gemini/skills"),
    ("GitHub Copilot", ".github/skills"),
    ("OpenClaw", ".openclaw/skills"),
    ("Windsurf", ".codeium/windsurf/skills"),
];

// --- Types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillIndex {
    pub skills: Vec<SkillEntry>,
    pub fetched_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillEntry {
    pub org: String,
    pub name: String,
    pub slug: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
struct GitHubContent {
    name: String,
    #[serde(rename = "type")]
    content_type: String,
    path: String,
    download_url: Option<String>,
    #[allow(dead_code)]
    sha: Option<String>,
}

// --- Path helpers ---

fn skills_dir() -> Result<PathBuf> {
    use etcetera::base_strategy::{BaseStrategy, choose_base_strategy};
    let strategy = choose_base_strategy().map_err(|e| anyhow::anyhow!("{}", e))?;
    let dir = strategy.config_dir().join("seren").join("skills");
    std::fs::create_dir_all(&dir).context("Could not create skills directory")?;
    Ok(dir)
}

fn index_path() -> Result<PathBuf> {
    Ok(skills_dir()?.join(INDEX_FILE_NAME))
}

fn home_dir() -> Result<PathBuf> {
    etcetera::home_dir().map_err(|e| anyhow::anyhow!("Could not determine home directory: {}", e))
}

fn slug_candidates(slug: &str) -> Vec<(String, String)> {
    let mut candidates = Vec::new();
    for (idx, ch) in slug.char_indices() {
        if ch != '-' {
            continue;
        }
        let org = &slug[..idx];
        let name = &slug[idx + 1..];
        if org.is_empty() || name.is_empty() {
            continue;
        }
        candidates.push((org.to_string(), name.to_string()));
    }
    candidates
}

fn resolve_installed_slug(base: &Path, slug: &str) -> Result<(String, String)> {
    let candidates = slug_candidates(slug);
    if candidates.is_empty() {
        anyhow::bail!("Invalid slug '{}'. Expected format: org-skill-name", slug);
    }

    let matches: Vec<_> = candidates
        .into_iter()
        .filter(|(org, name)| base.join(org).join(name).exists())
        .collect();

    match matches.len() {
        1 => Ok(matches[0].clone()),
        0 => anyhow::bail!("Skill '{}' is not installed", slug),
        _ => {
            let options = matches
                .iter()
                .map(|(org, name)| format!("{}/{}", org, name))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "Slug '{}' matches multiple installed skills: {}",
                slug,
                options
            );
        }
    }
}

async fn resolve_remote_slug(client: &reqwest::Client, slug: &str) -> Result<(String, String)> {
    let candidates = slug_candidates(slug);
    if candidates.is_empty() {
        anyhow::bail!("Invalid slug '{}'. Expected format: org-skill-name", slug);
    }

    let mut matches = Vec::new();
    for (org, name) in candidates {
        let path = format!("{}/{}", org, name);
        if fetch_github_contents_if_exists(client, &path)
            .await?
            .is_some()
        {
            matches.push((org, name));
        }
    }

    match matches.len() {
        1 => Ok(matches[0].clone()),
        0 => anyhow::bail!("Skill '{}' not found", slug),
        _ => {
            let options = matches
                .iter()
                .map(|(org, name)| format!("{}/{}", org, name))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "Slug '{}' matches multiple skills in the catalog: {}",
                slug,
                options
            );
        }
    }
}

// --- GitHub API ---

fn github_client() -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        "application/vnd.github.v3+json".parse().unwrap(),
    );
    headers.insert(reqwest::header::USER_AGENT, "seren-cli".parse().unwrap());

    // Respect GITHUB_TOKEN for higher rate limits
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
    }

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .context("Failed to create HTTP client")
}

async fn fetch_github_contents_if_exists(
    client: &reqwest::Client,
    path: &str,
) -> Result<Option<Vec<GitHubContent>>> {
    let url = if path.is_empty() {
        format!("{}/contents", GITHUB_API_BASE)
    } else {
        format!("{}/contents/{}", GITHUB_API_BASE, path)
    };
    let response = client.get(&url).send().await?;

    if response.status() == reqwest::StatusCode::FORBIDDEN {
        anyhow::bail!(
            "GitHub API rate limit exceeded. Set GITHUB_TOKEN env var for higher limits.\n\
            Get a token at: https://github.com/settings/tokens"
        );
    }

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !response.status().is_success() {
        anyhow::bail!(
            "GitHub API error: {} for path '{}'",
            response.status(),
            path
        );
    }

    let contents = response
        .json()
        .await
        .context("Failed to parse GitHub API response")?;
    Ok(Some(contents))
}

async fn fetch_github_contents(client: &reqwest::Client, path: &str) -> Result<Vec<GitHubContent>> {
    fetch_github_contents_if_exists(client, path)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "GitHub API error: {} for path '{}'",
                reqwest::StatusCode::NOT_FOUND,
                path
            )
        })
}

async fn fetch_raw_file(client: &reqwest::Client, download_url: &str) -> Result<String> {
    let response = client.get(download_url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("Failed to download file: {}", response.status());
    }
    response.text().await.context("Failed to read file content")
}

async fn fetch_raw_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("Failed to download: {}", response.status());
    }
    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}

// --- Frontmatter parsing ---

fn parse_frontmatter(content: &str) -> (String, String) {
    let mut name = String::new();
    let mut description = String::new();

    if !content.starts_with("---") {
        return (name, description);
    }

    if let Some(end) = content[3..].find("---") {
        let frontmatter = &content[3..3 + end];
        for line in frontmatter.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("name:") {
                name = val.trim().trim_matches('"').trim_matches('\'').to_string();
            } else if let Some(val) = line.strip_prefix("description:") {
                description = val.trim().trim_matches('"').trim_matches('\'').to_string();
            }
        }
    }

    (name, description)
}

// --- Index management ---

fn load_cached_index() -> Result<Option<SkillIndex>> {
    let path = index_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&path).context("Failed to read skills index")?;
    let index: SkillIndex = match serde_json::from_str(&content) {
        Ok(index) => index,
        Err(err) => {
            eprintln!(
                "{}",
                format!(
                    "Ignoring corrupted skills cache at {}: {}",
                    path.display(),
                    err
                )
                .dimmed()
            );
            std::fs::remove_file(&path).ok();
            return Ok(None);
        }
    };

    let now = jiff::Timestamp::now().as_second();
    if now - index.fetched_at > INDEX_CACHE_SECONDS {
        return Ok(None); // stale
    }

    Ok(Some(index))
}

fn save_index(index: &SkillIndex) -> Result<()> {
    let path = index_path()?;
    let content = serde_json::to_string_pretty(index)?;
    std::fs::write(&path, content).context("Failed to write skills index")?;
    Ok(())
}

async fn fetch_or_load_index(refresh: bool) -> Result<SkillIndex> {
    if !refresh && let Some(index) = load_cached_index()? {
        return Ok(index);
    }

    eprintln!("{}", "Fetching skills index from GitHub...".dimmed());

    let client = github_client()?;
    let mut skills = Vec::new();

    // Get top-level directories (orgs)
    let top_level = fetch_github_contents(&client, "").await?;
    let org_dirs: Vec<_> = top_level
        .iter()
        .filter(|c| {
            c.content_type == "dir"
                && !c.name.starts_with('.')
                && c.name != "node_modules"
                && c.name != ".github"
        })
        .collect();

    for org_dir in &org_dirs {
        // Get skill directories within each org
        let org_contents = match fetch_github_contents(&client, &org_dir.path).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        for skill_dir in org_contents.iter().filter(|c| c.content_type == "dir") {
            let slug = format!("{}-{}", org_dir.name, skill_dir.name);

            // Try to fetch SKILL.md for frontmatter
            let skill_md_url = format!(
                "https://raw.githubusercontent.com/serenorg/seren-skills/main/{}/{}/SKILL.md",
                org_dir.name, skill_dir.name
            );

            let description = match fetch_raw_file(&client, &skill_md_url).await {
                Ok(content) => {
                    let (_, desc) = parse_frontmatter(&content);
                    desc
                }
                Err(_) => String::new(),
            };

            skills.push(SkillEntry {
                org: org_dir.name.clone(),
                name: skill_dir.name.clone(),
                slug,
                description,
            });
        }
    }

    let index = SkillIndex {
        skills,
        fetched_at: jiff::Timestamp::now().as_second(),
    };

    save_index(&index)?;
    Ok(index)
}

// --- Agent directory detection ---

fn detect_agent_dirs() -> Result<Vec<(String, PathBuf)>> {
    let home = home_dir()?;
    let mut found = Vec::new();

    for (agent_name, relative_path) in AGENT_DIRS {
        let dir = home.join(relative_path);
        if dir.exists() {
            found.push((agent_name.to_string(), dir));
        }
    }

    Ok(found)
}

fn prompt_yes_no(message: &str) -> bool {
    eprint!("{} [Y/n] ", message);
    io::stderr().flush().ok();

    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return false;
    }

    let answer = line.trim().to_lowercase();
    answer.is_empty() || answer == "y" || answer == "yes"
}

fn copy_skill_to_dir(skill_dir: &Path, target_base: &Path, org: &str, name: &str) -> Result<()> {
    let target = target_base.join(format!("{}-{}", org, name));
    if target.exists() {
        std::fs::remove_dir_all(&target).ok();
    }
    copy_dir_recursive(skill_dir, &target)?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn remove_skill_from_agents(slug: &str) -> Result<()> {
    let home = home_dir()?;
    for (agent_name, relative_path) in AGENT_DIRS {
        let skill_path = home.join(relative_path).join(slug);
        if skill_path.exists() {
            std::fs::remove_dir_all(&skill_path)
                .with_context(|| format!("Failed to remove from {} directory", agent_name))?;
            eprintln!("  Removed from {}", agent_name);
        }
    }
    Ok(())
}

// --- Install helpers ---

async fn install_single_skill(
    client: &reqwest::Client,
    org: &str,
    name: &str,
    target_dir: &Path,
) -> Result<()> {
    let org_dir = target_dir.join(org);
    std::fs::create_dir_all(&org_dir)?;

    let final_path = org_dir.join(name);
    let staging_path = org_dir.join(format!(".{}.staging-{}", name, Uuid::new_v4()));
    std::fs::create_dir_all(&staging_path)?;

    let github_path = format!("{}/{}", org, name);
    if let Err(err) = install_directory_recursive(client, &github_path, &staging_path).await {
        std::fs::remove_dir_all(&staging_path).ok();
        return Err(err);
    }

    if !staging_path.join("SKILL.md").exists() {
        std::fs::remove_dir_all(&staging_path).ok();
        anyhow::bail!("Downloaded skill '{}/{}' is missing SKILL.md", org, name);
    }

    if final_path.exists() {
        let backup_path = org_dir.join(format!(".{}.backup-{}", name, Uuid::new_v4()));
        std::fs::rename(&final_path, &backup_path).with_context(|| {
            format!(
                "Failed to backup existing skill at {}",
                final_path.display()
            )
        })?;

        if let Err(err) = std::fs::rename(&staging_path, &final_path) {
            let _ = std::fs::rename(&backup_path, &final_path);
            let _ = std::fs::remove_dir_all(&staging_path);
            return Err(anyhow::anyhow!(
                "Failed to finalize install for '{}/{}': {}",
                org,
                name,
                err
            ));
        }

        std::fs::remove_dir_all(&backup_path).ok();
    } else {
        std::fs::rename(&staging_path, &final_path)
            .with_context(|| format!("Failed to finalize install at {}", final_path.display()))?;
    }

    Ok(())
}

fn install_directory_recursive<'a>(
    client: &'a reqwest::Client,
    github_path: &'a str,
    local_path: &'a Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let contents = fetch_github_contents(client, github_path).await?;

        for item in &contents {
            let item_local_path = local_path.join(&item.name);

            // Path traversal protection
            if item.name.contains("..") || item.name.starts_with('/') {
                continue;
            }

            if item.content_type == "dir" {
                std::fs::create_dir_all(&item_local_path)?;
                install_directory_recursive(client, &item.path, &item_local_path).await?;
            } else if item.content_type == "file"
                && let Some(download_url) = &item.download_url
            {
                let content = fetch_raw_file(client, download_url).await?;
                std::fs::write(&item_local_path, &content)?;
            }
        }

        Ok(())
    })
}

async fn install_all_via_tarball(target_dir: &Path) -> Result<usize> {
    let client = github_client()?;
    eprintln!("{}", "Downloading skills repository...".dimmed());
    let tarball_bytes = fetch_raw_bytes(&client, GITHUB_TARBALL_URL).await?;

    eprintln!("{}", "Extracting skills...".dimmed());
    let decoder = flate2::read::GzDecoder::new(&tarball_bytes[..]);
    let mut archive = tar::Archive::new(decoder);

    let mut installed_count = 0;
    let mut seen_skills: HashMap<String, bool> = HashMap::new();

    for entry in archive.entries().context("Failed to read tar archive")? {
        let mut entry = entry.context("Failed to read tar entry")?;
        let raw_path = entry
            .path()
            .context("Invalid path in tar entry")?
            .into_owned();
        let raw_name = raw_path.to_string_lossy().to_string();

        // Tar entries look like: seren-skills-main/org/skill-name/file.md
        // Strip the top-level directory prefix
        let parts: Vec<&str> = raw_name.splitn(2, '/').collect();
        if parts.len() < 2 || parts[1].is_empty() {
            continue;
        }
        let relative = parts[1];

        // Skip dotfiles, README, CONTRIBUTING at root level
        let segments: Vec<&str> = relative.split('/').collect();
        if segments.is_empty() {
            continue;
        }
        if segments[0].starts_with('.')
            || segments[0] == "README.md"
            || segments[0] == "CONTRIBUTING.md"
        {
            continue;
        }

        // Only process files that are at least org/skill-name depth
        if segments.len() < 2 {
            continue;
        }

        // Path traversal protection
        if segments.iter().any(|s| s.contains("..")) {
            continue;
        }

        let target_path = target_dir.join(relative);

        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&target_path)?;
        } else if entry.header().entry_type().is_file() {
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut content = Vec::new();
            entry.read_to_end(&mut content)?;
            std::fs::write(&target_path, &content)?;

            // Track unique skills
            if segments.len() >= 2 {
                let key = format!("{}/{}", segments[0], segments[1]);
                if let std::collections::hash_map::Entry::Vacant(e) = seen_skills.entry(key) {
                    e.insert(true);
                    installed_count += 1;
                }
            }
        }
    }

    Ok(installed_count)
}

fn scan_installed_skills(base_dir: &Path) -> Result<Vec<SkillEntry>> {
    let mut skills = Vec::new();

    if !base_dir.exists() {
        return Ok(skills);
    }

    for org_entry in std::fs::read_dir(base_dir)? {
        let org_entry = org_entry?;
        if !org_entry.file_type()?.is_dir() {
            continue;
        }
        let org_name = org_entry.file_name().to_string_lossy().to_string();
        if org_name.starts_with('.') {
            continue;
        }

        for skill_entry in std::fs::read_dir(org_entry.path())? {
            let skill_entry = skill_entry?;
            if !skill_entry.file_type()?.is_dir() {
                continue;
            }
            let skill_name = skill_entry.file_name().to_string_lossy().to_string();

            let skill_md_path = skill_entry.path().join("SKILL.md");
            if !skill_md_path.exists() {
                continue;
            }

            let description = match std::fs::read_to_string(&skill_md_path) {
                Ok(content) => {
                    let (_, desc) = parse_frontmatter(&content);
                    desc
                }
                Err(_) => String::new(),
            };

            skills.push(SkillEntry {
                org: org_name.clone(),
                name: skill_name.clone(),
                slug: format!("{}-{}", org_name, skill_name),
                description,
            });
        }
    }

    Ok(skills)
}

// --- Command implementations ---

pub async fn list(refresh: bool, ctx: &CommandContext) -> Result<()> {
    let index = fetch_or_load_index(refresh).await?;

    if index.skills.is_empty() {
        println!("No skills found");
        return Ok(());
    }

    match ctx.format {
        OutputFormat::Json => output::print_json(&index.skills)?,
        OutputFormat::Table => print_skills_table(&index.skills),
    }

    Ok(())
}

pub async fn search(query: &str, ctx: &CommandContext) -> Result<()> {
    let index = fetch_or_load_index(false).await?;
    let query_lower = query.to_lowercase();

    let matches: Vec<_> = index
        .skills
        .iter()
        .filter(|s| {
            s.slug.to_lowercase().contains(&query_lower)
                || s.description.to_lowercase().contains(&query_lower)
                || s.org.to_lowercase().contains(&query_lower)
                || s.name.to_lowercase().contains(&query_lower)
        })
        .cloned()
        .collect();

    if matches.is_empty() {
        println!("No skills found matching '{}'", query);
        return Ok(());
    }

    match ctx.format {
        OutputFormat::Json => output::print_json(&matches)?,
        OutputFormat::Table => print_skills_table(&matches),
    }

    Ok(())
}

pub async fn show(slug: &str, ctx: &CommandContext) -> Result<()> {
    let client = github_client()?;
    let (org, name) = resolve_remote_slug(&client, slug).await?;
    let github_path = format!("{}/{}", org, name);
    let contents = fetch_github_contents(&client, &github_path)
        .await
        .with_context(|| format!("Skill '{}' not found", slug))?;

    // Fetch SKILL.md content
    let skill_md = contents.iter().find(|c| c.name == "SKILL.md");
    let skill_content = if let Some(md) = skill_md {
        if let Some(url) = &md.download_url {
            fetch_raw_file(&client, url).await.ok()
        } else {
            None
        }
    } else {
        None
    };

    match ctx.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "slug": slug,
                "org": org,
                "name": name,
                "files": contents.iter().map(|c| &c.name).collect::<Vec<_>>(),
                "skill_md": skill_content,
            });
            output::print_json(&json)?;
        }
        OutputFormat::Table => {
            let (parsed_name, description) = skill_content
                .as_deref()
                .map(parse_frontmatter)
                .unwrap_or_default();

            println!("{}", format!("  {}", slug).bold());
            println!();
            if !parsed_name.is_empty() {
                println!("  Name:        {}", parsed_name);
            }
            if !description.is_empty() {
                println!("  Description: {}", description);
            }
            println!("  Org:         {}", org);
            println!();

            println!("  {}", "Files:".bold());
            for item in &contents {
                let icon = if item.content_type == "dir" {
                    "📁"
                } else {
                    "📄"
                };
                println!("    {} {}", icon, item.name);
            }

            // Show first ~20 lines of SKILL.md body (after frontmatter)
            if let Some(content) = &skill_content
                && let Some(body) = extract_body(content)
            {
                println!();
                println!("  {}", "Preview:".bold());
                for line in body.lines().take(20) {
                    println!("    {}", line);
                }
                let total_lines = body.lines().count();
                if total_lines > 20 {
                    println!(
                        "    {}",
                        format!("... ({} more lines)", total_lines - 20).dimmed()
                    );
                }
            }
        }
    }

    Ok(())
}

pub async fn add(slug: Option<&str>, all: bool, yes: bool) -> Result<()> {
    let base = skills_dir()?;

    if all {
        let count = install_all_via_tarball(&base).await?;
        eprintln!(
            "{}",
            format!("Installed {} skills to {}", count, base.display()).green()
        );
        offer_agent_install_all(&base, yes)?;
    } else {
        let slug = slug.ok_or_else(|| anyhow::anyhow!("Provide a skill slug, or use --all"))?;
        let client = github_client()?;
        let (org, name) = resolve_remote_slug(&client, slug).await.with_context(|| {
            format!(
                "Skill '{}' not found. Try: seren skills search <query>",
                slug
            )
        })?;
        eprintln!("{}", format!("Installing {}...", slug).dimmed());
        install_single_skill(&client, &org, &name, &base).await?;

        let skill_path = base.join(&org).join(&name);
        eprintln!(
            "{}",
            format!("Installed {} to {}", slug, skill_path.display()).green()
        );

        offer_agent_install_single(&skill_path, &org, &name, yes)?;
    }

    Ok(())
}

pub async fn installed(ctx: &CommandContext) -> Result<()> {
    let base = skills_dir()?;
    let skills = scan_installed_skills(&base)?;

    if skills.is_empty() {
        println!("No skills installed");
        println!(
            "{}",
            "Run 'seren skills add <slug>' to install a skill".dimmed()
        );
        return Ok(());
    }

    match ctx.format {
        OutputFormat::Json => output::print_json(&skills)?,
        OutputFormat::Table => {
            println!(
                "{}\n",
                format!("Skills directory: {}", base.display()).dimmed()
            );
            print_skills_table(&skills);
        }
    }

    Ok(())
}

pub async fn remove(slug: &str) -> Result<()> {
    let base = skills_dir()?;
    let (org, name) = resolve_installed_slug(&base, slug)?;
    let skill_path = base.join(&org).join(&name);

    std::fs::remove_dir_all(&skill_path)
        .with_context(|| format!("Failed to remove {}", skill_path.display()))?;

    // Clean up empty org directory
    let org_path = base.join(&org);
    if org_path.exists()
        && let Ok(mut entries) = std::fs::read_dir(&org_path)
        && entries.next().is_none()
    {
        std::fs::remove_dir(&org_path).ok();
    }

    eprintln!(
        "{}",
        format!("Removed {} from {}", slug, base.display()).green()
    );

    // Also remove from agent directories
    let resolved_slug = format!("{}-{}", org, name);
    remove_skill_from_agents(&resolved_slug)?;

    Ok(())
}

pub async fn update(slug: Option<&str>, yes: bool) -> Result<()> {
    let base = skills_dir()?;

    if let Some(slug) = slug {
        // Update a single skill
        let (org, name) = resolve_installed_slug(&base, slug).with_context(|| {
            format!(
                "Skill '{}' is not installed. Use 'seren skills add {}' first.",
                slug, slug
            )
        })?;

        let client = github_client()?;
        eprintln!("{}", format!("Updating {}...", slug).dimmed());
        install_single_skill(&client, &org, &name, &base).await?;
        eprintln!("{}", format!("Updated {}", slug).green());

        let skill_path = base.join(&org).join(&name);
        offer_agent_install_single(&skill_path, &org, &name, yes)?;
    } else {
        // Update all installed skills
        let installed_skills = scan_installed_skills(&base)?;
        if installed_skills.is_empty() {
            println!("No skills installed to update");
            return Ok(());
        }

        eprintln!(
            "{}",
            format!("Updating {} installed skills...", installed_skills.len()).dimmed()
        );

        // Use tarball download for efficiency
        let count = install_all_via_tarball(&base).await?;
        eprintln!("{}", format!("Updated {} skills", count).green());

        offer_agent_install_all(&base, yes)?;
    }

    // Refresh index
    fetch_or_load_index(true).await?;

    Ok(())
}

pub fn init(name: Option<&str>, path: Option<&str>) -> Result<()> {
    let base_dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let skill_dir = if let Some(name) = name {
        base_dir.join(name)
    } else {
        base_dir.clone()
    };

    std::fs::create_dir_all(&skill_dir)?;

    let skill_name = name.unwrap_or_else(|| {
        skill_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my-skill")
    });

    let skill_md_path = skill_dir.join("SKILL.md");
    if skill_md_path.exists() {
        anyhow::bail!("SKILL.md already exists at {}", skill_md_path.display());
    }

    let display_name: String = skill_name
        .split('-')
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let template = format!(
        r#"---
name: {skill_name}
description: ""
---

# {display_name}

## When to Use

Describe when an agent should activate this skill.

## Workflow

1. Step one
2. Step two
3. Step three

## Examples

```
Example usage here
```
"#
    );

    std::fs::write(&skill_md_path, template)?;
    eprintln!("{}", format!("Created {}", skill_md_path.display()).green());
    eprintln!(
        "{}",
        "Edit the SKILL.md file to define your skill, then submit it to the skills repo.".dimmed()
    );

    Ok(())
}

// --- Agent install helpers ---

fn offer_agent_install_single(skill_path: &Path, org: &str, name: &str, yes: bool) -> Result<()> {
    let detected = detect_agent_dirs()?;
    if detected.is_empty() {
        return Ok(());
    }

    eprintln!();
    eprintln!("{}", "Detected agent directories:".bold());

    for (agent_name, agent_dir) in &detected {
        let should_install = if yes {
            true
        } else {
            prompt_yes_no(&format!(
                "  Install to {} ({})?",
                agent_name,
                agent_dir.display()
            ))
        };

        if should_install {
            copy_skill_to_dir(skill_path, agent_dir, org, name)?;
            eprintln!("    {}", format!("Installed to {}", agent_name).green());
        }
    }

    Ok(())
}

fn offer_agent_install_all(skills_base: &Path, yes: bool) -> Result<()> {
    let detected = detect_agent_dirs()?;
    if detected.is_empty() {
        return Ok(());
    }

    let skills = scan_installed_skills(skills_base)?;
    if skills.is_empty() {
        return Ok(());
    }

    eprintln!();
    eprintln!("{}", "Detected agent directories:".bold());

    for (agent_name, agent_dir) in &detected {
        let should_install = if yes {
            true
        } else {
            prompt_yes_no(&format!(
                "  Install all {} skills to {} ({})?",
                skills.len(),
                agent_name,
                agent_dir.display()
            ))
        };

        if should_install {
            for skill in &skills {
                let skill_path = skills_base.join(&skill.org).join(&skill.name);
                copy_skill_to_dir(&skill_path, agent_dir, &skill.org, &skill.name)?;
            }
            eprintln!(
                "    {}",
                format!("Installed {} skills to {}", skills.len(), agent_name).green()
            );
        }
    }

    Ok(())
}

// --- Output helpers ---

fn print_skills_table(skills: &[SkillEntry]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Slug").fg(Color::Green),
        Cell::new("Org").fg(Color::Green),
        Cell::new("Description").fg(Color::Green),
    ]);

    for skill in skills {
        let desc = if skill.description.len() > 80 {
            format!("{}...", &skill.description[..77])
        } else {
            skill.description.clone()
        };
        table.add_row(vec![
            Cell::new(&skill.slug),
            Cell::new(&skill.org),
            Cell::new(desc),
        ]);
    }

    println!("{table}");
}

fn extract_body(content: &str) -> Option<&str> {
    if !content.starts_with("---") {
        return Some(content);
    }
    let after_first = &content[3..];
    let end = after_first.find("---")?;
    let body = &after_first[end + 3..];
    let body = body.trim_start();
    if body.is_empty() { None } else { Some(body) }
}
