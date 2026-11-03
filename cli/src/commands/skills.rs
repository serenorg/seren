use std::io::{self, BufRead, Write};
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

/// Path of the public skills publisher under the configured Seren API address.
/// Catalog and download reads answer without a login, so no credential is sent.
const SKILLS_PUBLISHER_PATH: &str = "/publishers/seren-skills";
const CATALOG_PAGE_LIMIT: usize = 100;
/// Bounded fan-out for `add --all` and `update` (no bulk download route exists).
const BULK_INSTALL_CONCURRENCY: usize = 6;
/// Per-file fan-out when an oversized bundle falls back to split downloads.
const SPLIT_DOWNLOAD_CONCURRENCY: usize = 4;
/// Backoff before each retry of a transient gateway failure.
const TRANSIENT_RETRY_DELAYS_MS: &[u64] = &[250, 1000];
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

#[derive(Debug, Clone, Deserialize)]
struct CatalogSkill {
    slug: String,
    #[serde(default)]
    skill_folder_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CatalogPage {
    data: Vec<CatalogSkill>,
    #[serde(default)]
    pagination: Option<CatalogPagination>,
}

#[derive(Debug, Deserialize)]
struct CatalogPagination {
    #[serde(default)]
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct SkillBundle {
    skill: CatalogSkill,
    skill_md: String,
    #[serde(default)]
    files: Vec<BundleFile>,
}

#[derive(Debug, Deserialize)]
struct BundleFile {
    path: String,
    content_b64: String,
    #[serde(default)]
    mode: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SkillManifest {
    skill: CatalogSkill,
    skill_md: String,
    #[serde(default)]
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    path: String,
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

/// Local `<org>/<name>` folder for a catalog skill, chosen so that
/// `{org}-{name}` always rebuilds the catalog slug.
///
/// The name is the skill's `skill_folder_name` and the org is the rest of the
/// slug. A user-owned skill's slug can equal its folder name
/// (`solo-arb-bot`); it then splits at its first dash (`solo/arb-bot`).
fn install_layout(slug: &str, folder: Option<&str>) -> Result<(String, String)> {
    if let Some(folder) = folder.filter(|f| !f.is_empty())
        && let Some(org) = slug
            .strip_suffix(folder)
            .and_then(|rest| rest.strip_suffix('-'))
        && !org.is_empty()
    {
        return Ok((org.to_string(), folder.to_string()));
    }
    slug_candidates(slug)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Skill slug '{}' has no org-name form to install", slug))
}

fn validate_slug(slug: &str) -> Result<()> {
    let valid = !slug.is_empty()
        && slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !slug.starts_with('.');
    if !valid {
        anyhow::bail!("Invalid slug '{}'. Expected format: org-skill-name", slug);
    }
    Ok(())
}

// --- Skills catalog (seren-skills publisher) ---

/// What a catalog read answered, once transient gateway failures are retried.
enum CatalogReply {
    Found(Vec<u8>),
    NotFound,
    /// Any other HTTP status; a 500 on a bundle download means "too large".
    Status(reqwest::StatusCode),
}

#[derive(Clone)]
struct SkillsCatalog {
    client: reqwest::Client,
    base: String,
}

impl SkillsCatalog {
    fn new(api_base: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("seren-cli/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .context("Failed to create HTTP client")?;
        Ok(Self {
            client,
            base: format!(
                "{}{}",
                api_base.trim_end_matches('/'),
                SKILLS_PUBLISHER_PATH
            ),
        })
    }

    fn from_ctx(ctx: &CommandContext) -> Result<Self> {
        Self::new(&ctx.api_base())
    }

    fn unreachable(&self, reason: impl std::fmt::Display) -> anyhow::Error {
        anyhow::anyhow!(
            "Couldn't reach the Seren skills catalog at {}: {}",
            self.base,
            reason
        )
    }

    async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<CatalogReply> {
        let url = format!("{}{}", self.base, path);
        let mut attempt = 0;
        loop {
            let delay = TRANSIENT_RETRY_DELAYS_MS.get(attempt).copied();
            attempt += 1;
            match self.client.get(&url).query(query).send().await {
                Ok(response) => {
                    let status = response.status();
                    if matches!(status.as_u16(), 502..=504) {
                        if let Some(ms) = delay {
                            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                            continue;
                        }
                        return Err(self.unreachable(format!("HTTP {}", status)));
                    }
                    if status == reqwest::StatusCode::NOT_FOUND {
                        return Ok(CatalogReply::NotFound);
                    }
                    if !status.is_success() {
                        return Ok(CatalogReply::Status(status));
                    }
                    let body = response.bytes().await.map_err(|e| self.unreachable(e))?;
                    return Ok(CatalogReply::Found(body.to_vec()));
                }
                Err(err) => {
                    if let Some(ms) = delay {
                        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                        continue;
                    }
                    return Err(self.unreachable(err));
                }
            }
        }
    }

    /// Read a JSON reply; `None` means the catalog has no such skill.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Option<T>> {
        match self.get(path, query).await? {
            CatalogReply::Found(body) => {
                let envelope: Envelope<T> = serde_json::from_slice(&body)
                    .map_err(|e| self.unreachable(format!("unexpected reply ({})", e)))?;
                Ok(Some(envelope.data))
            }
            CatalogReply::NotFound => Ok(None),
            CatalogReply::Status(status) => Err(self.unreachable(format!("HTTP {}", status))),
        }
    }

    async fn list_all(&self) -> Result<Vec<CatalogSkill>> {
        let mut skills = Vec::new();
        loop {
            let query = [
                ("limit", CATALOG_PAGE_LIMIT.to_string()),
                ("offset", skills.len().to_string()),
            ];
            let page = match self.get("/skills", &query).await? {
                CatalogReply::Found(body) => serde_json::from_slice::<CatalogPage>(&body)
                    .map_err(|e| self.unreachable(format!("unexpected reply ({})", e)))?,
                CatalogReply::NotFound => {
                    return Err(self.unreachable("HTTP 404 Not Found"));
                }
                CatalogReply::Status(status) => {
                    return Err(self.unreachable(format!("HTTP {}", status)));
                }
            };
            let count = page.data.len();
            skills.extend(page.data);
            let has_more = page.pagination.map(|p| p.has_more).unwrap_or(false);
            if !has_more || count == 0 {
                return Ok(skills);
            }
        }
    }

    async fn manifest(&self, slug: &str) -> Result<Option<SkillManifest>> {
        validate_slug(slug)?;
        self.get_json(&format!("/skills/{}/download/manifest", slug), &[])
            .await
    }

    /// Download a skill's files; `None` means the catalog has no such skill.
    async fn bundle(&self, slug: &str) -> Result<Option<SkillBundle>> {
        validate_slug(slug)?;
        match self.get(&format!("/skills/{}/download", slug), &[]).await? {
            CatalogReply::Found(body) => {
                let envelope: Envelope<SkillBundle> = serde_json::from_slice(&body)
                    .map_err(|e| self.unreachable(format!("unexpected reply ({})", e)))?;
                Ok(Some(envelope.data))
            }
            CatalogReply::NotFound => Ok(None),
            // The gateway answers an oversized bundle with a 500: fetch the
            // manifest and then each file on its own.
            CatalogReply::Status(status)
                if status == reqwest::StatusCode::INTERNAL_SERVER_ERROR =>
            {
                self.split_bundle(slug).await
            }
            CatalogReply::Status(status) => Err(self.unreachable(format!("HTTP {}", status))),
        }
    }

    async fn split_bundle(&self, slug: &str) -> Result<Option<SkillBundle>> {
        use futures_util::stream::{self, StreamExt, TryStreamExt};

        let Some(manifest) = self.manifest(slug).await? else {
            return Ok(None);
        };
        let path = format!("/skills/{}/download/file", slug);
        let files: Vec<BundleFile> = stream::iter(manifest.files)
            .map(|meta| {
                let path = path.clone();
                async move {
                    self.get_json::<BundleFile>(&path, &[("path", meta.path.clone())])
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Skill '{}' changed during download: file '{}' is gone. Try again.",
                                slug,
                                meta.path
                            )
                        })
                }
            })
            .buffered(SPLIT_DOWNLOAD_CONCURRENCY)
            .try_collect()
            .await?;
        Ok(Some(SkillBundle {
            skill: manifest.skill,
            skill_md: manifest.skill_md,
            files,
        }))
    }
}

fn catalog_entry(skill: CatalogSkill) -> Option<SkillEntry> {
    let (org, name) = install_layout(&skill.slug, skill.skill_folder_name.as_deref()).ok()?;
    Some(SkillEntry {
        org,
        name,
        slug: skill.slug,
        description: skill.description.unwrap_or_default(),
    })
}

/// A bundle path as a safe relative path, or `None` when it would escape the
/// skill folder.
fn safe_relative_path(path: &str) -> Option<PathBuf> {
    use std::path::Component;
    let relative = Path::new(path);
    if path.is_empty() || path.contains('\\') {
        return None;
    }
    let mut out = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn write_bundle(bundle: &SkillBundle, dir: &Path) -> Result<()> {
    use base64::Engine as _;

    for file in &bundle.files {
        let relative = safe_relative_path(&file.path).ok_or_else(|| {
            anyhow::anyhow!(
                "Skill '{}' has an unsafe file path '{}'",
                bundle.skill.slug,
                file.path
            )
        })?;
        let content = base64::engine::general_purpose::STANDARD
            .decode(file.content_b64.as_bytes())
            .with_context(|| format!("Skill file '{}' is not valid base64", file.path))?;
        let target = dir.join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, &content)
            .with_context(|| format!("Failed to write {}", target.display()))?;
        #[cfg(unix)]
        if let Some(mode) = file.mode {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode & 0o777))?;
        }
    }

    // SKILL.md comes in its own field, never in `files`.
    std::fs::write(dir.join("SKILL.md"), &bundle.skill_md).context("Failed to write SKILL.md")?;
    Ok(())
}

// --- Frontmatter parsing ---

fn parse_frontmatter(content: &str) -> (String, String) {
    let mut name = String::new();
    let mut description = String::new();

    if !content.starts_with("---") {
        return (name, description);
    }

    if let Some(end) = content[3..].find("\n---") {
        let frontmatter = &content[3..3 + end];
        let lines: Vec<&str> = frontmatter.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let raw = lines[i];
            let line = raw.trim();
            i += 1;
            let (field, val) = if let Some(val) = line.strip_prefix("name:") {
                (&mut name, val.trim())
            } else if let Some(val) = line.strip_prefix("description:") {
                (&mut description, val.trim())
            } else {
                continue;
            };
            if raw.starts_with(char::is_whitespace) {
                continue; // nested key, not top level
            }
            if matches!(val, "" | ">" | ">-" | "|" | "|-") {
                // YAML block scalar: join the indented lines that follow.
                let mut parts = Vec::new();
                while i < lines.len() && lines[i].starts_with(char::is_whitespace) {
                    parts.push(lines[i].trim());
                    i += 1;
                }
                *field = parts.join(" ");
            } else {
                *field = val.trim_matches('"').trim_matches('\'').to_string();
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

async fn fetch_or_load_index(catalog: &SkillsCatalog, refresh: bool) -> Result<SkillIndex> {
    if !refresh && let Some(index) = load_cached_index()? {
        return Ok(index);
    }

    eprintln!("{}", "Fetching the Seren skills catalog...".dimmed());

    let skills = catalog
        .list_all()
        .await?
        .into_iter()
        .filter_map(catalog_entry)
        .collect();

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

/// Download a skill from the catalog and install it at `<target_dir>/<org>/<name>`.
async fn install_single_skill(
    catalog: &SkillsCatalog,
    slug: &str,
    target_dir: &Path,
) -> Result<(String, String)> {
    let bundle = catalog.bundle(slug).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "Skill '{}' not found. Try: seren skills search <query>",
            slug
        )
    })?;
    let (org, name) = install_layout(
        &bundle.skill.slug,
        bundle.skill.skill_folder_name.as_deref(),
    )?;

    let org_dir = target_dir.join(&org);
    std::fs::create_dir_all(&org_dir)?;

    let final_path = org_dir.join(&name);
    let staging_path = org_dir.join(format!(".{}.staging-{}", name, Uuid::new_v4()));
    std::fs::create_dir_all(&staging_path)?;

    if let Err(err) = write_bundle(&bundle, &staging_path) {
        std::fs::remove_dir_all(&staging_path).ok();
        return Err(err);
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

    Ok((org, name))
}

/// Install each slug with bounded concurrency; returns the installed count and
/// the failures.
async fn install_many(
    catalog: &SkillsCatalog,
    slugs: Vec<String>,
    target_dir: &Path,
) -> (usize, Vec<(String, anyhow::Error)>) {
    use futures_util::stream::{self, StreamExt};

    let results: Vec<(String, Result<(String, String)>)> = stream::iter(slugs)
        .map(|slug| async move {
            let result = install_single_skill(catalog, &slug, target_dir).await;
            (slug, result)
        })
        .buffer_unordered(BULK_INSTALL_CONCURRENCY)
        .collect()
        .await;

    let mut installed = 0;
    let mut failures = Vec::new();
    for (slug, result) in results {
        match result {
            Ok(_) => installed += 1,
            Err(err) => failures.push((slug, err)),
        }
    }
    (installed, failures)
}

fn report_failures(failures: &[(String, anyhow::Error)], verb: &str) -> Result<()> {
    if failures.is_empty() {
        return Ok(());
    }
    for (slug, err) in failures {
        eprintln!("{}", format!("  {}: {:#}", slug, err).red());
    }
    anyhow::bail!("{} skills failed to {}", failures.len(), verb)
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
    let catalog = SkillsCatalog::from_ctx(ctx)?;
    let index = fetch_or_load_index(&catalog, refresh).await?;

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
    let catalog = SkillsCatalog::from_ctx(ctx)?;
    let index = fetch_or_load_index(&catalog, false).await?;
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
    let catalog = SkillsCatalog::from_ctx(ctx)?;
    let manifest = catalog.manifest(slug).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "Skill '{}' not found. Try: seren skills search <query>",
            slug
        )
    })?;
    let (org, name) = install_layout(
        &manifest.skill.slug,
        manifest.skill.skill_folder_name.as_deref(),
    )?;
    let files: Vec<&str> = std::iter::once("SKILL.md")
        .chain(manifest.files.iter().map(|f| f.path.as_str()))
        .collect();
    let skill_content = Some(manifest.skill_md.clone());

    match ctx.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "slug": manifest.skill.slug,
                "org": org,
                "name": name,
                "description": manifest.skill.description,
                "files": files,
                "skill_md": skill_content,
            });
            output::print_json(&json)?;
        }
        OutputFormat::Table => {
            let (parsed_name, parsed_description) = parse_frontmatter(&manifest.skill_md);
            let description = manifest
                .skill
                .description
                .clone()
                .filter(|d| !d.is_empty())
                .unwrap_or(parsed_description);

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
            for file in &files {
                println!("    📄 {}", file);
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

pub async fn add(slug: Option<&str>, all: bool, yes: bool, ctx: &CommandContext) -> Result<()> {
    let base = skills_dir()?;
    let catalog = SkillsCatalog::from_ctx(ctx)?;

    if all {
        let index = fetch_or_load_index(&catalog, true).await?;
        let slugs: Vec<String> = index.skills.iter().map(|s| s.slug.clone()).collect();
        eprintln!(
            "{}",
            format!("Installing {} skills...", slugs.len()).dimmed()
        );
        let (count, failures) = install_many(&catalog, slugs, &base).await;
        eprintln!(
            "{}",
            format!("Installed {} skills to {}", count, base.display()).green()
        );
        offer_agent_install_all(&base, yes)?;
        report_failures(&failures, "install")?;
    } else {
        let slug = slug.ok_or_else(|| anyhow::anyhow!("Provide a skill slug, or use --all"))?;
        eprintln!("{}", format!("Installing {}...", slug).dimmed());
        let (org, name) = install_single_skill(&catalog, slug, &base).await?;

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

pub async fn update(slug: Option<&str>, yes: bool, ctx: &CommandContext) -> Result<()> {
    let base = skills_dir()?;
    let catalog = SkillsCatalog::from_ctx(ctx)?;

    if let Some(slug) = slug {
        // Update a single skill
        let (org, name) = resolve_installed_slug(&base, slug).with_context(|| {
            format!(
                "Skill '{}' is not installed. Use 'seren skills add {}' first.",
                slug, slug
            )
        })?;

        eprintln!("{}", format!("Updating {}...", slug).dimmed());
        install_single_skill(&catalog, &format!("{}-{}", org, name), &base).await?;
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

        let slugs = installed_skills.into_iter().map(|s| s.slug).collect();
        let (count, failures) = install_many(&catalog, slugs, &base).await;
        eprintln!("{}", format!("Updated {} skills", count).green());

        offer_agent_install_all(&base, yes)?;
        report_failures(&failures, "update")?;
    }

    // Refresh index
    fetch_or_load_index(&catalog, true).await?;

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
        "Edit the SKILL.md file to define your skill, then publish it to the Seren skills catalog."
            .dimmed()
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
        .load_style(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Slug").fg(Color::Green),
        Cell::new("Org").fg(Color::Green),
        Cell::new("Description").fg(Color::Green),
    ]);

    for skill in skills {
        let desc = if skill.description.chars().count() > 80 {
            format!(
                "{}...",
                skill.description.chars().take(77).collect::<String>()
            )
        } else {
            skill.description.clone()
        };
        table.add_row(vec![
            Cell::new(&skill.slug),
            Cell::new(&skill.org),
            Cell::new(desc),
        ]);
    }

    output::print_table(&mut table);
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn b64(text: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    fn skill_json(slug: &str, folder: &str) -> serde_json::Value {
        json!({ "slug": slug, "skill_folder_name": folder, "description": format!("{slug} description") })
    }

    fn bundle_json(slug: &str, folder: &str) -> serde_json::Value {
        json!({ "data": {
            "skill": skill_json(slug, folder),
            "skill_md": "---\ndescription: Unquoted: manage issues\nname: issue-tracking\n---\n\n# Body\n",
            "files": [
                { "path": "requirements.txt", "content_b64": b64("requests\n"), "mode": 33188, "is_binary": false },
                { "path": "scripts/agent.py", "content_b64": b64("print('hi')\n"), "mode": 33261, "is_binary": false }
            ]
        }})
    }

    #[tokio::test]
    async fn list_pages_through_the_whole_catalog_without_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/publishers/seren-skills/skills"))
            .and(query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [skill_json("acme-issue-tracking", "issue-tracking")],
                "pagination": { "has_more": true }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/publishers/seren-skills/skills"))
            .and(query_param("offset", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [skill_json("solo-arb-bot", "solo-arb-bot")],
                "pagination": { "has_more": false }
            })))
            .mount(&server)
            .await;

        let catalog = SkillsCatalog::new(&server.uri()).unwrap();
        let entries: Vec<SkillEntry> = catalog
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .filter_map(catalog_entry)
            .collect();
        let layout: Vec<_> = entries
            .iter()
            .map(|e| (e.slug.as_str(), e.org.as_str(), e.name.as_str()))
            .collect();
        assert_eq!(
            layout,
            vec![
                ("acme-issue-tracking", "acme", "issue-tracking"),
                ("solo-arb-bot", "solo", "arb-bot"),
            ]
        );
        for request in server.received_requests().await.unwrap() {
            assert!(!request.headers.contains_key("authorization"));
        }
    }

    #[tokio::test]
    async fn add_writes_skill_md_and_every_file_and_removes_by_slug() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/publishers/seren-skills/skills/acme-issue-tracking/download",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(bundle_json("acme-issue-tracking", "issue-tracking")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/publishers/seren-skills/skills/solo-arb-bot/download",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(bundle_json("solo-arb-bot", "solo-arb-bot")),
            )
            .mount(&server)
            .await;
        let catalog = SkillsCatalog::new(&server.uri()).unwrap();
        let dir = tempfile::tempdir().unwrap();

        let (org, name) = install_single_skill(&catalog, "acme-issue-tracking", dir.path())
            .await
            .unwrap();
        let skill = dir.path().join(&org).join(&name);
        assert_eq!((org.as_str(), name.as_str()), ("acme", "issue-tracking"));
        assert!(
            std::fs::read_to_string(skill.join("SKILL.md"))
                .unwrap()
                .contains("# Body")
        );
        assert_eq!(
            std::fs::read_to_string(skill.join("requirements.txt")).unwrap(),
            "requests\n"
        );
        assert_eq!(
            std::fs::read_to_string(skill.join("scripts/agent.py")).unwrap(),
            "print('hi')\n"
        );
        let installed = scan_installed_skills(dir.path()).unwrap();
        assert_eq!(installed[0].slug, "acme-issue-tracking");
        assert_eq!(installed[0].description, "Unquoted: manage issues");

        install_single_skill(&catalog, "solo-arb-bot", dir.path())
            .await
            .unwrap();
        assert_eq!(
            resolve_installed_slug(dir.path(), "solo-arb-bot").unwrap(),
            ("solo".to_string(), "arb-bot".to_string())
        );
    }

    #[tokio::test]
    async fn unknown_slug_says_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(json!({"error": {"code": 404, "message": "skill not found"}})),
            )
            .mount(&server)
            .await;
        let catalog = SkillsCatalog::new(&server.uri()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let err = install_single_skill(&catalog, "made-up-skill", dir.path())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("'made-up-skill' not found"),
            "{err}"
        );
        assert!(catalog.manifest("made-up-skill").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unreachable_catalog_says_it_could_not_be_reached() {
        let catalog = SkillsCatalog::new("http://127.0.0.1:9").unwrap();
        let err = catalog.list_all().await.unwrap_err().to_string();
        assert!(
            err.contains("Couldn't reach the Seren skills catalog"),
            "{err}"
        );
        let err = catalog
            .bundle("acme-issue-tracking")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Couldn't reach the Seren skills catalog"),
            "{err}"
        );
        assert!(!err.contains("not found"), "{err}");
    }

    #[tokio::test]
    async fn retries_transient_gateway_failures() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/publishers/seren-skills/skills"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/publishers/seren-skills/skills"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [skill_json("acme-issue-tracking", "issue-tracking")],
                "pagination": { "has_more": false }
            })))
            .mount(&server)
            .await;
        let catalog = SkillsCatalog::new(&server.uri()).unwrap();
        assert_eq!(catalog.list_all().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn oversized_bundle_falls_back_to_per_file_downloads() {
        let server = MockServer::start().await;
        let base = "/publishers/seren-skills/skills/big-skill";
        Mock::given(method("GET"))
            .and(path(format!("{base}/download")))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{base}/download/manifest")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {
                "skill": skill_json("big-skill", "skill"),
                "skill_md": "---\nname: skill\n---\n",
                "files": [{ "path": "data/large.bin", "size_bytes": 5 }]
            }})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{base}/download/file")))
            .and(query_param("path", "data/large.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {
                "path": "data/large.bin", "content_b64": b64("hello")
            }})))
            .mount(&server)
            .await;
        let catalog = SkillsCatalog::new(&server.uri()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (org, name) = install_single_skill(&catalog, "big-skill", dir.path())
            .await
            .unwrap();
        let skill = dir.path().join(org).join(name);
        assert_eq!(
            std::fs::read_to_string(skill.join("data/large.bin")).unwrap(),
            "hello"
        );
        assert!(skill.join("SKILL.md").exists());
    }

    #[test]
    fn bundle_paths_cannot_escape_the_skill_folder() {
        assert!(safe_relative_path("../evil").is_none());
        assert!(safe_relative_path("/etc/passwd").is_none());
        assert!(safe_relative_path("a/../../b").is_none());
        assert!(safe_relative_path("").is_none());
        assert_eq!(
            safe_relative_path("scripts/agent.py").unwrap(),
            PathBuf::from("scripts/agent.py")
        );
    }

    #[test]
    fn frontmatter_reads_reformatted_and_block_descriptions() {
        let (name, description) =
            parse_frontmatter("---\ndescription: Plain words, no quotes\nname: tool\n---\nbody");
        assert_eq!(
            (name.as_str(), description.as_str()),
            ("tool", "Plain words, no quotes")
        );
        let (_, description) = parse_frontmatter(
            "---\nname: tool\ndescription: >-\n  First line\n  second line\n---\n",
        );
        assert_eq!(description, "First line second line");
    }
}
