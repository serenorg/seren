use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    CatalogOwnerKind, CatalogSkill, SkillBundle, SkillEntry, SkillsCatalog,
    check_skill_destination, check_skill_file, check_skill_tree, home_dir, install_bundle_at,
    install_layout, parse_frontmatter, resolve_skill_path, skills_dir,
};
use crate::commands::memory_agent::{
    claude_settings_path, codex_settings_path, load_settings, owned_command_matches,
    write_new_file, write_settings_with_backup,
};

pub const CATALOG_ORIGIN: &str = "https://api.serendb.com";
const MCP_URL: &str = "https://mcp.serendb.com/mcp";
const SEREN_ORGANIZATION: Uuid = Uuid::from_u128(0x29);
const MANAGED_AGENT_SLUG: &str = "seren-seren-agent";
const MANAGED_AGENT_GUIDE: &str = "/publishers/seren-agent/skill.md";
const MAX_GUIDE_BYTES: usize = 256 * 1024;
const STARTER_SKILLS: &[&str] = &[
    "seren-api",
    MANAGED_AGENT_SLUG,
    "seren-seren-publishers",
    "seren-seren-db",
];
const STATE_FILE: &str = ".onboarding.json";
const CHECK_INTERVAL: i64 = 24 * 60 * 60;
const RETRY_INTERVAL: i64 = 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SkillAgent {
    ClaudeCode,
    Codex,
}

impl SkillAgent {
    fn label(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
        }
    }

    fn settings(self) -> Result<PathBuf> {
        match self {
            Self::ClaudeCode => claude_settings_path(),
            Self::Codex => codex_settings_path(),
        }
    }

    fn target(self) -> InstallTarget {
        match self {
            Self::ClaudeCode => InstallTarget::ClaudeCode,
            Self::Codex => InstallTarget::Shared,
        }
    }

    fn hook(self) -> &'static str {
        match self {
            Self::ClaudeCode => "seren skills update --hook --agent claude-code",
            Self::Codex => "seren skills update --hook --agent codex",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum InstallTarget {
    ClaudeCode,
    // Keep the recorded key for the shared directory previously set up for Codex.
    #[serde(rename = "codex")]
    Shared,
    Gemini,
}

impl InstallTarget {
    fn skills_root(self) -> Result<PathBuf> {
        let root = match self {
            Self::ClaudeCode => claude_settings_path()?.with_file_name("skills"),
            Self::Shared => home_dir()?.join(".agents/skills"),
            Self::Gemini => gemini_home(&home_dir()?).join(".agents/skills"),
        };
        resolve_skill_path(&root)
    }

    fn label(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Shared => "the shared skills directory",
            Self::Gemini => "Gemini CLI",
        }
    }
}

#[derive(Default, Deserialize, Serialize)]
struct State {
    #[serde(default)]
    dismissed: bool,
    #[serde(default)]
    agents: BTreeMap<InstallTarget, InstalledAgent>,
}

#[derive(Default, Deserialize, Serialize)]
struct InstalledAgent {
    root: PathBuf,
    enabled: bool,
    next_check: i64,
    skills: BTreeMap<String, Receipt>,
}

#[derive(Deserialize, Serialize)]
struct Receipt {
    version: Option<String>,
    publisher_hash: String,
    installed_hash: String,
}

fn read_state(base: &Path) -> Result<State> {
    let path = base.join(STATE_FILE);
    check_skill_file(&path)?;
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("Cannot read Seren skills setup state at {}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(State::default()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn list_managed(base: &Path) -> Result<Vec<SkillEntry>> {
    let mut skills = BTreeMap::new();
    for (target, installed) in read_state(base)?.agents {
        if target.skills_root()? != installed.root {
            continue;
        }
        for slug in installed.skills.keys() {
            if skills.contains_key(slug) {
                continue;
            }
            if let Ok(path) = check_skill_destination(&installed.root, &[slug.as_str()])
                && let Ok(markdown) = fs::read_to_string(path.join("SKILL.md"))
            {
                let (org, name) = install_layout(slug, None)?;
                let description = parse_frontmatter(&markdown).1;
                skills.insert(
                    slug.clone(),
                    SkillEntry {
                        org,
                        name,
                        slug: slug.clone(),
                        description,
                    },
                );
            }
        }
    }
    Ok(skills.into_values().collect())
}

fn save_state(base: &Path, state: &State) -> Result<()> {
    let path = base.join(STATE_FILE);
    check_skill_file(&path)?;
    let temporary = base.join(format!(".onboarding-{}.tmp", Uuid::new_v4()));
    let mut bytes = serde_json::to_vec_pretty(state)?;
    bytes.push(b'\n');
    write_new_file(&temporary, &bytes, None)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(temporary);
        return Err(error.into());
    }
    Ok(())
}

/// Explicit commands wait for the lock; the startup hook skips when another
/// process holds it. No holder prompts while locked, so waiting stays bounded.
fn lock_state(base: &Path, wait: bool) -> Result<Option<File>> {
    let path = base.join(".onboarding.lock");
    check_skill_file(&path)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    if wait {
        file.lock()?;
        return Ok(Some(file));
    }
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

fn wait_for_state(base: &Path) -> Result<File> {
    lock_state(base, true)?.context("Seren skills setup state is unavailable")
}

/// Remove setup-installed copies of a skill and forget their receipts.
/// Returns the paths handled here so legacy removal cannot touch them again.
pub(super) fn remove_managed(base: &Path, slug: &str) -> Result<Option<Vec<PathBuf>>> {
    super::validate_slug(slug)?;
    let _lock = wait_for_state(base)?;
    let mut state = read_state(base)?;
    let mut forgotten = false;
    let mut managed_paths = Vec::new();
    for (target, installed) in &mut state.agents {
        let Some(receipt) = installed.skills.get(slug) else {
            continue;
        };
        let path = resolve_skill_path(&installed.root)?.join(slug);
        managed_paths.push(path.clone());
        if target.skills_root()? != installed.root {
            eprintln!(
                "Kept {slug} in {} from another configuration directory.",
                path.display()
            );
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.is_dir()
                    && hash_tree(&path).is_ok_and(|hash| hash == receipt.installed_hash) =>
            {
                fs::remove_dir_all(&path)
                    .with_context(|| format!("Failed to remove {}", path.display()))?;
                eprintln!("Removed {slug} from {}.", path.display());
            }
            Ok(_) => {
                eprintln!(
                    "Kept the locally modified {slug} in {} and stopped managing it.",
                    path.display()
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!("Stopped managing {slug} in {}.", path.display());
            }
            Err(error) => return Err(error.into()),
        }
        installed.skills.remove(slug);
        forgotten = true;
    }
    if forgotten {
        save_state(base, &state)?;
    }
    Ok((!managed_paths.is_empty()).then_some(managed_paths))
}

/// How setup state treats a `seren skills add` copy into an agent directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SetupCopy {
    Free,
    /// A current default that setup and its updater refresh.
    Managed,
    /// A locally modified copy of a default setup no longer installs.
    Edited,
}

/// Hold the setup lock while `seren skills add` copies into `root`.
pub(super) fn lock_setup_copy(base: &Path, root: &Path, slug: &str) -> Result<(File, SetupCopy)> {
    let lock = wait_for_state(base)?;
    let root = resolve_skill_path(root)?;
    let mut state = read_state(base)?;
    let mut copy = SetupCopy::Free;
    let mut released = false;
    for installed in state
        .agents
        .values_mut()
        .filter(|installed| installed.root == root)
    {
        let Some(receipt) = installed.skills.get(slug) else {
            continue;
        };
        if STARTER_SKILLS.contains(&slug) {
            copy = SetupCopy::Managed;
            continue;
        }
        // Earlier setups installed defaults that are now optional, such as
        // Getting Started. Hand an unmodified copy over to `seren skills add`.
        let path = root.join(slug);
        let unmodified = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                metadata.is_dir()
                    && hash_tree(&path).is_ok_and(|hash| hash == receipt.installed_hash)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        };
        if unmodified {
            installed.skills.remove(slug);
            released = true;
        } else if copy == SetupCopy::Free {
            copy = SetupCopy::Edited;
        }
    }
    if released {
        save_state(base, &state)?;
    }
    Ok((lock, copy))
}

struct SetupTarget {
    location: InstallTarget,
    label: String,
    configure: Option<SkillAgent>,
}

fn gemini_home(home: &Path) -> PathBuf {
    std::env::var_os("GEMINI_CLI_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.to_owned())
}

fn detected_agents() -> Result<Vec<SetupTarget>> {
    let home = home_dir()?;
    let gemini_home = gemini_home(&home);
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let claude = claude_settings_path()?.parent().is_some_and(Path::is_dir);
    let codex = codex_settings_path()?.parent().is_some_and(Path::is_dir);
    let gemini = gemini_home.join(".gemini").is_dir();
    let opencode = config.join("opencode").is_dir();
    let grok = std::env::var_os("GROK_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".grok"))
        .is_dir();
    // Compare resolved roots so an override that points back at the shared
    // directory still gets one copy.
    let separate_gemini =
        gemini && InstallTarget::Gemini.skills_root()? != InstallTarget::Shared.skills_root()?;
    let mut targets = Vec::new();
    if claude {
        targets.push(SetupTarget {
            location: InstallTarget::ClaudeCode,
            label: InstallTarget::ClaudeCode.label().into(),
            configure: Some(SkillAgent::ClaudeCode),
        });
    }
    let shared: Vec<_> = [
        ("Codex", codex),
        ("Gemini CLI", gemini && !separate_gemini),
        ("OpenCode", opencode),
        ("Grok Build", grok),
        ("Cursor", home.join(".cursor").is_dir()),
        ("GitHub Copilot CLI", home.join(".copilot").is_dir()),
    ]
    .into_iter()
    .filter_map(|(name, found)| found.then_some(name))
    .collect();
    if home.join(".agents").is_dir() || !shared.is_empty() {
        targets.push(SetupTarget {
            location: InstallTarget::Shared,
            label: if shared.is_empty() {
                "the shared skills directory".into()
            } else {
                format!("the shared skills directory ({})", shared.join(", "))
            },
            configure: codex.then_some(SkillAgent::Codex),
        });
    }
    if separate_gemini {
        targets.push(SetupTarget {
            location: InstallTarget::Gemini,
            label: InstallTarget::Gemini.label().into(),
            configure: None,
        });
    }
    Ok(targets)
}

fn prompt(question: &str) -> Result<String> {
    eprint!("{question} ");
    io::stderr().flush()?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0 {
        return Ok("n".into());
    }
    Ok(answer.trim().to_ascii_lowercase())
}

fn confirm(question: &str, default_yes: bool) -> Result<bool> {
    let choices = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        match prompt(&format!("{question} {choices}"))?.as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("Enter yes or no."),
        }
    }
}

pub async fn offer_after_login() -> Result<()> {
    let api_base = crate::defaults::api_base_url(&crate::defaults::runtime_api_host());
    let oauth_host = std::env::var("SEREN_OAUTH_HOST")
        .ok()
        .map(|host| host.trim().trim_end_matches('/').to_owned())
        .filter(|host| !host.is_empty())
        .unwrap_or_else(|| crate::defaults::DEFAULT_OAUTH_HOST.to_owned());
    if api_base != CATALOG_ORIGIN || oauth_host != CATALOG_ORIGIN {
        return Ok(());
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() || detected_agents()?.is_empty() {
        return Ok(());
    }
    let base = skills_dir()?;
    let state = read_state(&base)?;
    if state.dismissed
        || state
            .agents
            .values()
            .any(|installed| !installed.skills.is_empty())
    {
        return Ok(());
    }
    loop {
        match prompt("Set up Seren skills and MCP for your coding agents? [y/n/never]")?.as_str() {
            "y" | "yes" => return setup().await,
            "" | "n" | "no" => return Ok(()),
            "never" => {
                let _lock = wait_for_state(&base)?;
                let mut state = read_state(&base)?;
                state.dismissed = true;
                return save_state(&base, &state);
            }
            _ => eprintln!("Enter yes, no, or never."),
        }
    }
}

pub async fn setup() -> Result<()> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        bail!("Seren skills setup needs an interactive terminal");
    }
    let agents = detected_agents()?;
    if agents.is_empty() {
        bail!("Open a supported coding agent once, then run `seren skills setup` again");
    }
    eprintln!("Default Seren skills: Seren API, Seren Agent (Employees), Publishers, and SerenDB.");
    let base = skills_dir()?;
    let catalog = starter_catalog(CATALOG_ORIGIN)?;
    let mut failures = Vec::new();
    for SetupTarget {
        location,
        label,
        configure,
    } in agents
    {
        if !confirm(&format!("Set up {label}?"), true)? {
            continue;
        }
        let root = location.skills_root()?;
        if confirm(
            &format!("Install the default skills in {}?", root.display()),
            true,
        )? {
            let _lock = wait_for_state(&base)?;
            let mut state = read_state(&base)?;
            let installed = state.agents.entry(location).or_default();
            if installed.root != root {
                if installed.enabled || !installed.skills.is_empty() {
                    failures.push(format!(
                        "{label}: existing setup uses {}. Use that configuration to manage those skills.",
                        installed.root.display()
                    ));
                    continue;
                }
                *installed = InstalledAgent {
                    root,
                    ..InstalledAgent::default()
                };
            }
            for slug in STARTER_SKILLS {
                let installed = state
                    .agents
                    .get_mut(&location)
                    .context("Setup state disappeared")?;
                let result = tokio::time::timeout(
                    Duration::from_secs(20),
                    refresh_skill(&catalog, installed, slug, true),
                )
                .await
                .context("Catalog request timed out")
                .and_then(|result| result);
                match result {
                    Ok(Refresh::Installed) => {
                        // Record each receipt at once so an interrupted setup can update it later.
                        save_state(&base, &state)?;
                        eprintln!("Installed {slug} for {label}.");
                    }
                    Ok(Refresh::Current) => {
                        eprintln!("{slug} is already current for {label}.")
                    }
                    Ok(Refresh::Kept(reason)) => eprintln!(
                        "Kept {slug} in {label}: {reason}. Remove it and run `seren skills setup` to install Seren's copy."
                    ),
                    Ok(Refresh::Missing) => {}
                    Err(error) => failures.push(format!("{label}: {slug}: {error:#}")),
                }
            }
        }
        let Some(agent) = configure else {
            continue;
        };
        if confirm(&format!("Connect Seren MCP in {}?", agent.label()), false)?
            && let Err(error) = connect_mcp(agent).await
        {
            failures.push(format!("{}: MCP setup: {error:#}", agent.label()));
        }
        if read_state(&base)?
            .agents
            .get(&location)
            .is_some_and(|installed| !installed.skills.is_empty())
            && confirm(
                &format!("Keep these skills up to date in {}?", agent.label()),
                false,
            )?
            && let Err(error) = set_auto_update(agent, false)
        {
            failures.push(format!("{}: automatic updates: {error:#}", agent.label()));
        }
    }
    if !failures.is_empty() {
        bail!("{}", failures.join("\n"));
    }
    Ok(())
}

fn hash_tree(path: &Path) -> Result<String> {
    fn hash_entries(root: &Path, dir: &Path, digest: &mut Sha256) -> Result<()> {
        let mut entries = fs::read_dir(dir)?.collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root)?.as_os_str().as_encoded_bytes();
            let ty = entry.file_type()?;
            digest.update((relative.len() as u64).to_le_bytes());
            digest.update(relative);
            if ty.is_dir() {
                digest.update(b"d");
                hash_entries(root, &path, digest)?;
            } else if ty.is_file() {
                digest.update(b"f");
                let mut file = File::open(&path)?;
                let metadata = file.metadata()?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    digest.update(metadata.permissions().mode().to_le_bytes());
                }
                digest.update(metadata.len().to_le_bytes());
                let mut buffer = [0; 8192];
                loop {
                    let length = file.read(&mut buffer)?;
                    if length == 0 {
                        break;
                    }
                    digest.update(&buffer[..length]);
                }
            } else {
                bail!(
                    "Refusing to update a skill with a non-regular file at {}",
                    path.display()
                );
            }
        }
        Ok(())
    }
    check_skill_tree(path)?;
    let mut digest = Sha256::new();
    hash_entries(path, path, &mut digest)?;
    Ok(hex::encode(digest.finalize()))
}

#[derive(Debug, PartialEq, Eq)]
enum Refresh {
    Installed,
    Current,
    /// A local copy that setup must not replace, with the reason.
    Kept(&'static str),
    /// Removed locally; only explicit setup restores it.
    Missing,
}

const EDITED: &str = "it has local changes";
const UNMANAGED: &str = "it was not installed by Seren skills setup";
const LINKED: &str = "it is a symbolic link";

fn starter_catalog(origin: &str) -> Result<SkillsCatalog> {
    SkillsCatalog::with_client(
        origin,
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()),
    )
}

async fn refresh_skill(
    catalog: &SkillsCatalog,
    installed: &mut InstalledAgent,
    slug: &str,
    allow_install: bool,
) -> Result<Refresh> {
    if fs::symlink_metadata(installed.root.join(slug))
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Ok(Refresh::Kept(LINKED));
    }
    let destination = check_skill_destination(&installed.root, &[slug])?;
    let receipt = if destination.exists() {
        let Some(receipt) = installed.skills.get(slug) else {
            return Ok(Refresh::Kept(UNMANAGED));
        };
        if !destination.is_dir() || hash_tree(&destination)? != receipt.installed_hash {
            return Ok(Refresh::Kept(EDITED));
        }
        Some(receipt)
    } else if allow_install {
        None
    } else {
        return Ok(Refresh::Missing);
    };
    let Some((bundle, publisher_hash)) = (if slug == MANAGED_AGENT_SLUG {
        fetch_managed_agent_guide(catalog, receipt).await?
    } else {
        fetch_catalog_starter(catalog, slug, receipt).await?
    }) else {
        return Ok(Refresh::Current);
    };
    // Check again after downloading so an edit during the request is preserved.
    check_skill_destination(&installed.root, &[slug])?;
    if let Some(receipt) = receipt {
        if !destination.exists() {
            return Ok(Refresh::Missing);
        }
        if !destination.is_dir() || hash_tree(&destination)? != receipt.installed_hash {
            return Ok(Refresh::Kept(EDITED));
        }
    } else if destination.exists() {
        return Ok(Refresh::Kept(UNMANAGED));
    }
    install_bundle_at(&bundle, &destination)?;
    installed.skills.insert(
        slug.into(),
        Receipt {
            version: bundle.version,
            publisher_hash,
            installed_hash: hash_tree(&destination)?,
        },
    );
    Ok(Refresh::Installed)
}

async fn fetch_catalog_starter(
    catalog: &SkillsCatalog,
    slug: &str,
    receipt: Option<&Receipt>,
) -> Result<Option<(SkillBundle, String)>> {
    let manifest = catalog
        .manifest(slug)
        .await?
        .context("Default skill is unavailable in the public catalog")?;
    let publisher_hash = manifest
        .content_hash_bundle
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(|hash| hash.to_ascii_lowercase())
        .context("Skill manifest has no valid bundle hash")?;
    if manifest.skill.owner_kind != Some(CatalogOwnerKind::Organization)
        || manifest.skill.owner_organization_id != Some(SEREN_ORGANIZATION)
    {
        bail!("Skill is not owned by Seren");
    }
    if receipt.is_some_and(|receipt| {
        receipt.version.as_deref() == Some(manifest.version.as_str())
            && receipt.publisher_hash == publisher_hash
    }) {
        return Ok(None);
    }
    let bundle = catalog
        .bundle(slug)
        .await?
        .context("Skill bundle is unavailable")?;
    super::validate_catalog_skill(&bundle.skill, slug)?;
    if bundle.skill.owner_kind != Some(CatalogOwnerKind::Organization)
        || bundle.skill.owner_organization_id != Some(SEREN_ORGANIZATION)
        || bundle.version.as_deref() != Some(manifest.version.as_str())
        || !bundle
            .content_hash_bundle
            .as_deref()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(&publisher_hash))
        || bundle_hash(&bundle)? != publisher_hash
    {
        bail!("Skill bundle does not match the Seren catalog manifest");
    }
    Ok(Some((bundle, publisher_hash)))
}

async fn fetch_managed_agent_guide(
    catalog: &SkillsCatalog,
    receipt: Option<&Receipt>,
) -> Result<Option<(SkillBundle, String)>> {
    let mut response = catalog
        .client
        .get(format!("{}{MANAGED_AGENT_GUIDE}", catalog.api_base))
        .send()
        .await
        .context("Could not fetch the Seren Agent guide")?;
    if !response.status().is_success() {
        bail!("Seren Agent guide returned HTTP {}", response.status());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_GUIDE_BYTES - bytes.len() {
            bail!("Seren Agent guide exceeds the download size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    let publisher_hash = hex::encode(Sha256::digest(&bytes));
    if receipt.is_some_and(|receipt| {
        receipt.version.is_none() && receipt.publisher_hash == publisher_hash
    }) {
        return Ok(None);
    }
    let skill_md = String::from_utf8(bytes).context("Seren Agent guide is not UTF-8")?;
    let (name, description) = parse_frontmatter(&skill_md);
    if name != "seren-agent" || description.is_empty() {
        bail!("Seren Agent guide has invalid skill frontmatter");
    }
    let bundle = SkillBundle {
        skill: CatalogSkill {
            slug: MANAGED_AGENT_SLUG.into(),
            owner_organization_id: None,
            owner_kind: None,
            skill_folder_name: Some(name),
            description: Some(description),
        },
        skill_md,
        version: None,
        content_hash_bundle: None,
        files: Vec::new(),
    };
    Ok(Some((bundle, publisher_hash)))
}

// Match the publisher's canonical, length-prefixed skill bundle hash.
fn bundle_hash(bundle: &SkillBundle) -> Result<String> {
    fn add_bytes(hash: &mut Sha256, bytes: &[u8]) -> Result<()> {
        hash.update(u32::try_from(bytes.len())?.to_le_bytes());
        hash.update(bytes);
        Ok(())
    }

    let mut files: Vec<_> = bundle.files.iter().collect();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let mut hash = Sha256::new();
    hash.update(b"SBV1");
    add_bytes(&mut hash, bundle.skill_md.as_bytes())?;
    hash.update(u32::try_from(files.len())?.to_le_bytes());
    for file in files {
        add_bytes(&mut hash, file.path.as_bytes())?;
        hash.update(
            file.mode
                .context("Skill bundle file is missing its mode")?
                .to_le_bytes(),
        );
        let bytes = base64::engine::general_purpose::STANDARD.decode(&file.content_b64)?;
        add_bytes(&mut hash, &Sha256::digest(&bytes))?;
    }
    Ok(hex::encode(hash.finalize()))
}

fn change_hook(settings: &mut Value, agent: SkillAgent, enable: bool) -> Result<bool> {
    let before = settings.clone();
    edit_hook(settings, agent, enable)?;
    Ok(*settings != before)
}

fn edit_hook(settings: &mut Value, agent: SkillAgent, enable: bool) -> Result<()> {
    let settings = settings
        .as_object_mut()
        .context("Agent settings must be a JSON object")?;
    if !enable && !settings.contains_key("hooks") {
        return Ok(());
    }
    let hooks = settings
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("Agent hooks must be a JSON object")?;
    if !enable && !hooks.contains_key("SessionStart") {
        return Ok(());
    }
    let entries = hooks
        .entry("SessionStart")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("SessionStart hooks must be a JSON array")?;
    let owned = |hook: &Value| {
        hook.get("command")
            .and_then(Value::as_str)
            .is_some_and(|command| owned_command_matches(command, agent.hook()))
    };
    let already_installed = entries.iter().any(|group| {
        group
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| hooks.iter().any(owned))
    });
    if enable && !already_installed {
        entries.push(json!({
            "matcher": "startup",
            "hooks": [{"type": "command", "command": agent.hook(), "timeout": 10}]
        }));
    } else if !enable && already_installed {
        entries.retain_mut(|group| {
            let Some(hooks) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
                return true;
            };
            let count = hooks.len();
            hooks.retain(|hook| !owned(hook));
            count == hooks.len() || !hooks.is_empty()
        });
        // Drop containers this removal emptied so disabling restores the original shape.
        if entries.is_empty() {
            hooks.remove("SessionStart");
        }
        if hooks.is_empty() {
            settings.remove("hooks");
        }
    }
    Ok(())
}

pub fn set_auto_update(agent: SkillAgent, disable: bool) -> Result<()> {
    let base = skills_dir()?;
    let _lock = wait_for_state(&base)?;
    let mut state = read_state(&base)?;
    let target = agent.target();
    let root = target.skills_root()?;
    let installed = state
        .agents
        .get_mut(&target)
        .filter(|installed| installed.root == root);
    if disable {
        if let Some(installed) = installed.filter(|installed| installed.enabled) {
            installed.enabled = false;
            save_state(&base, &state)?;
        }
    } else if !installed.is_some_and(|installed| !installed.skills.is_empty()) {
        bail!("Run `seren skills setup` to install the default skills first");
    }

    let path = agent.settings()?;
    let (mut settings, original) = load_settings(&path)?;
    if change_hook(&mut settings, agent, !disable)? {
        write_settings_with_backup(&path, &settings, original.as_deref())?;
    }
    if !disable {
        if let Some(installed) = state.agents.get_mut(&target) {
            installed.enabled = true;
            installed.next_check = 0;
        }
        save_state(&base, &state)?;
        if agent == SkillAgent::Codex {
            eprintln!("Open Codex and use /hooks to review and trust the Seren updater.");
        }
        if agent == SkillAgent::ClaudeCode
            && settings.get("disableAllHooks").and_then(Value::as_bool) == Some(true)
        {
            eprintln!("Claude Code has disableAllHooks set, so the updater will not run.");
        }
    }
    eprintln!(
        "Automatic Seren skill updates {} for {}.",
        if disable { "disabled" } else { "enabled" },
        agent.label()
    );
    Ok(())
}

pub async fn update_hook(agent: SkillAgent) -> Result<()> {
    let base = skills_dir()?;
    let Some(_lock) = lock_state(&base, false)? else {
        return Ok(());
    };
    let mut state = read_state(&base)?;
    let now = jiff::Timestamp::now().as_second();
    let target = agent.target();
    let root = target.skills_root()?;
    let Some(installed) = state.agents.get_mut(&target).filter(|installed| {
        installed.enabled && installed.root == root && installed.next_check <= now
    }) else {
        return Ok(());
    };
    installed.next_check = now + RETRY_INTERVAL;
    save_state(&base, &state)?;
    let catalog = starter_catalog(CATALOG_ORIGIN)?;
    let mut updated = Vec::new();
    let check = tokio::time::timeout(Duration::from_secs(7), async {
        let mut successful = true;
        for &slug in STARTER_SKILLS {
            let installed = state
                .agents
                .get_mut(&target)
                .context("Updater state disappeared")?;
            if !installed.skills.contains_key(slug) {
                continue;
            }
            match tokio::time::timeout(
                Duration::from_millis(1500),
                refresh_skill(&catalog, installed, slug, false),
            )
            .await
            {
                Ok(Ok(Refresh::Installed)) => {
                    // Save before the next request in case the agent stops the hook.
                    save_state(&base, &state)?;
                    updated.push(slug);
                }
                Ok(Ok(Refresh::Missing)) => {
                    installed.skills.remove(slug);
                    save_state(&base, &state)?;
                }
                Ok(Ok(Refresh::Current | Refresh::Kept(_))) => {}
                _ => successful = false,
            }
        }
        anyhow::Ok(successful)
    })
    .await;
    if matches!(check, Ok(Ok(true))) {
        let installed = state
            .agents
            .get_mut(&target)
            .context("Updater state disappeared")?;
        installed.next_check = now + CHECK_INTERVAL;
    }
    save_state(&base, &state)?;
    if let Ok(Err(error)) = check {
        return Err(error);
    }
    if !updated.is_empty() {
        let message = format!("Updated Seren skills: {}.", updated.join(", "));
        match agent {
            SkillAgent::ClaudeCode => println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext": message,
                        "reloadSkills": true
                    }
                })
            ),
            SkillAgent::Codex => println!("{message}"),
        }
    }
    Ok(())
}

async fn connect_mcp(agent: SkillAgent) -> Result<()> {
    use std::process::Stdio;
    use tokio::process::Command;

    let mut command = match agent {
        SkillAgent::ClaudeCode => {
            let path = match std::env::var_os("CLAUDE_CONFIG_DIR").filter(|value| !value.is_empty())
            {
                Some(dir) => PathBuf::from(dir).join(".claude.json"),
                None => home_dir()?.join(".claude.json"),
            };
            let (settings, _) = load_settings(&path)?;
            if settings.pointer("/mcpServers/seren").is_some() {
                eprintln!("Kept the existing Seren MCP entry in Claude Code.");
                return Ok(());
            }
            let mut command = Command::new("claude");
            command.args([
                "mcp",
                "add",
                "--scope",
                "user",
                "--transport",
                "http",
                "seren",
                MCP_URL,
            ]);
            command
        }
        SkillAgent::Codex => {
            let path = agent.settings()?.with_file_name("config.toml");
            match fs::read_to_string(&path) {
                Ok(text) => {
                    let config: toml::Table =
                        toml::from_str(&text).context("Cannot parse Codex settings")?;
                    if config
                        .get("mcp_servers")
                        .and_then(|servers| servers.get("seren"))
                        .is_some()
                    {
                        eprintln!("Kept the existing Seren MCP entry in Codex.");
                        return Ok(());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let mut command = Command::new("codex");
            command.args(["mcp", "add", "seren", "--url", MCP_URL]);
            command
        }
    };
    command.stdin(Stdio::null()).kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(20), command.status())
        .await
        .context("MCP configuration command timed out")?
        .with_context(|| format!("Could not run the {} CLI", agent.label()))?;
    if !status.success() {
        bail!("MCP configuration command exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[test]
    fn setup_hook_keeps_other_agent_settings_and_can_be_removed() {
        let original = json!({
            "hooks": {"SessionStart": [{"matcher": "startup", "hooks": [
                {"type": "command", "command": "aws agent-toolkit update-skill --hook"}
            ]}]},
            "mcpServers": {"existing": {"url": "https://example.com/mcp"}}
        });
        let mut settings = original.clone();
        assert!(change_hook(&mut settings, SkillAgent::Codex, true).unwrap());
        assert!(!change_hook(&mut settings, SkillAgent::Codex, true).unwrap());
        assert!(change_hook(&mut settings, SkillAgent::Codex, false).unwrap());
        assert_eq!(settings, original);

        let mut empty = json!({});
        assert!(change_hook(&mut empty, SkillAgent::ClaudeCode, true).unwrap());
        assert!(change_hook(&mut empty, SkillAgent::ClaudeCode, false).unwrap());
        assert_eq!(empty, json!({}));
    }

    #[test]
    fn remove_preserves_a_skill_from_another_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let root = base.join("skills");
        let path = root.join(MANAGED_AGENT_SLUG);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("SKILL.md"), "# Local edit").unwrap();
        let mut state = State::default();
        state.agents.insert(
            InstallTarget::ClaudeCode,
            InstalledAgent {
                root,
                skills: BTreeMap::from([(
                    MANAGED_AGENT_SLUG.into(),
                    Receipt {
                        version: None,
                        publisher_hash: String::new(),
                        installed_hash: String::new(),
                    },
                )]),
                ..InstalledAgent::default()
            },
        );
        save_state(base, &state).unwrap();

        let protected = remove_managed(base, MANAGED_AGENT_SLUG).unwrap().unwrap();
        assert_eq!(protected, [resolve_skill_path(&path).unwrap()]);
        assert_eq!(
            fs::read_to_string(path.join("SKILL.md")).unwrap(),
            "# Local edit"
        );
        assert!(
            read_state(base).unwrap().agents[&InstallTarget::ClaudeCode]
                .skills
                .contains_key(MANAGED_AGENT_SLUG)
        );
    }

    #[test]
    fn earlier_getting_started_copies_hand_over_only_when_unmodified() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let root = resolve_skill_path(&base.join("skills")).unwrap();
        let slug = "seren-getting-started";
        assert!(!STARTER_SKILLS.contains(&slug));
        let path = root.join(slug);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("SKILL.md"), "# Getting Started").unwrap();
        let receipt = || Receipt {
            version: Some("first".into()),
            publisher_hash: String::new(),
            installed_hash: hash_tree(&path).unwrap(),
        };
        let save = |receipt: Receipt| {
            let mut state = State::default();
            state.agents.insert(
                InstallTarget::Shared,
                InstalledAgent {
                    root: root.clone(),
                    skills: BTreeMap::from([(slug.into(), receipt)]),
                    ..InstalledAgent::default()
                },
            );
            save_state(base, &state).unwrap();
        };
        let receipts = || {
            let state = read_state(base).unwrap();
            state.agents[&InstallTarget::Shared].skills.len()
        };

        save(receipt());
        fs::write(path.join("SKILL.md"), "# Local edit").unwrap();
        assert_eq!(
            lock_setup_copy(base, &root, slug).unwrap().1,
            SetupCopy::Edited
        );
        assert_eq!(receipts(), 1);
        assert_eq!(
            fs::read_to_string(path.join("SKILL.md")).unwrap(),
            "# Local edit"
        );

        save(receipt());
        assert_eq!(
            lock_setup_copy(base, &root, slug).unwrap().1,
            SetupCopy::Free
        );
        assert_eq!(receipts(), 0);
    }

    #[tokio::test]
    async fn managed_agent_guide_comes_from_its_publisher() {
        let server = MockServer::start().await;
        let catalog = starter_catalog(&server.uri()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut installed = InstalledAgent {
            root: dir.path().into(),
            ..InstalledAgent::default()
        };
        let markdown =
            "---\nname: seren-agent\ndescription: Operate managed agents.\n---\n# Guide\n";
        Mock::given(method("GET"))
            .and(path(MANAGED_AGENT_GUIDE))
            .respond_with(ResponseTemplate::new(200).set_body_string(markdown))
            .expect(2)
            .mount(&server)
            .await;
        assert_eq!(
            refresh_skill(&catalog, &mut installed, MANAGED_AGENT_SLUG, true)
                .await
                .unwrap(),
            Refresh::Installed
        );
        assert_eq!(
            refresh_skill(&catalog, &mut installed, MANAGED_AGENT_SLUG, false)
                .await
                .unwrap(),
            Refresh::Current
        );
        assert_eq!(
            fs::read_to_string(dir.path().join(MANAGED_AGENT_SLUG).join("SKILL.md")).unwrap(),
            markdown
        );
    }

    #[tokio::test]
    async fn starter_updates_reuse_the_catalog_and_preserve_local_changes() {
        let server = MockServer::start().await;
        let catalog = starter_catalog(&server.uri()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut installed = InstalledAgent {
            root: dir.path().into(),
            ..InstalledAgent::default()
        };
        let slug = "seren-api";
        assert!(STARTER_SKILLS.contains(&slug));
        let route = format!("/publishers/seren-skills/skills/{slug}/download");
        let manifest = format!("{route}/manifest");
        let mut data = json!({
            "skill": {"slug": slug, "owner_kind": "organization", "owner_organization_id": SEREN_ORGANIZATION},
            "version": "first",
            "content_hash_bundle": "054dd13c1f6280cda7d0854668fdc27cc0cc9640649e770ab823b2bc2076267c",
            "skill_md": "# Seren API",
            "files": [
                {"path": "notes.txt", "mode": 0o640, "content_b64": "bm90ZXMK"},
                {"path": "examples/a.txt", "mode": 0o644, "content_b64": "ZXhhbXBsZQo="}
            ]
        });
        Mock::given(method("GET"))
            .and(path(&manifest))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":data})))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(&route))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":data})))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            refresh_skill(&catalog, &mut installed, slug, true)
                .await
                .unwrap(),
            Refresh::Installed
        );
        assert_eq!(
            refresh_skill(&catalog, &mut installed, slug, false)
                .await
                .unwrap(),
            Refresh::Current
        );
        let destination = dir.path().join(slug);
        let markdown = destination.join("SKILL.md");
        assert_eq!(fs::read_to_string(&markdown).unwrap(), "# Seren API");
        assert_eq!(
            fs::read_to_string(destination.join("examples/a.txt")).unwrap(),
            "example\n"
        );
        fs::write(&markdown, "# User edit").unwrap();
        assert_eq!(
            refresh_skill(&catalog, &mut installed, slug, false)
                .await
                .unwrap(),
            Refresh::Kept(EDITED)
        );
        assert_eq!(fs::read_to_string(&markdown).unwrap(), "# User edit");
        fs::remove_dir_all(&destination).unwrap();
        assert_eq!(
            refresh_skill(&catalog, &mut installed, slug, false)
                .await
                .unwrap(),
            Refresh::Missing
        );
        assert!(!destination.exists());

        server.verify().await;
        server.reset().await;
        data["skill"]["owner_organization_id"] = json!(Uuid::nil());
        Mock::given(method("GET"))
            .and(path(&manifest))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":data})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(&route))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        assert!(
            refresh_skill(&catalog, &mut installed, slug, true)
                .await
                .is_err()
        );
        assert!(!destination.exists());
    }
}
