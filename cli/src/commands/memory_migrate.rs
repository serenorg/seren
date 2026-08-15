// ABOUTME: Plans, snapshots, imports, verifies, and rolls back claude-mem migrations.
// ABOUTME: Source content stays local except for explicitly accepted, redacted import records.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::commands::memory_gateway::memory_gateway_data;
use crate::commands::memory_hooks::redact_secrets;
use crate::{CommandContext, config};

const IMPORT_NAMESPACE: &str = "import:claude-mem";
const MAX_CONTENT_CHARS: usize = 40_000;
const IMPORT_BATCH_SIZE: usize = 100;
const TARGET_REPORT_CHECKPOINTS: usize = 8;
const VERIFY_SAMPLE_SIZE: usize = 20;
const EMBEDDING_RETRY_ATTEMPTS: u32 = 4;
const EMBEDDING_RETRY_BASE_DELAY_MS: u64 = 250;
/// The service bounds the serialized `source_metadata` object as a whole, not
/// only its individual values, and adds its own `source_project` entry before
/// validating. Reserve more than a kilobyte beyond the worst-case escaped
/// project entry so small server-side additions cannot put a record over the
/// service's 16,000-byte bound.
const MAX_SOURCE_METADATA_BYTES: usize = 12_500;
const MIN_SOURCE_METADATA_VALUE_CHARS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WorkspaceDisposition {
    Map,
    Isolated,
    Skip,
    ReviewRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkspaceMapping {
    legacy_project: String,
    disposition: WorkspaceDisposition,
    workspace_key: Option<String>,
    workspace_uri: Option<String>,
    path_exists: bool,
    candidate_records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlanEstimate {
    observations: u64,
    session_summaries: u64,
    selected_records: u64,
    skipped_by_workspace: u64,
    unresolved_workspace_records: u64,
    empty_records: u64,
    redacted_records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationPlan {
    accepted: bool,
    plan_hash: String,
    destination_api: String,
    destination_profile: String,
    destination_organization_id: Uuid,
    source_database: PathBuf,
    source_instance_id: String,
    source_schema_identity: String,
    migration_series_id: Uuid,
    policy_version: Option<String>,
    include_observations: bool,
    include_session_summaries: bool,
    include_raw_prompts: bool,
    workspaces: Vec<WorkspaceMapping>,
    estimate: PlanEstimate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SourceInstanceRegistry {
    sources: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalRunState {
    migration_id: Uuid,
    migration_series_id: Uuid,
    plan_path: PathBuf,
    report_path: PathBuf,
    snapshot_path: Option<PathBuf>,
    snapshot_id: String,
    plan_hash: String,
    source_instance_id: String,
    final_catch_up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotInventory {
    total_records: u64,
    submitted_records: u64,
    skipped_records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRunState {
    plan_path: PathBuf,
    snapshot_path: PathBuf,
    snapshot_id: String,
    plan_hash: String,
    final_catch_up: bool,
    inventory: SnapshotInventory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordReport {
    source_external_id: String,
    status: String,
    conversation_source_id: Option<Uuid>,
    memory_id: Option<Uuid>,
    content_sha256: Option<String>,
    redacted: bool,
    metadata_trimmed: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerificationReport {
    verified_at: jiff::Timestamp,
    passed: bool,
    sampled_records: usize,
    sampled_hash_matches: usize,
    checks: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationReport {
    migration_id: Uuid,
    migration_series_id: Uuid,
    source_instance_id: String,
    plan_hash: String,
    snapshot_id: String,
    final_catch_up: bool,
    destination_organization_id: Uuid,
    policy_version: Option<String>,
    workspaces: Vec<WorkspaceMapping>,
    started_at: jiff::Timestamp,
    completed_at: Option<jiff::Timestamp>,
    imported: u64,
    unchanged: u64,
    failed: u64,
    skipped: u64,
    inventory: SnapshotInventory,
    records: BTreeMap<String, RecordReport>,
    verification: Option<VerificationReport>,
}

#[derive(Debug, Clone, Serialize)]
struct SourceActivity {
    process_detected: bool,
    detected_process_ids: Vec<u32>,
    worker_pid_detected: bool,
    claude_capture_enabled: bool,
    codex_capture_enabled: bool,
    wal_present: bool,
    active: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SourceSchema {
    migration_version: Option<i64>,
    identity: String,
    tables: BTreeMap<String, Vec<String>>,
}

#[derive(Debug)]
struct PreparedRecord {
    api: seren::SerenMemoryImportRecord,
    content_sha256: String,
    redacted: bool,
    metadata_trimmed: bool,
}

#[derive(Debug)]
enum PreparedOutcome {
    Record(Box<PreparedRecord>),
    Skipped {
        source_external_id: String,
        reason: String,
    },
}

fn open_read_only(database: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("could not open {} read-only", database.display()))
}

fn canonical_database_path(database: &Path) -> Result<PathBuf> {
    database
        .canonicalize()
        .with_context(|| format!("could not resolve {}", database.display()))
}

fn mapped_memory_type(claude_mem_type: &str) -> &'static str {
    match claude_mem_type {
        "bugfix" => "error_fix",
        "decision" | "discovery" => "semantic",
        "feature" | "refactor" | "change" => "code",
        _ => "semantic",
    }
}

fn epoch_to_timestamp(epoch: i64) -> Option<jiff::Timestamp> {
    let seconds = if epoch > 1_000_000_000_000 {
        epoch / 1_000
    } else {
        epoch
    };
    jiff::Timestamp::from_second(seconds).ok()
}

fn joined_content(parts: &[Option<String>]) -> (String, bool) {
    let content = parts
        .iter()
        .filter_map(|part| part.as_deref().map(str::trim))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    let bounded: String = content.chars().take(MAX_CONTENT_CHARS).collect();
    let redacted = redact_secrets(&bounded);
    let redacted = redacted.trim();
    let changed = redacted != bounded;
    (redacted.to_string(), changed)
}

fn default_source_instance(database: &Path) -> String {
    let identity = format!(
        "{}:{}",
        std::env::var("HOSTNAME")
            .ok()
            .or_else(hostname_fallback)
            .unwrap_or_default(),
        database.display()
    );
    let digest = hex::encode(Sha256::digest(identity.as_bytes()));
    digest[..16].to_string()
}

fn hostname_fallback() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

fn migration_state_root() -> Result<PathBuf> {
    use etcetera::base_strategy::{BaseStrategy, choose_base_strategy};
    let strategy = choose_base_strategy().context("Could not determine state directory")?;
    let base = strategy.state_dir().unwrap_or_else(|| strategy.data_dir());
    let root = base.join("seren").join("memory_migrations");
    create_private_dir(&root)?;
    Ok(root)
}

fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    Ok(())
}

fn write_json_file<T: Serialize>(path: &Path, value: &T, replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .context("JSON output path did not have a parent directory")?;
    if !parent.exists() {
        create_private_dir(parent)?;
    }
    if !replace && path.exists() {
        anyhow::bail!("{} already exists", path.display());
    }
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .context("JSON output filename was not valid UTF-8")?,
        Uuid::new_v4()
    ));
    let serialized = serde_json::to_vec_pretty(value)?;
    let result = (|| -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&serialized)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path)?.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(path, permissions)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let raw = std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("could not parse {}", path.display()))
}

fn resolve_source_instance(database: &Path, requested: Option<String>) -> Result<String> {
    let registry_path = migration_state_root()?.join("source_instances.json");
    let mut registry = if registry_path.exists() {
        read_json_file::<SourceInstanceRegistry>(&registry_path)?
    } else {
        SourceInstanceRegistry {
            sources: BTreeMap::new(),
        }
    };
    let key = database.to_string_lossy().to_string();
    if let Some(existing) = registry.sources.get(&key) {
        if requested.as_deref().is_some_and(|value| value != existing) {
            anyhow::bail!(
                "this database is already registered as source instance {existing}; reuse that identity"
            );
        }
        return Ok(existing.clone());
    }
    let source_instance = requested.unwrap_or_else(|| default_source_instance(database));
    if source_instance.is_empty()
        || source_instance.len() > 128
        || !source_instance
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        anyhow::bail!(
            "source_instance must contain 1 to 128 ASCII letters, digits, hyphens, or underscores"
        );
    }
    registry.sources.insert(key, source_instance.clone());
    write_json_file(&registry_path, &registry, true)?;
    Ok(source_instance)
}

fn table_columns(connection: &Connection, table: &str) -> Result<BTreeSet<String>> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    Ok(columns)
}

fn source_schema(connection: &Connection) -> Result<SourceSchema> {
    let mut tables = BTreeMap::new();
    for table in ["observations", "session_summaries", "sdk_sessions"] {
        let columns = table_columns(connection, table)?;
        if columns.is_empty() {
            anyhow::bail!("claude-mem database is missing required table {table}");
        }
        tables.insert(table.to_string(), columns.into_iter().collect::<Vec<_>>());
    }
    for table in [
        "memory_items",
        "memory_sources",
        "projects",
        "server_sessions",
    ] {
        let columns = table_columns(connection, table)?;
        if !columns.is_empty() {
            tables.insert(table.to_string(), columns.into_iter().collect::<Vec<_>>());
        }
    }
    let schema_rows = {
        let mut statement = connection.prepare(
            "SELECT name, sql FROM sqlite_master
            WHERE type = 'table' AND name IN (
                'observations', 'session_summaries', 'sdk_sessions',
                'memory_items', 'memory_sources', 'projects', 'server_sessions'
            )
            ORDER BY name",
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let migration_version = if table_columns(connection, "schema_versions")?.is_empty() {
        None
    } else {
        connection.query_row("SELECT MAX(version) FROM schema_versions", [], |row| {
            row.get::<_, Option<i64>>(0)
        })?
    };
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&schema_rows)?));
    let version_label = migration_version
        .map(|version| version.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    Ok(SourceSchema {
        migration_version,
        identity: format!("sqlite-{version_label}-{}", &digest[..16]),
        tables,
    })
}

fn optional_table_count(connection: &Connection, table: &str) -> Result<u64> {
    if table_columns(connection, table)?.is_empty() {
        Ok(0)
    } else {
        count(connection, &format!("SELECT COUNT(*) FROM {table}"))
    }
}

fn ensure_supported_source_corpus(connection: &Connection) -> Result<()> {
    let memory_items = optional_table_count(connection, "memory_items")?;
    if memory_items > 0 {
        anyhow::bail!(
            "claude-mem contains {memory_items} local /v1 memory_items records; this importer currently handles SessionStore observations and summaries only and refuses to omit those records"
        );
    }
    Ok(())
}

fn count(connection: &Connection, sql: &str) -> Result<u64> {
    let value: i64 = connection.query_row(sql, [], |row| row.get(0))?;
    u64::try_from(value).context("source count was negative")
}

fn distinct_projects(connection: &Connection) -> Result<Vec<(String, u64)>> {
    let mut statement = connection.prepare(
        "SELECT project, SUM(records)
        FROM (
            SELECT project, COUNT(*) AS records FROM observations GROUP BY project
            UNION ALL
            SELECT project, COUNT(*) AS records FROM session_summaries GROUP BY project
        )
        GROUP BY project
        ORDER BY project",
    )?;
    statement
        .query_map([], |row| {
            let count: i64 = row.get(1)?;
            Ok((row.get(0)?, u64::try_from(count).unwrap_or(0)))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn normalized_git_remote(remote: &str) -> Option<String> {
    let remote = remote.trim();
    if let Ok(url) = url::Url::parse(remote)
        && matches!(url.scheme(), "http" | "https" | "ssh" | "git")
    {
        let host = url.host_str()?;
        let path = url.path().trim_matches('/').trim_end_matches(".git");
        if !host.is_empty() && !path.is_empty() {
            return Some(format!("{host}/{path}"));
        }
    }
    let (_, host_and_path) = remote.rsplit_once('@')?;
    let (host, path) = host_and_path.split_once(':')?;
    let path = path.trim_matches('/').trim_end_matches(".git");
    (!host.is_empty() && !path.is_empty()).then(|| format!("{host}/{path}"))
}

fn workspace_identity(path: &Path) -> (String, Option<String>) {
    let remote = std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|remote| normalized_git_remote(&remote));
    if let Some(remote) = remote {
        return (format!("git:{remote}"), Some(format!("https://{remote}")));
    }
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let digest = hex::encode(Sha256::digest(canonical.to_string_lossy().as_bytes()));
    (
        format!("path:{}", &digest[..32]),
        url::Url::from_file_path(canonical)
            .ok()
            .map(|uri| uri.to_string()),
    )
}

fn planned_workspace(
    project: String,
    candidate_records: u64,
    source_instance: &str,
    missing: &str,
) -> Result<WorkspaceMapping> {
    let path = PathBuf::from(&project);
    let path_exists = path.is_absolute() && path.is_dir();
    if path_exists {
        let (workspace_key, workspace_uri) = workspace_identity(&path);
        return Ok(WorkspaceMapping {
            legacy_project: project,
            disposition: WorkspaceDisposition::Map,
            workspace_key: Some(workspace_key),
            workspace_uri,
            path_exists,
            candidate_records,
        });
    }
    let digest = hex::encode(Sha256::digest(project.as_bytes()));
    let workspace_key = Some(format!(
        "legacy:claude-mem:{source_instance}:{}",
        &digest[..24]
    ));
    let disposition = match missing {
        "isolated" => WorkspaceDisposition::Isolated,
        "skip" => WorkspaceDisposition::Skip,
        "review" => WorkspaceDisposition::ReviewRequired,
        _ => anyhow::bail!("missing_workspaces must be review, isolated, or skip"),
    };
    Ok(WorkspaceMapping {
        legacy_project: project,
        disposition,
        workspace_key,
        workspace_uri: None,
        path_exists,
        candidate_records,
    })
}

fn plan_hash(plan: &MigrationPlan) -> Result<String> {
    let mut hash_input = plan.clone();
    hash_input.accepted = false;
    hash_input.plan_hash.clear();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(
        &hash_input,
    )?)))
}

fn validate_plan(
    plan: &MigrationPlan,
    require_live_source_schema: bool,
    ctx: &CommandContext,
) -> Result<()> {
    if plan.plan_hash != plan_hash(plan)? {
        anyhow::bail!("plan hash does not match the plan contents");
    }
    if !plan.accepted {
        anyhow::bail!("plan has not been accepted; review it and set accepted to true");
    }
    if plan.include_raw_prompts {
        anyhow::bail!("raw prompt migration is not supported by this migration path");
    }
    if plan
        .policy_version
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > 128)
    {
        anyhow::bail!("policy_version must contain between 1 and 128 characters");
    }
    if plan.source_schema_identity.is_empty() || plan.source_schema_identity.len() > 64 {
        anyhow::bail!("source_schema_identity must contain between 1 and 64 characters");
    }
    if require_live_source_schema {
        let connection = open_read_only(&plan.source_database)?;
        let current_schema = source_schema(&connection)?;
        if current_schema.identity != plan.source_schema_identity {
            anyhow::bail!(
                "claude-mem schema changed after planning; create and review a new migration plan"
            );
        }
        let planned_projects = plan
            .workspaces
            .iter()
            .map(|mapping| mapping.legacy_project.as_str())
            .collect::<BTreeSet<_>>();
        if let Some((project, _)) = distinct_projects(&connection)?
            .into_iter()
            .find(|(project, _)| !planned_projects.contains(project.as_str()))
        {
            anyhow::bail!(
                "claude-mem added workspace {project} after planning; create and review a new migration plan"
            );
        }
        ensure_supported_source_corpus(&connection)?;
    }
    if plan.destination_api != ctx.api_base() {
        anyhow::bail!(
            "plan targets {}, but the active CLI context targets {}",
            plan.destination_api,
            ctx.api_base()
        );
    }
    if plan.destination_profile != config::active_profile() {
        anyhow::bail!(
            "plan targets profile {}, but profile {} is active",
            plan.destination_profile,
            config::active_profile()
        );
    }
    let configured_org = config::ContextConfig::load()
        .ok()
        .and_then(|context| context.org_id)
        .and_then(|value| value.parse::<Uuid>().ok());
    if configured_org != Some(plan.destination_organization_id) {
        anyhow::bail!(
            "active organization does not match plan destination {}; select that organization first",
            plan.destination_organization_id
        );
    }
    for mapping in &plan.workspaces {
        match mapping.disposition {
            WorkspaceDisposition::ReviewRequired => anyhow::bail!(
                "workspace {} still requires an explicit map, isolated, or skip decision",
                mapping.legacy_project
            ),
            WorkspaceDisposition::Map | WorkspaceDisposition::Isolated
                if mapping.workspace_key.as_deref().is_none_or(str::is_empty) =>
            {
                anyhow::bail!(
                    "workspace {} is missing workspace_key",
                    mapping.legacy_project
                );
            }
            _ => {}
        }
        if mapping
            .workspace_key
            .as_ref()
            .is_some_and(|value| value.len() > 512)
        {
            anyhow::bail!(
                "workspace {} has a workspace_key longer than 512 characters",
                mapping.legacy_project
            );
        }
    }
    Ok(())
}

fn recursive_string_contains(value: &serde_json::Value, needle: &str) -> bool {
    match value {
        serde_json::Value::String(value) => value.contains(needle),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| recursive_string_contains(value, needle)),
        serde_json::Value::Object(object) => object
            .iter()
            .any(|(key, value)| key.contains(needle) || recursive_string_contains(value, needle)),
        _ => false,
    }
}

fn claude_settings_capture_enabled(value: &serde_json::Value) -> bool {
    let plugin_enabled = value
        .get("enabledPlugins")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|plugins| {
            plugins.iter().any(|(name, enabled)| {
                name.contains("claude-mem") && enabled.as_bool() == Some(true)
            })
        });
    let hook_enabled = value
        .get("hooks")
        .is_some_and(|hooks| recursive_string_contains(hooks, "claude-mem"));
    plugin_enabled || hook_enabled
}

fn claude_capture_enabled() -> bool {
    let path = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| etcetera::home_dir().ok().map(|home| home.join(".claude")))
        .map(|dir| dir.join("settings.json"));
    path.and_then(|path| std::fs::read(path).ok())
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .is_some_and(|value| claude_settings_capture_enabled(&value))
}

fn codex_config_capture_enabled(value: &toml::Value) -> bool {
    value
        .get("plugins")
        .and_then(toml::Value::as_table)
        .is_some_and(|plugins| {
            plugins.iter().any(|(name, plugin)| {
                name.contains("claude-mem")
                    && plugin
                        .get("enabled")
                        .and_then(toml::Value::as_bool)
                        .unwrap_or(true)
            })
        })
}

fn codex_capture_enabled() -> bool {
    let path = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| etcetera::home_dir().ok().map(|home| home.join(".codex")))
        .map(|dir| dir.join("config.toml"));
    path.and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|raw| toml::from_str::<toml::Value>(&raw).ok())
        .is_some_and(|value| codex_config_capture_enabled(&value))
}

fn is_claude_mem_runtime_command(command: &str) -> bool {
    let executable = command
        .split_whitespace()
        .next()
        .and_then(|value| Path::new(value).file_name())
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let runtime_launcher =
        matches!(executable, "node" | "bun" | "bunx") || command.contains("worker-service-v");
    // A marketplace install resolves its scripts under
    // `plugins/marketplaces/thedotmack/plugin`, where no path component spells
    // out claude-mem, so the publisher is the second accepted install marker.
    let install_marker = command.contains("claude-mem") || command.contains("thedotmack");
    runtime_launcher
        && install_marker
        && [
            "worker-service.cjs",
            "worker-wrapper.cjs",
            "server-service.cjs",
            "server-beta-service.cjs",
            "mcp-server.cjs",
            "worker-service-v",
        ]
        .iter()
        .any(|marker| command.contains(marker))
}

fn claude_mem_process_ids() -> Vec<u32> {
    let current_pid = std::process::id().to_string();
    std::process::Command::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| {
            output
                .lines()
                .filter_map(|line| {
                    let mut parts = line.trim().splitn(2, char::is_whitespace);
                    let pid = parts.next().unwrap_or_default();
                    let command = parts.next().unwrap_or_default();
                    (pid != current_pid
                        && is_claude_mem_runtime_command(command)
                        && !command.contains("seren memory migrate"))
                    .then(|| pid.parse::<u32>().ok())
                    .flatten()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn process_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "pid="])
            .output()
            .ok()
            .is_some_and(|output| output.status.success() && !output.stdout.is_empty())
    }
    #[cfg(windows)]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .is_some_and(|output| {
                !output.trim().is_empty() && !output.trim_start().starts_with("INFO:")
            })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

fn claude_mem_worker_pid_detected(database: &Path) -> bool {
    database
        .parent()
        .map(|parent| parent.join("worker.pid"))
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .and_then(|value| value.get("pid").and_then(serde_json::Value::as_u64))
        .and_then(|pid| u32::try_from(pid).ok())
        .is_some_and(process_is_alive)
}

fn source_activity(database: &Path) -> SourceActivity {
    let detected_process_ids = claude_mem_process_ids();
    let process_detected = !detected_process_ids.is_empty();
    let worker_pid_detected = claude_mem_worker_pid_detected(database);
    let claude_capture_enabled = claude_capture_enabled();
    let codex_capture_enabled = codex_capture_enabled();
    let wal_path = PathBuf::from(format!("{}-wal", database.display()));
    let wal_present = wal_path.exists();
    SourceActivity {
        process_detected,
        detected_process_ids,
        worker_pid_detected,
        claude_capture_enabled,
        codex_capture_enabled,
        wal_present,
        active: process_detected
            || worker_pid_detected
            || claude_capture_enabled
            || codex_capture_enabled,
    }
}

fn configured_organization(requested: Option<Uuid>) -> Result<Uuid> {
    let configured = config::ContextConfig::load()
        .ok()
        .and_then(|context| context.org_id)
        .and_then(|value| value.parse::<Uuid>().ok());
    match (requested, configured) {
        (Some(requested), Some(configured)) if requested != configured => anyhow::bail!(
            "requested organization {requested} does not match active organization {configured}"
        ),
        (Some(requested), _) => Ok(requested),
        (None, Some(configured)) => Ok(configured),
        (None, None) => anyhow::bail!(
            "select an organization or pass --organization-id before planning a migration"
        ),
    }
}

pub async fn inspect(
    database: PathBuf,
    organization_id: Option<Uuid>,
    ctx: &CommandContext,
) -> Result<()> {
    let database = canonical_database_path(&database)?;
    let connection = open_read_only(&database)?;
    let schema = source_schema(&connection)?;
    let mut observations_by_type = serde_json::Map::new();
    let mut statement = connection
        .prepare("SELECT type, COUNT(*) FROM observations GROUP BY type ORDER BY type")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        let count: i64 = row.get(1)?;
        observations_by_type.insert(kind, serde_json::json!(count));
    }
    let mut platforms = serde_json::Map::new();
    if table_columns(&connection, "sdk_sessions")?.contains("platform_source") {
        let mut statement = connection.prepare(
            "SELECT platform_source, COUNT(*) FROM sdk_sessions
            GROUP BY platform_source ORDER BY platform_source",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let platform: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            platforms.insert(platform, serde_json::json!(count));
        }
    } else {
        platforms.insert(
            "unknown".to_string(),
            serde_json::json!(count(&connection, "SELECT COUNT(*) FROM sdk_sessions")?),
        );
    }
    let destination = configured_organization(organization_id)?;
    let memory_items = optional_table_count(&connection, "memory_items")?;
    let summary = serde_json::json!({
        "database": database,
        "source_schema": schema,
        "activity": source_activity(&database),
        "destination_api": ctx.api_base(),
        "destination_profile": config::active_profile(),
        "destination_organization_id": destination,
        "observations": count(&connection, "SELECT COUNT(*) FROM observations")?,
        "observations_by_type": observations_by_type,
        "session_summaries": count(&connection, "SELECT COUNT(*) FROM session_summaries")?,
        "unsupported_memory_items": memory_items,
        "sessions": count(&connection, "SELECT COUNT(*) FROM sdk_sessions")?,
        "platforms": platforms,
        "distinct_projects": distinct_projects(&connection)?,
        "raw_prompts_selected": false,
    });
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn create_plan(
    database: PathBuf,
    output: PathBuf,
    source_instance: Option<String>,
    organization_id: Option<Uuid>,
    policy_version: Option<String>,
    missing_workspaces: String,
    accept: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let database = canonical_database_path(&database)?;
    let connection = open_read_only(&database)?;
    let schema = source_schema(&connection)?;
    ensure_supported_source_corpus(&connection)?;
    let source_instance_id = resolve_source_instance(&database, source_instance)?;
    let projects = distinct_projects(&connection)?;
    let workspaces = projects
        .iter()
        .map(|(project, candidate_records)| {
            planned_workspace(
                project.clone(),
                *candidate_records,
                &source_instance_id,
                &missing_workspaces,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let estimate = estimate_plan(&connection, &source_instance_id, &workspaces)?;
    let mut plan = MigrationPlan {
        accepted: accept,
        plan_hash: String::new(),
        destination_api: ctx.api_base(),
        destination_profile: config::active_profile().to_string(),
        destination_organization_id: configured_organization(organization_id)?,
        source_database: database,
        source_instance_id,
        source_schema_identity: schema.identity,
        migration_series_id: Uuid::new_v4(),
        policy_version,
        include_observations: true,
        include_session_summaries: true,
        include_raw_prompts: false,
        workspaces,
        estimate,
    };
    if accept && plan.estimate.unresolved_workspace_records > 0 {
        anyhow::bail!(
            "the plan has unresolved workspaces; choose --missing-workspaces isolated or skip, or edit the generated mappings before acceptance"
        );
    }
    plan.plan_hash = plan_hash(&plan)?;
    write_json_file(&output, &plan, false)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "plan": output,
            "plan_hash": plan.plan_hash,
            "accepted": plan.accepted,
            "migration_series_id": plan.migration_series_id,
            "source_instance_id": plan.source_instance_id,
            "selected_records": plan.estimate.selected_records,
            "skipped_records": plan.estimate.skipped_by_workspace,
            "unresolved_workspace_records": plan.estimate.unresolved_workspace_records,
            "empty_records": plan.estimate.empty_records,
            "redacted_records": plan.estimate.redacted_records,
        }))?
    );
    Ok(())
}

pub async fn accept_plan(plan_path: PathBuf) -> Result<()> {
    let mut plan: MigrationPlan = read_json_file(&plan_path)?;
    for mapping in &plan.workspaces {
        match mapping.disposition {
            WorkspaceDisposition::ReviewRequired => anyhow::bail!(
                "workspace {} still requires a map, isolated, or skip decision",
                mapping.legacy_project
            ),
            WorkspaceDisposition::Map | WorkspaceDisposition::Isolated
                if mapping.workspace_key.as_deref().is_none_or(str::is_empty) =>
            {
                anyhow::bail!(
                    "workspace {} is missing workspace_key",
                    mapping.legacy_project
                );
            }
            _ => {}
        }
    }
    let connection = open_read_only(&plan.source_database)?;
    ensure_supported_source_corpus(&connection)?;
    plan.estimate = estimate_plan(&connection, &plan.source_instance_id, &plan.workspaces)?;
    plan.accepted = true;
    plan.plan_hash = plan_hash(&plan)?;
    write_json_file(&plan_path, &plan, true)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "plan": plan_path,
            "accepted": true,
            "plan_hash": plan.plan_hash,
            "migration_series_id": plan.migration_series_id,
        }))?
    );
    Ok(())
}

pub async fn rehearse(
    database: PathBuf,
    output: PathBuf,
    source_instance: Option<String>,
    limit: Option<u64>,
) -> Result<()> {
    let database = canonical_database_path(&database)?;
    let activity_before = source_activity(&database);
    let source_instance = source_instance.unwrap_or_else(|| default_source_instance(&database));
    create_private_dir(&output)?;
    let snapshot = output.join(format!(".source_snapshot-{}.db", Uuid::new_v4()));
    create_snapshot(&database, &snapshot)?;
    let snapshot = TemporarySnapshot(snapshot);
    let connection = open_read_only(&snapshot.0)?;
    let schema = source_schema(&connection)?;
    ensure_supported_source_corpus(&connection)?;
    let mappings = distinct_projects(&connection)?
        .into_iter()
        .map(|(project, candidate_records)| {
            let digest = hex::encode(Sha256::digest(project.as_bytes()));
            (
                project.clone(),
                WorkspaceMapping {
                    legacy_project: project,
                    disposition: WorkspaceDisposition::Isolated,
                    workspace_key: Some(format!(
                        "legacy:claude-mem:{source_instance}:{}",
                        &digest[..24]
                    )),
                    workspace_uri: None,
                    path_exists: false,
                    candidate_records,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let records_path = output.join("records.jsonl");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut sink = std::io::BufWriter::new(options.open(&records_path)?);
    let mut written = 0u64;
    let mut skipped = 0u64;
    let row_limit = limit.unwrap_or(u64::MAX);
    for category in [RecordCategory::Observation, RecordCategory::Summary] {
        let mut after_id = i64::MIN;
        while written.saturating_add(skipped) < row_limit {
            let page_limit = usize::try_from(
                row_limit
                    .saturating_sub(written.saturating_add(skipped))
                    .min(IMPORT_BATCH_SIZE as u64),
            )
            .unwrap_or(IMPORT_BATCH_SIZE);
            let page = load_page(
                &connection,
                category,
                after_id,
                page_limit,
                &source_instance,
                &mappings,
            )?;
            if page.is_empty() {
                break;
            }
            after_id = page.last().expect("non-empty page").0;
            for (_, outcome) in page {
                match outcome {
                    PreparedOutcome::Record(record) => {
                        serde_json::to_writer(
                            &mut sink,
                            &serde_json::json!({
                                "source_external_id": record.api.source_external_id,
                                "memory_type": record.api.memory_type,
                                "content": record.api.content,
                                "observed_at": record.api.observed_at,
                                "project": record.api.project,
                                "workspace_key": record.api.workspace_key,
                                "workspace_uri": record.api.workspace_uri,
                                "source_record_type": record.api.source_record_type,
                                "source_uri": record.api.source_uri,
                                "agent_platform": record.api.agent_platform,
                                "external_session_id": record.api.external_session_id,
                                "external_parent_session_id": record.api.external_parent_session_id,
                                "external_turn_id": record.api.external_turn_id,
                                "source_metadata": record.api.source_metadata,
                                "content_sha256": record.content_sha256,
                                "redacted": record.redacted,
                                "metadata_trimmed": record.metadata_trimmed,
                            }),
                        )?;
                        sink.write_all(b"\n")?;
                        written += 1;
                    }
                    PreparedOutcome::Skipped { .. } => skipped += 1,
                }
            }
        }
    }
    sink.flush()?;
    drop(sink);
    let records_sha256 = sha256_file(&records_path)?;
    let records_bytes = records_path.metadata()?.len();
    let activity_after = source_activity(&database);
    let manifest_path = output.join("rehearsal.json");
    let manifest = serde_json::json!({
        "source_instance": source_instance,
        "source_schema_identity": schema.identity,
        "source_activity_before": activity_before,
        "source_activity_after": activity_after,
        "records_path": records_path,
        "records_sha256": records_sha256,
        "records_bytes": records_bytes,
        "written": written,
        "skipped": skipped,
        "limited": limit.is_some(),
        "service_calls": 0,
        "completed_at": jiff::Timestamp::now(),
    });
    write_json_file(&manifest_path, &manifest, true)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "manifest": manifest_path,
            "rehearsal": manifest,
        }))?
    );
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, Copy)]
enum RecordCategory {
    Observation,
    Summary,
}

fn optional_column(columns: &BTreeSet<String>, column: &str) -> String {
    if columns.contains(column) {
        column.to_string()
    } else {
        format!("NULL AS {column}")
    }
}

fn optional_text_column(columns: &BTreeSet<String>, column: &str) -> String {
    if columns.contains(column) {
        format!("CAST({column} AS TEXT) AS {column}")
    } else {
        format!("NULL AS {column}")
    }
}

fn session_platform_expression(connection: &Connection, session_column: &str) -> Result<String> {
    let session_columns = table_columns(connection, "sdk_sessions")?;
    if session_columns.contains("memory_session_id") && session_columns.contains("platform_source")
    {
        Ok(format!(
            "(SELECT platform_source FROM sdk_sessions
            WHERE sdk_sessions.memory_session_id = source.{session_column}
            LIMIT 1) AS platform_source"
        ))
    } else {
        Ok("NULL AS platform_source".to_string())
    }
}

fn bounded_metadata_value(value: Option<String>) -> Option<(serde_json::Value, bool)> {
    bounded_redacted_value(value, 800)
        .map(|(value, redacted)| (serde_json::Value::String(value), redacted))
}

fn bounded_source_value(value: Option<String>, max_chars: usize) -> Option<String> {
    bounded_redacted_value(value, max_chars).map(|(value, _)| value)
}

fn bounded_redacted_value(value: Option<String>, max_chars: usize) -> Option<(String, bool)> {
    value.and_then(|value| {
        let original = value.trim();
        let redacted = redact_secrets(original);
        let redacted = redacted.trim();
        let was_redacted = redacted != original;
        let mut end = redacted.len().min(max_chars);
        while !redacted.is_char_boundary(end) {
            end -= 1;
        }
        let bounded = redacted[..end].to_string();
        (!bounded.is_empty()).then_some((bounded, was_redacted))
    })
}

fn insert_metadata(
    metadata: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<String>,
) -> bool {
    if let Some((value, redacted)) = bounded_metadata_value(value) {
        metadata.insert(key.to_string(), value);
        redacted
    } else {
        false
    }
}

fn insert_metadata_group(
    metadata: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    group: serde_json::Map<String, serde_json::Value>,
) {
    if !group.is_empty() {
        metadata.insert(key.to_string(), serde_json::Value::Object(group));
    }
}

fn source_metadata_len(metadata: &serde_json::Map<String, serde_json::Value>) -> usize {
    serde_json::to_vec(metadata).map_or(usize::MAX, |bytes| bytes.len())
}

/// Largest grouped string value, ordered so equal lengths resolve to one
/// deterministic entry. Returns the group, key, and character count.
fn largest_metadata_entry(
    metadata: &serde_json::Map<String, serde_json::Value>,
) -> Option<(String, String, usize)> {
    metadata
        .iter()
        .filter_map(|(group, value)| Some((group, value.as_object()?)))
        .flat_map(|(group, entries)| {
            entries.iter().filter_map(move |(key, value)| {
                Some((group.clone(), key.clone(), value.as_str()?.chars().count()))
            })
        })
        .max_by(|left, right| {
            left.2
                .cmp(&right.2)
                .then_with(|| left.0.cmp(&right.0))
                .then_with(|| left.1.cmp(&right.1))
        })
}

/// Shrink grouped metadata until the whole object fits the service bound,
/// halving the largest value each pass and dropping values that reach the
/// floor. The order is deterministic so a repeated run submits the same
/// object and keeps its canonical import fingerprint unchanged.
fn fit_source_metadata(metadata: &mut serde_json::Map<String, serde_json::Value>) -> bool {
    let mut trimmed = false;
    while source_metadata_len(metadata) > MAX_SOURCE_METADATA_BYTES {
        let Some((group, key, chars)) = largest_metadata_entry(metadata) else {
            break;
        };
        let group_is_empty = {
            let Some(entries) = metadata
                .get_mut(&group)
                .and_then(serde_json::Value::as_object_mut)
            else {
                break;
            };
            if chars <= MIN_SOURCE_METADATA_VALUE_CHARS {
                entries.remove(&key);
            } else {
                let Some(value) = entries.get(&key).and_then(serde_json::Value::as_str) else {
                    break;
                };
                let shortened: String = value.chars().take(chars / 2).collect();
                entries.insert(key, serde_json::Value::String(shortened));
            }
            entries.is_empty()
        };
        if group_is_empty {
            metadata.remove(&group);
        }
        trimmed = true;
    }
    trimmed
}

fn workspace_mapping<'a>(
    mappings: &'a BTreeMap<String, WorkspaceMapping>,
    project: &str,
) -> Result<&'a WorkspaceMapping> {
    mappings
        .get(project)
        .with_context(|| format!("plan has no workspace decision for {project}"))
}

fn memory_type(value: &str) -> Result<seren::SerenMemoryMemoryType> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("unsupported Seren memory type {value}"))
}

fn observation_page(
    connection: &Connection,
    after_id: i64,
    limit: usize,
    source_instance: &str,
    mappings: &BTreeMap<String, WorkspaceMapping>,
) -> Result<Vec<(i64, PreparedOutcome)>> {
    let columns = table_columns(connection, "observations")?;
    for required in ["id", "type", "created_at_epoch", "project"] {
        if !columns.contains(required) {
            anyhow::bail!("observations table is missing required column {required}");
        }
    }
    let platform = session_platform_expression(connection, "memory_session_id")?;
    let content_columns = [
        "title",
        "subtitle",
        "narrative",
        "facts",
        "text",
        "memory_session_id",
    ]
    .map(|column| optional_column(&columns, column))
    .join(", ");
    let metadata_columns = [
        "concepts",
        "files_read",
        "files_modified",
        "generated_by_model",
        "agent_type",
        "agent_id",
        "content_hash",
        "origin_device_id",
        "origin_local_id",
        "merged_into_project",
        "prompt_number",
        "discovery_tokens",
        "relevance_count",
        "metadata",
    ]
    .map(|column| optional_column(&columns, column))
    .into_iter()
    .chain(std::iter::once(optional_text_column(&columns, "sync_rev")))
    .collect::<Vec<_>>()
    .join(", ");
    let sql = format!(
        "SELECT id, type, {content_columns}, created_at_epoch, project, {metadata_columns},
                {platform}
        FROM observations source
        WHERE id > ?1
        ORDER BY id
        LIMIT ?2"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(
        params![after_id, i64::try_from(limit).unwrap_or(i64::MAX)],
        |row| {
            let id: i64 = row.get(0)?;
            let claude_mem_type: String = row.get(1)?;
            let project: String = row.get(9)?;
            let mapping = workspace_mapping(mappings, &project).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?;
            let source_external_id =
                format!("{IMPORT_NAMESPACE}:{source_instance}:observation:{id}");
            if mapping.disposition == WorkspaceDisposition::Skip {
                return Ok((
                    id,
                    PreparedOutcome::Skipped {
                        source_external_id,
                        reason: "workspace_skipped".to_string(),
                    },
                ));
            }
            let title = row.get::<_, Option<String>>(2)?;
            let subtitle = row.get::<_, Option<String>>(3)?;
            let narrative = row.get::<_, Option<String>>(4)?;
            let facts = row.get::<_, Option<String>>(5)?;
            let fallback_text = row.get::<_, Option<String>>(6)?;
            let mut content_parts = vec![
                title.clone(),
                subtitle.clone(),
                narrative.clone(),
                facts.clone(),
            ];
            if content_parts
                .iter()
                .all(|part| part.as_deref().is_none_or(|value| value.trim().is_empty()))
            {
                content_parts.push(fallback_text.clone());
            }
            let (content, mut redacted) = joined_content(&content_parts);
            if content.is_empty() {
                return Ok((
                    id,
                    PreparedOutcome::Skipped {
                        source_external_id,
                        reason: "empty_content".to_string(),
                    },
                ));
            }
            let mut metadata = serde_json::Map::new();
            let mut legacy = serde_json::Map::new();
            redacted |= insert_metadata(&mut legacy, "title", title);
            redacted |= insert_metadata(&mut legacy, "subtitle", subtitle);
            redacted |= insert_metadata(&mut legacy, "text", fallback_text);
            redacted |= insert_metadata(&mut legacy, "concepts", row.get(10)?);
            redacted |= insert_metadata(&mut legacy, "content_hash", row.get(16)?);
            redacted |= insert_metadata(&mut legacy, "merged_into_project", row.get(19)?);
            if let Some(prompt_number) = row.get::<_, Option<i64>>(20)? {
                legacy.insert("prompt_number".to_string(), prompt_number.into());
            }
            if let Some(discovery_tokens) = row.get::<_, Option<i64>>(21)? {
                legacy.insert("discovery_tokens".to_string(), discovery_tokens.into());
            }
            if let Some(relevance_count) = row.get::<_, Option<i64>>(22)? {
                legacy.insert("relevance_count".to_string(), relevance_count.into());
            }
            redacted |= insert_metadata(&mut legacy, "metadata", row.get(23)?);
            insert_metadata_group(&mut metadata, "legacy", legacy);
            let mut files = serde_json::Map::new();
            redacted |= insert_metadata(&mut files, "read", row.get(11)?);
            redacted |= insert_metadata(&mut files, "modified", row.get(12)?);
            insert_metadata_group(&mut metadata, "files", files);
            let mut agent = serde_json::Map::new();
            redacted |= insert_metadata(&mut agent, "model", row.get(13)?);
            redacted |= insert_metadata(&mut agent, "type", row.get(14)?);
            redacted |= insert_metadata(&mut agent, "id", row.get(15)?);
            insert_metadata_group(&mut metadata, "agent", agent);
            let mut origin = serde_json::Map::new();
            redacted |= insert_metadata(&mut origin, "device_id", row.get(17)?);
            redacted |= insert_metadata(&mut origin, "local_id", row.get(18)?);
            redacted |= insert_metadata(&mut origin, "sync_revision", row.get(24)?);
            insert_metadata_group(&mut metadata, "origin", origin);
            let metadata_trimmed = fit_source_metadata(&mut metadata);
            let platform_source = row.get::<_, Option<String>>(25)?;
            let agent_type = row.get::<_, Option<String>>(14)?;
            let content_sha256 = hex::encode(Sha256::digest(content.as_bytes()));
            Ok((
                id,
                PreparedOutcome::Record(Box::new(PreparedRecord {
                    api: seren::SerenMemoryImportRecord {
                        agent_platform: bounded_source_value(platform_source.or(agent_type), 64),
                        content,
                        external_session_id: bounded_source_value(row.get(7)?, 256),
                        memory_type: memory_type(mapped_memory_type(&claude_mem_type)).map_err(
                            |error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    1,
                                    rusqlite::types::Type::Text,
                                    error.into(),
                                )
                            },
                        )?,
                        observed_at: epoch_to_timestamp(row.get(8)?),
                        project: bounded_source_value(Some(project), 1_000),
                        source_record_type: bounded_source_value(Some(claude_mem_type), 1_000),
                        source_external_id,
                        source_metadata: (!metadata.is_empty()).then_some(metadata),
                        source_uri: Some(format!(
                            "claude-mem://{source_instance}/observations/{id}"
                        )),
                        workspace_key: mapping.workspace_key.clone(),
                        workspace_uri: mapping.workspace_uri.clone(),
                        external_parent_session_id: None,
                        external_turn_id: None,
                    },
                    content_sha256,
                    redacted,
                    metadata_trimmed,
                })),
            ))
        },
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn summary_page(
    connection: &Connection,
    after_id: i64,
    limit: usize,
    source_instance: &str,
    mappings: &BTreeMap<String, WorkspaceMapping>,
) -> Result<Vec<(i64, PreparedOutcome)>> {
    let columns = table_columns(connection, "session_summaries")?;
    for required in ["id", "created_at_epoch", "project"] {
        if !columns.contains(required) {
            anyhow::bail!("session_summaries table is missing required column {required}");
        }
    }
    let platform = session_platform_expression(connection, "memory_session_id")?;
    let content_columns = [
        "request",
        "investigated",
        "learned",
        "completed",
        "next_steps",
        "notes",
    ]
    .map(|column| optional_column(&columns, column))
    .join(", ");
    let metadata_columns = [
        "memory_session_id",
        "files_read",
        "files_edited",
        "merged_into_project",
        "origin_device_id",
        "origin_local_id",
        "prompt_number",
        "discovery_tokens",
    ]
    .map(|column| optional_column(&columns, column))
    .into_iter()
    .chain(std::iter::once(optional_text_column(&columns, "sync_rev")))
    .collect::<Vec<_>>()
    .join(", ");
    let sql = format!(
        "SELECT id, {content_columns}, created_at_epoch, project, {metadata_columns},
                {platform}
        FROM session_summaries source
        WHERE id > ?1
        ORDER BY id
        LIMIT ?2"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(
        params![after_id, i64::try_from(limit).unwrap_or(i64::MAX)],
        |row| {
            let id: i64 = row.get(0)?;
            let project: String = row.get(8)?;
            let mapping = workspace_mapping(mappings, &project).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?;
            let source_external_id = format!("{IMPORT_NAMESPACE}:{source_instance}:summary:{id}");
            if mapping.disposition == WorkspaceDisposition::Skip {
                return Ok((
                    id,
                    PreparedOutcome::Skipped {
                        source_external_id,
                        reason: "workspace_skipped".to_string(),
                    },
                ));
            }
            let (content, mut redacted) = joined_content(&[
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ]);
            if content.is_empty() {
                return Ok((
                    id,
                    PreparedOutcome::Skipped {
                        source_external_id,
                        reason: "empty_content".to_string(),
                    },
                ));
            }
            let mut metadata = serde_json::Map::new();
            let mut files = serde_json::Map::new();
            redacted |= insert_metadata(&mut files, "read", row.get(10)?);
            redacted |= insert_metadata(&mut files, "edited", row.get(11)?);
            insert_metadata_group(&mut metadata, "files", files);
            let mut legacy = serde_json::Map::new();
            redacted |= insert_metadata(&mut legacy, "merged_into_project", row.get(12)?);
            if let Some(prompt_number) = row.get::<_, Option<i64>>(15)? {
                legacy.insert("prompt_number".to_string(), prompt_number.into());
            }
            if let Some(discovery_tokens) = row.get::<_, Option<i64>>(16)? {
                legacy.insert("discovery_tokens".to_string(), discovery_tokens.into());
            }
            insert_metadata_group(&mut metadata, "legacy", legacy);
            let mut origin = serde_json::Map::new();
            redacted |= insert_metadata(&mut origin, "device_id", row.get(13)?);
            redacted |= insert_metadata(&mut origin, "local_id", row.get(14)?);
            redacted |= insert_metadata(&mut origin, "sync_revision", row.get(17)?);
            insert_metadata_group(&mut metadata, "origin", origin);
            let metadata_trimmed = fit_source_metadata(&mut metadata);
            let content_sha256 = hex::encode(Sha256::digest(content.as_bytes()));
            Ok((
                id,
                PreparedOutcome::Record(Box::new(PreparedRecord {
                    api: seren::SerenMemoryImportRecord {
                        agent_platform: bounded_source_value(row.get(18)?, 64),
                        content,
                        external_session_id: bounded_source_value(row.get(9)?, 256),
                        memory_type: seren::SerenMemoryMemoryType::Episodic,
                        observed_at: epoch_to_timestamp(row.get(7)?),
                        project: bounded_source_value(Some(project), 1_000),
                        source_record_type: Some("session_summary".to_string()),
                        source_external_id,
                        source_metadata: (!metadata.is_empty()).then_some(metadata),
                        source_uri: Some(format!(
                            "claude-mem://{source_instance}/session-summaries/{id}"
                        )),
                        workspace_key: mapping.workspace_key.clone(),
                        workspace_uri: mapping.workspace_uri.clone(),
                        external_parent_session_id: None,
                        external_turn_id: None,
                    },
                    content_sha256,
                    redacted,
                    metadata_trimmed,
                })),
            ))
        },
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn load_page(
    connection: &Connection,
    category: RecordCategory,
    after_id: i64,
    limit: usize,
    source_instance: &str,
    mappings: &BTreeMap<String, WorkspaceMapping>,
) -> Result<Vec<(i64, PreparedOutcome)>> {
    match category {
        RecordCategory::Observation => {
            observation_page(connection, after_id, limit, source_instance, mappings)
        }
        RecordCategory::Summary => {
            summary_page(connection, after_id, limit, source_instance, mappings)
        }
    }
}

fn inventory_page(
    connection: &Connection,
    category: RecordCategory,
    after_id: i64,
    limit: usize,
    source_instance: &str,
    mappings: &BTreeMap<String, WorkspaceMapping>,
) -> Result<Vec<(i64, String, bool)>> {
    let (table, content_columns, identity_kind): (&str, &[&str], &str) = match category {
        RecordCategory::Observation => (
            "observations",
            &["title", "subtitle", "narrative", "facts", "text"],
            "observation",
        ),
        RecordCategory::Summary => (
            "session_summaries",
            &[
                "request",
                "investigated",
                "learned",
                "completed",
                "next_steps",
                "notes",
            ],
            "summary",
        ),
    };
    let columns = table_columns(connection, table)?;
    for required in ["id", "project"] {
        if !columns.contains(required) {
            anyhow::bail!("{table} table is missing required column {required}");
        }
    }
    let selected_content = content_columns
        .iter()
        .map(|column| optional_column(&columns, column))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT id, project, {selected_content}
        FROM {table}
        WHERE id > ?1
        ORDER BY id
        LIMIT ?2"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(
        params![after_id, i64::try_from(limit).unwrap_or(i64::MAX)],
        |row| {
            let id: i64 = row.get(0)?;
            let project: String = row.get(1)?;
            let mapping = workspace_mapping(mappings, &project).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?;
            let source_external_id =
                format!("{IMPORT_NAMESPACE}:{source_instance}:{identity_kind}:{id}");
            let mut content_present = false;
            for offset in 0..content_columns.len() {
                let value: Option<String> = row.get(offset + 2)?;
                content_present |= value.is_some_and(|value| !value.trim().is_empty());
            }
            content_present &= mapping.disposition != WorkspaceDisposition::Skip;
            Ok((id, source_external_id, content_present))
        },
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn report_checkpoint_batches(total_records: u64) -> usize {
    let total_records = usize::try_from(total_records).unwrap_or(usize::MAX);
    let total_batches = total_records.div_ceil(IMPORT_BATCH_SIZE).max(1);
    total_batches.div_ceil(TARGET_REPORT_CHECKPOINTS).max(1)
}

fn snapshot_inventory(plan: &MigrationPlan, snapshot: &Path) -> Result<SnapshotInventory> {
    let connection = open_read_only(snapshot)?;
    let mappings = plan
        .workspaces
        .iter()
        .cloned()
        .map(|mapping| (mapping.legacy_project.clone(), mapping))
        .collect::<BTreeMap<_, _>>();
    let mut identities = BTreeSet::new();
    let mut total_records = 0u64;
    let mut submitted_records = 0u64;
    let mut skipped_records = 0u64;
    for (category, enabled) in [
        (RecordCategory::Observation, plan.include_observations),
        (RecordCategory::Summary, plan.include_session_summaries),
    ] {
        if !enabled {
            continue;
        }
        let mut after_id = i64::MIN;
        loop {
            let page = inventory_page(
                &connection,
                category,
                after_id,
                IMPORT_BATCH_SIZE,
                &plan.source_instance_id,
                &mappings,
            )?;
            if page.is_empty() {
                break;
            }
            after_id = page.last().expect("non-empty page").0;
            for (_, source_external_id, submitted) in page {
                total_records += 1;
                if submitted {
                    submitted_records += 1;
                } else {
                    skipped_records += 1;
                }
                if !identities.insert(source_external_id) {
                    anyhow::bail!("fixed snapshot produced a duplicate stable record identity");
                }
            }
        }
    }
    Ok(SnapshotInventory {
        total_records,
        submitted_records,
        skipped_records,
    })
}

fn estimate_plan(
    connection: &Connection,
    source_instance: &str,
    workspaces: &[WorkspaceMapping],
) -> Result<PlanEstimate> {
    let observations = count(connection, "SELECT COUNT(*) FROM observations")?;
    let session_summaries = count(connection, "SELECT COUNT(*) FROM session_summaries")?;
    let skipped_by_workspace = workspaces
        .iter()
        .filter(|workspace| workspace.disposition == WorkspaceDisposition::Skip)
        .map(|workspace| workspace.candidate_records)
        .sum();
    let unresolved_workspace_records = workspaces
        .iter()
        .filter(|workspace| workspace.disposition == WorkspaceDisposition::ReviewRequired)
        .map(|workspace| workspace.candidate_records)
        .sum();
    let mappings = workspaces
        .iter()
        .cloned()
        .map(|mut mapping| {
            if mapping.disposition == WorkspaceDisposition::ReviewRequired {
                mapping.disposition = WorkspaceDisposition::Skip;
            }
            (mapping.legacy_project.clone(), mapping)
        })
        .collect::<BTreeMap<_, _>>();
    let mut selected_records = 0u64;
    let mut empty_records = 0u64;
    let mut redacted_records = 0u64;
    for category in [RecordCategory::Observation, RecordCategory::Summary] {
        let mut after_id = i64::MIN;
        loop {
            let page = load_page(
                connection,
                category,
                after_id,
                IMPORT_BATCH_SIZE,
                source_instance,
                &mappings,
            )?;
            if page.is_empty() {
                break;
            }
            after_id = page.last().expect("non-empty page").0;
            for (_, outcome) in page {
                match outcome {
                    PreparedOutcome::Record(record) => {
                        selected_records += 1;
                        redacted_records += u64::from(record.redacted);
                    }
                    PreparedOutcome::Skipped { reason, .. } if reason == "empty_content" => {
                        empty_records += 1;
                    }
                    PreparedOutcome::Skipped { .. } => {}
                }
            }
        }
    }
    Ok(PlanEstimate {
        observations,
        session_summaries,
        selected_records,
        skipped_by_workspace,
        unresolved_workspace_records,
        empty_records,
        redacted_records,
    })
}

fn create_snapshot(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        anyhow::bail!("snapshot {} already exists", destination.display());
    }
    let parent = destination
        .parent()
        .context("snapshot path did not have a parent directory")?;
    create_private_dir(parent)?;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(destination)?;
    let source_connection = open_read_only(source)?;
    let mut destination_connection = Connection::open(destination)?;
    let backup = rusqlite::backup::Backup::new(&source_connection, &mut destination_connection)?;
    let result = backup.run_to_completion(256, Duration::from_millis(25), None);
    drop(backup);
    drop(destination_connection);
    if let Err(error) = result {
        let _ = remove_snapshot_files(destination);
        return Err(error.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(destination)?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(destination, permissions)?;
    }
    Ok(())
}

fn snapshot_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

fn remove_snapshot_files(path: &Path) -> Result<()> {
    for file in [
        path.to_path_buf(),
        snapshot_sidecar(path, "-wal"),
        snapshot_sidecar(path, "-shm"),
    ] {
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("could not remove snapshot file {}", file.display()));
            }
        }
    }
    Ok(())
}

struct TemporarySnapshot(PathBuf);

impl Drop for TemporarySnapshot {
    fn drop(&mut self) {
        let _ = remove_snapshot_files(&self.0);
    }
}

fn run_state_path(migration_id: Uuid) -> Result<PathBuf> {
    Ok(migration_state_root()?
        .join("runs")
        .join(format!("{migration_id}.json")))
}

fn report_path(migration_id: Uuid) -> Result<PathBuf> {
    Ok(migration_state_root()?
        .join("reports")
        .join(format!("{migration_id}.json")))
}

fn pending_run_path(plan_hash: &str, final_catch_up: bool) -> Result<PathBuf> {
    Ok(migration_state_root()?.join("pending").join(format!(
        "{plan_hash}-{}.json",
        if final_catch_up {
            "final"
        } else {
            "incremental"
        }
    )))
}

fn save_run_state(state: &LocalRunState) -> Result<()> {
    write_json_file(&run_state_path(state.migration_id)?, state, true)
}

fn load_run_state(migration_id: Uuid) -> Result<LocalRunState> {
    read_json_file(&run_state_path(migration_id)?).with_context(|| {
        format!(
            "no local migration state is available for {migration_id}; resume requires the original fixed snapshot"
        )
    })
}

fn resumable_migration_ids_at(
    root: &Path,
    plan: &MigrationPlan,
    final_catch_up: bool,
) -> Result<Vec<Uuid>> {
    let runs = root.join("runs");
    if !runs.exists() {
        return Ok(Vec::new());
    }
    let mut migration_ids = Vec::new();
    for entry in std::fs::read_dir(&runs)
        .with_context(|| format!("could not inspect migration runs in {}", runs.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let state: LocalRunState = read_json_file(&path)
            .with_context(|| format!("could not inspect migration state {}", path.display()))?;
        if state.plan_hash != plan.plan_hash
            || state.migration_series_id != plan.migration_series_id
            || state.source_instance_id != plan.source_instance_id
            || state.final_catch_up != final_catch_up
            || !state
                .snapshot_path
                .as_ref()
                .is_some_and(|snapshot| snapshot.exists())
        {
            continue;
        }
        let completed = if state.report_path.exists() {
            let report: MigrationReport =
                read_json_file(&state.report_path).with_context(|| {
                    format!(
                        "could not inspect migration report {}",
                        state.report_path.display()
                    )
                })?;
            report.completed_at.is_some()
        } else {
            false
        };
        if !completed {
            migration_ids.push(state.migration_id);
        }
    }
    migration_ids.sort_unstable();
    Ok(migration_ids)
}

fn embedding_retry_delay(attempt: u32) -> Duration {
    let multiplier = 1_u64
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(u64::MAX);
    Duration::from_millis(EMBEDDING_RETRY_BASE_DELAY_MS.saturating_mul(multiplier))
}

async fn transition(
    migration_id: Uuid,
    state: seren::SerenMemoryMigrationTransitionState,
    ctx: &CommandContext,
) -> Result<seren::SerenMemoryMemoryMigration> {
    let result = ctx
        .client()
        .await?
        .seren_memory_set_migration_state(
            &migration_id,
            &seren::SerenMemorySetMigrationStateRequest { state },
        )
        .await;
    let response = memory_gateway_data(result, "could not transition migration")?;
    Ok(response.data)
}

async fn mark_interrupted(migration_id: Uuid, ctx: &CommandContext) {
    let _ = transition(
        migration_id,
        seren::SerenMemoryMigrationTransitionState::Interrupted,
        ctx,
    )
    .await;
}

fn report_counts(report: &mut MigrationReport) {
    report.imported = report
        .records
        .values()
        .filter(|record| record.status == "imported")
        .count() as u64;
    report.unchanged = report
        .records
        .values()
        .filter(|record| record.status == "unchanged")
        .count() as u64;
    report.failed = report
        .records
        .values()
        .filter(|record| record.status == "failed")
        .count() as u64;
    report.skipped = report
        .records
        .values()
        .filter(|record| record.status == "skipped")
        .count() as u64;
}

fn successful_record_ids(report: &MigrationReport) -> BTreeSet<String> {
    report
        .records
        .values()
        .filter(|record| matches!(record.status.as_str(), "imported" | "unchanged"))
        .map(|record| record.source_external_id.clone())
        .collect()
}

async fn send_batch(
    migration_id: Uuid,
    batch: Vec<PreparedRecord>,
    report: &mut MigrationReport,
    ctx: &CommandContext,
) -> Result<()> {
    let hashes = batch
        .iter()
        .map(|record| {
            (
                record.api.source_external_id.clone(),
                (
                    record.content_sha256.clone(),
                    record.redacted,
                    record.metadata_trimmed,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let request = seren::SerenMemoryImportRecordsRequest {
        records: batch.into_iter().map(|record| record.api).collect(),
    };
    let result = ctx
        .client()
        .await?
        .seren_memory_import_migration_records(&migration_id, &request)
        .await;
    let response = memory_gateway_data(result, "migration batch failed")?.data;
    let returned_ids = response
        .records
        .iter()
        .map(|outcome| outcome.source_external_id.as_str())
        .collect::<BTreeSet<_>>();
    if response.records.len() != hashes.len()
        || returned_ids.len() != hashes.len()
        || returned_ids
            .iter()
            .any(|source_external_id| !hashes.contains_key(*source_external_id))
    {
        anyhow::bail!("migration batch response did not match the submitted record identities");
    }
    for outcome in response.records {
        let (content_sha256, redacted, metadata_trimmed) = hashes
            .get(&outcome.source_external_id)
            .map(|(hash, redacted, trimmed)| (Some(hash.clone()), *redacted, *trimmed))
            .expect("validated response identity");
        let source_external_id = outcome.source_external_id;
        report.records.insert(
            source_external_id.clone(),
            RecordReport {
                source_external_id,
                status: outcome.status.to_string(),
                conversation_source_id: outcome.conversation_source_id,
                memory_id: outcome.memory_id,
                content_sha256,
                redacted,
                metadata_trimmed,
                error: outcome.error.map(|error| {
                    redact_secrets(&error)
                        .chars()
                        .take(1_000)
                        .collect::<String>()
                }),
            },
        );
    }
    report_counts(report);
    Ok(())
}

async fn embed_imported_records(migration_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let mut previous_remaining = i64::MAX;
    loop {
        let mut attempt = 1;
        let counts = loop {
            let result = client
                .seren_memory_embed_migration_records(
                    &migration_id,
                    &seren::SerenMemoryEmbedMigrationRecordsRequest {
                        limit: std::num::NonZeroU64::new(100),
                    },
                )
                .await;
            match memory_gateway_data(result, "migration embedding batch failed") {
                Ok(response) => break response.data,
                Err(error) if error.is_retryable() && attempt < EMBEDDING_RETRY_ATTEMPTS => {
                    let delay = embedding_retry_delay(attempt);
                    let reason = error.status().map_or_else(
                        || "transport error".to_string(),
                        |status| status.to_string(),
                    );
                    eprintln!(
                        "Transient migration embedding failure ({reason}); retrying in {} ms (attempt {}/{EMBEDDING_RETRY_ATTEMPTS})",
                        delay.as_millis(),
                        attempt + 1,
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "migration embedding batch failed after {attempt} attempt(s): {error}"
                    ));
                }
            }
        };
        let remaining = counts
            .embedding_pending
            .saturating_add(counts.embedding_failed);
        if remaining == 0 {
            return Ok(());
        }
        if remaining >= previous_remaining {
            anyhow::bail!(
                "migration embedding backfill made no progress; {remaining} records remain"
            );
        }
        previous_remaining = remaining;
    }
}

async fn execute_snapshot(
    plan: &MigrationPlan,
    state: &mut LocalRunState,
    report: &mut MigrationReport,
    ctx: &CommandContext,
) -> Result<()> {
    let snapshot_path = state
        .snapshot_path
        .as_deref()
        .context("the local fixed snapshot is no longer available")?;
    let connection = open_read_only(snapshot_path)?;
    let mappings = plan
        .workspaces
        .iter()
        .cloned()
        .map(|mapping| (mapping.legacy_project.clone(), mapping))
        .collect::<BTreeMap<_, _>>();
    let already_successful = successful_record_ids(report);
    let mut completed_batches = 0usize;
    let checkpoint_batches = report_checkpoint_batches(report.inventory.total_records);
    for (category, enabled) in [
        (RecordCategory::Observation, plan.include_observations),
        (RecordCategory::Summary, plan.include_session_summaries),
    ] {
        if !enabled {
            continue;
        }
        let mut after_id = i64::MIN;
        loop {
            let page = load_page(
                &connection,
                category,
                after_id,
                IMPORT_BATCH_SIZE,
                &plan.source_instance_id,
                &mappings,
            )?;
            if page.is_empty() {
                break;
            }
            after_id = page.last().expect("non-empty page").0;
            let mut batch = Vec::new();
            for (_, outcome) in page {
                match outcome {
                    PreparedOutcome::Record(record)
                        if already_successful.contains(&record.api.source_external_id) => {}
                    PreparedOutcome::Record(record) => batch.push(*record),
                    PreparedOutcome::Skipped {
                        source_external_id,
                        reason,
                    } if !report.records.contains_key(&source_external_id) => {
                        report.records.insert(
                            source_external_id.clone(),
                            RecordReport {
                                source_external_id,
                                status: "skipped".to_string(),
                                conversation_source_id: None,
                                memory_id: None,
                                content_sha256: None,
                                redacted: false,
                                metadata_trimmed: false,
                                error: Some(reason),
                            },
                        );
                    }
                    PreparedOutcome::Skipped { .. } => {}
                }
            }
            if !batch.is_empty()
                && let Err(error) = send_batch(state.migration_id, batch, report, ctx).await
            {
                report_counts(report);
                write_json_file(&state.report_path, report, true)?;
                mark_interrupted(state.migration_id, ctx).await;
                return Err(error);
            }
            completed_batches += 1;
            if completed_batches.is_multiple_of(checkpoint_batches) {
                report_counts(report);
                write_json_file(&state.report_path, report, true)?;
            }
        }
    }
    report_counts(report);
    let reported_records = u64::try_from(report.records.len()).unwrap_or(u64::MAX);
    if reported_records != report.inventory.total_records
        || report.skipped != report.inventory.skipped_records
        || report
            .imported
            .saturating_add(report.unchanged)
            .saturating_add(report.failed)
            != report.inventory.submitted_records
    {
        mark_interrupted(state.migration_id, ctx).await;
        write_json_file(&state.report_path, report, true)?;
        anyhow::bail!(
            "fixed snapshot coverage is incomplete; the snapshot was retained for resume"
        );
    }
    if report.failed > 0 {
        mark_interrupted(state.migration_id, ctx).await;
        write_json_file(&state.report_path, report, true)?;
        anyhow::bail!(
            "{} records failed; the fixed snapshot was retained for resume",
            report.failed
        );
    }
    if let Err(error) = embed_imported_records(state.migration_id, ctx).await {
        mark_interrupted(state.migration_id, ctx).await;
        write_json_file(&state.report_path, report, true)?;
        return Err(error);
    }
    drop(connection);
    transition(
        state.migration_id,
        seren::SerenMemoryMigrationTransitionState::Completed,
        ctx,
    )
    .await?;
    report.completed_at = Some(jiff::Timestamp::now());
    write_json_file(&state.report_path, report, true)?;
    if let Some(snapshot) = state.snapshot_path.take() {
        remove_snapshot_files(&snapshot)?;
    }
    save_run_state(state)?;
    Ok(())
}

pub async fn run(
    plan_path: PathBuf,
    final_catch_up: bool,
    source_stopped: bool,
    force_new_snapshot: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let plan_path = plan_path
        .canonicalize()
        .with_context(|| format!("could not resolve {}", plan_path.display()))?;
    let plan: MigrationPlan = read_json_file(&plan_path)?;
    validate_plan(&plan, true, ctx)?;
    let activity = source_activity(&plan.source_database);
    if final_catch_up && !source_stopped {
        anyhow::bail!("--final-catch-up requires --source-stopped confirmation");
    }
    if final_catch_up && activity.active {
        anyhow::bail!(
            "claude-mem still appears active; disable its hooks and worker before final catch-up"
        );
    }
    let pending_path = pending_run_path(&plan.plan_hash, final_catch_up)?;
    if !pending_path.exists() && !force_new_snapshot {
        let resumable =
            resumable_migration_ids_at(&migration_state_root()?, &plan, final_catch_up)?;
        if !resumable.is_empty() {
            let migration_ids = resumable
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "an earlier run for this plan still has a resumable fixed snapshot ({migration_ids}); use `seren memory migrate claude-mem resume {}` or pass --force-new-snapshot only when a distinct snapshot is intentional",
                resumable[0]
            );
        }
    }
    let (snapshot_id, snapshot_path, inventory, activity_at_snapshot) = if pending_path.exists() {
        let pending: PendingRunState = read_json_file(&pending_path)?;
        if pending.plan_path != plan_path
            || pending.plan_hash != plan.plan_hash
            || pending.final_catch_up != final_catch_up
            || !pending.snapshot_path.exists()
        {
            anyhow::bail!(
                "pending migration intent {} does not match this run; resolve it before starting another migration",
                pending_path.display()
            );
        }
        let activity_at_snapshot = source_activity(&plan.source_database);
        if final_catch_up && activity_at_snapshot.active {
            anyhow::bail!(
                "claude-mem appears active; the retained final snapshot was not submitted"
            );
        }
        (
            pending.snapshot_id,
            pending.snapshot_path,
            pending.inventory,
            activity_at_snapshot,
        )
    } else {
        let snapshot_id = Uuid::new_v4().to_string();
        let snapshot_path = migration_state_root()?
            .join("snapshots")
            .join(format!("{snapshot_id}.db"));
        create_snapshot(&plan.source_database, &snapshot_path)?;
        let activity_at_snapshot = source_activity(&plan.source_database);
        if final_catch_up && activity_at_snapshot.active {
            let _ = remove_snapshot_files(&snapshot_path);
            anyhow::bail!("claude-mem became active while the final snapshot was created");
        }
        let inventory = snapshot_inventory(&plan, &snapshot_path)?;
        let pending = PendingRunState {
            plan_path: plan_path.clone(),
            snapshot_path: snapshot_path.clone(),
            snapshot_id: snapshot_id.clone(),
            plan_hash: plan.plan_hash.clone(),
            final_catch_up,
            inventory: inventory.clone(),
        };
        write_json_file(&pending_path, &pending, false)?;
        (snapshot_id, snapshot_path, inventory, activity_at_snapshot)
    };
    let expected_record_count = i64::try_from(inventory.submitted_records)
        .context("snapshot contains too many records for the migration contract")?;
    let create_result = ctx
        .client()
        .await?
        .seren_memory_create_migration(&seren::SerenMemoryCreateMigrationRequest {
            final_catch_up: Some(final_catch_up),
            plan_hash: plan.plan_hash.clone(),
            policy_version: plan.policy_version.clone(),
            expected_record_count,
            series_id: Some(plan.migration_series_id),
            snapshot_id: Some(snapshot_id.clone()),
            source_instance_id: plan.source_instance_id.clone(),
            source_type: "claude-mem".to_string(),
        })
        .await;
    let create_result = memory_gateway_data(create_result, "could not create migration");
    let migration = match create_result {
        Ok(response) => response.data,
        Err(error) => {
            return Err(anyhow::anyhow!(
                "could not create migration: {error}; the fixed snapshot and pending intent were retained for an idempotent retry"
            ));
        }
    };
    if migration.org_id != Some(plan.destination_organization_id) {
        anyhow::bail!(
            "authenticated organization does not match plan destination {}",
            plan.destination_organization_id
        );
    }
    let report_path = report_path(migration.id)?;
    let mut state = LocalRunState {
        migration_id: migration.id,
        migration_series_id: migration.series_id,
        plan_path,
        report_path: report_path.clone(),
        snapshot_path: Some(snapshot_path),
        snapshot_id,
        plan_hash: plan.plan_hash.clone(),
        source_instance_id: plan.source_instance_id.clone(),
        final_catch_up,
    };
    save_run_state(&state)?;
    let mut report = MigrationReport {
        migration_id: migration.id,
        migration_series_id: migration.series_id,
        source_instance_id: plan.source_instance_id.clone(),
        plan_hash: plan.plan_hash.clone(),
        snapshot_id: state.snapshot_id.clone(),
        final_catch_up,
        destination_organization_id: plan.destination_organization_id,
        policy_version: plan.policy_version.clone(),
        workspaces: plan.workspaces.clone(),
        started_at: jiff::Timestamp::now(),
        completed_at: None,
        imported: 0,
        unchanged: 0,
        failed: 0,
        skipped: 0,
        inventory,
        records: BTreeMap::new(),
        verification: None,
    };
    write_json_file(&report_path, &report, true)?;
    std::fs::remove_file(&pending_path).with_context(|| {
        format!(
            "migration was created but pending intent {} could not be cleared",
            pending_path.display()
        )
    })?;
    transition(
        migration.id,
        seren::SerenMemoryMigrationTransitionState::Running,
        ctx,
    )
    .await?;
    execute_snapshot(&plan, &mut state, &mut report, ctx).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "migration_id": migration.id,
            "migration_series_id": migration.series_id,
            "state": "completed",
            "imported": report.imported,
            "unchanged": report.unchanged,
            "skipped": report.skipped,
            "report": report_path,
            "activity_before_snapshot": activity,
            "activity_at_snapshot": activity_at_snapshot,
        }))?
    );
    Ok(())
}

pub async fn status(migration_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_get_migration(&migration_id)
        .await;
    let remote = memory_gateway_data(result, "could not get migration")?.data;
    let local = load_run_state(migration_id).ok();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "remote": remote,
            "local": local.as_ref().map(|state| serde_json::json!({
                "plan": state.plan_path,
                "report": state.report_path,
                "fixed_snapshot_available": state.snapshot_path.as_ref().is_some_and(|path| path.exists()),
                "resumable": state.snapshot_path.as_ref().is_some_and(|path| path.exists()),
            })),
        }))?
    );
    Ok(())
}

pub async fn resume(migration_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let mut state = load_run_state(migration_id)?;
    let plan: MigrationPlan = read_json_file(&state.plan_path)?;
    validate_plan(&plan, false, ctx)?;
    let mut report: MigrationReport = read_json_file(&state.report_path)?;
    if plan.plan_hash != state.plan_hash
        || plan.plan_hash != report.plan_hash
        || plan.migration_series_id != state.migration_series_id
        || plan.source_instance_id != state.source_instance_id
    {
        anyhow::bail!("the accepted plan no longer matches this migration's fixed snapshot");
    }
    transition(
        migration_id,
        seren::SerenMemoryMigrationTransitionState::Running,
        ctx,
    )
    .await?;
    execute_snapshot(&plan, &mut state, &mut report, ctx).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "migration_id": migration_id,
            "state": "completed",
            "imported": report.imported,
            "unchanged": report.unchanged,
            "skipped": report.skipped,
            "report": state.report_path,
        }))?
    );
    Ok(())
}

fn verification_sample(report: &MigrationReport) -> Vec<&RecordReport> {
    let candidates = report
        .records
        .values()
        .filter(|record| {
            matches!(record.status.as_str(), "imported" | "unchanged")
                && record.memory_id.is_some()
                && record.content_sha256.is_some()
        })
        .collect::<Vec<_>>();
    if candidates.len() <= VERIFY_SAMPLE_SIZE {
        return candidates;
    }
    (0..VERIFY_SAMPLE_SIZE)
        .map(|index| {
            let position = index * (candidates.len() - 1) / (VERIFY_SAMPLE_SIZE - 1);
            candidates[position]
        })
        .collect()
}

pub async fn verify(migration_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let state = load_run_state(migration_id)?;
    let mut report: MigrationReport = read_json_file(&state.report_path)?;
    if state.plan_hash != report.plan_hash
        || state.migration_series_id != report.migration_series_id
        || state.source_instance_id != report.source_instance_id
    {
        anyhow::bail!("local migration state and reconciliation report do not match");
    }
    let client = ctx.client().await?;
    let result = client.seren_memory_get_migration(&migration_id).await;
    let remote = memory_gateway_data(result, "could not get migration")?.data;
    if !matches!(
        remote.migration.state,
        seren::SerenMemoryMigrationState::Completed
            | seren::SerenMemoryMigrationState::VerificationFailed
    ) {
        anyhow::bail!(
            "migration must be completed before verification; current state is {}",
            remote.migration.state
        );
    }
    let sample = verification_sample(&report);
    let mut sampled_hash_matches = 0usize;
    for record in &sample {
        let memory_id = record.memory_id.expect("sample requires memory ID");
        let result = client.seren_memory_get_memory(&memory_id).await;
        let memory = memory_gateway_data(result, "could not verify migration memory")?
            .data
            .with_context(|| format!("memory {memory_id} was not found during verification"))?;
        let actual = hex::encode(Sha256::digest(memory.content.as_bytes()));
        if record.content_sha256.as_deref() == Some(actual.as_str()) {
            sampled_hash_matches += 1;
        }
    }
    let successful = report.imported.saturating_add(report.unchanged);
    let mut checks = BTreeMap::new();
    checks.insert("no_failed_records".to_string(), report.failed == 0);
    checks.insert(
        "plan_hash_matches".to_string(),
        remote.migration.plan_hash == report.plan_hash,
    );
    checks.insert(
        "source_instance_matches".to_string(),
        remote.migration.source_instance_id == report.source_instance_id,
    );
    checks.insert(
        "attributed_counts_balanced".to_string(),
        remote.attributed_memories == remote.attributed_sources,
    );
    checks.insert(
        "attributed_records_match_imported".to_string(),
        u64::try_from(remote.attributed_memories)
            .ok()
            .is_some_and(|count| count == report.imported),
    );
    checks.insert(
        "snapshot_report_is_complete".to_string(),
        u64::try_from(report.records.len())
            .ok()
            .is_some_and(|count| count == report.inventory.total_records)
            && report.skipped == report.inventory.skipped_records
            && successful == report.inventory.submitted_records,
    );
    checks.insert(
        "server_expected_snapshot_matches".to_string(),
        u64::try_from(remote.migration.expected_record_count)
            .ok()
            .is_some_and(|count| count == report.inventory.submitted_records),
    );
    checks.insert(
        "server_processed_records_exact".to_string(),
        u64::try_from(remote.processed_records)
            .ok()
            .is_some_and(|count| count == report.inventory.submitted_records)
            && remote.migration.imported_count
                == i64::try_from(report.imported).unwrap_or(i64::MAX)
            && remote.migration.unchanged_count
                == i64::try_from(report.unchanged).unwrap_or(i64::MAX)
            && remote.migration.failed_count == 0,
    );
    checks.insert(
        "semantic_indexing_complete".to_string(),
        remote.embedding_pending == 0
            && remote.embedding_failed == 0
            && remote.embedding_ready == remote.attributed_memories,
    );
    checks.insert(
        "sampled_hashes_match".to_string(),
        sampled_hash_matches == sample.len(),
    );
    let passed = checks.values().all(|value| *value);
    let verification = VerificationReport {
        verified_at: jiff::Timestamp::now(),
        passed,
        sampled_records: sample.len(),
        sampled_hash_matches,
        checks,
    };
    report.verification = Some(verification.clone());
    write_json_file(&state.report_path, &report, true)?;
    if passed && remote.migration.state == seren::SerenMemoryMigrationState::VerificationFailed {
        transition(
            migration_id,
            seren::SerenMemoryMigrationTransitionState::Completed,
            ctx,
        )
        .await?;
    } else if !passed && remote.migration.state == seren::SerenMemoryMigrationState::Completed {
        transition(
            migration_id,
            seren::SerenMemoryMigrationTransitionState::VerificationFailed,
            ctx,
        )
        .await?;
    }
    println!("{}", serde_json::to_string_pretty(&verification)?);
    if !passed {
        anyhow::bail!(
            "migration verification failed; see {}",
            state.report_path.display()
        );
    }
    Ok(())
}

fn cleanup_local_snapshots(migration_id: Uuid, series_id: Option<Uuid>) -> Result<()> {
    let runs_dir = migration_state_root()?.join("runs");
    if !runs_dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(runs_dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let Ok(mut state) = read_json_file::<LocalRunState>(&path) else {
            continue;
        };
        let selected = state.migration_id == migration_id
            || series_id.is_some_and(|series_id| state.migration_series_id == series_id);
        if !selected {
            continue;
        }
        if let Some(snapshot) = state.snapshot_path.take() {
            let _ = remove_snapshot_files(&snapshot);
            save_run_state(&state)?;
        }
    }
    Ok(())
}

pub async fn rollback(
    migration_id: Uuid,
    series: bool,
    confirmed: bool,
    ctx: &CommandContext,
) -> Result<()> {
    if !confirmed {
        anyhow::bail!("rollback requires --yes confirmation");
    }
    let client = ctx.client().await?;
    let series_id = if series {
        Some(
            memory_gateway_data(
                client.seren_memory_get_migration(&migration_id).await,
                "could not get migration",
            )?
            .data
            .migration
            .series_id,
        )
    } else {
        None
    };
    let response = client
        .seren_memory_rollback_migration(
            &migration_id,
            &seren::SerenMemoryRollbackMigrationRequest {
                series: Some(series),
            },
        )
        .await;
    let result = memory_gateway_data(response, "could not roll back migration")?.data;
    cleanup_local_snapshots(migration_id, series_id)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "migration_id": migration_id,
            "series": series,
            "removed_memories": result.removed_memories,
            "removed_sources": result.removed_sources,
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_detection_ignores_unrelated_claude_mem_commands() {
        assert!(is_claude_mem_runtime_command(
            "bun /plugins/claude-mem/scripts/worker-service.cjs"
        ));
        assert!(is_claude_mem_runtime_command(
            "/opt/claude-mem/worker-service-v13.12.4"
        ));
        assert!(!is_claude_mem_runtime_command(
            "rg claude-mem /workspace/readme.md"
        ));
        assert!(!is_claude_mem_runtime_command(
            "code /workspace/claude-mem/src/services/worker-service.ts"
        ));
        assert!(!is_claude_mem_runtime_command(
            "code /workspace/claude-mem/plugin/scripts/mcp-server.cjs"
        ));
        // A marketplace install has no claude-mem path component.
        assert!(is_claude_mem_runtime_command(
            "node /home/u/.claude/plugins/marketplaces/thedotmack/plugin/scripts/bun-runner.js /home/u/.claude/plugins/marketplaces/thedotmack/plugin/scripts/worker-service.cjs start"
        ));
        assert!(!is_claude_mem_runtime_command(
            "rg thedotmack /workspace/notes.md"
        ));
    }

    #[test]
    fn embedding_retry_backoff_is_bounded_and_exponential() {
        assert_eq!(embedding_retry_delay(1), Duration::from_millis(250));
        assert_eq!(embedding_retry_delay(2), Duration::from_millis(500));
        assert_eq!(embedding_retry_delay(3), Duration::from_millis(1_000));
        assert_eq!(
            embedding_retry_delay(u32::MAX),
            Duration::from_millis(u64::MAX)
        );
    }

    fn seeded_database(dir: &Path) -> PathBuf {
        let path = dir.join("claude-mem.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_versions (
                    id INTEGER PRIMARY KEY, version INTEGER UNIQUE NOT NULL,
                    applied_at TEXT NOT NULL);
                INSERT INTO schema_versions (version, applied_at)
                    VALUES (49, '2026-07-23T00:00:00Z');
                PRAGMA user_version = 7;
                CREATE TABLE observations (
                    id INTEGER PRIMARY KEY, type TEXT, title TEXT, subtitle TEXT,
                    narrative TEXT, facts TEXT, created_at_epoch INTEGER,
                    project TEXT, memory_session_id TEXT, text TEXT, concepts TEXT,
                    files_read TEXT, files_modified TEXT, generated_by_model TEXT,
                    agent_type TEXT, agent_id TEXT, content_hash TEXT,
                    origin_device_id TEXT, origin_local_id TEXT,
                    merged_into_project TEXT, prompt_number INTEGER,
                    discovery_tokens INTEGER, relevance_count INTEGER,
                    metadata TEXT, sync_rev TEXT);
                CREATE TABLE session_summaries (
                    id INTEGER PRIMARY KEY, request TEXT, learned TEXT, completed TEXT,
                    next_steps TEXT, created_at_epoch INTEGER, project TEXT,
                    memory_session_id TEXT, discovery_tokens INTEGER, sync_rev TEXT);
                CREATE TABLE sdk_sessions (
                    memory_session_id TEXT, project TEXT, platform_source TEXT);
                INSERT INTO observations (
                    id, type, title, subtitle, narrative, facts, created_at_epoch,
                    project, memory_session_id, concepts, files_read, files_modified,
                    generated_by_model, agent_type, agent_id, content_hash,
                    origin_device_id, origin_local_id, merged_into_project, prompt_number,
                    discovery_tokens, relevance_count, metadata, sync_rev
                ) VALUES
                    (7, 'bugfix', 'Fixed retry', NULL,
                        'Root cause was api_key=abc123secret in logs', NULL,
                        1753300000000, 'seren-memory', 'sess-1',
                        'api_key=metadata-secret', '[\"src/lib.rs\"]', '[\"src/main.rs\"]',
                        'claude-test', 'primary', 'agent-1', 'legacy-hash',
                        'device-1', 'local-1', NULL, 4, 123, 5,
                        '{\"source\":\"manual\",\"password\":\"metadata-secret\"}', '9'),
                    (8, 'discovery', NULL, NULL, NULL, NULL,
                        1753300001000, 'seren-memory', 'sess-1',
                        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                        0, 0, NULL, '1');
                INSERT INTO session_summaries (
                    id, request, learned, completed, next_steps, created_at_epoch,
                    project, memory_session_id, discovery_tokens, sync_rev
                ) VALUES
                    (3, 'Investigate flake', 'It was a race', 'Fixed it', NULL,
                        1753300002, 'seren-memory', 'sess-1', 42, '3');
                INSERT INTO sdk_sessions VALUES ('sess-1', 'seren-memory', 'claude');",
            )
            .unwrap();
        path
    }

    fn isolated_mappings(connection: &Connection) -> BTreeMap<String, WorkspaceMapping> {
        distinct_projects(connection)
            .unwrap()
            .into_iter()
            .map(|(project, _)| {
                (
                    project.clone(),
                    WorkspaceMapping {
                        legacy_project: project,
                        disposition: WorkspaceDisposition::Isolated,
                        workspace_key: Some("legacy:test".to_string()),
                        workspace_uri: None,
                        path_exists: false,
                        candidate_records: 3,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn type_mapping_matches_the_plan_table() {
        assert_eq!(mapped_memory_type("bugfix"), "error_fix");
        assert_eq!(mapped_memory_type("decision"), "semantic");
        assert_eq!(mapped_memory_type("discovery"), "semantic");
        assert_eq!(mapped_memory_type("feature"), "code");
        assert_eq!(mapped_memory_type("refactor"), "code");
        assert_eq!(mapped_memory_type("change"), "code");
    }

    #[test]
    fn epoch_handles_seconds_and_milliseconds() {
        let from_ms = epoch_to_timestamp(1_753_300_000_000).unwrap();
        let from_s = epoch_to_timestamp(1_753_300_000).unwrap();
        assert_eq!(from_ms, from_s);
    }

    #[test]
    fn default_source_instance_preserves_existing_rehearsal_identity_width() {
        assert_eq!(
            default_source_instance(Path::new("/tmp/claude-mem.db")).len(),
            16
        );
    }

    #[test]
    fn source_schema_uses_claude_mem_migration_version() {
        let dir = tempfile::tempdir().unwrap();
        let database = seeded_database(dir.path());
        let connection = open_read_only(&database).unwrap();
        let schema = source_schema(&connection).unwrap();
        assert_eq!(schema.migration_version, Some(49));
        assert!(schema.identity.starts_with("sqlite-49-"));
    }

    #[test]
    fn unsupported_local_server_memories_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let database = seeded_database(dir.path());
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE memory_items (id TEXT PRIMARY KEY);
                INSERT INTO memory_items (id) VALUES ('server-memory-1');",
            )
            .unwrap();
        let schema = source_schema(&connection).unwrap();
        assert!(schema.tables.contains_key("memory_items"));
        let error = ensure_supported_source_corpus(&connection).unwrap_err();
        assert!(error.to_string().contains("refuses to omit those records"));
    }

    #[test]
    fn capture_configuration_detection_matches_claude_mem_installers() {
        assert!(claude_settings_capture_enabled(&serde_json::json!({
            "enabledPlugins": {"claude-mem@thedotmack": true}
        })));
        assert!(!claude_settings_capture_enabled(&serde_json::json!({
            "enabledPlugins": {"claude-mem@thedotmack": false}
        })));
        let enabled: toml::Value =
            toml::from_str("[plugins.\"claude-mem@claude-mem-local\"]\nenabled = true\n").unwrap();
        assert!(codex_config_capture_enabled(&enabled));
        let disabled: toml::Value =
            toml::from_str("[plugins.\"claude-mem@thedotmack\"]\nenabled = false\n").unwrap();
        assert!(!codex_config_capture_enabled(&disabled));
    }

    #[test]
    fn oversized_metadata_is_bounded_deterministically_before_upload() {
        let build = || {
            let mut metadata = serde_json::Map::new();
            for group in ["legacy", "files", "agent", "origin"] {
                let mut entries = serde_json::Map::new();
                for key in ["a", "b", "c", "d"] {
                    entries.insert(
                        key.to_string(),
                        // JSON strings that escape heavily, as claude-mem's
                        // array- and object-valued TEXT columns do.
                        serde_json::Value::String("[\"x\",\"y\",\"z\"]".repeat(70)),
                    );
                }
                metadata.insert(group.to_string(), serde_json::Value::Object(entries));
            }
            metadata
        };

        let mut oversized = build();
        assert!(source_metadata_len(&oversized) > MAX_SOURCE_METADATA_BYTES);
        assert!(fit_source_metadata(&mut oversized));
        assert!(source_metadata_len(&oversized) <= MAX_SOURCE_METADATA_BYTES);

        let mut repeated = build();
        assert!(fit_source_metadata(&mut repeated));
        assert_eq!(oversized, repeated, "trimming must be deterministic");

        let mut already_small = serde_json::Map::new();
        already_small.insert(
            "legacy".to_string(),
            serde_json::json!({"title": "short title"}),
        );
        let unchanged = already_small.clone();
        assert!(!fit_source_metadata(&mut already_small));
        assert_eq!(already_small, unchanged);
    }

    /// The service rejects any metadata object carrying more than ten keys, and
    /// a fully populated `legacy` group already sits on that limit. Adding one
    /// more claude-mem column to a group would otherwise fail every record that
    /// populates it, and only against a real service during an import run.
    #[test]
    fn metadata_groups_stay_within_the_service_key_bound() {
        const MAX_SERVICE_METADATA_KEYS: usize = 10;
        let dir = tempfile::tempdir().unwrap();
        let database = seeded_database(dir.path());
        // Populate every optional column so each group reaches its widest shape.
        let writable = Connection::open(&database).unwrap();
        writable
            .execute_batch(
                "UPDATE observations SET
                    title = 'title', subtitle = 'subtitle', text = 'text',
                    concepts = 'concepts', content_hash = 'hash',
                    merged_into_project = 'merged', prompt_number = 1,
                    discovery_tokens = 1, relevance_count = 1, metadata = '{}',
                    files_read = '[]', files_modified = '[]',
                    generated_by_model = 'model', agent_type = 'type',
                    agent_id = 'agent', origin_device_id = 'device',
                    origin_local_id = 'local', sync_rev = '1';",
            )
            .unwrap();
        drop(writable);
        let connection = open_read_only(&database).unwrap();
        let mappings = isolated_mappings(&connection);
        let mut checked = 0;
        for category in [RecordCategory::Observation, RecordCategory::Summary] {
            let page =
                load_page(&connection, category, i64::MIN, 100, "instance", &mappings).unwrap();
            let PreparedOutcome::Record(record) = &page[0].1 else {
                panic!("{category:?} record should be importable");
            };
            let metadata = record
                .api
                .source_metadata
                .as_ref()
                .expect("record carries source metadata");
            // The service adds `source_project` to the top-level object.
            assert!(
                metadata.len() < MAX_SERVICE_METADATA_KEYS,
                "{category:?} top-level metadata leaves no room for source_project: {:?}",
                metadata.keys().collect::<Vec<_>>()
            );
            for (group, value) in metadata {
                let entries = value
                    .as_object()
                    .unwrap_or_else(|| panic!("{category:?} group {group} must be an object"));
                assert!(
                    entries.len() <= MAX_SERVICE_METADATA_KEYS,
                    "{category:?} group {group} has {} keys, over the service bound of {MAX_SERVICE_METADATA_KEYS}",
                    entries.len()
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "the fixture must populate metadata groups");
    }

    #[test]
    fn pages_preserve_metadata_and_redact_before_upload() {
        let dir = tempfile::tempdir().unwrap();
        let database = seeded_database(dir.path());
        let connection = open_read_only(&database).unwrap();
        let mappings = isolated_mappings(&connection);
        let records = observation_page(&connection, i64::MIN, 100, "instance", &mappings).unwrap();
        assert_eq!(records.len(), 2);
        let PreparedOutcome::Record(record) = &records[0].1 else {
            panic!("first observation should be importable");
        };
        assert_eq!(
            record.api.source_external_id,
            "import:claude-mem:instance:observation:7"
        );
        assert_eq!(
            record.api.memory_type,
            seren::SerenMemoryMemoryType::ErrorFix
        );
        assert_eq!(record.api.agent_platform.as_deref(), Some("claude"));
        assert!(record.redacted);
        assert!(!record.api.content.contains("abc123secret"));
        let metadata = serde_json::to_string(&record.api.source_metadata).unwrap();
        assert!(!metadata.contains("metadata-secret"));
        assert!(metadata.len() < 16_000);
        assert_eq!(
            record
                .api
                .source_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("legacy"))
                .and_then(serde_json::Value::as_object)
                .and_then(|legacy| legacy.get("title")),
            Some(&serde_json::json!("Fixed retry"))
        );
        let legacy = record
            .api
            .source_metadata
            .as_ref()
            .and_then(|metadata| metadata.get("legacy"))
            .and_then(serde_json::Value::as_object)
            .unwrap();
        assert_eq!(
            legacy.get("discovery_tokens"),
            Some(&serde_json::json!(123))
        );
        assert_eq!(legacy.get("relevance_count"), Some(&serde_json::json!(5)));
        assert!(
            !legacy
                .get("metadata")
                .and_then(serde_json::Value::as_str)
                .unwrap()
                .contains("metadata-secret")
        );
        assert_eq!(
            record
                .api
                .source_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("origin"))
                .and_then(serde_json::Value::as_object)
                .and_then(|origin| origin.get("sync_revision")),
            Some(&serde_json::json!("9"))
        );
        assert!(matches!(
            records[1].1,
            PreparedOutcome::Skipped { ref reason, .. } if reason == "empty_content"
        ));
        let summaries = summary_page(&connection, i64::MIN, 100, "instance", &mappings).unwrap();
        let PreparedOutcome::Record(summary) = &summaries[0].1 else {
            panic!("summary should be importable");
        };
        assert_eq!(summary.api.agent_platform.as_deref(), Some("claude"));
        assert_eq!(
            summary
                .api
                .source_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("legacy"))
                .and_then(serde_json::Value::as_object)
                .and_then(|legacy| legacy.get("discovery_tokens")),
            Some(&serde_json::json!(42))
        );
        assert_eq!(
            summary
                .api
                .source_metadata
                .as_ref()
                .and_then(|metadata| metadata.get("origin"))
                .and_then(serde_json::Value::as_object)
                .and_then(|origin| origin.get("sync_revision")),
            Some(&serde_json::json!("3"))
        );
        let estimate = estimate_plan(
            &connection,
            "instance",
            &mappings.values().cloned().collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(estimate.observations, 2);
        assert_eq!(estimate.session_summaries, 1);
        assert_eq!(estimate.selected_records, 2);
        assert_eq!(estimate.empty_records, 1);
        assert_eq!(estimate.redacted_records, 1);
    }

    #[test]
    fn snapshot_inventory_counts_submitted_and_skipped_records_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let database = seeded_database(dir.path());
        let connection = open_read_only(&database).unwrap();
        let workspaces = isolated_mappings(&connection).into_values().collect();
        let plan = MigrationPlan {
            accepted: true,
            plan_hash: "a".repeat(64),
            destination_api: "https://api.example.test".to_string(),
            destination_profile: "default".to_string(),
            destination_organization_id: Uuid::nil(),
            source_database: database.clone(),
            source_instance_id: "instance".to_string(),
            source_schema_identity: "schema".to_string(),
            migration_series_id: Uuid::nil(),
            policy_version: None,
            include_observations: true,
            include_session_summaries: true,
            include_raw_prompts: false,
            workspaces,
            estimate: PlanEstimate {
                observations: 2,
                session_summaries: 1,
                selected_records: 2,
                skipped_by_workspace: 0,
                unresolved_workspace_records: 0,
                empty_records: 1,
                redacted_records: 1,
            },
        };

        let inventory = snapshot_inventory(&plan, &database).unwrap();
        assert_eq!(inventory.total_records, 3);
        assert_eq!(inventory.submitted_records, 2);
        assert_eq!(inventory.skipped_records, 1);
    }

    #[test]
    fn report_checkpoint_frequency_stays_bounded_for_a_large_corpus() {
        let total_records = 45_000;
        let interval = report_checkpoint_batches(total_records);
        let total_batches = usize::try_from(total_records)
            .unwrap()
            .div_ceil(IMPORT_BATCH_SIZE);
        assert!(
            interval > 10,
            "large imports must not rewrite every ten batches"
        );
        assert!(
            total_batches.div_ceil(interval) <= TARGET_REPORT_CHECKPOINTS,
            "checkpoint rewrites must stay within the target"
        );
        assert_eq!(report_checkpoint_batches(3), 1);
    }

    #[test]
    fn resumable_snapshot_is_detected_before_starting_an_overlapping_run() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("state");
        let snapshot = root.join("snapshots").join("snapshot.db");
        create_private_dir(snapshot.parent().unwrap()).unwrap();
        std::fs::write(&snapshot, b"fixed snapshot").unwrap();
        let migration_id = Uuid::new_v4();
        let series_id = Uuid::new_v4();
        let plan = MigrationPlan {
            accepted: true,
            plan_hash: "a".repeat(64),
            destination_api: "https://api.example.test".to_string(),
            destination_profile: "default".to_string(),
            destination_organization_id: Uuid::new_v4(),
            source_database: dir.path().join("claude-mem.db"),
            source_instance_id: "instance".to_string(),
            source_schema_identity: "schema".to_string(),
            migration_series_id: series_id,
            policy_version: None,
            include_observations: true,
            include_session_summaries: true,
            include_raw_prompts: false,
            workspaces: Vec::new(),
            estimate: PlanEstimate {
                observations: 0,
                session_summaries: 0,
                selected_records: 0,
                skipped_by_workspace: 0,
                unresolved_workspace_records: 0,
                empty_records: 0,
                redacted_records: 0,
            },
        };
        let state = LocalRunState {
            migration_id,
            migration_series_id: series_id,
            plan_path: dir.path().join("plan.json"),
            report_path: root.join("reports").join(format!("{migration_id}.json")),
            snapshot_path: Some(snapshot.clone()),
            snapshot_id: "snapshot".to_string(),
            plan_hash: plan.plan_hash.clone(),
            source_instance_id: plan.source_instance_id.clone(),
            final_catch_up: false,
        };
        write_json_file(
            &root.join("runs").join(format!("{migration_id}.json")),
            &state,
            false,
        )
        .unwrap();

        assert_eq!(
            resumable_migration_ids_at(&root, &plan, false).unwrap(),
            vec![migration_id]
        );
        assert!(
            resumable_migration_ids_at(&root, &plan, true)
                .unwrap()
                .is_empty(),
            "incremental and final catch-up runs must not block each other"
        );

        std::fs::remove_file(snapshot).unwrap();
        assert!(
            resumable_migration_ids_at(&root, &plan, false)
                .unwrap()
                .is_empty(),
            "a missing snapshot cannot be resumed and must not block a replacement run"
        );
    }

    #[test]
    fn snapshot_includes_wal_consistently() {
        let dir = tempfile::tempdir().unwrap();
        let database = seeded_database(dir.path());
        let destination = dir.path().join("snapshot.db");
        create_snapshot(&database, &destination).unwrap();
        let snapshot = open_read_only(&destination).unwrap();
        assert_eq!(
            count(&snapshot, "SELECT COUNT(*) FROM observations").unwrap(),
            2
        );
        drop(snapshot);
        remove_snapshot_files(&destination).unwrap();
        assert!(!destination.exists());
        assert!(!snapshot_sidecar(&destination, "-wal").exists());
        assert!(!snapshot_sidecar(&destination, "-shm").exists());
    }

    #[test]
    fn plan_hash_ignores_acceptance_but_detects_mapping_changes() {
        let mut plan = MigrationPlan {
            accepted: false,
            plan_hash: String::new(),
            destination_api: "https://api.example.test".to_string(),
            destination_profile: "default".to_string(),
            destination_organization_id: Uuid::nil(),
            source_database: PathBuf::from("/tmp/claude-mem.db"),
            source_instance_id: "source".to_string(),
            source_schema_identity: "schema".to_string(),
            migration_series_id: Uuid::nil(),
            policy_version: None,
            include_observations: true,
            include_session_summaries: true,
            include_raw_prompts: false,
            workspaces: vec![WorkspaceMapping {
                legacy_project: "project".to_string(),
                disposition: WorkspaceDisposition::Isolated,
                workspace_key: Some("legacy:project".to_string()),
                workspace_uri: None,
                path_exists: false,
                candidate_records: 1,
            }],
            estimate: PlanEstimate {
                observations: 1,
                session_summaries: 0,
                selected_records: 1,
                skipped_by_workspace: 0,
                unresolved_workspace_records: 0,
                empty_records: 0,
                redacted_records: 0,
            },
        };
        let initial = plan_hash(&plan).unwrap();
        plan.accepted = true;
        assert_eq!(plan_hash(&plan).unwrap(), initial);
        plan.workspaces[0].workspace_key = Some("legacy:changed".to_string());
        assert_ne!(plan_hash(&plan).unwrap(), initial);
    }
}
