// ABOUTME: `seren agent dev <dir>` packages an agent directory into a draft AgentSpec,
// ABOUTME: deploys it to a profile-scoped dev namespace, streams logs, and deletes on SIGINT.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use colored::Colorize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::CommandContext;
use crate::commands::auth::get_bearer_token;

/// Slug prefix that scopes `seren agent dev` deployments away from production agents.
pub const DEV_NAMESPACE_PREFIX: &str = "dev-";

/// Server-side AgentBundle limits, enforced client-side so an oversized
/// upload fails locally with a clear message instead of being rejected after
/// a long round trip.
///
/// The values mirror the server contract: total payload <= 16 MiB,
/// each instruction file <= 1 MiB, each asset <= 8 MiB.
pub const MAX_BUNDLE_TOTAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_INSTRUCTION_BYTES: usize = 1024 * 1024;
pub const MAX_ASSET_BYTES: usize = 8 * 1024 * 1024;

/// File name -> AgentInstructionKind mapping for recognized instruction files.
///
/// Lookup is case-insensitive on the file name (e.g. `SKILL.md`, `skill.md`,
/// `Skill.MD` all map to the `skill` kind).
const INSTRUCTION_FILES: &[(&str, seren::AgentInstructionKind)] = &[
    ("SKILL.md", seren::AgentInstructionKind::Skill),
    ("IDENTITY.md", seren::AgentInstructionKind::Identity),
    ("SOUL.md", seren::AgentInstructionKind::Soul),
    ("AGENTS.md", seren::AgentInstructionKind::Agents),
    ("TOOLS.md", seren::AgentInstructionKind::Tools),
    ("MEMORY.md", seren::AgentInstructionKind::Memory),
    ("HEARTBEAT.md", seren::AgentInstructionKind::Heartbeat),
    ("USER.md", seren::AgentInstructionKind::User),
    ("EVAL.md", seren::AgentInstructionKind::Eval),
];

/// Inputs to `dev_agent_run` / the `seren agent dev` subcommand.
#[derive(Debug, Clone)]
pub struct DevAgentOptions {
    /// Directory containing instruction files (and optional assets) to package.
    pub directory: PathBuf,
    /// Optional display name override. Defaults to the directory file name.
    pub name: Option<String>,
    /// Optional agent slug override. Defaults to `dev-<user>-<dir>` (slugified).
    pub agent_slug: Option<String>,
    /// Per-user discriminator inserted into the slug so that two developers
    /// in the same org running `seren agent dev` against identical inputs do
    /// not collide on a single `dev-<slug>` namespace.
    ///
    /// When `None`, the slug is built without a discriminator (legacy form);
    /// the CLI entrypoint populates this from the active auth context before
    /// calling [`package_agent_directory`].
    pub user_discriminator: Option<String>,
    /// When true, build the spec but skip the network calls (deploy/logs/delete).
    pub dry_run: bool,
}

/// Result of packaging a directory into an in-memory `AgentSpec` draft.
///
/// Returned separately so the packaging step can be unit-tested without
/// invoking the SDK or the network.
#[derive(Debug, Clone)]
pub struct AgentSpecDraft {
    pub spec: seren::AgentSpec,
    pub directory: PathBuf,
    pub instruction_count: usize,
    pub asset_count: usize,
}

/// Build an `AgentSpec` draft from the contents of a directory.
///
/// Recognized instruction files at the top level of the directory become
/// typed `AgentInstructionFile` entries (see [`INSTRUCTION_FILES`]). Every
/// other regular file -- including files nested inside subdirectories --
/// becomes a base64-encoded `AgentAssetFile` resource with its directory-
/// relative path preserved (using forward slashes regardless of platform).
///
/// Hidden entries (names starting with `.`) are skipped at every depth so a
/// `.git` checkout or `.env` is never accidentally packaged.
///
/// Symlinks are rejected if their canonical target resolves outside the
/// input directory. This prevents a `notes -> /etc/passwd` link from
/// silently shipping its contents to the bundle.
///
/// The function also enforces the server-side AgentBundle size limits
/// ([`MAX_INSTRUCTION_BYTES`], [`MAX_ASSET_BYTES`], [`MAX_BUNDLE_TOTAL_BYTES`])
/// up-front so an oversized directory fails locally with a clear error
/// naming the offending file instead of being rejected after a long upload.
pub fn package_agent_directory(options: &DevAgentOptions) -> Result<AgentSpecDraft> {
    let dir = options.directory.as_path();
    if !dir.is_dir() {
        anyhow::bail!("'{}' is not a directory", dir.display());
    }

    // Canonicalize the root once; every nested file's canonical parent must
    // start with this prefix, otherwise it is a symlink escape.
    let root_canonical = dir
        .canonicalize()
        .with_context(|| format!("Could not canonicalize '{}'", dir.display()))?;

    let dir_label = dir
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("agent")
        .to_string();

    let display_name = options
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| dir_label.clone());

    let slug_base = options
        .agent_slug
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| dir_label.clone());
    let agent_slug = build_dev_agent_slug(&slug_base, options.user_discriminator.as_deref())?;

    // Walk the directory in sorted order so the resulting bundle is stable
    // across runs and platforms. The map is keyed by the bundle-relative
    // path so each file's intended target slot is explicit.
    let mut entries: BTreeMap<String, PathBuf> = BTreeMap::new();
    collect_files(dir, dir, &root_canonical, &mut entries)?;

    let mut instructions: Vec<seren::AgentInstructionFile> = Vec::new();
    let mut assets: Vec<seren::AgentAssetFile> = Vec::new();
    let mut total_bytes: usize = 0;

    for (rel_path, path) in &entries {
        // Instruction recognition is intentionally limited to top-level files.
        // A nested SKILL.md at arbitrary depth would otherwise either silently
        // override the top-level one or fail unpredictably; treating nested
        // files as plain assets keeps the contract obvious.
        let top_level_kind = if rel_path.contains('/') {
            None
        } else {
            instruction_kind_for(rel_path)
        };

        if let Some(kind) = top_level_kind {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Could not read instruction file '{}'", path.display()))?;
            if content.len() > MAX_INSTRUCTION_BYTES {
                anyhow::bail!(
                    "Instruction file '{}' is {} bytes, exceeds per-instruction limit of {} bytes.",
                    rel_path,
                    content.len(),
                    MAX_INSTRUCTION_BYTES
                );
            }
            total_bytes = total_bytes.saturating_add(content.len());
            ensure_total_under_limit(total_bytes, rel_path)?;
            instructions.push(seren::AgentInstructionFile {
                allowed_tools: None,
                content,
                kind,
                path: Some(rel_path.clone()),
                sha256: None,
                skill_name: None,
            });
        } else {
            let bytes = std::fs::read(path)
                .with_context(|| format!("Could not read asset '{}'", path.display()))?;
            if bytes.len() > MAX_ASSET_BYTES {
                anyhow::bail!(
                    "Asset '{}' is {} bytes, exceeds per-asset limit of {} bytes.",
                    rel_path,
                    bytes.len(),
                    MAX_ASSET_BYTES
                );
            }
            total_bytes = total_bytes.saturating_add(bytes.len());
            ensure_total_under_limit(total_bytes, rel_path)?;
            assets.push(seren::AgentAssetFile {
                content_base64: BASE64_STANDARD.encode(bytes),
                content_type: None,
                path: rel_path.clone(),
                purpose: Some(seren::AgentAssetPurpose::Resource),
                sha256: None,
            });
        }
    }

    if instructions.is_empty() {
        anyhow::bail!(
            "'{}' has no recognized instruction files (SKILL.md, IDENTITY.md, SOUL.md, AGENTS.md, TOOLS.md, MEMORY.md, HEARTBEAT.md).",
            dir.display()
        );
    }

    let bundle = seren::AgentBundle {
        assets: assets.clone(),
        instructions: instructions.clone(),
    };

    let workload = seren::WorkloadSpec {
        compute_backend: None,
        config: None,
        execution: seren::WorkloadExecution::Llm {
            adapter: None,
            bundle,
            fallback_models: None,
            llm_connection: None,
            model_config: None,
            model_id: None,
            tool_definitions: None,
        },
        limits: None,
        network_policy: None,
        publisher_only: None,
        requirements: None,
        secrets: None,
        side_effect_policy: None,
    };

    let spec = seren::AgentSpec {
        agent_identity_id: None,
        agent_slug: Some(agent_slug),
        alert_policy: None,
        allowed_remote_agent_origins: None,
        approval_policy: None,
        credentials: None,
        cron_schedule: None,
        cron_timezone: None,
        dashboard_config: None,
        eval_gate: None,
        guardrails: None,
        memory_policy: None,
        capability_policy: None,
        mode: seren::CloudDeploymentMode::AlwaysOn,
        model_policy: None,
        name: Some(display_name),
        private_output_policy: None,
        runtime_policy: None,
        secret_resolution_delegation: None,
        session_database: None,
        template: None,
        tool_presets: None,
        tool_refs: None,
        visibility: None,
        workload,
    };

    Ok(AgentSpecDraft {
        spec,
        directory: dir.to_path_buf(),
        instruction_count: instructions.len(),
        asset_count: assets.len(),
    })
}

/// Recursively walk `dir`, populating `entries` with bundle-relative paths
/// for every regular file under the input directory. Hidden entries are
/// skipped at every depth. Symlinks whose canonical target escapes
/// `root_canonical` are rejected with an error.
fn collect_files(
    dir: &std::path::Path,
    root: &std::path::Path,
    root_canonical: &std::path::Path,
    entries: &mut BTreeMap<String, PathBuf>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Could not read directory '{}'", dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let file_type = entry.file_type()?;

        // Both files and dirs reached via symlinks have to canonicalize back
        // inside the root. Resolving here covers the symlink-to-outside case
        // that `read_to_string`/`read` would otherwise follow transparently.
        let canonical = path
            .canonicalize()
            .with_context(|| format!("Could not canonicalize entry '{}'", path.display()))?;
        if !canonical.starts_with(root_canonical) {
            anyhow::bail!(
                "Entry '{}' resolves to '{}', which is outside the agent directory.",
                path.display(),
                canonical.display()
            );
        }

        if file_type.is_dir() || (file_type.is_symlink() && canonical.is_dir()) {
            collect_files(&path, root, root_canonical, entries)?;
            continue;
        }

        if !(file_type.is_file() || (file_type.is_symlink() && canonical.is_file())) {
            continue;
        }

        let rel = path.strip_prefix(root).unwrap_or(&path);
        // Forward slashes are stable across platforms; the wire format uses
        // POSIX-style paths even when assembled on Windows.
        let rel_string: String = rel
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect::<Vec<_>>()
            .join("/");

        entries.insert(rel_string, path);
    }
    Ok(())
}

fn ensure_total_under_limit(total: usize, rel_path: &str) -> Result<()> {
    if total > MAX_BUNDLE_TOTAL_BYTES {
        anyhow::bail!(
            "Adding '{}' would push the bundle past the total limit of {} bytes (current total {}).",
            rel_path,
            MAX_BUNDLE_TOTAL_BYTES,
            total
        );
    }
    Ok(())
}

/// Map a file name (case-insensitive) to its instruction kind, if any.
pub fn instruction_kind_for(file_name: &str) -> Option<seren::AgentInstructionKind> {
    INSTRUCTION_FILES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(file_name))
        .map(|(_, kind)| *kind)
}

/// Length of the per-user discriminator embedded in the dev slug.
///
/// A 6-character hex prefix gives 16^6 = ~16M values, which keeps the chance
/// of two developers in the same org colliding on `dev-<hash>-<slug>` low
/// enough to ignore in practice while leaving the slug short and readable.
pub const USER_DISCRIMINATOR_LEN: usize = 6;

/// Build a stable `agent_slug` value inside the `dev-` namespace.
///
/// The base value is lowercased; runs of non-alphanumeric characters collapse
/// to a single `-`. Leading/trailing dashes are trimmed. The final slug is
/// always prefixed with `DEV_NAMESPACE_PREFIX` so production agents and dev
/// drafts never collide on the same name.
///
/// When a non-empty `user_discriminator` is provided, the form is
/// `dev-<user>-<slug>`; this keeps two developers running
/// `seren agent dev <same-dir>` from colliding on a single namespace.
pub fn build_dev_agent_slug(base: &str, user_discriminator: Option<&str>) -> Result<String> {
    let normalized = normalize_slug(base);
    if normalized.is_empty() {
        anyhow::bail!(
            "Could not derive a valid agent slug from '{}'. Provide --agent-slug.",
            base
        );
    }

    let discriminator = user_discriminator
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_slug)
        .filter(|value| !value.is_empty());

    // Avoid double-prefixing if the caller already provided a `dev-` slug.
    let unprefixed = normalized
        .strip_prefix(DEV_NAMESPACE_PREFIX)
        .unwrap_or(&normalized);

    match discriminator {
        Some(disc) => Ok(format!("{DEV_NAMESPACE_PREFIX}{disc}-{unprefixed}")),
        None => Ok(format!("{DEV_NAMESPACE_PREFIX}{unprefixed}")),
    }
}

/// Derive a stable, per-user discriminator from the active auth context.
///
/// Uses the first 6 hex characters of SHA-256 over the bearer token. The
/// hash never leaves the local machine; it is only used to namespace dev
/// deployments. Returns `None` when no bearer token is available so callers
/// can fall back to the plain `dev-<slug>` form.
pub async fn user_discriminator_from_auth(ctx: &CommandContext) -> Option<String> {
    let token = get_bearer_token(ctx.api_key.clone()).await.ok()?;
    Some(hash_user_discriminator(&token))
}

/// Compute the 6-character hex discriminator for an arbitrary identifying
/// string. Exposed for tests so different "users" can be mocked without
/// wiring up real auth.
pub fn hash_user_discriminator(identity: &str) -> String {
    let digest = Sha256::digest(identity.as_bytes());
    let hex = hex::encode(digest);
    hex[..USER_DISCRIMINATOR_LEN].to_string()
}

fn normalize_slug(value: &str) -> String {
    let mut slug = String::with_capacity(value.len());
    let mut last_was_dash = false;
    for ch in value.trim().chars().flat_map(char::to_lowercase) {
        let next = if ch.is_ascii_alphanumeric() { ch } else { '-' };
        if next == '-' {
            if last_was_dash {
                continue;
            }
            last_was_dash = true;
        } else {
            last_was_dash = false;
        }
        slug.push(next);
    }
    slug.trim_matches('-').to_string()
}

/// Trait abstraction over the seren-agent operations used by `agent dev`.
///
/// Allows unit tests to exercise the deploy/log/delete flow without hitting the
/// network. The real `seren::Client` implementation is wired in [`SdkClient`].
pub trait DevAgentClient: Send + Sync {
    fn deploy<'a>(
        &'a self,
        spec: &'a seren::AgentSpec,
    ) -> impl std::future::Future<Output = Result<Uuid>> + Send + 'a;
    fn delete(
        &self,
        deployment_id: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send + '_;
    fn stream_logs(
        &self,
        deployment_id: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send + '_;
}

/// Real `seren::Client`-backed implementation of [`DevAgentClient`].
pub struct SdkClient<'a> {
    pub inner: &'a seren::Client,
}

impl DevAgentClient for SdkClient<'_> {
    async fn deploy(&self, spec: &seren::AgentSpec) -> Result<Uuid> {
        let response = self
            .inner
            .seren_agent_deploy(spec)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to deploy dev agent: {}", e))?;
        let detail = response.into_inner();
        Ok(detail.data.id)
    }

    async fn delete(&self, deployment_id: Uuid) -> Result<()> {
        self.inner
            .seren_agent_delete_managed_deployment(&deployment_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to delete dev agent: {}", e))?;
        Ok(())
    }

    async fn stream_logs(&self, deployment_id: Uuid) -> Result<()> {
        println!(
            "    Log streaming is unavailable for deployment {deployment_id}; press Ctrl-C to stop and delete."
        );
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// CLI entrypoint: package `options.directory`, deploy it, stream logs until
/// SIGINT, then delete.
pub async fn dev_agent_run(mut options: DevAgentOptions, ctx: &CommandContext) -> Result<()> {
    // Stamp the slug with a per-user discriminator so two developers in the
    // same org can run `seren agent dev <same-dir>` without colliding on a
    // single `dev-<slug>` namespace.
    if options.user_discriminator.is_none() {
        options.user_discriminator = user_discriminator_from_auth(ctx).await;
    }

    let draft = package_agent_directory(&options)?;
    print_draft_summary(&draft);

    if options.dry_run {
        println!(
            "{} Dry run - draft AgentSpec built, skipping deploy.",
            "i".cyan()
        );
        return Ok(());
    }

    let client = ctx.client().await?;
    let sdk = SdkClient { inner: &client };
    run_with_client(draft.spec, &sdk).await
}

/// Core deploy/tail/delete flow expressed against the trait. Public so
/// integration tests in this crate can exercise it with a fake client.
pub async fn run_with_client<C: DevAgentClient>(spec: seren::AgentSpec, client: &C) -> Result<()> {
    let display_name = spec.name.clone().unwrap_or_else(|| "agent".to_string());
    let slug = spec.agent_slug.clone().unwrap_or_default();

    println!(
        "{} Deploying dev agent {} ({})...",
        "->".blue(),
        display_name.bold(),
        slug
    );

    let deployment_id = client.deploy(&spec).await?;
    println!("{} Dev deployment created: {}", "ok".green(), deployment_id);
    println!("    Logs follow; press Ctrl-C to stop and delete.");

    let log_outcome = tokio::select! {
        result = client.stream_logs(deployment_id) => Some(result),
        _ = tokio::signal::ctrl_c() => None,
    };

    // Always attempt to clean up the deployment so a Ctrl-C never leaks state.
    // Retry once on transient failure before surfacing an error so a CI
    // invocation does not silently exit zero while leaving an orphan running.
    let delete_outcome = delete_with_retry(client, deployment_id).await;

    if let Some(result) = log_outcome {
        // Surface log-stream errors (but not Ctrl-C interruption).
        result?;
    }

    match delete_outcome {
        Ok(()) => {
            println!(
                "\n{} Dev deployment {} deleted.",
                "ok".green(),
                deployment_id
            );
            Ok(())
        }
        Err(err) => {
            eprintln!(
                "\n{} Failed to delete dev deployment {}: {}",
                "warn".yellow(),
                deployment_id,
                err
            );
            eprintln!(
                "    Run `seren agent cloud delete {}` to clean up the orphaned deployment.",
                deployment_id
            );
            Err(anyhow::anyhow!(
                "dev deployment {} was not deleted: {}",
                deployment_id,
                err
            ))
        }
    }
}

/// Best-effort delete with one retry. The first failure is logged, then a
/// second attempt runs after a short backoff. The final error (if any) is
/// returned to the caller.
async fn delete_with_retry<C: DevAgentClient>(client: &C, deployment_id: Uuid) -> Result<()> {
    match client.delete(deployment_id).await {
        Ok(()) => Ok(()),
        Err(first_err) => {
            eprintln!(
                "\n{} Delete attempt failed: {}. Retrying...",
                "warn".yellow(),
                first_err
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            client.delete(deployment_id).await
        }
    }
}

fn print_draft_summary(draft: &AgentSpecDraft) {
    let slug = draft.spec.agent_slug.as_deref().unwrap_or("(unset)");
    let name = draft.spec.name.as_deref().unwrap_or("(unset)");
    println!(
        "{} Packaging '{}' as {} (slug {})",
        "->".blue(),
        draft.directory.display(),
        name.bold(),
        slug
    );
    println!(
        "    {} instruction file(s), {} asset(s)",
        draft.instruction_count, draft.asset_count
    );

    if let seren::WorkloadExecution::Llm { bundle, .. } = &draft.spec.workload.execution {
        let mut kinds: Vec<&str> = bundle
            .instructions
            .iter()
            .map(|i| instruction_kind_label(&i.kind))
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        if !kinds.is_empty() {
            println!("    Instruction kinds: {}", kinds.join(", "));
        }
    }
}

fn instruction_kind_label(kind: &seren::AgentInstructionKind) -> &'static str {
    match kind {
        seren::AgentInstructionKind::Identity => "identity",
        seren::AgentInstructionKind::Soul => "soul",
        seren::AgentInstructionKind::Skill => "skill",
        seren::AgentInstructionKind::Agents => "agents",
        seren::AgentInstructionKind::User => "user",
        seren::AgentInstructionKind::Tools => "tools",
        seren::AgentInstructionKind::Memory => "memory",
        seren::AgentInstructionKind::Heartbeat => "heartbeat",
        seren::AgentInstructionKind::Eval => "eval",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[test]
    fn normalize_slug_collapses_non_alnum_and_strips_edges() {
        assert_eq!(normalize_slug("Hello World!"), "hello-world");
        assert_eq!(normalize_slug("  weird __ Name  "), "weird-name");
        assert_eq!(normalize_slug("---"), "");
    }

    #[test]
    fn build_dev_agent_slug_prefixes_dev_namespace() {
        assert_eq!(
            build_dev_agent_slug("My Agent", None).unwrap(),
            "dev-my-agent"
        );
    }

    #[test]
    fn build_dev_agent_slug_avoids_double_prefix() {
        assert_eq!(
            build_dev_agent_slug("dev-existing", None).unwrap(),
            "dev-existing"
        );
    }

    #[test]
    fn build_dev_agent_slug_rejects_empty_after_normalization() {
        let err = build_dev_agent_slug("!!!", None).unwrap_err();
        assert!(err.to_string().contains("agent slug"));
    }

    #[test]
    fn build_dev_agent_slug_includes_user_discriminator_when_present() {
        let slug = build_dev_agent_slug("myagent", Some("abc123")).unwrap();
        assert_eq!(slug, "dev-abc123-myagent");
    }

    #[test]
    fn build_dev_agent_slug_inserts_discriminator_before_existing_dev_prefix() {
        // If the caller already passed a `dev-`-prefixed slug, the
        // discriminator goes between the namespace and the user portion so
        // the slug stays single-prefixed.
        let slug = build_dev_agent_slug("dev-existing", Some("abc123")).unwrap();
        assert_eq!(slug, "dev-abc123-existing");
    }

    #[test]
    fn build_dev_agent_slug_normalizes_discriminator() {
        // A raw email-prefix like "Alice@" should be slugified just like the
        // base portion: lowercased and stripped of non-alnum.
        let slug = build_dev_agent_slug("myagent", Some("Alice@")).unwrap();
        assert_eq!(slug, "dev-alice-myagent");
    }

    #[test]
    fn build_dev_agent_slug_ignores_empty_discriminator() {
        // Empty / whitespace-only discriminator falls back to the legacy
        // `dev-<slug>` form so callers that can't resolve auth still work.
        assert_eq!(
            build_dev_agent_slug("myagent", Some("")).unwrap(),
            "dev-myagent"
        );
        assert_eq!(
            build_dev_agent_slug("myagent", Some("   ")).unwrap(),
            "dev-myagent"
        );
    }

    #[test]
    fn two_users_packaging_same_dir_get_distinct_slugs() {
        // The collision the discriminator is designed to prevent: two
        // developers in the same org run `seren agent dev myagent`.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "skill").unwrap();

        let alice = hash_user_discriminator("alice@example.com");
        let bob = hash_user_discriminator("bob@example.com");
        assert_ne!(alice, bob);

        let draft_alice = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: None,
            agent_slug: Some("myagent".to_string()),
            user_discriminator: Some(alice.clone()),
            dry_run: true,
        })
        .unwrap();

        let draft_bob = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: None,
            agent_slug: Some("myagent".to_string()),
            user_discriminator: Some(bob.clone()),
            dry_run: true,
        })
        .unwrap();

        let slug_alice = draft_alice.spec.agent_slug.unwrap();
        let slug_bob = draft_bob.spec.agent_slug.unwrap();
        assert_ne!(slug_alice, slug_bob);
        assert_eq!(slug_alice, format!("dev-{alice}-myagent"));
        assert_eq!(slug_bob, format!("dev-{bob}-myagent"));
    }

    #[test]
    fn hash_user_discriminator_is_stable_and_correct_length() {
        let first = hash_user_discriminator("alice@example.com");
        let second = hash_user_discriminator("alice@example.com");
        assert_eq!(first, second);
        assert_eq!(first.len(), USER_DISCRIMINATOR_LEN);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn instruction_kind_for_is_case_insensitive() {
        assert_eq!(
            instruction_kind_for("skill.md"),
            Some(seren::AgentInstructionKind::Skill)
        );
        assert_eq!(
            instruction_kind_for("IDENTITY.MD"),
            Some(seren::AgentInstructionKind::Identity)
        );
        assert_eq!(
            instruction_kind_for("user.md"),
            Some(seren::AgentInstructionKind::User)
        );
        assert_eq!(
            instruction_kind_for("EVAL.md"),
            Some(seren::AgentInstructionKind::Eval)
        );
        assert_eq!(instruction_kind_for("notes.txt"), None);
    }

    #[test]
    fn package_agent_directory_builds_expected_bundle() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "follow the skill").unwrap();
        std::fs::write(dir.path().join("IDENTITY.md"), "you are dev").unwrap();
        std::fs::write(dir.path().join("USER.md"), "user context").unwrap();
        std::fs::write(dir.path().join("EVAL.md"), "eval criteria").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"some bytes").unwrap();
        // Hidden file is ignored.
        std::fs::write(dir.path().join(".env"), b"SECRET=1").unwrap();

        let draft = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: Some("My Dev Agent".to_string()),
            agent_slug: None,
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap();

        assert_eq!(draft.instruction_count, 4);
        assert_eq!(draft.asset_count, 1);
        assert_eq!(draft.spec.name.as_deref(), Some("My Dev Agent"));
        let slug = draft.spec.agent_slug.as_deref().unwrap();
        assert!(slug.starts_with(DEV_NAMESPACE_PREFIX));
        assert!(matches!(
            draft.spec.mode,
            seren::CloudDeploymentMode::AlwaysOn
        ));

        match &draft.spec.workload.execution {
            seren::WorkloadExecution::Llm { bundle, .. } => {
                assert_eq!(bundle.instructions.len(), 4);
                let kinds: Vec<_> = bundle.instructions.iter().map(|i| i.kind).collect();
                assert!(kinds.contains(&seren::AgentInstructionKind::Skill));
                assert!(kinds.contains(&seren::AgentInstructionKind::Identity));
                assert!(kinds.contains(&seren::AgentInstructionKind::User));
                assert!(kinds.contains(&seren::AgentInstructionKind::Eval));
                assert_eq!(bundle.assets.len(), 1);
                assert_eq!(bundle.assets[0].path, "notes.txt");
                assert!(matches!(
                    bundle.assets[0].purpose,
                    Some(seren::AgentAssetPurpose::Resource)
                ));
                // Asset bodies are base64.
                let decoded = BASE64_STANDARD
                    .decode(bundle.assets[0].content_base64.as_bytes())
                    .unwrap();
                assert_eq!(decoded, b"some bytes");
            }
            other => panic!("expected LLM workload, got {other:?}"),
        }
    }

    #[test]
    fn package_agent_directory_errors_when_no_instructions_present() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), b"hi").unwrap();
        let err = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: None,
            agent_slug: None,
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap_err();
        assert!(err.to_string().contains("no recognized instruction files"));
    }

    #[test]
    fn package_agent_directory_falls_back_to_dir_name_for_slug() {
        let parent = tempdir().unwrap();
        let child = parent.path().join("my agent");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("SKILL.md"), "x").unwrap();
        let draft = package_agent_directory(&DevAgentOptions {
            directory: child.clone(),
            name: None,
            agent_slug: None,
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap();
        assert_eq!(draft.spec.agent_slug.as_deref(), Some("dev-my-agent"));
        assert_eq!(draft.spec.name.as_deref(), Some("my agent"));
    }

    #[test]
    fn package_agent_directory_walks_subdirectories_as_assets() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "skill").unwrap();
        std::fs::create_dir(dir.path().join("data")).unwrap();
        std::fs::write(dir.path().join("data").join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir(dir.path().join("data").join("nested")).unwrap();
        std::fs::write(
            dir.path().join("data").join("nested").join("b.txt"),
            b"beta",
        )
        .unwrap();
        // Hidden directory must be skipped entirely, including its contents.
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git").join("HEAD"), b"ref: x").unwrap();

        let draft = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: None,
            agent_slug: Some("walk".to_string()),
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap();

        assert_eq!(draft.instruction_count, 1);
        assert_eq!(draft.asset_count, 2);
        let asset_paths: Vec<&str> = match &draft.spec.workload.execution {
            seren::WorkloadExecution::Llm { bundle, .. } => {
                bundle.assets.iter().map(|a| a.path.as_str()).collect()
            }
            _ => panic!("expected llm workload"),
        };
        // POSIX-style forward slashes regardless of platform.
        assert!(asset_paths.contains(&"data/a.txt"));
        assert!(asset_paths.contains(&"data/nested/b.txt"));
        // Hidden .git contents never reach the bundle.
        assert!(!asset_paths.iter().any(|p| p.contains(".git")));
    }

    #[test]
    fn package_agent_directory_treats_nested_skill_md_as_asset_not_instruction() {
        // Top-level instruction names only match at the top level so a nested
        // `SKILL.md` cannot silently shadow the real one.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "real skill").unwrap();
        std::fs::create_dir(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs").join("SKILL.md"), "shadow").unwrap();

        let draft = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: None,
            agent_slug: Some("nested".to_string()),
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap();

        assert_eq!(draft.instruction_count, 1);
        assert_eq!(draft.asset_count, 1);
        match &draft.spec.workload.execution {
            seren::WorkloadExecution::Llm { bundle, .. } => {
                assert_eq!(bundle.assets[0].path, "docs/SKILL.md");
            }
            _ => panic!("expected llm workload"),
        }
    }

    #[test]
    fn package_agent_directory_rejects_oversized_instruction() {
        let dir = tempdir().unwrap();
        let huge = "a".repeat(MAX_INSTRUCTION_BYTES + 1);
        std::fs::write(dir.path().join("SKILL.md"), &huge).unwrap();
        let err = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: None,
            agent_slug: Some("big".to_string()),
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("SKILL.md"), "error missing file name: {msg}");
        assert!(
            msg.contains("per-instruction limit"),
            "error missing limit description: {msg}"
        );
    }

    #[test]
    fn package_agent_directory_rejects_oversized_asset() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "ok").unwrap();
        let huge = vec![0u8; MAX_ASSET_BYTES + 1];
        std::fs::write(dir.path().join("blob.bin"), &huge).unwrap();
        let err = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: None,
            agent_slug: Some("bigasset".to_string()),
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("blob.bin"), "error missing file name: {msg}");
        assert!(
            msg.contains("per-asset limit"),
            "error missing limit description: {msg}"
        );
    }

    #[test]
    fn package_agent_directory_rejects_when_total_exceeds_bundle_limit() {
        // Three large assets, each individually under the per-asset cap, but
        // together they push past MAX_BUNDLE_TOTAL_BYTES.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "ok").unwrap();
        let chunk = vec![0u8; MAX_ASSET_BYTES];
        std::fs::write(dir.path().join("a.bin"), &chunk).unwrap();
        std::fs::write(dir.path().join("b.bin"), &chunk).unwrap();
        std::fs::write(dir.path().join("c.bin"), &chunk).unwrap();
        let err = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: None,
            agent_slug: Some("totals".to_string()),
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("total limit"),
            "error missing total-limit text: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn package_agent_directory_rejects_symlink_escape() {
        // A symlink whose target is outside the agent directory must not be
        // packaged. read_to_string/read would otherwise follow the link.
        let parent = tempdir().unwrap();
        let outside = parent.path().join("secret.txt");
        std::fs::write(&outside, b"shh").unwrap();

        let agent_dir = parent.path().join("agent");
        std::fs::create_dir(&agent_dir).unwrap();
        std::fs::write(agent_dir.join("SKILL.md"), "ok").unwrap();
        std::os::unix::fs::symlink(&outside, agent_dir.join("leak.txt")).unwrap();

        let err = package_agent_directory(&DevAgentOptions {
            directory: agent_dir,
            name: None,
            agent_slug: Some("escape".to_string()),
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("outside the agent directory"),
            "expected escape error, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn package_agent_directory_allows_in_directory_symlinks() {
        // A symlink that resolves inside the agent directory is treated like
        // any other file.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "ok").unwrap();
        std::fs::write(dir.path().join("real.txt"), b"hello").unwrap();
        std::os::unix::fs::symlink("real.txt", dir.path().join("link.txt")).unwrap();

        let draft = package_agent_directory(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: None,
            agent_slug: Some("links".to_string()),
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap();
        // Both `real.txt` and `link.txt` become assets.
        assert_eq!(draft.asset_count, 2);
    }

    /// Stub client capturing every call for assertion in tests.
    #[derive(Default)]
    struct StubClient {
        deploy_count: Mutex<usize>,
        delete_count: Mutex<usize>,
        stream_count: Mutex<usize>,
        deployment_id: Uuid,
        last_spec_name: Mutex<Option<String>>,
    }

    impl DevAgentClient for StubClient {
        async fn deploy(&self, spec: &seren::AgentSpec) -> Result<Uuid> {
            *self.deploy_count.lock().unwrap() += 1;
            *self.last_spec_name.lock().unwrap() = spec.name.clone();
            Ok(self.deployment_id)
        }
        async fn delete(&self, _deployment_id: Uuid) -> Result<()> {
            *self.delete_count.lock().unwrap() += 1;
            Ok(())
        }
        async fn stream_logs(&self, _deployment_id: Uuid) -> Result<()> {
            *self.stream_count.lock().unwrap() += 1;
            // Log stream "ends" immediately, mirroring a server-closed log feed.
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_with_client_invokes_deploy_then_stream_then_delete() {
        let stub = StubClient {
            deployment_id: Uuid::nil(),
            ..Default::default()
        };
        let draft = package_agent_directory(&DevAgentOptions {
            directory: {
                let dir = tempdir().unwrap();
                std::fs::write(dir.path().join("SKILL.md"), "x").unwrap();
                // tempdir() returned value is dropped at end of expression;
                // keep the directory alive via leak so package_agent_directory's
                // borrow stays valid for the whole test.
                let path = dir.path().to_path_buf();
                std::mem::forget(dir);
                path
            },
            name: Some("Smoke".to_string()),
            agent_slug: None,
            user_discriminator: None,
            dry_run: false,
        })
        .unwrap();

        run_with_client(draft.spec, &stub).await.unwrap();

        assert_eq!(*stub.deploy_count.lock().unwrap(), 1);
        assert_eq!(*stub.stream_count.lock().unwrap(), 1);
        assert_eq!(*stub.delete_count.lock().unwrap(), 1);
        assert_eq!(
            stub.last_spec_name.lock().unwrap().as_deref(),
            Some("Smoke")
        );
    }

    /// Client whose first N delete calls fail. Used to verify the retry path.
    struct FlakyDeleteClient {
        fail_first_n_deletes: Mutex<usize>,
        delete_count: Mutex<usize>,
    }

    impl DevAgentClient for FlakyDeleteClient {
        async fn deploy(&self, _spec: &seren::AgentSpec) -> Result<Uuid> {
            Ok(Uuid::nil())
        }
        async fn delete(&self, _deployment_id: Uuid) -> Result<()> {
            *self.delete_count.lock().unwrap() += 1;
            let mut remaining = self.fail_first_n_deletes.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                anyhow::bail!("transient network error");
            }
            Ok(())
        }
        async fn stream_logs(&self, _deployment_id: Uuid) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn delete_with_retry_recovers_after_single_transient_failure() {
        let client = FlakyDeleteClient {
            fail_first_n_deletes: Mutex::new(1),
            delete_count: Mutex::new(0),
        };
        let spec = seren::AgentSpec {
            agent_slug: Some("dev-retry".to_string()),
            alert_policy: None,
            allowed_remote_agent_origins: None,
            approval_policy: None,
            credentials: None,
            cron_schedule: None,
            cron_timezone: None,
            dashboard_config: None,
            eval_gate: None,
            guardrails: None,
            memory_policy: None,
            capability_policy: None,
            mode: seren::CloudDeploymentMode::AlwaysOn,
            model_policy: None,
            name: Some("retry".to_string()),
            private_output_policy: None,
            runtime_policy: None,
            session_database: None,
            template: None,
            tool_presets: None,
            tool_refs: None,
            visibility: None,
            workload: seren::WorkloadSpec {
                compute_backend: None,
                config: None,
                execution: seren::WorkloadExecution::Llm {
                    adapter: None,
                    bundle: seren::AgentBundle {
                        assets: vec![],
                        instructions: vec![],
                    },
                    fallback_models: None,
                    llm_connection: None,
                    model_config: None,
                    model_id: None,
                    tool_definitions: None,
                },
                limits: None,
                network_policy: None,
                publisher_only: None,
                requirements: None,
                secrets: None,
                side_effect_policy: None,
            },
        };
        run_with_client(spec, &client).await.unwrap();
        assert_eq!(*client.delete_count.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn run_with_client_returns_err_when_delete_fails_after_retry() {
        let client = FlakyDeleteClient {
            // Both attempts fail -> caller must see a non-zero result so a
            // scripted invocation cannot exit clean while leaking an agent.
            fail_first_n_deletes: Mutex::new(2),
            delete_count: Mutex::new(0),
        };
        let spec = seren::AgentSpec {
            agent_slug: Some("dev-orphan".to_string()),
            alert_policy: None,
            allowed_remote_agent_origins: None,
            approval_policy: None,
            credentials: None,
            cron_schedule: None,
            cron_timezone: None,
            dashboard_config: None,
            eval_gate: None,
            guardrails: None,
            memory_policy: None,
            capability_policy: None,
            mode: seren::CloudDeploymentMode::AlwaysOn,
            model_policy: None,
            name: Some("orphan".to_string()),
            private_output_policy: None,
            runtime_policy: None,
            session_database: None,
            template: None,
            tool_presets: None,
            tool_refs: None,
            visibility: None,
            workload: seren::WorkloadSpec {
                compute_backend: None,
                config: None,
                execution: seren::WorkloadExecution::Llm {
                    adapter: None,
                    bundle: seren::AgentBundle {
                        assets: vec![],
                        instructions: vec![],
                    },
                    fallback_models: None,
                    llm_connection: None,
                    model_config: None,
                    model_id: None,
                    tool_definitions: None,
                },
                limits: None,
                network_policy: None,
                publisher_only: None,
                requirements: None,
                secrets: None,
                side_effect_policy: None,
            },
        };
        let err = run_with_client(spec, &client).await.unwrap_err();
        assert!(err.to_string().contains("was not deleted"));
        assert_eq!(*client.delete_count.lock().unwrap(), 2);
    }
}
