// ABOUTME: Library surface for seren-cli, so embedders (e.g. seren-desktop) can call
// ABOUTME: deploy/tail/apply flows directly without shelling out to the `seren` binary.

//! # seren-cli library surface
//!
//! `seren-cli` exposes two layers for downstream crates:
//!
//! 1. **Curated top-level API** -- the short list of re-exports below
//!    ([`run_dev_agent`], [`build_dev_agent_spec`], [`deploy_agent`],
//!    [`tail_logs`], [`apply_catalog_entry`], etc.). These are the entry
//!    points an embedder typically reaches for and they take typed argument
//!    structs (e.g. [`DevAgentOptions`]).
//!
//! 2. **Full command module tree** -- `pub mod commands`, which mirrors the
//!    layout the binary uses for argv dispatch. It exports roughly the same
//!    set of functions the `seren` binary calls in `main.rs`, organized by
//!    subcommand (`commands::agent`, `commands::projects`, etc.). This
//!    surface is intentionally wide so an embedder can reach any flow the
//!    CLI itself implements, but the contract is therefore also wide:
//!    treat `commands::*` as a stable but large surface and prefer the
//!    curated re-exports when one exists for the flow you need. New
//!    `commands::*` functions appear as the CLI grows; we do not narrow the
//!    surface, but we also do not stabilize every individual signature.
//!
//! Argument structs, configuration helpers, and a few output utilities also
//! live at the crate root ([`OutputFormat`], [`config`], [`defaults`],
//! [`output`], [`CommandContext`]).

pub mod command_context;
pub mod commands;
pub mod config;
pub mod defaults;
pub mod money;
pub mod output;

pub use command_context::CommandContext;

/// Output rendering mode shared across CLI commands and library consumers.
///
/// Mirrors the value the binary parses from `--format`. Library consumers can
/// construct one directly when calling into the typed APIs below.
#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    Table,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "table" => Ok(OutputFormat::Table),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

// =============================================================================
// Top-level library API.
//
// The CLI binary parses argv and dispatches into these functions; downstream
// crates can use the same functions directly. Each function takes a typed
// argument struct (or value) and returns a typed `anyhow::Result`.
// =============================================================================

/// Deploy a cloud agent skill bundle to Seren Cloud.
///
/// Thin re-export of [`commands::agent::cloud_deploy`].
pub use commands::agent::cloud_deploy as deploy_agent;

/// Deploy a managed prompt-based agent through the `seren-agent` publisher.
pub use commands::agent::cloud_deploy_prompt as deploy_prompt_agent;

/// Tail the log stream for a running cloud deployment.
pub use commands::agent::cloud_logs as tail_logs;

/// Package a local instruction directory and run it in a `dev-` namespace.
pub use commands::agent_dev::dev_agent_run as run_dev_agent;
pub use commands::agent_dev::package_agent_directory as build_dev_agent_spec;
pub use commands::agent_dev::{AgentSpecDraft, DevAgentClient, DevAgentOptions, SdkClient};

/// Apply a catalog publisher entry (create-if-missing) for the active profile.
pub use commands::agent::create_publisher as apply_catalog_entry;

#[cfg(test)]
mod tests {
    //! Library API smoke tests.
    //!
    //! These don't hit the network. They verify the typed entry points are
    //! callable from an external consumer (the public re-exports + structured
    //! argument structs) and that arguments propagate through the call.

    use super::*;
    use anyhow::Result;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct RecordingClient {
        deploys: Mutex<Vec<seren::AgentSpec>>,
        deletes: Mutex<Vec<Uuid>>,
    }

    impl DevAgentClient for RecordingClient {
        async fn deploy(&self, spec: &seren::AgentSpec) -> Result<Uuid> {
            self.deploys.lock().unwrap().push(spec.clone());
            Ok(Uuid::nil())
        }
        async fn delete(&self, deployment_id: Uuid) -> Result<()> {
            self.deletes.lock().unwrap().push(deployment_id);
            Ok(())
        }
        async fn stream_logs(&self, _deployment_id: Uuid) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn build_dev_agent_spec_is_reachable_as_library_api() {
        // Re-exported `build_dev_agent_spec` is callable from outside the
        // binary and returns the same shape the CLI consumes.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "skill body").unwrap();
        std::fs::write(dir.path().join("IDENTITY.md"), "id body").unwrap();

        let draft = build_dev_agent_spec(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: Some("ext consumer".to_string()),
            agent_slug: Some("ext".to_string()),
            user_discriminator: None,
            dry_run: true,
        })
        .unwrap();

        assert_eq!(draft.instruction_count, 2);
        assert_eq!(draft.spec.agent_slug.as_deref(), Some("dev-ext"));
        assert_eq!(draft.spec.name.as_deref(), Some("ext consumer"));
    }

    #[tokio::test]
    async fn run_dev_agent_threads_typed_args_to_underlying_client() {
        // Smoke: typed args -> deploy -> stream -> delete, no network.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("SKILL.md"), "x").unwrap();

        let draft = build_dev_agent_spec(&DevAgentOptions {
            directory: dir.path().to_path_buf(),
            name: Some("Lib Smoke".to_string()),
            agent_slug: None,
            user_discriminator: None,
            dry_run: false,
        })
        .unwrap();

        let client = RecordingClient::default();
        commands::agent_dev::run_with_client(draft.spec, &client)
            .await
            .unwrap();

        let deploys = client.deploys.lock().unwrap();
        assert_eq!(deploys.len(), 1);
        assert_eq!(deploys[0].name.as_deref(), Some("Lib Smoke"));
        assert!(
            deploys[0]
                .agent_slug
                .as_deref()
                .unwrap()
                .starts_with("dev-")
        );
        assert_eq!(client.deletes.lock().unwrap().len(), 1);
    }
}
