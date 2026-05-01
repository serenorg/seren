# Changelog

Changes to Seren are documented in this file.

## [0.7.0] - 2026-05-01

seren-models SDK support and managed agent lifecycle controls.

This release adds `seren-models` SDK support, exposes managed `seren-agent` start/stop/delete lifecycle operations in the CLI and MCP server, and updates CLI and MCP managed-agent flows for the new workload model.

### Added

- `seren-models` publisher OpenAPI spec support in SDK generation
- `seren agent managed-start|managed-stop|managed-delete` commands for managed `seren-agent` deployment lifecycle operations
- MCP tools for managed `seren-agent` deployment start, stop, and delete operations

### Changed

- Publisher-specific OpenAPI paths now take precedence during SDK generation
- OpenAPI specs synced with the latest seren-core agent, cloud, db, models, and private-models schemas
- CLI and MCP managed-agent deploy/update flows now use the regenerated `AgentSpec`, `AgentSpecUpdate`, `WorkloadSpec`, `WorkloadExecution`, `WorkloadLimits`, `EvalGate`, and typed cloud deployment shapes
- Cloud config update helpers align with the latest SDK shape for alert policies and eval gates
- Cloud config update errors now point managed `seren-agent` users toward the managed-agent update path for workload-level changes

### Fixed

- Private-models chat request construction works with the publisher-specific generated SDK request type
- MCP SQL and SQL transaction requests apply the requested timeout to the underlying HTTP request, overriding shorter client defaults

### Documentation

- Root README package table now describes the workspace SDK, CLI, and MCP components without implying external package publication
- Root README release-install guidance now reflects the single `seren` binary and `seren mcp ...` commands
- CLI and MCP README files document managed `seren-agent` start, stop, and delete lifecycle commands

## [0.6.0] - 2026-04-24

seren-cloud, seren-agent, and private-model SDK updates.

This release adds seren-cloud audit inspection, deployment filesystem access, deployment spend output, and generated `seren-agent` and `seren-private-models` SDK methods to the CLI (`seren agent ...`, `seren orgs private-models-policy ...`) and MCP server.

### Added

- `seren agent cloud audit list|get|verify` for seren-cloud audit inspection
- `seren agent cloud deployment spend|audit|fs|fs-read-text|fs-read-bytes` for per-deployment spend and filesystem inspection
- `seren agent cloud run audit|evals|events` plus deployment-scoped variants via `--deployment-id`
- `seren agent cloud run artifacts|stream|stream-close` support `--deployment-id` for deployment-scoped endpoints
- `seren agent private-models list|catalog|chat` backed by the generated `seren-private-models` SDK
- `seren agent managed-capabilities|managed-list|managed-test-run` for seren-agent publisher discovery and draft execution
- `seren orgs private-models-policy get|update` for organization-level private-model policy management
- `seren orgs skills` organization custom skill management commands
- MCP tools for private models, seren-agent capabilities and draft runs, cloud audit/spend/fs/evals/events, and deployment-scoped run stream close
- Multi-arch `seren` binaries (macOS, Linux gnu/musl, Windows) published on each `v*.*.*` tag via GitHub Releases
- `CHANGELOG.md` release notes

### Changed

- Managed seren-agent MCP tools use the generated SDK client instead of raw HTTP, preserving authentication and request metadata
- `approval_decisions[].decision` assertions compare against the typed `CloudRunApprovalDecisionValue` enum
- CLI API base selection uses `SEREN_API_BASE`
- `cargo run` defaults to the `seren` binary
- Cloud CLI error messages clarified
- Tag trigger removed from `binaries.yml` so it no longer races the new `release.yml` on tag push
- Publisher OpenAPI specs synced with the latest core publisher APIs

### Removed

- MCP health endpoints

## [0.5.0] - 2026-03-28

Managed seren-agent, seren-cloud evals, and eval gate release.

This release adds managed deployment flows for the `seren-agent` publisher (inspect, update, preview, rollback, templates, presets, policies, revisions), seren-cloud eval management (eval sets, cases, runs, verdicts, scheduled execution, replay comparison, eval gates), SSE-resumable run streams, approval inbox actions, and organization-wide cloud overview commands. The CLI also exposes MCP server commands through the `seren` binary.

### Added

- Managed seren-agent deployment clients: inspect, update, preview, rollback, revisions, templates, presets, and policies
- seren-cloud eval control plane: eval sets, cases, runs, run summaries, criteria, verdicts, scheduled execution
- seren-cloud eval gates on managed seren-agent deployments
- Server-side replay capture comparison for seren-cloud runs
- Approval inbox downstream actions and approval action commands
- Organization-wide seren-cloud overview commands with deployment-labeled activity
- Run stream resume controls and async run controls across CLI and MCP
- `seren mcp` subcommands expose MCP server commands through the main `seren` binary
- Prompt-based cloud deploy flows with auto bundle/orchestration routing
- Remote delegation support on managed agents
- Onchain wallet status output on MCP
- Default prompt deployments route through `seren-agent`

### Changed

- Grouped `seren agent cloud` commands under a single command tree
- Run inspection output includes eval capture and trace details
- seren-cloud activity commands support JSON output
- Deploy clients forward orchestration configuration fields
- Managed revision summaries updated to match API
- Managed agent workflows simplified around generated `seren-agent` schemas
- Wallet responses preserved intact across MCP flows

### Fixed

- MCP normalizes stringified JSON payloads in `call_publisher`
- MCP wallet onchain status output includes complete response data
- SDK is wasm-compatible (removed non-portable dependency)

### Removed

- Previous CLI command aliases

### Documentation

- Managed-agent eval gate examples
- CLI configuration path documentation fixes
- MCP docs and branding refresh

## [0.4.0] - 2026-03-01

seren-db publisher support, initial seren-cloud support, agent tasks, and telemetry release.

This release adds `seren-db` publisher support to the CLI and MCP, including connection URI endpoints. It also adds seren-cloud agent deployment and run management (cron, ephemeral, always_on; Python/TypeScript/Rust runtimes; Daytona and Cloudflare backends; deploy/run/cancel/history/config-update/artifact filters), agent task and skills command groups, geographic routing, Prometheus metrics, and multi-arch GitHub Release binaries.

### Added

- `seren-db` publisher support in CLI and MCP, including connection URI endpoints
- seren-cloud agent deployment and management tools in CLI and MCP
- Deploy backend selection (Daytona, Cloudflare) and runtime-kind options
- TypeScript and Rust runtime support; Rust and Cloudflare Python routing for deploys
- `seren-agent` deploy publisher support in CLI and MCP cloud deploy flows
- Run history, run details, run filters, cancel support, run payloads, environment CRUD
- Source and artifact filters for run history
- Agent task MCP tools and CLI commands
- `seren cli skills` command group for discovering and installing agent skills
- `--follow` streaming and run-local A2A agent support
- Generic database config for publishers (CLI and MCP)
- Provider-specific `database_config` examples in docs
- Geographic routing support across MCP
- MCP geo proxy metrics
- Prometheus metrics and JSON structured logging for MCP
- Multi-arch GitHub Releases binaries workflow (`binaries.yml`)
- `pay_per_use` billing with `upstream_cost_response_path`
- Passthrough publisher auth in CLI and MCP

### Changed

- MCP issues permanent access tokens; refresh tokens removed from response
- MCP requires `OAUTH_TOKEN_ENCRYPTION_KEYS` and removes session auth fallback
- MCP telemetry metrics wired through the server and log noise reduced
- x402 auto-approve uses atomic units; USD deposits parsed as integer cents
- Upgraded `rmcp` 0.11 to 0.16 (MCP protocol), OpenTelemetry 0.27 to 0.31, and prometheus 0.13 to 0.14

### Fixed

- Atomic USD formatting no longer uses floats
- `use_cases` preserved on publisher create
- Templates support Python-only and TypeScript-only layouts
- CLI SSE streams normalize line endings and handle terminal status correctly

## [0.3.0] - 2026-02-06

MCP routing and DataResponse response envelope release.

This release moves MCP proxy routing under the `/_mcp/` prefix, centralizes transport handling with request-id support, and syncs the OpenAPI spec to the DataResponse response envelope standard.

### Changed

- MCP adopts `/_mcp/` routing prefix and separates query strings cleanly
- MCP proxy paths fixed, transport centralized, and request-id propagation added
- OpenAPI synced to DataResponse response envelope standard; CLI and MCP callers updated

## [0.2.0] - 2026-02-04

Org-scoped publisher APIs and publisher tool consolidation release.

### Changed

- CLI and MCP updated to use the new org-scoped publisher APIs
- MCP publisher tools consolidated into a single `call_publisher` tool
- MCP publisher calls use `/publishers` and GET payments

### Fixed

- `upload_publisher_logo` has timeout and tracing
- `call_publisher` validates parameters and forwards `request_id`

### Documentation

- README AI agents reference and skills section added

## [0.1.0] - 2026-02-03

Initial public release of the Seren CLI, MCP server, and Rust SDK.

### Added

- `seren` CLI for managing seren-db projects, databases, branches, endpoints, roles, organizations, publishers, and agent tasks
- CLI support for project defaults and context, branch expiration/reset/restore/metadata, schema diff, VPC options, logical replication, endpoint health/metrics, endpoint lifecycle commands, IP allow lists, and direct/proxy/pooled connection strings
- CLI support for billing usage, invoices, billing health, organization members and invites, sessions, webhooks, audit logs, RBAC, branch protection, replication slots, and `env init`
- Seren MCP server in three modes: stdio, HTTP with bearer token, and HTTP with OAuth 2.1 + PKCE (Postgres-backed token storage with embedded migrations)
- MCP tools for projects, branches, databases, roles, endpoints, SQL proxy access, publisher management, publisher documentation, API key management, wallet status, task suggestions, and x402 payment flows
- MCP session persistence, stale-session recovery, request ID middleware, OAuth protected resource metadata, consent flow, refresh-token hashing, upstream OAuth token encryption, JWT secret rotation, and upstream OAuth circuit breaker
- Rust SDK (`seren` crate) generated from the OpenAPI spec
- API key authentication for hosted OAuth mode with 5-minute validation cache; permanent access tokens with stable refresh; multi-session authentication across platforms
- OAuth BYOC publisher connections: CLI OAuth commands, MCP OAuth auth for publisher update and logo upload, CLI/MCP organization OAuth provider management, user identity forwarding to upstream APIs
- Publisher API endpoints under `/agent/mcp/*`, including BYOC OAuth fields (`oauth2_cc` credentials), per-HTTP-method pricing, endpoint-level pricing, `api_key_header`/`api_key_query_param`, `api_url`, `resource_name`, and `resource_description`
- Auto-recovery when an LLM uses the wrong tool for a publisher category
- `timeout_ms` parameter for SQL queries in MCP
- MongoDB Atlas database type support
- x402 payment proxy for remote gateway mode, prepaid credits, local wallet signing, checkout sessions, and SerenBucks terminology
- Dockerfile and hosted deployment support for the MCP server

### Documentation

- Root README, CLI documentation, MCP setup documentation, generated MCP tool docs, and Claude Code MCP installation instructions
