# Changelog

Changes to Seren are documented in this file.

## [0.9.0] - 2026-07-27

Self-contained Rust SDK packaging, broader Seren Storage and Seren Memory publisher workflows, and expanded managed employee operations.

### Added

- The Rust SDK package is named `seren-sdk` with the library name `seren`. It bundles synchronized OpenAPI inputs so it builds outside the workspace, supports environment-based client configuration, and exposes static Seren product examples.
- Runnable SDK examples: `quickstart`, `product_catalog`, `memory`, and `employee_lifecycle`, with `employee_lifecycle` previewing a bundle offline before testing and deploying it. Self-contained employee bundles cover the Chief Financial Officer, Launch Operations Coordinator, Research Analyst, and Site Reliability Engineer.
- Seren Storage publisher support across the SDK, CLI, and MCP for bucket and object operations (upload, download, list, delete), agent bucket grants, and deployment workspace snapshots. The generated SDK client covers the full Seren Storage API, including multipart transfers, lifecycle and restore operations, and usage reporting.
- Seren Memory publisher support across the SDK, CLI, and MCP for health, session context assembly, recall, durable storage, listing and retrieval, conversation-turn extraction, soft and permanent deletion, retained source export, dated relationship timelines, memory connections, and governed knowledge discovery. The generated SDK client covers the rest of the Seren Memory API, including document and error ingestion, memory revision and status operations, and knowledge-domain, grant, model, operation, and record administration.
- Seren Memory source erasure across the generated SDK, CLI, and MCP server. Callers can permanently delete retained sources and their derived memories by stable external source ID, source URI, or both, with optional project narrowing.
- Managed employee tools for cloud operations, deployment health, resources, activity, declared tool references, capability and realtime policies, and graph-memory defaults.
- Durable employee conversations across the CLI and MCP: `seren agent cloud conversation list|messages` pages conversations and their messages for a deployment, with optional run records for run-backed messages.
- Agent-owned future run schedules across the CLI and MCP: `seren agent cloud schedule list|create|cancel` creates one-shot (timestamp or delay) and cron schedules keyed by a caller-supplied idempotency key, optionally continuing a durable conversation. Scheduling currently requires an `always_on` deployment on the `aws_container` compute backend.
- `seren agent cloud run state` and the matching MCP tool return the current live state for a run, with optional deployment scoping.
- Employee tool catalog inspection across the CLI and MCP: list the tools visible to a managed deployment, describe a single tool, and list resolved tool groups.
- Generated `skill.md` guidance is retrievable for a publisher and for the core Seren API, through both the CLI and MCP.
- Managed deployments can attach existing SerenDB databases through skill manifests and managed-agent configuration, with read-only access by default and policy-gated read-write access.
- SerenDB connection strings can target a specific database through a new optional database-name override.
- `seren psql` opens an interactive psql session against a branch, resolving the connection string from CLI context with endpoint, database, role, pooling, and SSL-mode overrides.
- Private-model organization policies expose typed data-handling attestations across the generated SDK, CLI, and MCP server, including training-use and retention declarations.
- Publisher passthrough auth supports header rewrites: a JSON map of client header names to upstream header names (for example `X-Passthrough-Authorization` to `Authorization`), configurable on publisher create and update in the CLI and MCP.
- User OAuth account identities are visible and selectable through the MCP server. Assistants can list providers and connections, start a human consent flow, select a provider default, pass an explicit connection to publisher calls and MCP discovery, and pin `oauth_connection_id` on managed-agent publisher tool references. The CLI now displays default connections and provides `seren oauth default <connection-id>`.
- Hosted publisher calls forward settlement receipt and settled-charge metadata through MCP results so clients can correlate charges and apply local spend controls.
- Approval-gated Research Analyst publishing and Site Reliability Engineer coordination actions in the bundled employee examples.

### Changed

- Seren Passwords supports atomic vault membership access-level changes across the SDK, CLI, and MCP. Local mode applies the update directly; hosted mode returns a targeted browser handoff for user and agent identities, and rejects handoffs whose target has no active membership or whose access level is unchanged.
- **Breaking:** The `api` crate is renamed to `seren-sdk`; the Rust library name remains `seren`, so `use seren::...` code is unchanged. Update Git and path dependencies to reference the new package name. For this release, use `seren = { package = "seren-sdk", git = "https://github.com/serenorg/seren.git", tag = "v0.9.0" }`.
- **Breaking:** Generated SerenDB `seren_db_get_connection_string` callers must provide the new optional database-name argument, using `None` to retain the previous behavior.
- The bundled Seren Memory OpenAPI document uses the gateway-relative publisher path.
- Managed deployment clients use the current nested workload contracts and expose richer operation summaries, projection data, health, resources, and activity.
- Hosted Passwords grants bind to API-key credentials, reuse compatible pending grants, keep sessions warm through consent, and support reauthentication and reconsent without discarding retryable state.
- MCP managed-agent, publisher, and text-response API calls preserve bounded upstream status, response excerpts, headers, and request IDs instead of returning opaque failures.
- Tagged releases validate workspace and changelog metadata, isolate concurrent tag runs, use locked Cargo commands, and support safe reruns.

### Removed

- **Breaking:** Organization object storage moved from the Seren Core API to the Seren Storage publisher. The legacy core routes, generated SDK methods, `seren object-storage` command, and matching MCP tools are removed; use the `seren_storage_` SDK and MCP methods and `seren storage` CLI commands.
- **Breaking:** The seren-cloud run-stream close endpoints are gone from the API, so the generated `seren_cloud_run_stream_close` and `seren_cloud_deployment_run_stream_close` SDK methods, the `seren agent cloud run stream-close` command, and the corresponding MCP tools are removed. Close a run stream by ending the SSE connection, and reattach with `seren agent cloud run stream --last-event-id`.

### Fixed

- Seren Passwords uses canonical membership grants, validates local master-password length, routes local helper operations correctly, and restores hosted gateway transport authentication.
- Generated Passwords clients include the required invitation email contract and the current redemption and vault-rotation fields used by the CLI and MCP server.
- MCP publisher access handles streamable-HTTP handshakes, normalized tool schemas, upstream reauthentication, and transient session restore failures reliably.
- Managed cloud deployment requests use the current nested API shape and surface upload, deployment, and validation failures with actionable diagnostics.
- OAuth disconnect resolves connections by connection ID and treats already-removed upstream connections as a successful local cleanup.
- MCP publisher conflicts caused by multiple OAuth accounts now return connection-selection guidance and bounded identity metadata instead of being misreported as duplicate request IDs.

### Security

- Hosted Seren Passwords gateway URLs require HTTPS except for loopback development endpoints.
- Passwords membership and invitation flows verify canonical recipient identities while keeping plaintext invitee email transient.
- Upstream API error details are length-bounded before being returned through MCP, while request IDs remain available for support correlation.
- Managed-agent OAuth bindings are validated against the deployment user's active connection and the publisher's provider, and both native and Cloudflare runtimes reject per-call attempts to override the bound identity.
- API-key management and agent provisioning require a signed-in user session; API keys cannot list, create, revoke, or mint other API keys.
- MCP publisher calls reject the Seren `Authorization` header as an upstream credential and require the publisher's configured passthrough source header.

### Documentation

- Root, CLI, and MCP READMEs refreshed to describe Seren Employees, Seren Storage, and Seren Memory workflows. The root and SDK READMEs document using the `seren-sdk` package from the tagged Git release.
- SDK README and examples document environment-based configuration and the runnable quickstart, catalog, memory, and employee-lifecycle programs.
- Bundled OpenAPI specs synced and expanded to cover Seren Storage, Seren Memory, notes, skills, and the latest Seren Agent and seren-cloud schemas used by generated SDK clients.

## [0.8.0] - 2026-06-05

Seren Passwords CLI, MCP, and SDK integration release.

This release adds end-to-end encrypted Seren Passwords workflows across the CLI and MCP server, including hosted MCP delegation consent, local MCP user-mode unlocks, vault and item operations, attachments, live shares, approvals, invitations, membership management, vault key rotation, and native import/export. It also refreshes bundled OpenAPI specs so the generated SDK exposes the publisher and core methods used by these flows.

Alongside Seren Passwords, this release adds a profile-scoped `seren agent dev` workflow, direct seren-cloud bundle and runtime deployment across the CLI and MCP, managed agent bundle delivery, and MCP publisher fixes.

### Added

- Seren Passwords CLI command groups for vaults, items, attachments, agents, audit logs, approvals, memberships, invitations, live shares, import, export, and local password generation
- Hosted Seren Passwords MCP delegation flow with browser consent, grant status polling, hosted agent credential storage, and UI handoff URLs for hosted-only signing or bulk plaintext operations
- Local MCP Seren Passwords user mode with `passwords_unlock`, local-only vault creation, membership grants, invitation completion, and vault key rotation
- MCP Seren Passwords tools for vault and item access, attachments, approvals, invitations, memberships, live shares, import/export in local mode, and hosted handoffs where account signing or bulk plaintext should stay in the browser
- Attachment upload, list, download, delete, rotation re-wrap, and native import/export support across CLI and MCP
- Native plaintext vault import/export format with attachment inclusion by default and `--exclude-attachments` support
- Vault key rotation workflows for the CLI and local MCP
- Live item share inspection and revocation in the CLI and MCP
- CLI `seren passwords generate-password` for local random, hex, and passphrase generation
- CLI `--master-password-stdin` and `--master-password-file` options for noninteractive Seren Passwords unlocks
- Local MCP `--passwords-master-password-file` startup option for `seren-mcp start` and `seren-mcp start:http`
- Generated SDK support for Seren Passwords delegation requests, agent identities, attachments, vault rotation, and create-agent fields
- Generated SDK support for create-default-organization API keys with agent key type, agent identity id, and publisher scopes
- Wallet transfer client methods exposed through the generated SDK
- CLI `seren agent dev` packages a directory of instruction files and deploys it to a per-user `dev-` namespace, keeping developers in one org from colliding on a shared dev agent
- Direct seren-cloud bundle and runtime deployment from the CLI and MCP, with presigned bundle uploads and runtime overrides (auto, python, javascript, typescript, rust, rust_wasm_adk)
- `seren agent cloud deployment bundle get` for uploaded deployment bundle metadata, plus revision bundle download
- Managed agent bundle delivery across the CLI and MCP
- Generated SDK support for seren-agent instruction patch updates

### Changed

- Seren Passwords API calls in the CLI and MCP now use generated SDK methods instead of hand-rolled HTTP calls
- Publisher OpenAPI specs are merged under the generated `/publishers/<slug>` path convention, including the Seren Passwords publisher prefix
- CLI and MCP password export/import flows preserve attachment references by remapping attachment ids on import
- Hosted MCP uses UI handoffs for operations that require account signing keys or would return whole-vault plaintext
- Local MCP keeps account signing operations local-only and rejects hosted `passwords_unlock`
- CLI master password source precedence is explicit input flag, then `SEREN_PASSWORDS_MASTER_PASSWORD`, then interactive prompt
- CLI and MCP master password file reads strip exactly one terminal newline while preserving intentional password content
- MCP hosted mode rejects local master-password-file startup configuration

### Fixed

- Seren Passwords hosted delegation requests now use the generated publisher-prefixed endpoint instead of an unprefixed gateway path
- CLI and MCP gateway envelope parsing handles direct data responses, metered gateway envelopes, and stringified gateway bodies
- CLI and MCP import paths clean up newly created items when attachment upload fails
- CLI rejects attempts to read both the master password and an item secret from the same stdin stream
- Export shapes are aligned across CLI, MCP, and UI-compatible native format fields
- Generated SDK response parsing preserves useful upstream status and body diagnostics through CLI and MCP error mapping
- MCP bounds publisher logo upload hangs with a request timeout
- MCP supports raw (non-JSON) request bodies for publisher calls

### Security

- Hosted MCP stores hosted agent credentials encrypted at rest and keeps account signing keys out of hosted mode
- Password item output remains redact-by-default unless explicitly revealed
- Native import/export writes plaintext vault exports only to explicit files and avoids stdout secret dumps
- Local MCP and CLI derive account keys from the master password only for local user-mode operations and keep derived sessions in memory

### Documentation

- Bundled OpenAPI specs synced for Seren Passwords, Seren Agent, seren-cloud, credential secrets, remote HTTP audit kinds, and core API key fields used by generated SDK clients

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
