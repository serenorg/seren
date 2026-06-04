//! Seren Passwords vault tools for the MCP server.
//!
//! Seren Passwords is an end-to-end-encrypted password manager: the server
//! stores only ciphertext plus public keys, and this process decrypts vault
//! contents client-side using a held KEM private key (agent-key mode) or a
//! master-password-derived KEM private key (local user mode).
//!
//! Secret material is never logged or emitted. Tool output is redact-by-default:
//! item bodies are returned only when `reveal == true`.

use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use etcetera::base_strategy::{BaseStrategy, choose_base_strategy};
use rmcp::ErrorData as McpError;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Extensions};
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use seren::DelegationStatus;
use seren_secrets_crypto::keys::{
    IdentityKemKeypair, IdentityKemPrivateKey, IdentityKemPublicKey, IdentitySigningKeypair,
};
use seren_secrets_crypto::password_generator::PasswordRecipe;
use seren_secrets_crypto::prose;
use seren_secrets_crypto::protocol::item::{
    ApiCredentialContent, ApiCredentialKind, ItemContent, LoginContent, LoginUrl,
    SecureNoteContent, unwrap_item_content_key,
};
use seren_secrets_crypto::protocol::vault::{
    encrypt_vault_description, encrypt_vault_invitation_email, encrypt_vault_name,
    unwrap_vault_key, wrap_vault_key_for_identity,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::oauth::store::PendingHostedPasswordsAgentRequest;
use crate::server::SerenMcpServer;

/// Idle timeout for a user-mode unlocked session before it is discarded.
pub(crate) const SESSION_IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// User-mode (master-password) unlocked session. Held in memory only and
/// rebuilt into a fresh `VaultClient` per request; expires after idle TTL.
pub(crate) struct PasswordsSession {
    pub kem_private: IdentityKemPrivateKey,
    pub last_activity: Instant,
}

/// Background reaper for a user-mode session: zeroize the in-memory key once it
/// has been idle past the TTL, even if no further tool call arrives to trigger
/// the lazy check. Exits as soon as the session is gone (expired here, expired
/// lazily, or explicitly locked), so each unlock needs only its own reaper.
pub(crate) async fn reap_idle_session(
    session: std::sync::Arc<tokio::sync::Mutex<Option<PasswordsSession>>>,
) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let mut guard = session.lock().await;
        let expired = match guard.as_ref() {
            Some(s) => s.last_activity.elapsed() > SESSION_IDLE_TTL,
            None => return,
        };
        if expired {
            *guard = None;
            return;
        }
    }
}

/// Provisioned agent identity loaded once at startup (agent-key mode).
pub(crate) struct PasswordsAgentIdentity {
    pub api_key: Zeroizing<String>,
    pub kem_private: IdentityKemPrivateKey,
}

/// On-disk agent key file written by the seren CLI `passwords agent provision`.
///
/// Mirrors the CLI `AgentKeyFile`. Only `api_key` and `kem_private` are used
/// here; the rest are deserialized so the file shape matches exactly.
#[derive(Deserialize)]
struct AgentKeyFile {
    #[allow(dead_code)]
    identity_id: Uuid,
    #[allow(dead_code)]
    display_name: String,
    kem_private: String,
    signing_private: String,
    api_key: String,
    #[allow(dead_code)]
    granted_vaults: Vec<serde_json::Value>,
}

/// Locate the agent key directory used by the seren CLI.
fn agent_key_dir() -> Option<std::path::PathBuf> {
    Some(
        choose_base_strategy()
            .ok()?
            .config_dir()
            .join("seren")
            .join("passwords")
            .join("agents"),
    )
}

/// Load a provisioned agent identity for agent-key mode, if exactly one is
/// available (or one is selected via `SEREN_PASSWORDS_AGENT_ID`).
///
/// Returns `None` when no agent key is configured. Parse/decode failures are
/// logged to stderr (safe; not the JSON-RPC stream) and treated as absent.
pub(crate) fn load_agent_identity() -> Option<Arc<PasswordsAgentIdentity>> {
    let dir = agent_key_dir()?;
    let entries = std::fs::read_dir(&dir).ok()?;

    let mut key_files: Vec<std::path::PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();

    let target = match std::env::var("SEREN_PASSWORDS_AGENT_ID") {
        Ok(id) if !id.trim().is_empty() => {
            let id = id.trim();
            // The selector is a UUID, not a path fragment.
            if Uuid::parse_str(id).is_err() {
                tracing::warn!(
                    "SEREN_PASSWORDS_AGENT_ID is not a valid agent id; ignoring agent key selection"
                );
                return None;
            }
            dir.join(format!("{id}.json"))
        }
        _ => match key_files.len() {
            0 => return None,
            1 => key_files.pop()?,
            _ => {
                tracing::warn!(
                    "multiple seren-passwords agent keys found; set SEREN_PASSWORDS_AGENT_ID to select one"
                );
                return None;
            }
        },
    };

    let raw = match std::fs::read_to_string(&target) {
        Ok(contents) => Zeroizing::new(contents),
        Err(e) => {
            tracing::warn!("failed to read seren-passwords agent key file: {}", e);
            return None;
        }
    };

    let key_file: AgentKeyFile = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(e) => {
            tracing::warn!("failed to parse seren-passwords agent key file: {}", e);
            return None;
        }
    };

    let AgentKeyFile {
        kem_private,
        signing_private,
        api_key,
        ..
    } = key_file;
    let kem_private = Zeroizing::new(kem_private);
    let _signing_private = Zeroizing::new(signing_private);
    let api_key = Zeroizing::new(api_key);

    let kem_bytes = match BASE64.decode(kem_private.as_bytes()) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) => {
            tracing::warn!("failed to decode seren-passwords agent KEM key: {}", e);
            return None;
        }
    };

    let kem_private = match IdentityKemPrivateKey::from_slice(&kem_bytes) {
        Ok(key) => key,
        Err(e) => {
            tracing::warn!("invalid seren-passwords agent KEM key: {}", e);
            return None;
        }
    };

    Some(Arc::new(PasswordsAgentIdentity {
        api_key,
        kem_private,
    }))
}

// ============================================================================
// Tool parameter types
// ============================================================================

/// Parameters for listing items in a vault.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsItemsListParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
}

/// Parameters for fetching a single item.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsItemGetParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item ID (UUID).
    pub item_id: Uuid,
    /// When true, include the decrypted item content. Defaults to false.
    pub reveal: Option<bool>,
}

/// Parameters for creating an item. The secret fields (`password`, `key`,
/// `body`) are the data being stored; they are never logged or emitted.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PasswordsItemCreateParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item kind: "login", "api_credential", or "secure_note".
    pub kind: String,
    /// Display title for the item.
    pub title: String,
    /// Optional tags.
    pub tags: Option<Vec<String>>,
    /// Mark the item as sensitive. Defaults to false.
    pub sensitive: Option<bool>,
    /// Login username (login kind).
    pub username: Option<String>,
    /// Login password (login kind, required).
    pub password: Option<String>,
    /// Associated URLs (login kind).
    pub urls: Option<Vec<String>>,
    /// API credential secret value (api_credential kind, required).
    pub key: Option<String>,
    /// API credential kind (api_credential kind). Defaults to "api_key".
    pub credential_kind: Option<String>,
    /// Secure note body (secure_note kind, required).
    pub body: Option<String>,
    /// Free-form notes (login and api_credential kinds).
    pub notes: Option<String>,
}

/// Parameters for updating an item. Only the provided content fields are
/// changed; the rest are preserved. The secret fields are never logged.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PasswordsItemUpdateParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item ID (UUID).
    pub item_id: Uuid,
    /// New title. When omitted, the existing title is preserved.
    pub title: Option<String>,
    /// New tags. When omitted, the existing tags are preserved.
    pub tags: Option<Vec<String>>,
    /// New sensitive flag. When omitted, the existing flag is preserved.
    pub sensitive: Option<bool>,
    /// New login username (login kind).
    pub username: Option<String>,
    /// New login password (login kind).
    pub password: Option<String>,
    /// New associated URLs (login kind).
    pub urls: Option<Vec<String>>,
    /// New API credential secret value (api_credential kind).
    pub key: Option<String>,
    /// New API credential kind (api_credential kind).
    pub credential_kind: Option<String>,
    /// New secure note body (secure_note kind).
    pub body: Option<String>,
    /// New free-form notes (login and api_credential kinds).
    pub notes: Option<String>,
}

/// Parameters for deleting an item.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsItemDeleteParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item ID (UUID).
    pub item_id: Uuid,
}

/// Parameters for restoring a previously deleted item.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsItemRestoreParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item ID (UUID).
    pub item_id: Uuid,
}

/// Parameters for copying an item into another vault.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsItemCopyParams {
    /// Source vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item ID (UUID).
    pub item_id: Uuid,
    /// Destination vault ID (UUID).
    pub target_vault_id: Uuid,
}

/// Parameters for moving an item into another vault.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsItemMoveParams {
    /// Source vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item ID (UUID).
    pub item_id: Uuid,
    /// Destination vault ID (UUID).
    pub target_vault_id: Uuid,
}

/// Parameters for the local password generator. No vault access; the generated
/// value is returned to the caller and never stored or logged.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsGeneratePasswordParams {
    /// Generator mode: "random" (default), "passphrase", or "hex".
    pub mode: Option<String>,
    /// Random/hex length in characters. Random defaults to 20 (range 8..=256);
    /// hex defaults to 32 and must be even (range 2..=512).
    pub length: Option<u32>,
    /// Include uppercase letters (random mode). Defaults to true.
    pub upper: Option<bool>,
    /// Include lowercase letters (random mode). Defaults to true.
    pub lower: Option<bool>,
    /// Include digits (random mode). Defaults to true.
    pub digits: Option<bool>,
    /// Include symbols (random mode). Defaults to true.
    pub symbols: Option<bool>,
    /// Word count (passphrase mode). Defaults to 5 (range 4..=16).
    pub word_count: Option<u32>,
    /// Word separator (passphrase mode). Defaults to "-".
    pub separator: Option<char>,
    /// Capitalize the first letter of each word (passphrase mode). Defaults to true.
    pub capitalize_first: Option<bool>,
}

/// Parameters for opening hosted MCP vault-access consent.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsRequestAccessParams {
    /// Display name shown to the user in the grant page.
    pub display_name: Option<String>,
}

/// Parameters for polling a hosted MCP vault-access request.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsGrantStatusParams {
    /// Request ID returned by `passwords_request_access`.
    pub request_id: Uuid,
}

/// Parameters for listing password-vault audit events.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsAuditEventsListParams {
    /// Filter by exact audit action.
    pub action: Option<String>,
    /// Filter by actor identity id.
    pub actor_identity_id: Option<Uuid>,
    /// Filter by target kind.
    pub target_kind: Option<String>,
    /// Filter by target id.
    pub target_id: Option<Uuid>,
    /// Start timestamp, for example 2030-01-01T00:00:00Z.
    pub from: Option<String>,
    /// End timestamp, for example 2030-01-01T23:59:59Z.
    pub to: Option<String>,
    /// Maximum events to return. Defaults to the server default.
    pub limit: Option<i64>,
    /// Pagination offset. Defaults to the server default.
    pub offset: Option<i64>,
}

/// Parameters for archiving a vault.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsVaultArchiveParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
}

/// Password vault access level.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PasswordsAccessLevel {
    Read,
    Write,
    Admin,
}

impl From<PasswordsAccessLevel> for seren::AccessLevel {
    fn from(value: PasswordsAccessLevel) -> Self {
        match value {
            PasswordsAccessLevel::Read => seren::AccessLevel::Read,
            PasswordsAccessLevel::Write => seren::AccessLevel::Write,
            PasswordsAccessLevel::Admin => seren::AccessLevel::Admin,
        }
    }
}

/// Parameters for updating encrypted vault display metadata.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsVaultUpdateParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
    /// New vault name. Omit to leave unchanged.
    pub name: Option<String>,
    /// New vault description. Empty string clears it; omit to leave unchanged.
    pub description: Option<String>,
}

/// Target for a password approval request.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PasswordsApprovalTargetKind {
    Vault,
    Item,
}

impl From<PasswordsApprovalTargetKind> for seren::ApprovalTargetKind {
    fn from(value: PasswordsApprovalTargetKind) -> Self {
        match value {
            PasswordsApprovalTargetKind::Vault => seren::ApprovalTargetKind::Vault,
            PasswordsApprovalTargetKind::Item => seren::ApprovalTargetKind::Item,
        }
    }
}

/// Parameters for requesting approval for a vault or item target.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsApprovalRequestParams {
    /// Target kind: "vault" or "item".
    pub target_kind: PasswordsApprovalTargetKind,
    /// Target vault or item ID.
    pub target_id: Uuid,
    /// Seconds before the approval request expires. Defaults to server behavior.
    pub timeout_seconds: Option<i32>,
}

/// Parameters for fetching or denying a password approval request.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsApprovalIdParams {
    /// Approval request ID.
    pub approval_id: Uuid,
}

/// Parameters for listing memberships in a vault.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsMembershipsListParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
}

/// Parameters for revoking a vault membership.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsMembershipRevokeParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
    /// Identity ID to revoke from the vault.
    pub identity_id: Uuid,
}

/// Parameters for creating a vault invitation.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsInvitationCreateParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
    /// Invitee email address.
    pub email: String,
    /// Access level granted after completion.
    pub access_level: PasswordsAccessLevel,
    /// Hours until expiration. Omit for server default.
    pub expires_in_hours: Option<i64>,
}

/// Parameters for listing invitations.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsInvitationsListParams {
    /// Vault ID (UUID). Omit to list pending invitations for the caller.
    pub vault_id: Option<Uuid>,
}

/// Parameters for redeeming an invitation token.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsInvitationRedeemParams {
    /// Invitation token.
    pub token: String,
}

/// Parameters for listing outbound live shares.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsSharesOutboundListParams {
    /// Vault ID (UUID). Omit to list all outbound shares visible to the caller.
    pub vault_id: Option<Uuid>,
}

/// Parameters for fetching or revoking a live share.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsShareIdParams {
    /// Share ID.
    pub share_id: Uuid,
}

// ============================================================================
// Read tools (named router so it merges with the primary tool router)
// ============================================================================

#[tool_router(router = passwords_tool_router, vis = "pub(crate)")]
impl SerenMcpServer {
    #[tool(
        description = "Start hosted Seren Passwords access setup and return a browser consent URL",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_request_access(
        &self,
        Parameters(params): Parameters<PasswordsRequestAccessParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        if self.passwords_local_mode {
            return Err(McpError::invalid_request(
                "passwords_request_access is only available in hosted MCP mode",
                None,
            ));
        }
        let store = self.passwords_hosted_store.as_ref().ok_or_else(|| {
            McpError::invalid_request("Hosted passwords storage is not configured", None)
        })?;
        let user_id =
            crate::server::extract_user_id_from_extensions(&extensions).ok_or_else(|| {
                McpError::invalid_request(
                    "Missing authenticated user for hosted vault access",
                    None,
                )
            })?;
        if store
            .get_hosted_passwords_agent(user_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .is_some()
        {
            return Ok(CallToolResult::success(vec![crate::server::json_content(
                &serde_json::json!({ "status": "already_granted" }),
            )?]));
        }

        let display_name = params
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("Hosted MCP agent");
        if display_name.chars().count() > 128 {
            return Err(McpError::invalid_request(
                "display_name must be 1..=128 characters",
                None,
            ));
        }

        let request_id = Uuid::new_v4();
        let kem = IdentityKemKeypair::generate();
        let signing = IdentitySigningKeypair::generate();
        let kem_public = BASE64.encode(kem.public.as_bytes());
        let signing_public = BASE64.encode(signing.public.as_bytes());
        let kem_private = Zeroizing::new(BASE64.encode(kem.private.as_bytes()));
        let local_expires_at = time::OffsetDateTime::now_utc() + time::Duration::minutes(10);
        store
            .upsert_pending_hosted_passwords_agent(PendingHostedPasswordsAgentRequest {
                user_id,
                request_id,
                display_name,
                kem_public: &kem_public,
                signing_public: &signing_public,
                kem_private: &kem_private,
                expires_at: local_expires_at,
            })
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let created = match self
            .create_passwords_delegation_request(
                &extensions,
                request_id,
                display_name,
                &kem_public,
                &signing_public,
            )
            .await
        {
            Ok(record) => record,
            Err(err) => {
                let _ = store
                    .delete_pending_hosted_passwords_agent(user_id, request_id)
                    .await;
                return Err(err);
            }
        };
        let server_expires_at = match jiff_timestamp_to_offset_datetime(created.expires_at) {
            Ok(value) => value,
            Err(err) => {
                let _ = store
                    .delete_pending_hosted_passwords_agent(user_id, request_id)
                    .await;
                return Err(err);
            }
        };
        store
            .upsert_pending_hosted_passwords_agent(PendingHostedPasswordsAgentRequest {
                user_id,
                request_id,
                display_name,
                kem_public: &kem_public,
                signing_public: &signing_public,
                kem_private: &kem_private,
                expires_at: server_expires_at,
            })
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let consent_url = hosted_passwords_consent_url(request_id)?;
        Ok(CallToolResult::success(vec![crate::server::json_content(
            &serde_json::json!({
                "status": "pending",
                "request_id": created.request_id,
                "consent_url": consent_url,
                "expires_at": created.expires_at,
            }),
        )?]))
    }

    #[tool(
        description = "Check a hosted Seren Passwords access request and finalize it after browser approval",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_grant_status(
        &self,
        Parameters(params): Parameters<PasswordsGrantStatusParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let store = self.passwords_hosted_store.as_ref().ok_or_else(|| {
            McpError::invalid_request("Hosted passwords storage is not configured", None)
        })?;
        let user_id =
            crate::server::extract_user_id_from_extensions(&extensions).ok_or_else(|| {
                McpError::invalid_request(
                    "Missing authenticated user for hosted vault access",
                    None,
                )
            })?;
        store
            .delete_expired_pending_hosted_passwords_agents()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let pending = store
            .get_pending_hosted_passwords_agent(user_id, params.request_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .ok_or_else(|| McpError::invalid_request("Hosted access request not found", None))?;

        let record = self
            .get_passwords_delegation_request(&extensions, params.request_id)
            .await?;
        // The delegation record is a server-supplied value: pin it to this exact
        // request and authenticated user before minting/storing a credential
        // against record.identity_id.
        if record.request_id != params.request_id || record.user_id != user_id {
            return Err(McpError::internal_error(
                "Hosted access request identity mismatch",
                None,
            ));
        }
        if record.agent_kem_public != pending.kem_public
            || record.agent_signing_public != pending.signing_public
        {
            return Err(McpError::internal_error(
                "Hosted access request binding mismatch",
                None,
            ));
        }

        match &record.status {
            DelegationStatus::Pending => {
                let consent_url = hosted_passwords_consent_url(params.request_id)?;
                Ok(CallToolResult::success(vec![crate::server::json_content(
                    &serde_json::json!({
                        "status": "pending",
                        "request_id": record.request_id,
                        "consent_url": consent_url,
                        "expires_at": record.expires_at,
                    }),
                )?]))
            }
            DelegationStatus::Denied | DelegationStatus::Expired => {
                store
                    .delete_pending_hosted_passwords_agent(user_id, params.request_id)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                Ok(CallToolResult::success(vec![crate::server::json_content(
                    &serde_json::json!({
                        "status": &record.status,
                        "request_id": record.request_id,
                    }),
                )?]))
            }
            DelegationStatus::Approved => {
                let identity_id = record.identity_id.ok_or_else(|| {
                    McpError::internal_error("Approved delegation is missing identity id", None)
                })?;
                let claimed = store
                    .claim_pending_hosted_passwords_agent(user_id, params.request_id)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?
                    .ok_or_else(|| {
                        McpError::invalid_request(
                            "Hosted access request is already being finalized",
                            None,
                        )
                    })?;
                if record.agent_kem_public != claimed.kem_public
                    || record.agent_signing_public != claimed.signing_public
                {
                    return Err(McpError::internal_error(
                        "Hosted access request binding mismatch",
                        None,
                    ));
                }
                let api_key = self
                    .mint_hosted_passwords_agent_key(&extensions, identity_id, &record.display_name)
                    .await?;
                let granted_vaults = serde_json::Value::Array(
                    record
                        .granted_vault_ids
                        .iter()
                        .map(|vault_id| serde_json::json!({ "vault_id": vault_id }))
                        .collect(),
                );
                store
                    .upsert_hosted_passwords_agent(
                        user_id,
                        identity_id,
                        &record.display_name,
                        &claimed.kem_private,
                        &api_key,
                        &granted_vaults,
                    )
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                store
                    .delete_pending_hosted_passwords_agent(user_id, params.request_id)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                Ok(CallToolResult::success(vec![crate::server::json_content(
                    &serde_json::json!({
                        "status": "granted",
                        "request_id": record.request_id,
                        "identity_id": identity_id,
                        "granted_vault_ids": record.granted_vault_ids,
                    }),
                )?]))
            }
        }
    }

    async fn create_passwords_delegation_request(
        &self,
        extensions: &Extensions,
        request_id: Uuid,
        display_name: &str,
        kem_public: &str,
        signing_public: &str,
    ) -> Result<seren::DelegationRequestRecord, McpError> {
        let client = self.api_client(extensions)?;
        let response = match client
            .delegation_request_create(&seren::CreateDelegationRequest {
                request_id: Some(request_id),
                agent_kem_public: kem_public.to_owned(),
                agent_signing_public: signing_public.to_owned(),
                display_name: display_name.to_owned(),
            })
            .await
        {
            Ok(response) => response,
            Err(seren::Error::InvalidResponsePayload(bytes, e)) => {
                return crate::server::decode_publisher_gateway_body::<
                    seren::DataResponseDelegationRequestRecord,
                >(&bytes)
                .map(|response| response.data)
                .map_err(|fallback| {
                    McpError::internal_error(
                        format!(
                            "Invalid response payload: {e}; gateway envelope parse failed: {fallback}"
                        ),
                        None,
                    )
                });
            }
            Err(e) => return Err(crate::server::seren_error_to_mcp_error(e).await),
        };
        Ok(response.into_inner().data)
    }

    async fn get_passwords_delegation_request(
        &self,
        extensions: &Extensions,
        request_id: Uuid,
    ) -> Result<seren::DelegationRequestRecord, McpError> {
        let client = self.api_client(extensions)?;
        let response = match client.delegation_request_get(&request_id).await {
            Ok(response) => response,
            Err(seren::Error::InvalidResponsePayload(bytes, e)) => {
                return crate::server::decode_publisher_gateway_body::<
                    seren::DataResponseDelegationRequestRecord,
                >(&bytes)
                .map(|response| response.data)
                .map_err(|fallback| {
                    McpError::internal_error(
                        format!(
                            "Invalid response payload: {e}; gateway envelope parse failed: {fallback}"
                        ),
                        None,
                    )
                });
            }
            Err(e) => return Err(crate::server::seren_error_to_mcp_error(e).await),
        };
        Ok(response.into_inner().data)
    }

    async fn mint_hosted_passwords_agent_key(
        &self,
        extensions: &Extensions,
        identity_id: Uuid,
        display_name: &str,
    ) -> Result<Zeroizing<String>, McpError> {
        let client = self.api_client(extensions)?;
        let response = match client
            .create_default_org_api_key(&seren::CreateApiKeyRequest {
                name: format!("{display_name} (seren-passwords hosted MCP)"),
                key_type: Some(seren::ApiKeyType::Agent),
                agent_identity_id: Some(identity_id),
                scopes: Some(vec!["publisher:seren-passwords".to_owned()]),
                expires_in_days: None,
            })
            .await
        {
            Ok(response) => response,
            Err(e) => return Err(crate::server::seren_error_to_mcp_error(e).await),
        };
        Ok(Zeroizing::new(response.into_inner().data.api_key))
    }

    #[tool(
        description = "List Seren Passwords vaults available to this agent or session",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_vaults_list(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let client = self.passwords_vault_client(&extensions).await?;
        let vaults = client.list_vaults().await.map_err(vault_err)?;

        let output = vaults
            .into_iter()
            .map(|vault| {
                serde_json::json!({
                    "vault_id": vault.vault_id,
                    "name": vault.name,
                    "key_version": vault.key_version,
                })
            })
            .collect::<Vec<_>>();

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Soft-archive a Seren Passwords vault. Requires admin membership",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_vault_archive(
        &self,
        Parameters(params): Parameters<PasswordsVaultArchiveParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let result = passwords_gateway_data(client.vault_archive(&params.vault_id).await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
        )?]))
    }

    #[tool(
        description = "List Seren Passwords agent identities and vault grants owned by the current user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_agents_list(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api_client(&extensions)?;
        let agents = passwords_gateway_data(client.agent_identity_list().await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &agents,
        )?]))
    }

    #[tool(
        description = "Revoke every active Seren Passwords agent identity owned by the current user",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_agents_freeze(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.api_client(&extensions)?;
        let hosted_user_id = if self.passwords_hosted_store.is_some() {
            Some(
                crate::server::extract_user_id_from_extensions(&extensions).ok_or_else(|| {
                    McpError::invalid_request(
                        "Missing authenticated user for hosted vault access",
                        None,
                    )
                })?,
            )
        } else {
            None
        };
        let active_agent_ids = passwords_gateway_data(client.agent_identity_list().await)
            .await?
            .data
            .into_iter()
            .filter(|agent| agent.identity.revoked_at.is_none())
            .map(|agent| agent.identity.identity_id)
            .collect::<Vec<_>>();
        let result = passwords_gateway_data(client.agent_identity_freeze().await)
            .await?
            .data;
        let mut hosted_credentials_removed = 0u64;
        if let (Some(store), Some(user_id)) = (&self.passwords_hosted_store, hosted_user_id) {
            for identity_id in active_agent_ids {
                hosted_credentials_removed += store
                    .delete_hosted_passwords_agent(user_id, identity_id)
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            }
        }

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &serde_json::json!({
                "revoked": result.revoked,
                "hosted_credentials_removed": hosted_credentials_removed,
            }),
        )?]))
    }

    #[tool(
        description = "List Seren Passwords audit events visible to the current user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_audit_events_list(
        &self,
        Parameters(params): Parameters<PasswordsAuditEventsListParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let from = parse_timestamp_param("from", params.from.as_deref())?;
        let to = parse_timestamp_param("to", params.to.as_deref())?;
        let client = self.api_client(&extensions)?;
        let events = passwords_gateway_data(
            client
                .audit_event_list(
                    params.action.as_deref(),
                    params.actor_identity_id.as_ref(),
                    from.as_ref(),
                    params.limit,
                    params.offset,
                    params.target_id.as_ref(),
                    params.target_kind.as_deref(),
                    to.as_ref(),
                )
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &events,
        )?]))
    }

    #[tool(
        description = "Verify the Seren Passwords audit hash chain for the current organization database",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_audit_verify(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api_client(&extensions)?;
        let result = passwords_gateway_data(client.audit_chain_verify().await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
        )?]))
    }

    #[tool(
        description = "Update encrypted Seren Passwords vault display metadata. Requires admin membership",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_vault_update(
        &self,
        Parameters(params): Parameters<PasswordsVaultUpdateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        if params.name.is_none() && params.description.is_none() {
            return Err(McpError::invalid_params(
                "At least one of name or description is required",
                None,
            ));
        }

        let vault_client = self.passwords_vault_client(&extensions).await?;
        let vault = vault_client
            .list_vaults()
            .await
            .map_err(vault_err)?
            .into_iter()
            .find(|vault| vault.vault_id == params.vault_id)
            .ok_or_else(|| McpError::invalid_request("Vault is not available", None))?;

        let mut patch = seren::VaultPatchRequest {
            name_ciphertext: None,
            description_ciphertext: None,
        };
        if let Some(name) = params.name {
            let name = name.trim();
            if name.is_empty() {
                return Err(McpError::invalid_params("name cannot be empty", None));
            }
            patch.name_ciphertext = Some(BASE64.encode(encrypt_vault_name(
                &vault.key,
                vault.vault_id.as_bytes(),
                name,
            )));
        }
        if let Some(description) = params.description {
            patch.description_ciphertext = Some(BASE64.encode(encrypt_vault_description(
                &vault.key,
                vault.vault_id.as_bytes(),
                description.trim(),
            )));
        }

        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let result = passwords_gateway_data(client.vault_update(&vault.vault_id, &patch).await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
        )?]))
    }

    #[tool(
        description = "Request Seren Passwords approval for a vault or item target",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_approval_request(
        &self,
        Parameters(params): Parameters<PasswordsApprovalRequestParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.api_client(&extensions)?;
        let approval = passwords_gateway_data(
            client
                .approval_create(&seren::CreateApprovalRequest {
                    target_id: params.target_id,
                    target_kind: params.target_kind.into(),
                    timeout_seconds: params.timeout_seconds,
                })
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &approval,
        )?]))
    }

    #[tool(
        description = "List pending Seren Passwords approvals visible to the current user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_approvals_list(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api_client(&extensions)?;
        let approvals = passwords_gateway_data(client.approval_list_pending().await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &approvals,
        )?]))
    }

    #[tool(
        description = "Get one Seren Passwords approval request",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_approval_get(
        &self,
        Parameters(params): Parameters<PasswordsApprovalIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api_client(&extensions)?;
        let approval = passwords_gateway_data(client.approval_get(&params.approval_id).await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &approval,
        )?]))
    }

    #[tool(
        description = "Approve a pending Seren Passwords approval request",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_approval_approve(
        &self,
        Parameters(params): Parameters<PasswordsApprovalIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let (bearer, kem_private) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let context =
            passwords_gateway_data(client.approval_approve_context(&params.approval_id).await)
                .await?
                .data;
        let one_shot_wrapped_key = build_approval_wrapped_key(&kem_private, &context)?;
        let approval = passwords_gateway_data(
            client
                .approval_approve(
                    &params.approval_id,
                    &seren::ApprovalDecisionRequest {
                        one_shot_wrapped_key: BASE64.encode(one_shot_wrapped_key),
                    },
                )
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &approval,
        )?]))
    }

    #[tool(
        description = "Deny a pending Seren Passwords approval request",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_approval_deny(
        &self,
        Parameters(params): Parameters<PasswordsApprovalIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.api_client(&extensions)?;
        let approval = passwords_gateway_data(client.approval_deny(&params.approval_id).await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &approval,
        )?]))
    }

    #[tool(
        description = "List active Seren Passwords memberships for a vault",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_memberships_list(
        &self,
        Parameters(params): Parameters<PasswordsMembershipsListParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let memberships = passwords_gateway_data(client.membership_list(&params.vault_id).await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &memberships,
        )?]))
    }

    #[tool(
        description = "Revoke an identity's Seren Passwords vault membership. Requires admin membership",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_membership_revoke(
        &self,
        Parameters(params): Parameters<PasswordsMembershipRevokeParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let result = passwords_gateway_data(
            client
                .membership_revoke(&params.vault_id, &params.identity_id)
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
        )?]))
    }

    #[tool(
        description = "Create a Seren Passwords vault invitation token. Requires admin membership",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_invitation_create(
        &self,
        Parameters(params): Parameters<PasswordsInvitationCreateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let email = params.email.trim().to_ascii_lowercase();
        if !email.contains('@') {
            return Err(McpError::invalid_params(
                "email must be a valid email address",
                None,
            ));
        }
        let vault_client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&vault_client, Some(params.vault_id)).await?;
        let invitation_id = Uuid::new_v4();
        let email_ciphertext = encrypt_vault_invitation_email(
            &vault.key,
            vault.vault_id.as_bytes(),
            invitation_id.as_bytes(),
            &email,
        );
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let invitation = passwords_gateway_data(
            client
                .invitation_create(
                    &vault.vault_id,
                    &seren::CreateInvitationRequest {
                        access_level: params.access_level.into(),
                        expires_in_hours: params.expires_in_hours,
                        invitation_id,
                        invitee_email_ciphertext: BASE64.encode(email_ciphertext),
                    },
                )
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &invitation,
        )?]))
    }

    #[tool(
        description = "List Seren Passwords invitations. Pass vault_id for vault invitations; omit for pending redeemed invitations",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_invitations_list(
        &self,
        Parameters(params): Parameters<PasswordsInvitationsListParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let invitations = if let Some(vault_id) = params.vault_id {
            let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
            let client = self.api_client_for_bearer(&bearer, &extensions)?;
            passwords_gateway_data(client.invitation_list_for_vault(&vault_id).await)
                .await?
                .data
        } else {
            let client = self.api_client(&extensions)?;
            passwords_gateway_data(client.invitation_list_pending().await)
                .await?
                .data
        };

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &invitations,
        )?]))
    }

    #[tool(
        description = "Redeem a Seren Passwords invitation token as the current identity",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_invitation_redeem(
        &self,
        Parameters(params): Parameters<PasswordsInvitationRedeemParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let token = params.token.trim().to_string();
        if token.is_empty() {
            return Err(McpError::invalid_params(
                "invitation token is required",
                None,
            ));
        }
        let client = self.api_client(&extensions)?;
        let invitation = passwords_gateway_data(
            client
                .invitation_redeem(&seren::RedeemRequest {
                    invitation_token: token,
                })
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &invitation,
        )?]))
    }

    #[tool(
        description = "List outbound Seren Passwords live shares visible to the current user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_shares_outbound_list(
        &self,
        Parameters(params): Parameters<PasswordsSharesOutboundListParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api_client(&extensions)?;
        let shares =
            passwords_gateway_data(client.share_list_outbound(params.vault_id.as_ref()).await)
                .await?
                .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &shares,
        )?]))
    }

    #[tool(
        description = "List received Seren Passwords live shares visible to the current user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_shares_received_list(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api_client(&extensions)?;
        let shares = passwords_gateway_data(client.share_list_received().await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &shares,
        )?]))
    }

    #[tool(
        description = "Get one Seren Passwords live share record visible to the current user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_share_get(
        &self,
        Parameters(params): Parameters<PasswordsShareIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api_client(&extensions)?;
        let share = passwords_gateway_data(client.share_get(&params.share_id).await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &share,
        )?]))
    }

    #[tool(
        description = "Revoke a Seren Passwords live share visible to the current user",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_share_revoke(
        &self,
        Parameters(params): Parameters<PasswordsShareIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.api_client(&extensions)?;
        let share = passwords_gateway_data(client.share_revoke(&params.share_id).await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &share,
        )?]))
    }

    #[tool(
        description = "List items (id and title only) in a Seren Passwords vault",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_items_list(
        &self,
        Parameters(params): Parameters<PasswordsItemsListParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&client, params.vault_id).await?;
        let items = client
            .list_items(vault.vault_id, &vault.key)
            .await
            .map_err(vault_err)?;

        let output = items
            .into_iter()
            .map(|(item_id, title)| {
                serde_json::json!({
                    "item_id": item_id,
                    "title": title,
                })
            })
            .collect::<Vec<_>>();

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Get a Seren Passwords item. Decrypted content is redacted unless reveal=true",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_item_get(
        &self,
        Parameters(params): Parameters<PasswordsItemGetParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let reveal = params.reveal.unwrap_or(false);
        let client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&client, params.vault_id).await?;
        let item = client
            .get_item(vault.vault_id, params.item_id, &vault.key)
            .await
            .map_err(vault_err)?;

        let item_kind = serde_json::from_str::<serde_json::Value>(&item.metadata_json)
            .ok()
            .and_then(|value| {
                value
                    .get("item_kind")
                    .and_then(|kind| kind.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "unknown".to_string());

        let mut output = serde_json::json!({
            "item_id": item.item_id,
            "title": item.title,
            "tags": item.tags,
            "item_kind": item_kind,
            "revealed": reveal,
        });

        if reveal {
            let content = serde_json::to_value(&item.content)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            output["content"] = content;
        }

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Create a Seren Passwords item (login, api_credential, or secure_note)",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_item_create(
        &self,
        Parameters(params): Parameters<PasswordsItemCreateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&client, params.vault_id).await?;

        let sensitive = params.sensitive.unwrap_or(false);
        let tags = params.tags.unwrap_or_default();

        let (content, reference_field) = match params.kind.as_str() {
            "login" => {
                if params.body.is_some() {
                    return Err(McpError::invalid_request(
                        "body is only valid for secure_note items",
                        None,
                    ));
                }
                if params.key.is_some() || params.credential_kind.is_some() {
                    return Err(McpError::invalid_request(
                        "key and credential_kind are only valid for api_credential items",
                        None,
                    ));
                }
                let password = params.password.ok_or_else(|| {
                    McpError::invalid_request("login items require a password", None)
                })?;
                let (notes, notes_text) =
                    prose::from_plaintext(params.notes.as_deref().unwrap_or_default());
                let content = ItemContent::Login(LoginContent {
                    username: params.username.unwrap_or_default(),
                    password,
                    urls: params
                        .urls
                        .unwrap_or_default()
                        .into_iter()
                        .map(LoginUrl::from)
                        .collect(),
                    notes,
                    notes_text,
                    ..LoginContent::default()
                });
                (content, "password")
            }
            "api_credential" => {
                if params.body.is_some() {
                    return Err(McpError::invalid_request(
                        "body is only valid for secure_note items",
                        None,
                    ));
                }
                if params.username.is_some() || params.urls.is_some() || params.password.is_some() {
                    return Err(McpError::invalid_request(
                        "username, password, and urls are only valid for login items",
                        None,
                    ));
                }
                let key = params.key.ok_or_else(|| {
                    McpError::invalid_request("api_credential items require a key", None)
                })?;
                let (notes, notes_text) =
                    prose::from_plaintext(params.notes.as_deref().unwrap_or_default());
                let content = ItemContent::ApiCredential(ApiCredentialContent {
                    kind: api_credential_kind(
                        params.credential_kind.as_deref().unwrap_or("api_key"),
                    )?,
                    primary_value: key,
                    notes,
                    notes_text,
                    ..ApiCredentialContent::default()
                });
                (content, "primary_value")
            }
            "secure_note" => {
                if params.username.is_some()
                    || params.password.is_some()
                    || params.urls.is_some()
                    || params.key.is_some()
                    || params.credential_kind.is_some()
                    || params.notes.is_some()
                {
                    return Err(McpError::invalid_request(
                        "only body is valid for secure_note items",
                        None,
                    ));
                }
                let body = params.body.ok_or_else(|| {
                    McpError::invalid_request("secure_note items require a body", None)
                })?;
                let (body, body_text) = prose::from_plaintext(&body);
                let content = ItemContent::SecureNote(SecureNoteContent {
                    body,
                    body_text,
                    ..SecureNoteContent::default()
                });
                (content, "body")
            }
            other => {
                return Err(McpError::invalid_request(
                    format!("unknown item kind: {other}"),
                    None,
                ));
            }
        };

        let item_id = client
            .create_item(
                vault.vault_id,
                &vault.key,
                content,
                &params.title,
                &tags,
                sensitive,
                vault.key_version,
            )
            .await
            .map_err(vault_err)?;

        let output = serde_json::json!({
            "vault_id": vault.vault_id,
            "item_id": item_id,
            "item_kind": params.kind,
            "reference": format!(
                "seren-secrets://{}/{}/{}",
                vault.vault_id, item_id, reference_field
            ),
        });

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Update a Seren Passwords item. Only provided fields change; the rest are preserved",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_item_update(
        &self,
        Parameters(params): Parameters<PasswordsItemUpdateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&client, params.vault_id).await?;
        let item = client
            .get_item(vault.vault_id, params.item_id, &vault.key)
            .await
            .map_err(vault_err)?;

        let title = params.title.unwrap_or(item.title);
        let tags = params.tags.unwrap_or(item.tags);
        let sensitive = match params.sensitive {
            Some(value) => value,
            None => serde_json::from_str::<serde_json::Value>(&item.metadata_json)
                .ok()
                .and_then(|value| value.get("sensitive").and_then(serde_json::Value::as_bool))
                .unwrap_or(false),
        };

        let mut content = item.content;
        match &mut content {
            ItemContent::Login(login) => {
                if let Some(username) = params.username {
                    login.username = username;
                }
                if let Some(password) = params.password {
                    login.password = password;
                }
                if let Some(urls) = params.urls {
                    login.urls = urls.into_iter().map(LoginUrl::from).collect();
                }
                if let Some(notes) = params.notes {
                    let (doc, text) = prose::from_plaintext(&notes);
                    login.notes = doc;
                    login.notes_text = text;
                }
                if params.key.is_some() || params.credential_kind.is_some() {
                    return Err(McpError::invalid_request(
                        "key and credential_kind are only valid for api_credential items",
                        None,
                    ));
                }
                if params.body.is_some() {
                    return Err(McpError::invalid_request(
                        "body is only valid for secure_note items",
                        None,
                    ));
                }
            }
            ItemContent::ApiCredential(cred) => {
                if let Some(key) = params.key {
                    cred.primary_value = key;
                }
                if let Some(kind) = params.credential_kind {
                    cred.kind = api_credential_kind(&kind)?;
                }
                if let Some(notes) = params.notes {
                    let (doc, text) = prose::from_plaintext(&notes);
                    cred.notes = doc;
                    cred.notes_text = text;
                }
                if params.password.is_some() || params.username.is_some() || params.urls.is_some() {
                    return Err(McpError::invalid_request(
                        "username, password, and urls are only valid for login items",
                        None,
                    ));
                }
                if params.body.is_some() {
                    return Err(McpError::invalid_request(
                        "body is only valid for secure_note items",
                        None,
                    ));
                }
            }
            ItemContent::SecureNote(note) => {
                if let Some(body) = params.body {
                    let (doc, text) = prose::from_plaintext(&body);
                    note.body = doc;
                    note.body_text = text;
                }
                if params.password.is_some() || params.username.is_some() || params.urls.is_some() {
                    return Err(McpError::invalid_request(
                        "username, password, and urls are only valid for login items",
                        None,
                    ));
                }
                if params.key.is_some() || params.credential_kind.is_some() {
                    return Err(McpError::invalid_request(
                        "key and credential_kind are only valid for api_credential items",
                        None,
                    ));
                }
                if params.notes.is_some() {
                    return Err(McpError::invalid_request(
                        "notes is only valid for login and api_credential items; use body for secure notes",
                        None,
                    ));
                }
            }
            _ => {
                if params.password.is_some()
                    || params.key.is_some()
                    || params.body.is_some()
                    || params.username.is_some()
                    || params.urls.is_some()
                    || params.credential_kind.is_some()
                    || params.notes.is_some()
                {
                    return Err(McpError::invalid_request(
                        "updating this item kind is not supported",
                        None,
                    ));
                }
            }
        }

        client
            .update_item(
                vault.vault_id,
                params.item_id,
                &vault.key,
                content,
                &title,
                &tags,
                sensitive,
                vault.key_version,
            )
            .await
            .map_err(vault_err)?;

        let output = serde_json::json!({
            "vault_id": vault.vault_id,
            "item_id": params.item_id,
            "updated": true,
        });

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Delete (trash) a Seren Passwords item",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_item_delete(
        &self,
        Parameters(params): Parameters<PasswordsItemDeleteParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&client, params.vault_id).await?;
        client
            .delete_item(vault.vault_id, params.item_id)
            .await
            .map_err(vault_err)?;

        let output = serde_json::json!({
            "vault_id": vault.vault_id,
            "item_id": params.item_id,
            "deleted": true,
        });

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Restore a previously deleted Seren Passwords item",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_item_restore(
        &self,
        Parameters(params): Parameters<PasswordsItemRestoreParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&client, params.vault_id).await?;
        client
            .restore_item(vault.vault_id, params.item_id)
            .await
            .map_err(vault_err)?;

        let output = serde_json::json!({
            "vault_id": vault.vault_id,
            "item_id": params.item_id,
            "restored": true,
        });

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Duplicate a Seren Passwords item into another vault",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_item_duplicate(
        &self,
        Parameters(params): Parameters<PasswordsItemCopyParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.passwords_vault_client(&extensions).await?;
        let source = select_vault(&client, params.vault_id).await?;
        let target = select_vault(&client, Some(params.target_vault_id)).await?;
        ensure_distinct_transfer_vaults(source.vault_id, target.vault_id)?;
        let new_item_id = client
            .copy_item(
                source.vault_id,
                params.item_id,
                &source.key,
                target.vault_id,
                &target.key,
                target.key_version,
            )
            .await
            .map_err(vault_err)?;

        let output = serde_json::json!({
            "source_vault_id": source.vault_id,
            "source_item_id": params.item_id,
            "target_vault_id": target.vault_id,
            "item_id": new_item_id,
            "copied": true,
        });

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Move a Seren Passwords item into another vault",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_item_move(
        &self,
        Parameters(params): Parameters<PasswordsItemMoveParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let client = self.passwords_vault_client(&extensions).await?;
        let source = select_vault(&client, params.vault_id).await?;
        let target = select_vault(&client, Some(params.target_vault_id)).await?;
        ensure_distinct_transfer_vaults(source.vault_id, target.vault_id)?;
        let new_item_id = client
            .move_item(
                source.vault_id,
                params.item_id,
                &source.key,
                target.vault_id,
                &target.key,
                target.key_version,
            )
            .await
            .map_err(vault_err)?;

        let output = serde_json::json!({
            "source_vault_id": source.vault_id,
            "source_item_id": params.item_id,
            "target_vault_id": target.vault_id,
            "item_id": new_item_id,
            "moved": true,
        });

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Unlock the Seren Passwords vault in user mode using the account master password. \
The master password is read from a secure source (SEREN_PASSWORDS_MASTER_PASSWORD env var or an \
attached terminal), never from tool arguments. Local MCP modes only.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_unlock(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        // The master password is sourced outside tool arguments and only the
        // derived key source is retained.
        self.passwords_unlock_session(&extensions).await?;
        Ok(CallToolResult::success(vec![crate::server::json_content(
            &serde_json::json!({ "unlocked": true }),
        )?]))
    }

    #[tool(
        description = "Lock the Seren Passwords vault, discarding any user-mode session and its derived key material",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_lock(&self, _extensions: Extensions) -> Result<CallToolResult, McpError> {
        self.passwords_lock_session().await;
        Ok(CallToolResult::success(vec![crate::server::json_content(
            &serde_json::json!({ "locked": true }),
        )?]))
    }

    #[tool(
        description = "Generate a strong password or passphrase (local, never stored)",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_generate_password(
        &self,
        Parameters(params): Parameters<PasswordsGeneratePasswordParams>,
    ) -> Result<CallToolResult, McpError> {
        let mode = params.mode.as_deref().unwrap_or("random");
        let recipe = match mode {
            "random" => PasswordRecipe::Random {
                length: params.length.unwrap_or(20),
                upper: params.upper.unwrap_or(true),
                lower: params.lower.unwrap_or(true),
                digits: params.digits.unwrap_or(true),
                symbols: params.symbols.unwrap_or(true),
            },
            "passphrase" => PasswordRecipe::Passphrase {
                word_count: params.word_count.unwrap_or(5),
                separator: params.separator.unwrap_or('-'),
                capitalize_first: params.capitalize_first.unwrap_or(true),
            },
            "hex" => PasswordRecipe::Hex {
                length: params.length.unwrap_or(32),
            },
            other => {
                return Err(McpError::invalid_request(
                    format!("unknown mode: {other}"),
                    None,
                ));
            }
        };

        let generated = seren_secrets_crypto::password_generator::generate(&recipe)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &serde_json::json!({ "password": generated }),
        )?]))
    }
}

fn ensure_distinct_transfer_vaults(
    source_vault_id: Uuid,
    target_vault_id: Uuid,
) -> Result<(), McpError> {
    if source_vault_id == target_vault_id {
        return Err(McpError::invalid_request(
            "target vault must be different from source vault",
            None,
        ));
    }
    Ok(())
}

const DEFAULT_SEREN_PASSWORDS_URL: &str = "https://passwords.serendb.com";
const PASSWORDS_URL_ENV: &str = "SEREN_PASSWORDS_URL";

fn hosted_passwords_consent_url(request_id: Uuid) -> Result<String, McpError> {
    let base = hosted_seren_passwords_url()?;
    Ok(format!("{base}/grant?request={request_id}"))
}

fn jiff_timestamp_to_offset_datetime(
    timestamp: jiff::Timestamp,
) -> Result<time::OffsetDateTime, McpError> {
    time::OffsetDateTime::from_unix_timestamp_nanos(timestamp.as_nanosecond())
        .map_err(|e| McpError::internal_error(e.to_string(), None))
}

fn hosted_seren_passwords_url() -> Result<String, McpError> {
    let raw = match std::env::var(PASSWORDS_URL_ENV) {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) | Err(std::env::VarError::NotPresent) => DEFAULT_SEREN_PASSWORDS_URL.to_string(),
        Err(e) => {
            return Err(McpError::internal_error(
                format!("invalid {PASSWORDS_URL_ENV}: {e}"),
                None,
            ));
        }
    };
    let trimmed = raw.trim().trim_end_matches('/').to_string();
    let url = reqwest::Url::parse(&trimmed)
        .map_err(|_| McpError::internal_error(format!("invalid {PASSWORDS_URL_ENV}"), None))?;
    if url.host_str().is_none() {
        return Err(McpError::internal_error(
            format!("{PASSWORDS_URL_ENV} must be an absolute http or https URL"),
            None,
        ));
    }
    let is_https = url.scheme() == "https";
    let is_loopback_http = url.scheme() == "http" && url_is_loopback(&url);
    if !is_https && !is_loopback_http {
        return Err(McpError::internal_error(
            format!("{PASSWORDS_URL_ENV} must use https except for loopback URLs"),
            None,
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(McpError::internal_error(
            format!("{PASSWORDS_URL_ENV} must not include a query string or fragment"),
            None,
        ));
    }
    Ok(trimmed)
}

fn url_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.is_loopback())
}

/// Read the account master password from a secure source for user-mode unlock.
///
/// The master password is sourced outside tool arguments, wrapped in
/// `Zeroizing`, and never logged. Mirrors the CLI `read_master_password`.
pub(crate) async fn read_master_password() -> Result<Zeroizing<Vec<u8>>, McpError> {
    if let Ok(value) = std::env::var("SEREN_PASSWORDS_MASTER_PASSWORD")
        && !value.is_empty()
    {
        return Ok(Zeroizing::new(value.into_bytes()));
    }

    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let password = tokio::task::spawn_blocking(|| {
            rpassword::prompt_password("Seren Passwords master password: ")
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        return Ok(Zeroizing::new(password.into_bytes()));
    }

    Err(McpError::invalid_request(
        "No master password source: set SEREN_PASSWORDS_MASTER_PASSWORD or run with an attached terminal.",
        None,
    ))
}

/// Map `VaultClient` errors without surfacing upstream response bodies.
pub(crate) fn vault_err(e: seren_secrets_resolver::ResolverError) -> McpError {
    use seren_secrets_resolver::ResolverError;
    match e {
        // The vault requires per-item approval for this read. Surface the
        // pending request id (never a secret) so the caller can approve it
        // out-of-band and retry, rather than seeing an opaque 403.
        ResolverError::ApprovalRequired { request_id } => McpError::invalid_request(
            format!(
                "Approval required for this item. A request ({request_id}) is pending; approve it in your Seren Passwords app, then retry."
            ),
            Some(serde_json::json!({
                "approval_required": true,
                "approval_request_id": request_id,
            })),
        ),
        ResolverError::ServerError { status, .. } => {
            McpError::internal_error(format!("vault server returned status {status}"), None)
        }
        other => McpError::internal_error(other.to_string(), None),
    }
}

/// Resolve a Seren Passwords publisher response into its typed wrapper.
///
/// These control ops reach Seren Passwords through the Seren publisher
/// gateway, which wraps the upstream `DataResponse<T>` in a metered envelope.
/// The generated SDK methods deserialize the direct `DataResponse<T>` shape, so
/// the gateway envelope is unwrapped here when it appears. Errors never carry an
/// upstream response body.
async fn passwords_gateway_data<T>(
    result: Result<seren::ResponseValue<T>, seren::Error<()>>,
) -> Result<T, McpError>
where
    T: serde::de::DeserializeOwned,
{
    match result {
        Ok(response) => Ok(response.into_inner()),
        Err(seren::Error::InvalidResponsePayload(bytes, _)) => {
            crate::server::decode_publisher_gateway_body::<T>(&bytes).map_err(|_| {
                McpError::internal_error("Invalid response payload from vault gateway", None)
            })
        }
        Err(e) => Err(crate::server::seren_error_to_mcp_error(e).await),
    }
}

fn build_approval_wrapped_key(
    kem_private: &IdentityKemPrivateKey,
    context: &seren::ApproveContext,
) -> Result<Vec<u8>, McpError> {
    let requester_public = decode_kem_public_key(&context.requester_kem_public_key)?;
    let approver_wrapped_vault_key = decode_passwords_b64_field(
        "approver_wrapped_vault_key",
        &context.approver_wrapped_vault_key,
    )?;
    let vault_key = unwrap_vault_key(kem_private, &approver_wrapped_vault_key)
        .map_err(|_| McpError::invalid_request("Could not unwrap approval vault key", None))?;

    match context.target_kind {
        seren::ApprovalTargetKind::Vault => {
            Ok(wrap_vault_key_for_identity(&vault_key, &requester_public))
        }
        seren::ApprovalTargetKind::Item => {
            let item_id = context.item_id.ok_or_else(|| {
                McpError::invalid_request("Approval context missing item_id", None)
            })?;
            let content_key_wrap = context.content_key_wrap.as_ref().ok_or_else(|| {
                McpError::invalid_request("Approval context missing content_key_wrap", None)
            })?;
            let content_key_wrap =
                decode_passwords_b64_field("content_key_wrap", content_key_wrap)?;
            let content_key =
                unwrap_item_content_key(&vault_key, item_id.as_bytes(), &content_key_wrap)
                    .map_err(|_| {
                        McpError::invalid_request("Could not unwrap approval item key", None)
                    })?;
            Ok(seren_secrets_crypto::kem::seal(
                &requester_public,
                content_key.as_bytes(),
            ))
        }
    }
}

fn decode_kem_public_key(encoded: &str) -> Result<IdentityKemPublicKey, McpError> {
    let bytes = decode_passwords_b64_field("requester_kem_public_key", encoded)?;
    IdentityKemPublicKey::from_slice(&bytes)
        .map_err(|_| McpError::invalid_request("Invalid requester KEM public key", None))
}

fn decode_passwords_b64_field(field: &'static str, encoded: &str) -> Result<Vec<u8>, McpError> {
    BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| McpError::invalid_request(format!("Invalid base64 field {field}"), None))
}

fn parse_timestamp_param(
    name: &str,
    value: Option<&str>,
) -> Result<Option<jiff::Timestamp>, McpError> {
    value
        .map(|raw| {
            raw.parse::<jiff::Timestamp>().map_err(|_| {
                McpError::invalid_params(format!("{name} must be an RFC3339 timestamp"), None)
            })
        })
        .transpose()
}

/// Map a textual API credential kind to the protocol enum, mirroring the CLI.
fn api_credential_kind(raw: &str) -> Result<ApiCredentialKind, McpError> {
    match raw.to_ascii_lowercase().as_str() {
        "api_key" | "api-key" | "key" => Ok(ApiCredentialKind::ApiKey),
        "oauth2_token" | "oauth2-token" | "oauth2" => Ok(ApiCredentialKind::Oauth2Token),
        "basic" => Ok(ApiCredentialKind::Basic),
        "mtls" => Ok(ApiCredentialKind::Mtls),
        "aws_sig_v4" | "aws-sig-v4" | "aws" => Ok(ApiCredentialKind::AwsSigV4),
        "gcp_service_account" | "gcp-service-account" | "gcp" => {
            Ok(ApiCredentialKind::GcpServiceAccount)
        }
        other => Err(McpError::invalid_request(
            format!("unsupported api credential kind: {other}"),
            None,
        )),
    }
}

/// Select the target vault, mirroring the CLI `select_vault` semantics:
/// match by id when given, otherwise default to the sole vault and error when
/// the choice is ambiguous.
async fn select_vault(
    client: &seren_secrets_resolver::VaultClient,
    vault_id: Option<Uuid>,
) -> Result<seren_secrets_resolver::vault::DecryptedVault, McpError> {
    let mut vaults = client.list_vaults().await.map_err(vault_err)?;
    match vault_id {
        Some(id) => vaults
            .into_iter()
            .find(|vault| vault.vault_id == id)
            .ok_or_else(|| {
                McpError::invalid_request(
                    format!("vault {id} is not available to this account"),
                    None,
                )
            }),
        None => {
            if vaults.len() != 1 {
                return Err(McpError::invalid_request(
                    "multiple vaults found; pass vault_id",
                    None,
                ));
            }
            vaults
                .pop()
                .ok_or_else(|| McpError::invalid_request("no password vaults found", None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_requires_distinct_vaults() {
        let source = Uuid::new_v4();
        let target = Uuid::new_v4();

        assert!(ensure_distinct_transfer_vaults(source, target).is_ok());
        assert!(ensure_distinct_transfer_vaults(source, source).is_err());
    }

    #[test]
    fn build_approval_wrapped_key_rewraps_vault_key_to_requester() {
        use seren_secrets_crypto::protocol::vault::generate_vault_key;

        let approver = IdentityKemKeypair::generate();
        let requester = IdentityKemKeypair::generate();
        let vault_key = generate_vault_key();
        let context = seren::ApproveContext {
            approver_wrapped_vault_key: BASE64
                .encode(wrap_vault_key_for_identity(&vault_key, &approver.public)),
            content_key_wrap: None,
            item_id: None,
            requester_kem_public_key: BASE64.encode(requester.public.as_bytes()),
            target_kind: seren::ApprovalTargetKind::Vault,
            vault_id: Uuid::new_v4(),
        };

        let rewrapped = build_approval_wrapped_key(&approver.private, &context).unwrap();

        // Only the requester's private key recovers the vault key; the approver's
        // key material never leaves the host.
        let recovered = unwrap_vault_key(&requester.private, &rewrapped).unwrap();
        assert_eq!(recovered.as_bytes(), vault_key.as_bytes());
    }

    #[test]
    fn build_approval_wrapped_key_rewraps_item_content_key_to_requester() {
        use seren_secrets_crypto::protocol::item::{
            generate_item_content_key, wrap_item_content_key,
        };
        use seren_secrets_crypto::protocol::vault::generate_vault_key;

        let approver = IdentityKemKeypair::generate();
        let requester = IdentityKemKeypair::generate();
        let vault_key = generate_vault_key();
        let item_id = Uuid::new_v4();
        let content_key = generate_item_content_key();
        let context = seren::ApproveContext {
            approver_wrapped_vault_key: BASE64
                .encode(wrap_vault_key_for_identity(&vault_key, &approver.public)),
            content_key_wrap: Some(BASE64.encode(wrap_item_content_key(
                &vault_key,
                item_id.as_bytes(),
                &content_key,
            ))),
            item_id: Some(item_id),
            requester_kem_public_key: BASE64.encode(requester.public.as_bytes()),
            target_kind: seren::ApprovalTargetKind::Item,
            vault_id: Uuid::new_v4(),
        };

        let rewrapped = build_approval_wrapped_key(&approver.private, &context).unwrap();

        let recovered = seren_secrets_crypto::kem::unseal(&requester.private, &rewrapped).unwrap();
        assert_eq!(recovered.as_slice(), &content_key.as_bytes()[..]);
    }

    #[test]
    fn passwords_consent_url_requires_https_except_loopback() {
        temp_env::with_var_unset(PASSWORDS_URL_ENV, || {
            let request_id = Uuid::nil();
            assert_eq!(
                hosted_passwords_consent_url(request_id).unwrap(),
                format!("{DEFAULT_SEREN_PASSWORDS_URL}/grant?request={request_id}")
            );
        });

        temp_env::with_var(
            PASSWORDS_URL_ENV,
            Some("https://passwords.example.com/"),
            || {
                assert_eq!(
                    hosted_seren_passwords_url().unwrap(),
                    "https://passwords.example.com"
                );
            },
        );
        temp_env::with_var(PASSWORDS_URL_ENV, Some("http://127.0.0.1:5173"), || {
            assert_eq!(
                hosted_seren_passwords_url().unwrap(),
                "http://127.0.0.1:5173"
            );
        });
        temp_env::with_var(
            PASSWORDS_URL_ENV,
            Some("http://passwords.example.com"),
            || {
                assert!(hosted_seren_passwords_url().is_err());
            },
        );
        temp_env::with_var(
            PASSWORDS_URL_ENV,
            Some("https://passwords.example.com/?x=1"),
            || {
                assert!(hosted_seren_passwords_url().is_err());
            },
        );
    }

    #[test]
    fn hosted_delegation_timestamp_conversion_preserves_instant() {
        let timestamp: jiff::Timestamp = "2030-01-01T18:19:00.123456789Z".parse().unwrap();
        let converted = jiff_timestamp_to_offset_datetime(timestamp).unwrap();

        assert_eq!(converted.unix_timestamp_nanos(), timestamp.as_nanosecond());
    }

    #[test]
    fn hosted_delegation_sdk_types_serialize_as_wire_strings() {
        let timestamp: jiff::Timestamp = "2030-01-01T18:19:00.123456789Z".parse().unwrap();
        let value = serde_json::json!({
            "expires_at": timestamp,
            "status": &seren::DelegationStatus::Denied,
        });

        assert_eq!(
            value,
            serde_json::json!({
                "expires_at": "2030-01-01T18:19:00.123456789Z",
                "status": "denied",
            })
        );
    }

    fn sample_delegation_record() -> seren::DelegationRequestRecord {
        let timestamp: jiff::Timestamp = "2030-01-01T18:19:00Z".parse().unwrap();
        seren::DelegationRequestRecord {
            agent_kem_public: "kem-public".to_string(),
            agent_signing_public: "signing-public".to_string(),
            created_at: timestamp,
            decided_at: None,
            display_name: "Hosted MCP".to_string(),
            expires_at: timestamp,
            granted_vault_ids: vec![Uuid::new_v4()],
            identity_id: None,
            request_id: Uuid::new_v4(),
            status: seren::DelegationStatus::Pending,
            user_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn hosted_delegation_parser_accepts_direct_sdk_response() {
        let record = sample_delegation_record();
        let body = serde_json::to_vec(&seren::DataResponseDelegationRequestRecord {
            data: record.clone(),
        })
        .unwrap();

        let parsed = crate::server::decode_publisher_gateway_body::<
            seren::DataResponseDelegationRequestRecord,
        >(&body)
        .unwrap()
        .data;

        assert_eq!(parsed.request_id, record.request_id);
        assert_eq!(parsed.status, record.status);
    }

    #[test]
    fn hosted_delegation_parser_accepts_gateway_envelope() {
        let record = sample_delegation_record();
        let upstream = serde_json::json!({
            "data": record,
        });
        let gateway = serde_json::json!({
            "data": {
                "status": 200,
                "body": upstream,
                "response_bytes": 123,
                "execution_time_ms": 4,
                "cost": "0",
                "asset_symbol": "USDC",
                "payment_source": "none"
            }
        });
        let parsed = crate::server::decode_publisher_gateway_body::<
            seren::DataResponseDelegationRequestRecord,
        >(serde_json::to_string(&gateway).unwrap().as_bytes())
        .unwrap()
        .data;

        assert_eq!(parsed.display_name, "Hosted MCP");
        assert_eq!(parsed.status, seren::DelegationStatus::Pending);
    }

    #[test]
    fn agent_freeze_response_parses_direct_and_gateway_envelope() {
        let direct = serde_json::to_vec(&seren::DataResponseAgentFreeze {
            data: seren::AgentFreezeResponse { revoked: 3 },
        })
        .unwrap();
        let parsed =
            crate::server::decode_publisher_gateway_body::<seren::DataResponseAgentFreeze>(&direct)
                .unwrap();
        assert_eq!(parsed.data.revoked, 3);

        let gateway = serde_json::json!({
            "data": {
                "status": 200,
                "body": { "data": { "revoked": 3 } },
                "response_bytes": 42,
                "execution_time_ms": 2,
                "cost": "0",
                "asset_symbol": "USDC",
                "payment_source": "none"
            }
        });
        let parsed =
            crate::server::decode_publisher_gateway_body::<seren::DataResponseAgentFreeze>(
                serde_json::to_string(&gateway).unwrap().as_bytes(),
            )
            .unwrap();
        assert_eq!(parsed.data.revoked, 3);
    }

    #[test]
    fn hosted_delegation_parser_accepts_string_gateway_body() {
        let record = sample_delegation_record();
        let upstream = serde_json::json!({
            "data": record,
        });
        let gateway = serde_json::json!({
            "data": {
                "status": 200,
                "body": upstream.to_string(),
                "response_bytes": 123,
                "execution_time_ms": 4,
                "cost": "0",
                "asset_symbol": "USDC",
                "payment_source": "none"
            }
        });
        let parsed = crate::server::decode_publisher_gateway_body::<
            seren::DataResponseDelegationRequestRecord,
        >(serde_json::to_string(&gateway).unwrap().as_bytes())
        .unwrap()
        .data;

        assert_eq!(parsed.display_name, "Hosted MCP");
        assert_eq!(parsed.status, seren::DelegationStatus::Pending);
    }
}
