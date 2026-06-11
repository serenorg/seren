//! Seren Passwords vault tools for the MCP server.
//!
//! Seren Passwords is an end-to-end-encrypted password manager: the server
//! stores only ciphertext plus public keys, and this process decrypts vault
//! contents client-side using a held KEM private key (agent-key mode) or
//! master-password-derived identity keys (local user mode).
//!
//! Secret material is never logged or emitted. Tool output is redact-by-default:
//! item bodies are returned only when `reveal == true`.

use std::collections::{HashMap, HashSet};
use std::path::Path;
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
    IdentitySigningPrivateKey, VaultKey,
};
use seren_secrets_crypto::password_generator::PasswordRecipe;
use seren_secrets_crypto::prose;
use seren_secrets_crypto::protocol::attachment::{
    decrypt_blob, decrypt_content_type, decrypt_filename, encrypt_blob, encrypt_content_type,
    encrypt_filename, generate_attachment_key, unwrap_attachment_key, wrap_attachment_key,
};
use seren_secrets_crypto::protocol::item::{
    ApiCredentialContent, ApiCredentialKind, ItemContent, LoginContent, LoginUrl,
    SecureNoteContent, decrypt_metadata_json, decrypt_tags, decrypt_title, encrypt_metadata_json,
    encrypt_tags, encrypt_title, unwrap_item_content_key, wrap_item_content_key,
};
use seren_secrets_crypto::protocol::vault::{
    decrypt_vault_description, decrypt_vault_name, encrypt_vault_description,
    encrypt_vault_invitation_email, encrypt_vault_name, generate_vault_key, unwrap_vault_key,
    wrap_vault_key_for_identity,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::oauth::store::PendingHostedPasswordsAgentRequest;
use crate::server::SerenMcpServer;

/// Idle timeout for a user-mode unlocked session before it is discarded.
pub(crate) const SESSION_IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const MAX_ATTACHMENT_CIPHERTEXT_BYTES: usize = 100 * 1024 * 1024;
const PASSWORDS_EXPORT_FORMAT: &str = "seren-passwords-mcp-export";
const PASSWORDS_EXPORT_VERSION: u32 = 1;
const ATTACHMENT_URI_SCHEME: &str = "seren-secrets://attachment/";

/// User-mode (master-password) unlocked session. Held in memory only and used
/// to rebuild a fresh `VaultClient` or sign local-only requests; expires after
/// idle TTL.
pub(crate) struct PasswordsSession {
    pub kem_private: IdentityKemPrivateKey,
    pub signing_private: IdentitySigningPrivateKey,
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

/// Parameters for listing attachments on an item.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsAttachmentListParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item ID (UUID).
    pub item_id: Uuid,
}

/// Parameters for uploading an encrypted attachment to an item.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsAttachmentUploadParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item ID (UUID).
    pub item_id: Uuid,
    /// Stored filename.
    pub filename: String,
    /// Stored content type. Defaults to application/octet-stream.
    pub content_type: Option<String>,
    /// Plaintext attachment content, base64 encoded.
    pub content_base64: String,
}

/// Parameters for fetching or deleting an attachment.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsAttachmentIdParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Item ID (UUID).
    pub item_id: Uuid,
    /// Attachment ID (UUID).
    pub attachment_id: Uuid,
}

#[derive(Debug, Serialize)]
struct DecryptedAttachmentMetadata {
    attachment_id: Uuid,
    item_id: Uuid,
    filename: String,
    content_type: String,
    size_bytes: i64,
    created_at: jiff::Timestamp,
}

#[derive(Debug, Serialize)]
struct DecryptedAttachmentOutput {
    attachment: DecryptedAttachmentMetadata,
    content_base64: String,
    content_bytes: usize,
}

struct AttachmentMetadataFields<'a> {
    attachment_id: Uuid,
    filename_ciphertext: &'a str,
    content_type_ciphertext: &'a str,
    response_item_id: Uuid,
    size_bytes: i64,
    created_at: jiff::Timestamp,
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

/// Parameters for creating a vault. Local user-mode only.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsVaultCreateParams {
    /// Vault name.
    pub name: String,
    /// Optional vault description.
    pub description: Option<String>,
    /// Approval policy for reads. Defaults to server behavior.
    pub requires_approval: Option<seren::VaultApprovalMode>,
}

/// Parameters for initiating vault key rotation.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsVaultRotateInitiateParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
}

/// Parameters for completing vault key rotation. Local user-mode only.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsVaultRotateCompleteParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
    /// Existing rotation token. Omit to initiate and complete in one call.
    pub rotation_token: Option<Uuid>,
}

/// Parameters for canceling vault key rotation.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsVaultRotateCancelParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
    /// Rotation token returned by initiate.
    pub rotation_token: Uuid,
}

/// Parameters for exporting a vault's decrypted item data.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsVaultExportParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Exclude attachments from the plaintext export. Defaults to false.
    pub exclude_attachments: Option<bool>,
}

/// One plaintext item in the Seren Passwords MCP export format.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsImportItem {
    /// Item title.
    pub title: String,
    /// Item tags.
    pub tags: Option<Vec<String>>,
    /// Whether the item is sensitive.
    pub sensitive: Option<bool>,
    /// Whether the item should be marked as a favorite.
    pub favorite: Option<bool>,
    /// Serialized `ItemContent` value from `passwords_vault_export`.
    pub content: serde_json::Value,
    /// Attachments exported with this item.
    pub attachments: Option<Vec<PasswordsImportAttachment>>,
}

/// One plaintext attachment in the Seren Passwords MCP export format.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsImportAttachment {
    /// Source attachment ID from the export.
    pub attachment_id: Option<Uuid>,
    /// Plaintext filename.
    pub filename: String,
    /// Plaintext content type.
    pub content_type: String,
    /// Decoded byte length for `content_base64`.
    pub size_bytes: usize,
    /// Base64-encoded plaintext attachment bytes.
    pub content_base64: String,
}

struct PasswordsPreparedImportAttachment {
    attachment_id: Uuid,
    filename: String,
    content_type: String,
    size_bytes: usize,
    content_base64: String,
}

/// Parameters for importing plaintext item data into a vault.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsVaultImportParams {
    /// Vault ID (UUID). Optional when exactly one vault is available.
    pub vault_id: Option<Uuid>,
    /// Export format marker from passwords_vault_export.
    pub format: Option<String>,
    /// Export format version from passwords_vault_export.
    pub version: Option<u32>,
    /// Whether the export includes attachments.
    pub attachments_included: Option<bool>,
    /// Attachment count declared by the export.
    pub attachment_count: Option<usize>,
    /// Attachment byte count declared by the export.
    pub attachment_bytes: Option<usize>,
    /// Items to import.
    pub items: Vec<PasswordsImportItem>,
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

/// Parameters for granting vault membership. Local user-mode only.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsMembershipGrantParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
    /// Identity ID to grant.
    pub identity_id: Uuid,
    /// Access level to grant.
    pub access_level: PasswordsAccessLevel,
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

/// Parameters for completing a redeemed invitation. Local user-mode only.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PasswordsInvitationCompleteParams {
    /// Vault ID (UUID).
    pub vault_id: Uuid,
    /// Invitation ID to complete.
    pub invitation_id: Uuid,
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
        description = "Create an encrypted Seren Passwords vault. Local MCP user mode only; call passwords_unlock first",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_vault_create(
        &self,
        Parameters(params): Parameters<PasswordsVaultCreateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let name = params.name.trim();
        if name.is_empty() {
            return Err(McpError::invalid_params("name cannot be empty", None));
        }
        if !self.passwords_local_mode {
            let mut query = vec![("name", name.to_string())];
            if let Some(description) = params
                .description
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                query.push(("description", description.to_string()));
            }
            if let Some(mode) = params.requires_approval.as_ref() {
                query.push((
                    "requires_approval",
                    vault_approval_mode_param(mode).to_string(),
                ));
            }
            return hosted_passwords_ui_action_result(
                "create-vault",
                HOSTED_PASSWORDS_SIGNING_HANDOFF_REASON,
                hosted_passwords_home_action_url("create-vault", &query)?,
            );
        }
        let (bearer, _, signing_private) = self.passwords_user_signing_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let identity = passwords_gateway_data(client.identity_get_me().await)
            .await?
            .data;
        let identity_public =
            decode_kem_public_key_field("kem_public_key", &identity.kem_public_key)?;
        let vault_id = Uuid::new_v4();
        let vault_key = generate_vault_key();
        let wrapped = wrap_vault_key_for_identity(&vault_key, &identity_public);
        let granted_signature = membership_grant_signature(
            &signing_private,
            vault_id,
            identity.identity_id,
            seren::AccessLevel::Admin,
            &wrapped,
        );
        let description_ciphertext = params
            .description
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|description| {
                BASE64.encode(encrypt_vault_description(
                    &vault_key,
                    vault_id.as_bytes(),
                    description,
                ))
            });
        let result = passwords_gateway_data(
            client
                .vault_create(&seren::CreateVaultRequest {
                    access_level: seren::AccessLevel::Admin,
                    description_ciphertext,
                    granted_signature,
                    initial_wrapped_vault_key: BASE64.encode(wrapped),
                    name_ciphertext: BASE64.encode(encrypt_vault_name(
                        &vault_key,
                        vault_id.as_bytes(),
                        name,
                    )),
                    owner_kind: seren::VaultOwnerKind::User,
                    requires_approval: params.requires_approval,
                    vault_id,
                })
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
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
        description = "Initiate Seren Passwords vault key rotation. Local MCP user mode only; call passwords_unlock first",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_vault_rotation_initiate(
        &self,
        Parameters(params): Parameters<PasswordsVaultRotateInitiateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        if !self.passwords_local_mode {
            return hosted_passwords_ui_action_result(
                "rotate-key",
                HOSTED_PASSWORDS_SIGNING_HANDOFF_REASON,
                hosted_passwords_vault_action_url(params.vault_id, "rotate-key", &[])?,
            );
        }
        let (bearer, _, _) = self.passwords_user_signing_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let result = passwords_gateway_data(client.vault_rotation_initiate(&params.vault_id).await)
            .await?
            .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
        )?]))
    }

    #[tool(
        description = "Complete Seren Passwords vault key rotation. Local MCP user mode only; call passwords_unlock first",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_vault_rotation_complete(
        &self,
        Parameters(params): Parameters<PasswordsVaultRotateCompleteParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        if !self.passwords_local_mode {
            return hosted_passwords_ui_action_result(
                "rotate-key",
                HOSTED_PASSWORDS_SIGNING_HANDOFF_REASON,
                hosted_passwords_vault_action_url(params.vault_id, "rotate-key", &[])?,
            );
        }
        let (bearer, kem_private, signing_private) =
            self.passwords_user_signing_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let initiated_here = params.rotation_token.is_none();
        let rotation_token = match params.rotation_token {
            Some(token) => token,
            None => {
                passwords_gateway_data(client.vault_rotation_initiate(&params.vault_id).await)
                    .await?
                    .data
                    .rotation_token
            }
        };

        let body = match build_rotation_complete_request(
            &client,
            params.vault_id,
            rotation_token,
            &kem_private,
            &signing_private,
        )
        .await
        {
            Ok(body) => body,
            Err(error) => {
                if initiated_here {
                    let _ = client
                        .vault_rotation_cancel(
                            &params.vault_id,
                            &seren::RotationCancelRequest { rotation_token },
                        )
                        .await;
                }
                return Err(error);
            }
        };
        let result = passwords_gateway_data(
            client
                .vault_rotation_complete(&params.vault_id, &body)
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
        )?]))
    }

    #[tool(
        description = "Cancel Seren Passwords vault key rotation. Requires admin membership",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_vault_rotation_cancel(
        &self,
        Parameters(params): Parameters<PasswordsVaultRotateCancelParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let result = passwords_gateway_data(
            client
                .vault_rotation_cancel(
                    &params.vault_id,
                    &seren::RotationCancelRequest {
                        rotation_token: params.rotation_token,
                    },
                )
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
        )?]))
    }

    #[tool(
        description = "Export decrypted Seren Passwords items and attachments from one vault as plaintext JSON. Local MCP modes only",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_vault_export(
        &self,
        Parameters(params): Parameters<PasswordsVaultExportParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        if !self.passwords_local_mode {
            let client = self.passwords_vault_client(&extensions).await?;
            let vault = select_vault(&client, params.vault_id).await?;
            let mut query = Vec::new();
            if params.exclude_attachments.unwrap_or(false) {
                query.push(("exclude_attachments", "true".to_string()));
            }
            return hosted_passwords_ui_action_result(
                "export-vault",
                HOSTED_PASSWORDS_BULK_PLAINTEXT_HANDOFF_REASON,
                hosted_passwords_vault_action_url(vault.vault_id, "export", &query)?,
            );
        }
        let client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&client, params.vault_id).await?;
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let api_client = self.api_client_for_bearer(&bearer, &extensions)?;
        let listed = client
            .list_items(vault.vault_id, &vault.key)
            .await
            .map_err(vault_err)?;
        let mut items = Vec::with_capacity(listed.len());
        let include_attachments = !params.exclude_attachments.unwrap_or(false);
        let mut attachment_plan = Vec::new();
        let mut attachment_count = 0usize;
        let mut attachments_omitted_count = 0usize;
        let mut attachments_omitted_bytes = 0usize;
        for (item_id, _) in listed {
            let item = client
                .get_item(vault.vault_id, item_id, &vault.key)
                .await
                .map_err(vault_err)?;
            let metadata = serde_json::from_str::<serde_json::Value>(&item.metadata_json).ok();
            let sensitive = metadata_bool(metadata.as_ref(), "sensitive");
            let favorite = metadata_bool(metadata.as_ref(), "favorite");
            let item_index = items.len();
            items.push(serde_json::json!({
                "item_id": item.item_id,
                "title": item.title,
                "tags": item.tags,
                "sensitive": sensitive,
                "favorite": favorite,
                "content": item.content,
                "attachments": [],
            }));
            let attachments = passwords_gateway_data(
                api_client
                    .attachment_list(&vault.vault_id, &item.item_id)
                    .await,
            )
            .await?
            .data;
            let item_attachment_bytes = attachments
                .iter()
                .map(|attachment| usize::try_from(attachment.size_bytes.max(0)).unwrap_or(0))
                .sum::<usize>();
            if include_attachments {
                attachment_count += attachments.len();
                attachment_plan.push((item_index, item.item_id, attachments));
            } else {
                attachments_omitted_count += attachments.len();
                attachments_omitted_bytes += item_attachment_bytes;
            }
        }

        let mut exported_attachment_bytes = 0usize;
        for (item_index, item_id, attachments) in attachment_plan {
            let mut exported_attachments = Vec::with_capacity(attachments.len());
            for attachment in attachments {
                let attachment = passwords_gateway_data(
                    api_client
                        .attachment_get(&vault.vault_id, &item_id, &attachment.attachment_id)
                        .await,
                )
                .await?
                .data;
                let metadata =
                    decrypt_attachment_metadata_with_blob(&vault.key, item_id, &attachment)?;
                let plaintext = decrypt_attachment_blob(&vault.key, item_id, &attachment)?;
                exported_attachment_bytes += plaintext.len();
                exported_attachments.push(serde_json::json!({
                    "attachment_id": metadata.attachment_id,
                    "filename": metadata.filename,
                    "content_type": metadata.content_type,
                    "size_bytes": plaintext.len(),
                    "content_base64": BASE64.encode(&plaintext),
                }));
            }
            items[item_index]["attachments"] = serde_json::Value::Array(exported_attachments);
        }

        let output = serde_json::json!({
            "format": PASSWORDS_EXPORT_FORMAT,
            "version": PASSWORDS_EXPORT_VERSION,
            "vault": {
                "vault_id": vault.vault_id,
                "name": vault.name,
                "key_version": vault.key_version,
            },
            "attachments_included": include_attachments,
            "attachment_count": attachment_count,
            "attachment_bytes": exported_attachment_bytes,
            "attachments_omitted_count": attachments_omitted_count,
            "attachments_omitted_bytes": attachments_omitted_bytes,
            "items": items,
        });

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Import plaintext Seren Passwords items into a vault from passwords_vault_export JSON",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_vault_import(
        &self,
        Parameters(params): Parameters<PasswordsVaultImportParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        if !self.passwords_local_mode {
            let client = self.passwords_vault_client(&extensions).await?;
            let vault = select_vault(&client, params.vault_id).await?;
            return hosted_passwords_ui_action_result(
                "import-vault",
                HOSTED_PASSWORDS_BULK_PLAINTEXT_HANDOFF_REASON,
                hosted_passwords_vault_action_url(vault.vault_id, "import", &[])?,
            );
        }
        validate_passwords_import_metadata(&params)?;
        if params.items.is_empty() {
            return Err(McpError::invalid_params("items cannot be empty", None));
        }
        let client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&client, params.vault_id).await?;
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let api_client = self.api_client_for_bearer(&bearer, &extensions)?;
        let mut imported = Vec::with_capacity(params.items.len());
        for item in params.items {
            let title = item.title.trim().to_string();
            if title.is_empty() {
                return Err(McpError::invalid_params(
                    "import item title cannot be empty",
                    None,
                ));
            }
            let attachments = item.attachments.unwrap_or_default();
            let sensitive = item.sensitive.unwrap_or(false);
            let favorite = item.favorite.unwrap_or(false);
            let (content_value, attachments) =
                prepare_passwords_import_item_content(item.content, attachments);
            let content = serde_json::from_value::<ItemContent>(content_value)
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
            let item_kind = item_content_kind(&content);
            let tags = item.tags.unwrap_or_default();
            let item_id = client
                .create_item(
                    vault.vault_id,
                    &vault.key,
                    content,
                    &title,
                    &tags,
                    sensitive,
                    vault.key_version,
                )
                .await
                .map_err(vault_err)?;
            let upload = async {
                if favorite {
                    restore_imported_item_favorite(
                        &api_client,
                        &vault,
                        item_id,
                        item_kind,
                        sensitive,
                    )
                    .await?;
                }
                let mut imported_attachment_count = 0usize;
                for attachment in attachments {
                    let filename = attachment.filename.trim();
                    if filename.is_empty() {
                        return Err(McpError::invalid_params(
                            "import attachment filename cannot be empty",
                            None,
                        ));
                    }
                    let content_type = attachment.content_type.trim();
                    if content_type.is_empty() {
                        return Err(McpError::invalid_params(
                            "import attachment content_type cannot be empty",
                            None,
                        ));
                    }
                    let plaintext = Zeroizing::new(decode_passwords_b64_field(
                        "attachment.content_base64",
                        &attachment.content_base64,
                    )?);
                    if plaintext.len() != attachment.size_bytes {
                        return Err(McpError::invalid_params(
                            "import attachment size does not match content_base64",
                            None,
                        ));
                    }
                    upload_plaintext_attachment(
                        &api_client,
                        &vault,
                        item_id,
                        Some(attachment.attachment_id),
                        filename,
                        content_type,
                        &plaintext,
                    )
                    .await?;
                    imported_attachment_count += 1;
                }
                Ok::<usize, McpError>(imported_attachment_count)
            }
            .await;
            let imported_attachment_count = match upload {
                Ok(count) => count,
                Err(error) => {
                    cleanup_imported_item(&client, vault.vault_id, item_id).await;
                    return Err(error);
                }
            };
            imported.push(serde_json::json!({
                "item_id": item_id,
                "title": title,
                "attachment_count": imported_attachment_count,
            }));
        }
        let imported_attachment_count = imported
            .iter()
            .map(|item| {
                item.get("attachment_count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as usize
            })
            .sum::<usize>();

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &serde_json::json!({
                "vault_id": vault.vault_id,
                "imported_count": imported.len(),
                "attachment_count": imported_attachment_count,
                "items": imported,
            }),
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
        description = "Grant Seren Passwords vault membership. Local MCP user mode only; call passwords_unlock first",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_membership_grant(
        &self,
        Parameters(params): Parameters<PasswordsMembershipGrantParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        if !self.passwords_local_mode {
            let query = [
                ("identity_id", params.identity_id.to_string()),
                (
                    "access_level",
                    passwords_access_level_param(&params.access_level).to_string(),
                ),
            ];
            return hosted_passwords_ui_action_result(
                "grant-membership",
                HOSTED_PASSWORDS_SIGNING_HANDOFF_REASON,
                hosted_passwords_vault_action_url(params.vault_id, "grant-membership", &query)?,
            );
        }
        let (bearer, _, signing_private) = self.passwords_user_signing_auth(&extensions).await?;
        let vault_client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&vault_client, Some(params.vault_id)).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let identity = passwords_gateway_data(client.identity_get(&params.identity_id).await)
            .await?
            .data;
        let recipient_public =
            decode_kem_public_key_field("kem_public_key", &identity.kem_public_key)?;
        let access_level = seren::AccessLevel::from(params.access_level);
        let wrapped = wrap_vault_key_for_identity(&vault.key, &recipient_public);
        let granted_signature = membership_grant_signature(
            &signing_private,
            vault.vault_id,
            params.identity_id,
            access_level,
            &wrapped,
        );
        let result = passwords_gateway_data(
            client
                .membership_grant(
                    &vault.vault_id,
                    &seren::MembershipGrantRequest {
                        access_level,
                        granted_signature,
                        identity_id: params.identity_id,
                        wrapped_vault_key: BASE64.encode(wrapped),
                    },
                )
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
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
        description = "Complete a redeemed Seren Passwords invitation. Local MCP user mode only; call passwords_unlock first",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_invitation_complete(
        &self,
        Parameters(params): Parameters<PasswordsInvitationCompleteParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        if !self.passwords_local_mode {
            let query = [("invitation_id", params.invitation_id.to_string())];
            return hosted_passwords_ui_action_result(
                "complete-invitation",
                HOSTED_PASSWORDS_SIGNING_HANDOFF_REASON,
                hosted_passwords_vault_action_url(params.vault_id, "complete-invitation", &query)?,
            );
        }
        let (bearer, _, signing_private) = self.passwords_user_signing_auth(&extensions).await?;
        let vault_client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&vault_client, Some(params.vault_id)).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let invitations =
            passwords_gateway_data(client.invitation_list_for_vault(&vault.vault_id).await)
                .await?
                .data;
        let invitation = invitations
            .into_iter()
            .find(|invitation| invitation.invitation_id == params.invitation_id)
            .ok_or_else(|| McpError::invalid_request("Invitation is not available", None))?;
        let identity_id = invitation
            .redeemed_by_identity
            .ok_or_else(|| McpError::invalid_request("Invitation has not been redeemed", None))?;
        let identity = passwords_gateway_data(client.identity_get(&identity_id).await)
            .await?
            .data;
        let recipient_public =
            decode_kem_public_key_field("kem_public_key", &identity.kem_public_key)?;
        let wrapped = wrap_vault_key_for_identity(&vault.key, &recipient_public);
        let granted_signature = membership_grant_signature(
            &signing_private,
            vault.vault_id,
            identity_id,
            invitation.access_level,
            &wrapped,
        );
        let result = passwords_gateway_data(
            client
                .membership_grant(
                    &vault.vault_id,
                    &seren::MembershipGrantRequest {
                        access_level: invitation.access_level,
                        granted_signature,
                        identity_id,
                        wrapped_vault_key: BASE64.encode(wrapped),
                    },
                )
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
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
        description = "List decrypted attachment metadata for a Seren Passwords item",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_attachments_list(
        &self,
        Parameters(params): Parameters<PasswordsAttachmentListParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let vault_client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&vault_client, params.vault_id).await?;
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let attachments = passwords_gateway_data(
            client
                .attachment_list(&vault.vault_id, &params.item_id)
                .await,
        )
        .await?
        .data
        .into_iter()
        .map(|attachment| decrypt_attachment_metadata(&vault.key, params.item_id, &attachment))
        .collect::<Result<Vec<_>, _>>()?;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &attachments,
        )?]))
    }

    #[tool(
        description = "Encrypt and upload one attachment to a Seren Passwords item",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_attachment_upload(
        &self,
        Parameters(params): Parameters<PasswordsAttachmentUploadParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let vault_client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&vault_client, params.vault_id).await?;
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let plaintext = Zeroizing::new(decode_passwords_b64_field(
            "content_base64",
            &params.content_base64,
        )?);
        if plaintext.is_empty() {
            return Err(McpError::invalid_request(
                "Attachment content cannot be empty",
                None,
            ));
        }
        let filename = params.filename.trim();
        if filename.is_empty() {
            return Err(McpError::invalid_request(
                "Attachment filename cannot be empty",
                None,
            ));
        }
        let content_type = params
            .content_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("application/octet-stream");

        let metadata = upload_plaintext_attachment(
            &client,
            &vault,
            params.item_id,
            None,
            filename,
            content_type,
            &plaintext,
        )
        .await?;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &metadata,
        )?]))
    }

    #[tool(
        description = "Download and decrypt one Seren Passwords attachment as base64 content",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn passwords_attachment_download(
        &self,
        Parameters(params): Parameters<PasswordsAttachmentIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let vault_client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&vault_client, params.vault_id).await?;
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let attachment = passwords_gateway_data(
            client
                .attachment_get(&vault.vault_id, &params.item_id, &params.attachment_id)
                .await,
        )
        .await?
        .data;
        let metadata =
            decrypt_attachment_metadata_with_blob(&vault.key, params.item_id, &attachment)?;
        let plaintext = decrypt_attachment_blob(&vault.key, params.item_id, &attachment)?;
        let output = DecryptedAttachmentOutput {
            attachment: metadata,
            content_base64: BASE64.encode(&plaintext),
            content_bytes: plaintext.len(),
        };

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &output,
        )?]))
    }

    #[tool(
        description = "Delete one Seren Passwords attachment from an item",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn passwords_attachment_delete(
        &self,
        Parameters(params): Parameters<PasswordsAttachmentIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        crate::server::ensure_writes_allowed(&extensions)?;
        let vault_client = self.passwords_vault_client(&extensions).await?;
        let vault = select_vault(&vault_client, params.vault_id).await?;
        let (bearer, _) = self.passwords_vault_auth(&extensions).await?;
        let client = self.api_client_for_bearer(&bearer, &extensions)?;
        let result = passwords_gateway_data(
            client
                .attachment_delete(&vault.vault_id, &params.item_id, &params.attachment_id)
                .await,
        )
        .await?
        .data;

        Ok(CallToolResult::success(vec![crate::server::json_content(
            &result,
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
const HOSTED_PASSWORDS_SIGNING_HANDOFF_REASON: &str =
    "This action requires the account signing key, which hosted MCP does not hold.";
const HOSTED_PASSWORDS_BULK_PLAINTEXT_HANDOFF_REASON: &str = "Bulk plaintext import and export must be performed in the browser so hosted MCP does not receive whole-vault plaintext.";

fn hosted_passwords_consent_url(request_id: Uuid) -> Result<String, McpError> {
    let base = hosted_seren_passwords_url()?;
    Ok(format!("{base}/grant?request={request_id}"))
}

fn hosted_passwords_ui_action_result(
    action: &str,
    reason: &str,
    action_url: String,
) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![crate::server::json_content(
        &serde_json::json!({
            "status": "ui_action_required",
            "action": action,
            "reason": reason,
            "action_url": action_url,
        }),
    )?]))
}

fn hosted_passwords_home_action_url(
    action: &str,
    query: &[(&str, String)],
) -> Result<String, McpError> {
    hosted_passwords_ui_action_url("/", action, query)
}

fn hosted_passwords_vault_action_url(
    vault_id: Uuid,
    action: &str,
    query: &[(&str, String)],
) -> Result<String, McpError> {
    hosted_passwords_ui_action_url(&format!("/vault/{vault_id}"), action, query)
}

fn hosted_passwords_ui_action_url(
    path: &str,
    action: &str,
    query: &[(&str, String)],
) -> Result<String, McpError> {
    let base = hosted_seren_passwords_url()?;
    let mut url = reqwest::Url::parse(&base)
        .map_err(|e| McpError::internal_error(format!("Invalid passwords URL: {e}"), None))?;
    url.set_path(path);
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("action", action);
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

fn passwords_access_level_param(access_level: &PasswordsAccessLevel) -> &'static str {
    match access_level {
        PasswordsAccessLevel::Read => "read",
        PasswordsAccessLevel::Write => "write",
        PasswordsAccessLevel::Admin => "admin",
    }
}

fn vault_approval_mode_param(mode: &seren::VaultApprovalMode) -> &'static str {
    match mode {
        seren::VaultApprovalMode::Never => "never",
        seren::VaultApprovalMode::SensitiveOnly => "sensitive_only",
        seren::VaultApprovalMode::Always => "always",
    }
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
pub(crate) async fn read_master_password(
    master_password_file: Option<&Path>,
) -> Result<Zeroizing<Vec<u8>>, McpError> {
    if let Some(path) = master_password_file {
        let path = path.to_path_buf();
        let password = tokio::task::spawn_blocking(move || {
            let mut value = std::fs::read_to_string(&path).map_err(|e| {
                McpError::internal_error(
                    format!(
                        "failed to read master password file {}: {e}",
                        path.display()
                    ),
                    None,
                )
            })?;
            strip_one_terminal_newline(&mut value);
            if value.is_empty() {
                return Err(McpError::invalid_request(
                    format!("master password file {} is empty", path.display()),
                    None,
                ));
            }
            Ok(value)
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))??;
        return Ok(Zeroizing::new(password.into_bytes()));
    }

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
        "No master password source: set SEREN_PASSWORDS_MASTER_PASSWORD, start local MCP with --passwords-master-password-file, or run with an attached terminal.",
        None,
    ))
}

fn strip_one_terminal_newline(value: &mut String) {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    } else if value.ends_with('\r') {
        value.pop();
    }
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

fn decode_kem_public_key_field(
    field: &'static str,
    encoded: &str,
) -> Result<IdentityKemPublicKey, McpError> {
    let bytes = decode_passwords_b64_field(field, encoded)?;
    IdentityKemPublicKey::from_slice(&bytes)
        .map_err(|_| McpError::invalid_request(format!("Invalid {field}"), None))
}

fn decode_passwords_b64_field(field: &'static str, encoded: &str) -> Result<Vec<u8>, McpError> {
    BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| McpError::invalid_request(format!("Invalid base64 field {field}"), None))
}

fn validate_passwords_import_metadata(params: &PasswordsVaultImportParams) -> Result<(), McpError> {
    if let Some(format) = params.format.as_deref()
        && format != PASSWORDS_EXPORT_FORMAT
    {
        return Err(McpError::invalid_params(
            format!("unsupported import format: {format}"),
            None,
        ));
    }
    if let Some(version) = params.version
        && version != PASSWORDS_EXPORT_VERSION
    {
        return Err(McpError::invalid_params(
            format!("unsupported import version: {version}"),
            None,
        ));
    }
    let exported_count = params
        .items
        .iter()
        .map(|item| item.attachments.as_ref().map(Vec::len).unwrap_or(0))
        .sum::<usize>();
    let exported_bytes = params
        .items
        .iter()
        .flat_map(|item| item.attachments.as_deref().unwrap_or(&[]))
        .map(|attachment| attachment.size_bytes)
        .sum::<usize>();
    let mut seen_attachment_ids = HashSet::new();
    for attachment_id in params
        .items
        .iter()
        .flat_map(|item| item.attachments.as_deref().unwrap_or(&[]))
        .filter_map(|attachment| attachment.attachment_id)
    {
        if !seen_attachment_ids.insert(attachment_id) {
            return Err(McpError::invalid_params(
                format!("import contains duplicate attachment_id: {attachment_id}"),
                None,
            ));
        }
    }
    if !params.attachments_included.unwrap_or(true) && exported_count > 0 {
        return Err(McpError::invalid_params(
            "import metadata says attachments are excluded but attachments were found",
            None,
        ));
    }
    if let Some(declared_count) = params.attachment_count
        && declared_count != exported_count
    {
        return Err(McpError::invalid_params(
            "import attachment_count does not match items",
            None,
        ));
    }
    if let Some(declared_bytes) = params.attachment_bytes
        && declared_bytes != exported_bytes
    {
        return Err(McpError::invalid_params(
            "import attachment_bytes does not match items",
            None,
        ));
    }
    Ok(())
}

fn membership_grant_signature(
    signing_private: &IdentitySigningPrivateKey,
    vault_id: Uuid,
    identity_id: Uuid,
    access_level: seren::AccessLevel,
    wrapped_vault_key: &[u8],
) -> String {
    let access_level_byte = match access_level {
        seren::AccessLevel::Read => {
            seren_secrets_crypto::protocol::membership_grant::ACCESS_LEVEL_READ
        }
        seren::AccessLevel::Write => {
            seren_secrets_crypto::protocol::membership_grant::ACCESS_LEVEL_WRITE
        }
        seren::AccessLevel::Admin => {
            seren_secrets_crypto::protocol::membership_grant::ACCESS_LEVEL_ADMIN
        }
    };

    BASE64.encode(
        seren_secrets_crypto::protocol::membership_grant::sign_membership_grant(
            signing_private,
            vault_id.as_bytes(),
            identity_id.as_bytes(),
            access_level_byte,
            wrapped_vault_key,
        ),
    )
}

async fn build_rotation_complete_request(
    client: &seren::Client,
    vault_id: Uuid,
    rotation_token: Uuid,
    kem_private: &IdentityKemPrivateKey,
    signing_private: &IdentitySigningPrivateKey,
) -> Result<seren::RotationCompleteRequest, McpError> {
    let sync = passwords_gateway_data(client.sync_get().await).await?.data;
    let vault = sync
        .vaults
        .iter()
        .find(|vault| vault.vault_id == vault_id)
        .ok_or_else(|| McpError::invalid_request("Vault is not available", None))?;
    let old_wrapped_key = vault
        .wrapped_vault_key
        .as_deref()
        .ok_or_else(|| McpError::invalid_request("Vault response missing wrapped key", None))?;
    let old_vault_key = unwrap_vault_key(
        kem_private,
        &decode_passwords_b64_field("wrapped_vault_key", old_wrapped_key)?,
    )
    .map_err(|_| McpError::invalid_request("Could not unwrap current vault key", None))?;
    let new_vault_key = generate_vault_key();
    let identities = sync
        .identities
        .iter()
        .map(|identity| (identity.identity_id, identity))
        .collect::<std::collections::HashMap<_, _>>();

    let memberships = sync
        .memberships
        .iter()
        .filter(|membership| membership.vault_id == vault_id && membership.revoked_at.is_none())
        .map(|membership| {
            let identity = identities.get(&membership.identity_id).ok_or_else(|| {
                McpError::invalid_request(
                    format!("Identity {} is not visible", membership.identity_id),
                    None,
                )
            })?;
            let recipient_public =
                decode_kem_public_key_field("kem_public_key", &identity.kem_public_key)?;
            let wrapped = wrap_vault_key_for_identity(&new_vault_key, &recipient_public);
            Ok(seren::RotationMembershipDto {
                access_level: membership.access_level,
                granted_signature: membership_grant_signature(
                    signing_private,
                    vault_id,
                    membership.identity_id,
                    membership.access_level,
                    &wrapped,
                ),
                identity_id: membership.identity_id,
                wrapped_vault_key: BASE64.encode(wrapped),
            })
        })
        .collect::<Result<Vec<_>, McpError>>()?;
    if memberships.is_empty() {
        return Err(McpError::invalid_request(
            "Vault has no active memberships to rotate",
            None,
        ));
    }

    let mut items = Vec::new();
    let mut attachments = Vec::new();
    for state in [
        seren::ListStateParam::Active,
        seren::ListStateParam::Trashed,
    ] {
        let summaries =
            passwords_gateway_data(client.item_list(&vault_id, Some(state), None, None).await)
                .await?
                .data;
        for summary in summaries {
            let item = passwords_gateway_data(client.item_get(&vault_id, &summary.item_id).await)
                .await?
                .data;
            let item_id = item.item_id;
            let item_id_bytes = item_id.as_bytes();
            let title = decrypt_title(
                &old_vault_key,
                item_id_bytes,
                &decode_passwords_b64_field("title_ciphertext", &item.title_ciphertext)?,
            )
            .map_err(|_| McpError::invalid_request("Could not decrypt item title", None))?;
            let tags_ciphertext = item
                .tags_ciphertext
                .as_deref()
                .map(|tags| {
                    let tags = decrypt_tags(
                        &old_vault_key,
                        item_id_bytes,
                        &decode_passwords_b64_field("tags_ciphertext", tags)?,
                    )
                    .map_err(|_| McpError::invalid_request("Could not decrypt item tags", None))?;
                    encrypt_tags(&new_vault_key, item_id_bytes, &tags)
                        .map(|ciphertext| BASE64.encode(ciphertext))
                        .map_err(|_| McpError::internal_error("Could not encrypt item tags", None))
                })
                .transpose()?;
            let metadata_json = decrypt_metadata_json(
                &old_vault_key,
                item_id_bytes,
                &decode_passwords_b64_field("metadata_ciphertext", &item.metadata_ciphertext)?,
            )
            .map_err(|_| McpError::invalid_request("Could not decrypt item metadata", None))?;
            let content_key = unwrap_item_content_key(
                &old_vault_key,
                item_id_bytes,
                &decode_passwords_b64_field("content_key_wrap", &item.content_key_wrap)?,
            )
            .map_err(|_| McpError::invalid_request("Could not unwrap item content key", None))?;
            items.push(seren::RotationItemDto {
                content_key_wrap: BASE64.encode(wrap_item_content_key(
                    &new_vault_key,
                    item_id_bytes,
                    &content_key,
                )),
                item_id,
                metadata_ciphertext: BASE64.encode(encrypt_metadata_json(
                    &new_vault_key,
                    item_id_bytes,
                    &metadata_json,
                )),
                tags_ciphertext,
                title_blind_index: item.title_blind_index,
                title_ciphertext: BASE64.encode(encrypt_title(
                    &new_vault_key,
                    item_id_bytes,
                    &title,
                )),
            });

            let listed_attachments =
                passwords_gateway_data(client.attachment_list(&vault_id, &item_id).await)
                    .await?
                    .data;
            for attachment in listed_attachments {
                attachments.push(rewrap_attachment_for_rotation(
                    &old_vault_key,
                    &new_vault_key,
                    item_id,
                    &attachment,
                )?);
            }
        }
    }

    let vault_name = decrypt_vault_name(
        &old_vault_key,
        vault_id.as_bytes(),
        &decode_passwords_b64_field("name_ciphertext", &vault.name_ciphertext)?,
    )
    .map_err(|_| McpError::invalid_request("Could not decrypt vault name", None))?;
    let vault_description_ciphertext = vault
        .description_ciphertext
        .as_deref()
        .map(|description| {
            let description = decrypt_vault_description(
                &old_vault_key,
                vault_id.as_bytes(),
                &decode_passwords_b64_field("description_ciphertext", description)?,
            )
            .map_err(|_| McpError::invalid_request("Could not decrypt vault description", None))?;
            Ok(BASE64.encode(encrypt_vault_description(
                &new_vault_key,
                vault_id.as_bytes(),
                &description,
            )))
        })
        .transpose()?;

    Ok(seren::RotationCompleteRequest {
        attachments,
        items,
        memberships,
        rotation_token,
        vault_description_ciphertext,
        vault_name_ciphertext: BASE64.encode(encrypt_vault_name(
            &new_vault_key,
            vault_id.as_bytes(),
            &vault_name,
        )),
    })
}

fn decrypt_attachment_metadata(
    vault_key: &VaultKey,
    item_id: Uuid,
    attachment: &seren::AttachmentView,
) -> Result<DecryptedAttachmentMetadata, McpError> {
    decrypt_attachment_metadata_fields(
        vault_key,
        item_id,
        AttachmentMetadataFields {
            attachment_id: attachment.attachment_id,
            filename_ciphertext: &attachment.filename_ciphertext,
            content_type_ciphertext: &attachment.content_type_ciphertext,
            response_item_id: attachment.item_id,
            size_bytes: attachment.size_bytes,
            created_at: attachment.created_at,
        },
    )
}

fn decrypt_attachment_metadata_with_blob(
    vault_key: &VaultKey,
    item_id: Uuid,
    attachment: &seren::AttachmentWithBlobView,
) -> Result<DecryptedAttachmentMetadata, McpError> {
    decrypt_attachment_metadata_fields(
        vault_key,
        item_id,
        AttachmentMetadataFields {
            attachment_id: attachment.attachment_id,
            filename_ciphertext: &attachment.filename_ciphertext,
            content_type_ciphertext: &attachment.content_type_ciphertext,
            response_item_id: attachment.item_id,
            size_bytes: attachment.size_bytes,
            created_at: attachment.created_at,
        },
    )
}

fn decrypt_attachment_metadata_fields(
    vault_key: &VaultKey,
    item_id: Uuid,
    fields: AttachmentMetadataFields<'_>,
) -> Result<DecryptedAttachmentMetadata, McpError> {
    let item_id_bytes = item_id.as_bytes();
    let attachment_id_bytes = fields.attachment_id.as_bytes();
    let filename = decrypt_filename(
        vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("filename_ciphertext", fields.filename_ciphertext)?,
    )
    .map_err(|_| McpError::invalid_request("Could not decrypt attachment filename", None))?;
    let content_type = decrypt_content_type(
        vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("content_type_ciphertext", fields.content_type_ciphertext)?,
    )
    .map_err(|_| McpError::invalid_request("Could not decrypt attachment content type", None))?;

    Ok(DecryptedAttachmentMetadata {
        attachment_id: fields.attachment_id,
        item_id: fields.response_item_id,
        filename,
        content_type,
        size_bytes: fields.size_bytes,
        created_at: fields.created_at,
    })
}

fn decrypt_attachment_blob(
    vault_key: &VaultKey,
    item_id: Uuid,
    attachment: &seren::AttachmentWithBlobView,
) -> Result<Zeroizing<Vec<u8>>, McpError> {
    let attachment_id = attachment.attachment_id;
    let item_id_bytes = item_id.as_bytes();
    let attachment_id_bytes = attachment_id.as_bytes();
    let content_key = unwrap_attachment_key(
        vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("wrapped_content_key", &attachment.wrapped_content_key)?,
    )
    .map_err(|_| McpError::invalid_request("Could not unwrap attachment content key", None))?;
    Ok(Zeroizing::new(
        decrypt_blob(
            &content_key,
            item_id_bytes,
            attachment_id_bytes,
            &decode_passwords_b64_field("blob", &attachment.blob)?,
        )
        .map_err(|_| McpError::invalid_request("Could not decrypt attachment blob", None))?,
    ))
}

fn prepare_passwords_import_item_content(
    content: serde_json::Value,
    attachments: Vec<PasswordsImportAttachment>,
) -> (serde_json::Value, Vec<PasswordsPreparedImportAttachment>) {
    let mut id_map = HashMap::new();
    let attachments = attachments
        .into_iter()
        .map(|attachment| {
            let target_id = Uuid::new_v4();
            if let Some(source_id) = attachment.attachment_id {
                id_map.insert(source_id.to_string(), target_id.to_string());
            }
            PasswordsPreparedImportAttachment {
                attachment_id: target_id,
                filename: attachment.filename,
                content_type: attachment.content_type,
                size_bytes: attachment.size_bytes,
                content_base64: attachment.content_base64,
            }
        })
        .collect();
    (rewrite_attachment_references(content, &id_map), attachments)
}

fn metadata_bool(metadata: Option<&serde_json::Value>, field: &str) -> bool {
    metadata
        .and_then(|value| value.get(field))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn item_content_kind(content: &ItemContent) -> &'static str {
    match content {
        ItemContent::Login(_) => "login",
        ItemContent::SecureNote(_) => "secure_note",
        ItemContent::ApiCredential(_) => "api_credential",
        ItemContent::Identity(_) => "identity",
        ItemContent::Card(_) => "card",
        ItemContent::SshKey(_) => "ssh_key",
        ItemContent::Document(_) => "document",
        ItemContent::BankAccount(_) => "bank_account",
        ItemContent::Passport(_) => "passport",
        ItemContent::DriverLicense(_) => "driver_license",
        ItemContent::CryptoWallet(_) => "crypto_wallet",
        ItemContent::Server(_) => "server",
        ItemContent::Database(_) => "database",
    }
}

async fn restore_imported_item_favorite(
    client: &seren::Client,
    vault: &seren_secrets_resolver::vault::DecryptedVault,
    item_id: Uuid,
    item_kind: &str,
    sensitive: bool,
) -> Result<(), McpError> {
    let record = passwords_gateway_data(client.item_get(&vault.vault_id, &item_id).await)
        .await?
        .data;
    let metadata_json = format!(
        r#"{{"item_kind":"{item_kind}","favorite":true,"sensitive":{sensitive},"reprompt":false}}"#
    );
    let request = seren::UpdateItemRequest {
        content_ciphertext: record.content_ciphertext,
        content_key_wrap: record.content_key_wrap,
        metadata_ciphertext: BASE64.encode(encrypt_metadata_json(
            &vault.key,
            item_id.as_bytes(),
            &metadata_json,
        )),
        sensitive,
        tags_ciphertext: record.tags_ciphertext,
        title_blind_index: record.title_blind_index,
        title_ciphertext: record.title_ciphertext,
        wrapping_key_version: Some(vault.key_version),
    };
    passwords_gateway_data(
        client
            .item_update(&vault.vault_id, &item_id, None, &request)
            .await,
    )
    .await?;
    Ok(())
}

async fn cleanup_imported_item(
    client: &seren_secrets_resolver::VaultClient,
    vault_id: Uuid,
    item_id: Uuid,
) {
    // A second delete removes an already-trashed item, keeping failed imports
    // out of the trash.
    let _ = client.delete_item(vault_id, item_id).await;
    let _ = client.delete_item(vault_id, item_id).await;
}

fn rewrite_attachment_references(
    value: serde_json::Value,
    id_map: &HashMap<String, String>,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(value) => {
            serde_json::Value::String(rewrite_attachment_string(value, id_map))
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .into_iter()
                .map(|value| rewrite_attachment_references(value, id_map))
                .collect(),
        ),
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, rewrite_attachment_references(value, id_map)))
                .collect(),
        ),
        value => value,
    }
}

fn rewrite_attachment_string(value: String, id_map: &HashMap<String, String>) -> String {
    let mut rewritten = value;
    for (source_id, target_id) in id_map {
        rewritten = rewritten.replace(
            &format!("{ATTACHMENT_URI_SCHEME}{source_id}"),
            &format!("{ATTACHMENT_URI_SCHEME}{target_id}"),
        );
    }
    rewritten
}

async fn upload_plaintext_attachment(
    client: &seren::Client,
    vault: &seren_secrets_resolver::vault::DecryptedVault,
    item_id: Uuid,
    attachment_id: Option<Uuid>,
    filename: &str,
    content_type: &str,
    plaintext: &[u8],
) -> Result<DecryptedAttachmentMetadata, McpError> {
    let attachment_id = attachment_id.unwrap_or_else(Uuid::new_v4);
    let request = build_attachment_create_request(
        &vault.key,
        item_id,
        attachment_id,
        filename,
        content_type,
        plaintext,
    )?;
    let created = passwords_gateway_data(
        client
            .attachment_create(&vault.vault_id, &item_id, &request)
            .await,
    )
    .await?
    .data;
    decrypt_attachment_metadata(&vault.key, item_id, &created)
}

fn build_attachment_create_request(
    vault_key: &VaultKey,
    item_id: Uuid,
    attachment_id: Uuid,
    filename: &str,
    content_type: &str,
    plaintext: &[u8],
) -> Result<seren::CreateAttachmentRequest, McpError> {
    let attachment_key = generate_attachment_key();
    let item_id_bytes = item_id.as_bytes();
    let attachment_id_bytes = attachment_id.as_bytes();
    let encrypted_blob = encrypt_blob(
        &attachment_key,
        item_id_bytes,
        attachment_id_bytes,
        plaintext,
    );
    if encrypted_blob.len() > MAX_ATTACHMENT_CIPHERTEXT_BYTES {
        return Err(McpError::invalid_request(
            "Encrypted attachment exceeds the 100 MiB upload limit",
            None,
        ));
    }
    Ok(seren::CreateAttachmentRequest {
        attachment_id,
        blob: BASE64.encode(encrypted_blob),
        content_type_ciphertext: BASE64.encode(encrypt_content_type(
            vault_key,
            item_id_bytes,
            attachment_id_bytes,
            content_type,
        )),
        filename_ciphertext: BASE64.encode(encrypt_filename(
            vault_key,
            item_id_bytes,
            attachment_id_bytes,
            filename,
        )),
        wrapped_content_key: BASE64.encode(wrap_attachment_key(
            vault_key,
            item_id_bytes,
            attachment_id_bytes,
            &attachment_key,
        )),
    })
}

fn rewrap_attachment_for_rotation(
    old_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    item_id: Uuid,
    attachment: &seren::AttachmentView,
) -> Result<seren::RotationAttachmentDto, McpError> {
    let attachment_id = attachment.attachment_id;
    let item_id_bytes = item_id.as_bytes();
    let attachment_id_bytes = attachment_id.as_bytes();
    let filename = decrypt_filename(
        old_vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("filename_ciphertext", &attachment.filename_ciphertext)?,
    )
    .map_err(|_| McpError::invalid_request("Could not decrypt attachment filename", None))?;
    let content_type = decrypt_content_type(
        old_vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field(
            "content_type_ciphertext",
            &attachment.content_type_ciphertext,
        )?,
    )
    .map_err(|_| McpError::invalid_request("Could not decrypt attachment content type", None))?;
    let attachment_key = unwrap_attachment_key(
        old_vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("wrapped_content_key", &attachment.wrapped_content_key)?,
    )
    .map_err(|_| McpError::invalid_request("Could not unwrap attachment content key", None))?;

    Ok(seren::RotationAttachmentDto {
        attachment_id,
        content_type_ciphertext: BASE64.encode(encrypt_content_type(
            new_vault_key,
            item_id_bytes,
            attachment_id_bytes,
            &content_type,
        )),
        filename_ciphertext: BASE64.encode(encrypt_filename(
            new_vault_key,
            item_id_bytes,
            attachment_id_bytes,
            &filename,
        )),
        wrapped_content_key: BASE64.encode(wrap_attachment_key(
            new_vault_key,
            item_id_bytes,
            attachment_id_bytes,
            &attachment_key,
        )),
    })
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
    fn membership_grant_signature_uses_canonical_access_bytes() {
        let signing_private = IdentitySigningPrivateKey::from_slice(&[7; 32]).unwrap();
        let signing_public = IdentitySigningKeypair::from_private(signing_private.clone()).public;
        let vault_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let identity_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let wrapped_vault_key = [3, 4, 5, 6];

        for (access_level, access_level_byte) in [
            (
                seren::AccessLevel::Read,
                seren_secrets_crypto::protocol::membership_grant::ACCESS_LEVEL_READ,
            ),
            (
                seren::AccessLevel::Write,
                seren_secrets_crypto::protocol::membership_grant::ACCESS_LEVEL_WRITE,
            ),
            (
                seren::AccessLevel::Admin,
                seren_secrets_crypto::protocol::membership_grant::ACCESS_LEVEL_ADMIN,
            ),
        ] {
            let signature = membership_grant_signature(
                &signing_private,
                vault_id,
                identity_id,
                access_level,
                &wrapped_vault_key,
            );
            let signature = BASE64.decode(signature).unwrap();
            let mut payload = b"seren-secrets/membership-grant".to_vec();
            payload.extend_from_slice(vault_id.as_bytes());
            payload.extend_from_slice(identity_id.as_bytes());
            payload.push(access_level_byte);
            payload.extend_from_slice(&wrapped_vault_key);

            seren_secrets_crypto::signing::verify(&signing_public, &payload, &signature).unwrap();
        }
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
    fn rewrap_attachment_for_rotation_preserves_decryptability_under_new_key() {
        use seren_secrets_crypto::protocol::vault::generate_vault_key;

        let old_vault_key = generate_vault_key();
        let new_vault_key = generate_vault_key();
        let item_id = Uuid::new_v4();
        let attachment_id = Uuid::new_v4();
        let attachment_key = generate_attachment_key();
        let plaintext = b"attachment-bytes".to_vec();
        // The blob stays encrypted under the unchanged attachment key across
        // rotation; only the wrapped key + metadata are re-encrypted.
        let blob = encrypt_blob(
            &attachment_key,
            item_id.as_bytes(),
            attachment_id.as_bytes(),
            &plaintext,
        );

        let created_at: jiff::Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();
        let view = seren::AttachmentView {
            attachment_id,
            content_type_ciphertext: BASE64.encode(encrypt_content_type(
                &old_vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                "text/plain",
            )),
            created_at,
            filename_ciphertext: BASE64.encode(encrypt_filename(
                &old_vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                "secret.txt",
            )),
            item_id,
            size_bytes: blob.len() as i64,
            wrapped_content_key: BASE64.encode(wrap_attachment_key(
                &old_vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                &attachment_key,
            )),
        };

        let dto =
            rewrap_attachment_for_rotation(&old_vault_key, &new_vault_key, item_id, &view).unwrap();

        assert_eq!(
            decrypt_filename(
                &new_vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                &BASE64.decode(dto.filename_ciphertext).unwrap(),
            )
            .unwrap(),
            "secret.txt"
        );
        assert_eq!(
            decrypt_content_type(
                &new_vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                &BASE64.decode(dto.content_type_ciphertext).unwrap(),
            )
            .unwrap(),
            "text/plain"
        );
        let recovered_key = unwrap_attachment_key(
            &new_vault_key,
            item_id.as_bytes(),
            attachment_id.as_bytes(),
            &BASE64.decode(dto.wrapped_content_key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decrypt_blob(
                &recovered_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                &blob,
            )
            .unwrap(),
            plaintext
        );
    }

    #[test]
    fn attachment_create_request_preserves_supplied_attachment_id() {
        use seren_secrets_crypto::protocol::vault::generate_vault_key;

        let vault_key = generate_vault_key();
        let item_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let attachment_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let plaintext = b"linked-document-bytes";

        let request = build_attachment_create_request(
            &vault_key,
            item_id,
            attachment_id,
            "document.pdf",
            "application/pdf",
            plaintext,
        )
        .unwrap();

        assert_eq!(request.attachment_id, attachment_id);
        assert_eq!(
            decrypt_filename(
                &vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                &BASE64.decode(&request.filename_ciphertext).unwrap(),
            )
            .unwrap(),
            "document.pdf"
        );
        assert_eq!(
            decrypt_content_type(
                &vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                &BASE64.decode(&request.content_type_ciphertext).unwrap(),
            )
            .unwrap(),
            "application/pdf"
        );
        let recovered_key = unwrap_attachment_key(
            &vault_key,
            item_id.as_bytes(),
            attachment_id.as_bytes(),
            &BASE64.decode(&request.wrapped_content_key).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decrypt_blob(
                &recovered_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                &BASE64.decode(&request.blob).unwrap(),
            )
            .unwrap(),
            plaintext
        );
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
    fn hosted_action_url_preserves_query_parameters() {
        temp_env::with_var(
            PASSWORDS_URL_ENV,
            Some("https://passwords.example.com"),
            || {
                let vault_id = Uuid::nil();
                let url = hosted_passwords_vault_action_url(
                    vault_id,
                    "export",
                    &[("exclude_attachments", "true".to_string())],
                )
                .unwrap();

                assert_eq!(
                    url,
                    format!(
                        "https://passwords.example.com/vault/{vault_id}?action=export&exclude_attachments=true"
                    )
                );
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

    #[test]
    fn import_metadata_accepts_supported_plaintext_item_exports() {
        let params = PasswordsVaultImportParams {
            vault_id: Some(Uuid::new_v4()),
            format: Some(PASSWORDS_EXPORT_FORMAT.to_string()),
            version: Some(PASSWORDS_EXPORT_VERSION),
            attachments_included: Some(false),
            attachment_count: Some(0),
            attachment_bytes: Some(0),
            items: vec![PasswordsImportItem {
                title: "Example".to_string(),
                tags: Some(vec!["team".to_string()]),
                sensitive: Some(true),
                favorite: Some(true),
                content: serde_json::json!({
                    "type": "secure_note",
                    "text": "example"
                }),
                attachments: None,
            }],
        };

        validate_passwords_import_metadata(&params).unwrap();
        assert_eq!(params.items[0].favorite, Some(true));

        let params = PasswordsVaultImportParams {
            vault_id: Some(Uuid::new_v4()),
            format: Some(PASSWORDS_EXPORT_FORMAT.to_string()),
            version: Some(PASSWORDS_EXPORT_VERSION),
            attachments_included: Some(true),
            attachment_count: Some(1),
            attachment_bytes: Some(7),
            items: vec![PasswordsImportItem {
                title: "Example".to_string(),
                tags: Some(vec!["team".to_string()]),
                sensitive: Some(true),
                favorite: Some(true),
                content: serde_json::json!({
                    "type": "secure_note",
                    "text": "example"
                }),
                attachments: Some(vec![PasswordsImportAttachment {
                    attachment_id: Some(Uuid::new_v4()),
                    filename: "example.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    size_bytes: 7,
                    content_base64: "ZXhhbXBsZQ==".to_string(),
                }]),
            }],
        };

        validate_passwords_import_metadata(&params).unwrap();
        assert_eq!(params.items[0].favorite, Some(true));
    }

    #[test]
    fn import_preparation_remaps_attachment_references() {
        let source_id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
        let content = serde_json::json!({
            "type": "document",
            "attachment_uri": format!("{ATTACHMENT_URI_SCHEME}{source_id}"),
            "doc": {
                "content": [
                    {
                        "attrs": {
                            "src": format!("{ATTACHMENT_URI_SCHEME}{source_id}")
                        }
                    }
                ]
            }
        });
        let (content, attachments) = prepare_passwords_import_item_content(
            content,
            vec![PasswordsImportAttachment {
                attachment_id: Some(source_id),
                filename: "doc.pdf".to_string(),
                content_type: "application/pdf".to_string(),
                size_bytes: 7,
                content_base64: "ZXhhbXBsZQ==".to_string(),
            }],
        );

        let target_id = attachments[0].attachment_id;
        assert_ne!(target_id, source_id);
        assert_eq!(
            content["attachment_uri"],
            format!("{ATTACHMENT_URI_SCHEME}{target_id}")
        );
        assert_eq!(
            content["doc"]["content"][0]["attrs"]["src"],
            format!("{ATTACHMENT_URI_SCHEME}{target_id}")
        );
    }

    #[test]
    fn metadata_bool_parses_item_flags() {
        let metadata = serde_json::json!({
            "favorite": true,
            "sensitive": false
        });
        assert!(metadata_bool(Some(&metadata), "favorite"));
        assert!(!metadata_bool(Some(&metadata), "sensitive"));
        assert!(!metadata_bool(Some(&metadata), "reprompt"));
        assert!(!metadata_bool(None, "favorite"));
    }

    #[test]
    fn import_metadata_rejects_unsupported_exports() {
        let mut params = PasswordsVaultImportParams {
            vault_id: None,
            format: Some(PASSWORDS_EXPORT_FORMAT.to_string()),
            version: Some(PASSWORDS_EXPORT_VERSION),
            attachments_included: Some(false),
            attachment_count: Some(0),
            attachment_bytes: Some(0),
            items: Vec::new(),
        };

        params.items = vec![PasswordsImportItem {
            title: "Example".to_string(),
            tags: None,
            sensitive: None,
            favorite: None,
            content: serde_json::json!({
                "type": "secure_note",
                "text": "example"
            }),
            attachments: Some(vec![PasswordsImportAttachment {
                attachment_id: None,
                filename: "example.txt".to_string(),
                content_type: "text/plain".to_string(),
                size_bytes: 7,
                content_base64: "ZXhhbXBsZQ==".to_string(),
            }]),
        }];
        assert!(validate_passwords_import_metadata(&params).is_err());

        params.items.clear();
        params.attachment_count = Some(1);
        assert!(validate_passwords_import_metadata(&params).is_err());

        params.attachment_count = Some(2);
        params.attachment_bytes = Some(14);
        params.attachments_included = Some(true);
        params.items = vec![PasswordsImportItem {
            title: "Example".to_string(),
            tags: None,
            sensitive: None,
            favorite: None,
            content: serde_json::json!({
                "type": "secure_note",
                "text": "example"
            }),
            attachments: Some(vec![
                PasswordsImportAttachment {
                    attachment_id: Some(
                        Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
                    ),
                    filename: "one.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    size_bytes: 7,
                    content_base64: "ZXhhbXBsZQ==".to_string(),
                },
                PasswordsImportAttachment {
                    attachment_id: Some(
                        Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
                    ),
                    filename: "two.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    size_bytes: 7,
                    content_base64: "ZXhhbXBsZQ==".to_string(),
                },
            ]),
        }];
        assert!(validate_passwords_import_metadata(&params).is_err());

        params.items.clear();
        params.attachments_included = Some(false);
        params.attachment_count = Some(0);
        params.attachment_bytes = Some(0);
        params.version = Some(PASSWORDS_EXPORT_VERSION + 1);
        assert!(validate_passwords_import_metadata(&params).is_err());

        params.version = Some(PASSWORDS_EXPORT_VERSION);
        params.format = Some("other-format".to_string());
        assert!(validate_passwords_import_metadata(&params).is_err());
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

    #[tokio::test]
    async fn read_master_password_reads_file_and_strips_one_newline() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "hunter2").unwrap();
        let value = read_master_password(Some(file.path())).await.unwrap();
        assert_eq!(value.as_slice(), b"hunter2".as_slice());
    }

    #[tokio::test]
    async fn read_master_password_rejects_empty_file() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file).unwrap();
        let err = read_master_password(Some(file.path())).await.unwrap_err();
        assert!(err.message.contains("empty"));
    }
}
