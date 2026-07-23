use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use colored::Colorize;
use etcetera::base_strategy::{BaseStrategy, choose_base_strategy};
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
    SecureNoteContent, decrypt_metadata_json, decrypt_tags, decrypt_title,
    encrypt_item_with_content_key, encrypt_metadata_json, encrypt_tags, encrypt_title,
    unwrap_item_content_key, wrap_item_content_key,
};
use seren_secrets_crypto::protocol::vault::{
    decrypt_vault_description, decrypt_vault_invitation_email, decrypt_vault_name,
    encrypt_vault_description, encrypt_vault_invitation_email, encrypt_vault_name,
    generate_vault_key, unwrap_vault_key, wrap_vault_key_for_identity,
};
use seren_secrets_resolver::{
    VaultClient, VaultClientConfig, VaultKeySource, create_agent_identity,
    fetch_master_password_key_source, grant_membership, revoke_agent_identity, revoke_membership,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::commands::auth::get_bearer_token;
use crate::{CommandContext, OutputFormat, output};

const SEREN_PASSWORDS_PUBLISHER_SLUG: &str = "seren-passwords";
const MAX_ATTACHMENT_CIPHERTEXT_BYTES: usize = 100 * 1024 * 1024;
const MIN_MASTER_PASSWORD_LEN: usize = 8;
const PASSWORDS_EXPORT_FORMAT: &str = "seren-passwords-mcp-export";
const PASSWORDS_EXPORT_VERSION: u32 = 1;
const ATTACHMENT_URI_SCHEME: &str = "seren-secrets://attachment/";

#[derive(Clone)]
pub struct PasswordsOptions {
    pub master_password: Option<Zeroizing<String>>,
}

impl PasswordsOptions {
    pub fn from_input(
        master_password_stdin: bool,
        master_password_file: Option<&Path>,
    ) -> Result<Self> {
        Ok(Self {
            master_password: master_password_from_input(
                master_password_stdin,
                master_password_file,
            )?,
        })
    }
}

pub struct PasswordGenerateOptions {
    pub mode: String,
    pub length: Option<u32>,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub word_count: u32,
    pub separator: char,
    pub capitalize_first: bool,
}

#[derive(Clone)]
pub struct AgentProvisionOptions {
    pub vault: String,
    pub access: String,
    pub name: String,
    /// Days until the minted agent API key expires; `None` mints a
    /// non-expiring key (a warning is emitted in that case).
    pub expires_in_days: Option<u32>,
}

#[derive(Clone)]
pub struct LoginCreateOptions {
    pub vault_id: Option<Uuid>,
    pub title: String,
    pub username: String,
    pub password: Option<String>,
    pub password_stdin: bool,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub sensitive: bool,
}

#[derive(Clone)]
pub struct ApiCredentialCreateOptions {
    pub vault_id: Option<Uuid>,
    pub title: String,
    pub key: Option<String>,
    pub key_stdin: bool,
    pub credential_kind: String,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub sensitive: bool,
}

#[derive(Clone)]
pub struct SecureNoteCreateOptions {
    pub vault_id: Option<Uuid>,
    pub title: String,
    pub body: Option<String>,
    pub body_stdin: bool,
    pub tags: Vec<String>,
    pub sensitive: bool,
}

#[derive(Clone)]
pub struct ItemUpdateOptions {
    pub vault_id: Option<Uuid>,
    pub item_id: Uuid,
    pub title: Option<String>,
    pub tags: Option<Vec<String>>,
    pub sensitive: Option<bool>,
    pub password: Option<String>,
    pub password_stdin: bool,
    pub username: Option<String>,
    pub urls: Option<Vec<String>>,
    pub key: Option<String>,
    pub key_stdin: bool,
    pub credential_kind: Option<String>,
    pub body: Option<String>,
    pub body_stdin: bool,
    pub notes: Option<String>,
}

#[derive(Clone)]
pub struct PasswordAuditListOptions {
    pub action: Option<String>,
    pub actor_identity_id: Option<Uuid>,
    pub target_kind: Option<String>,
    pub target_id: Option<Uuid>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Clone)]
pub struct VaultUpdateOptions {
    pub master_password: Option<Zeroizing<String>>,
    pub vault_id: Uuid,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone)]
pub struct VaultCreateOptions {
    pub master_password: Option<Zeroizing<String>>,
    pub name: String,
    pub description: Option<String>,
    pub requires_approval: Option<seren::VaultApprovalMode>,
}

#[derive(Clone)]
pub struct VaultRotationCancelOptions {
    pub vault_id: Uuid,
    pub rotation_token: Uuid,
}

#[derive(Clone)]
pub struct VaultRotationCompleteOptions {
    pub master_password: Option<Zeroizing<String>>,
    pub vault_id: Uuid,
    pub rotation_token: Option<Uuid>,
}

#[derive(Clone)]
pub struct MembershipGrantOptions {
    pub master_password: Option<Zeroizing<String>>,
    pub vault_id: Uuid,
    pub identity_id: Uuid,
    pub access_level: seren::AccessLevel,
}

#[derive(Clone)]
pub struct MembershipAccessUpdateOptions {
    pub master_password: Option<Zeroizing<String>>,
    pub vault_id: Uuid,
    pub identity_id: Uuid,
    pub access_level: seren::AccessLevel,
}

#[derive(Clone)]
pub struct InvitationCreateOptions {
    pub master_password: Option<Zeroizing<String>>,
    pub vault_id: Uuid,
    pub email: String,
    pub access_level: seren::AccessLevel,
    pub expires_in_hours: Option<i64>,
}

#[derive(Clone)]
pub struct InvitationCompleteOptions {
    pub master_password: Option<Zeroizing<String>>,
    pub vault_id: Uuid,
    pub invitation_id: Uuid,
}

#[derive(Debug, serde::Serialize)]
struct CreatedItemOutput {
    vault_id: Uuid,
    item_id: Uuid,
    item_kind: String,
    reference: String,
}

#[derive(Debug, serde::Serialize)]
struct VaultOutput {
    vault_id: Uuid,
    name: String,
    vault_key_version: i32,
}

#[derive(Debug, serde::Serialize)]
struct ItemSummaryOutput {
    item_id: Uuid,
    title: String,
}

#[derive(Debug, serde::Serialize)]
struct ItemDetailOutput {
    item_id: Uuid,
    title: String,
    tags: Vec<String>,
    item_kind: String,
    revealed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<serde_json::Value>,
}

#[derive(Debug, serde::Serialize)]
struct DeletedItemOutput {
    vault_id: Uuid,
    item_id: Uuid,
    deleted: bool,
}

#[derive(Debug, serde::Serialize)]
struct RestoredItemOutput {
    vault_id: Uuid,
    item_id: Uuid,
    restored: bool,
}

#[derive(Debug, serde::Serialize)]
struct CopiedItemOutput {
    source_vault_id: Uuid,
    source_item_id: Uuid,
    target_vault_id: Uuid,
    item_id: Uuid,
    copied: bool,
}

#[derive(Debug, serde::Serialize)]
struct MovedItemOutput {
    source_vault_id: Uuid,
    source_item_id: Uuid,
    target_vault_id: Uuid,
    item_id: Uuid,
    moved: bool,
}

#[derive(Debug, serde::Serialize)]
struct UpdatedItemOutput {
    vault_id: Uuid,
    item_id: Uuid,
    updated: bool,
}

pub async fn list_vaults(options: PasswordsOptions, ctx: &CommandContext) -> Result<()> {
    let client = build_vault_client(options, ctx).await?;
    let vaults = client
        .list_vaults()
        .await?
        .into_iter()
        .map(|vault| VaultOutput {
            vault_id: vault.vault_id,
            name: vault.name,
            vault_key_version: vault.key_version,
        })
        .collect::<Vec<_>>();

    match ctx.format {
        OutputFormat::Json => output::print_json(&vaults)?,
        OutputFormat::Table => {
            if vaults.is_empty() {
                println!("No password vaults found");
            } else {
                let rows = vaults
                    .iter()
                    .map(|vault| {
                        (
                            vault.name.as_str(),
                            format!(
                                "{} (key version {})",
                                vault.vault_id, vault.vault_key_version
                            ),
                        )
                    })
                    .collect::<Vec<_>>();
                output::print_key_value_table(Some("Password vaults"), &rows);
            }
        }
    }

    Ok(())
}

pub async fn archive_vault(vault_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let result = passwords_gateway_data(
        client.vault_archive(&vault_id).await,
        "failed to archive password vault",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => println!(
            "{}",
            format!("Archived password vault {vault_id}").green().bold()
        ),
    }

    Ok(())
}

pub async fn update_vault(options: VaultUpdateOptions, ctx: &CommandContext) -> Result<()> {
    if options.name.is_none() && options.description.is_none() {
        bail!("pass --name, --description, or both");
    }

    let vault_client = build_vault_client(
        PasswordsOptions {
            master_password: options.master_password,
        },
        ctx,
    )
    .await?;
    let vault = select_vault(&vault_client, Some(options.vault_id)).await?;

    let mut patch = seren::VaultPatchRequest {
        name_ciphertext: None,
        description_ciphertext: None,
    };
    if let Some(name) = options.name {
        let name = name.trim();
        if name.is_empty() {
            bail!("--name cannot be empty");
        }
        patch.name_ciphertext = Some(BASE64.encode(encrypt_vault_name(
            &vault.key,
            vault.vault_id.as_bytes(),
            name,
        )));
    }
    if let Some(description) = options.description {
        patch.description_ciphertext = Some(BASE64.encode(encrypt_vault_description(
            &vault.key,
            vault.vault_id.as_bytes(),
            description.trim(),
        )));
    }

    let client = passwords_api_client(ctx).await?;
    let result = passwords_gateway_data(
        client.vault_update(&vault.vault_id, &patch).await,
        "failed to update password vault",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => println!(
            "{}",
            format!("Updated password vault {}", vault.vault_id)
                .green()
                .bold()
        ),
    }

    Ok(())
}

pub async fn create_vault(options: VaultCreateOptions, ctx: &CommandContext) -> Result<()> {
    let name = options.name.trim();
    if name.is_empty() {
        bail!("--name cannot be empty");
    }

    let (_passwords_base_url, _bearer, key_source) = build_vault_key_source(
        PasswordsOptions {
            master_password: options.master_password,
        },
        ctx,
    )
    .await?;
    let signing_private = account_signing_private_from_key_source(&key_source)?;
    let client = passwords_api_client(ctx).await?;
    let identity = passwords_gateway_data(
        client.identity_get_me().await,
        "failed to load password identity",
    )?
    .data;
    let identity_public = decode_kem_public_key_field("kem_public_key", &identity.kem_public_key)?;
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
    let description = options.description.as_deref().map(str::trim);
    let description_ciphertext = description.filter(|value| !value.is_empty()).map(|value| {
        BASE64.encode(encrypt_vault_description(
            &vault_key,
            vault_id.as_bytes(),
            value,
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
                requires_approval: options.requires_approval,
                vault_id,
            })
            .await,
        "failed to create password vault",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => output::print_key_value_table(
            Some("Created password vault"),
            &[
                ("Vault ID", vault_id.to_string()),
                ("Name", name.to_string()),
            ],
        ),
    }

    Ok(())
}

pub async fn vault_rotation_initiate(vault_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let response = passwords_gateway_data(
        client.vault_rotation_initiate(&vault_id).await,
        "failed to start password vault key rotation",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => output::print_key_value_table(
            Some("Started password vault key rotation"),
            &[
                ("Vault ID", response.vault_id.to_string()),
                ("Rotation token", response.rotation_token.to_string()),
            ],
        ),
    }

    Ok(())
}

pub async fn vault_rotation_cancel(
    options: VaultRotationCancelOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let response = passwords_gateway_data(
        client
            .vault_rotation_cancel(
                &options.vault_id,
                &seren::RotationCancelRequest {
                    rotation_token: options.rotation_token,
                },
            )
            .await,
        "failed to cancel password vault key rotation",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => println!(
            "{}",
            format!(
                "Cancelled password vault key rotation {}",
                options.rotation_token
            )
            .green()
            .bold()
        ),
    }

    Ok(())
}

pub async fn vault_rotation_complete(
    options: VaultRotationCompleteOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let (_, _, key_source) = build_vault_key_source(
        PasswordsOptions {
            master_password: options.master_password,
        },
        ctx,
    )
    .await?;
    let signing_private = account_signing_private_from_key_source(&key_source)?;
    let kem_private = key_source
        .kem_private()
        .context("could not unlock vault key source")?
        .into_owned();
    let client = passwords_api_client(ctx).await?;
    let initiated_here = options.rotation_token.is_none();
    let rotation_token = match options.rotation_token {
        Some(token) => token,
        None => {
            passwords_gateway_data(
                client.vault_rotation_initiate(&options.vault_id).await,
                "failed to start password vault key rotation",
            )?
            .data
            .rotation_token
        }
    };

    let complete_result = build_rotation_complete_request(
        &client,
        options.vault_id,
        rotation_token,
        &kem_private,
        &signing_private,
    )
    .await;

    let body = match complete_result {
        Ok(body) => body,
        Err(error) => {
            if initiated_here {
                let _ = client
                    .vault_rotation_cancel(
                        &options.vault_id,
                        &seren::RotationCancelRequest { rotation_token },
                    )
                    .await;
            }
            return Err(error);
        }
    };
    let response = match passwords_gateway_data(
        client
            .vault_rotation_complete(&options.vault_id, &body)
            .await,
        "failed to complete password vault key rotation",
    ) {
        Ok(response) => response.data,
        Err(error) => {
            if initiated_here {
                let _ = client
                    .vault_rotation_cancel(
                        &options.vault_id,
                        &seren::RotationCancelRequest { rotation_token },
                    )
                    .await;
            }
            return Err(error);
        }
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => println!(
            "{}",
            format!("Completed password vault key rotation {}", rotation_token)
                .green()
                .bold()
        ),
    }

    Ok(())
}

pub async fn list_items(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, vault_id).await?;
    let items = client
        .list_items(vault.vault_id, &vault.key)
        .await?
        .into_iter()
        .map(|(item_id, title)| ItemSummaryOutput { item_id, title })
        .collect::<Vec<_>>();

    match ctx.format {
        OutputFormat::Json => output::print_json(&items)?,
        OutputFormat::Table => {
            if items.is_empty() {
                println!("No items found");
            } else {
                let owned = items
                    .iter()
                    .map(|item| (item.item_id.to_string(), item.title.clone()))
                    .collect::<Vec<_>>();
                let rows = owned
                    .iter()
                    .map(|(item_id, title)| (item_id.as_str(), title.clone()))
                    .collect::<Vec<_>>();
                output::print_key_value_table(Some("Items"), &rows);
            }
        }
    }

    Ok(())
}

pub async fn get_item(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    item_id: Uuid,
    reveal: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, vault_id).await?;
    let item = client.get_item(vault.vault_id, item_id, &vault.key).await?;

    let item_kind = serde_json::from_str::<serde_json::Value>(&item.metadata_json)
        .ok()
        .and_then(|value| {
            value
                .get("item_kind")
                .and_then(|kind| kind.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());

    let content = if reveal {
        Some(serde_json::to_value(&item.content)?)
    } else {
        None
    };

    let detail = ItemDetailOutput {
        item_id: item.item_id,
        title: item.title.clone(),
        tags: item.tags.clone(),
        item_kind,
        revealed: reveal,
        content,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&detail)?,
        OutputFormat::Table => {
            output::print_key_value_table(
                Some("Item"),
                &[
                    ("Item ID", detail.item_id.to_string()),
                    ("Title", detail.title.clone()),
                    ("Tags", detail.tags.join(", ")),
                    ("Kind", detail.item_kind.clone()),
                ],
            );
            if reveal {
                println!("{}", serde_json::to_string_pretty(&item.content)?);
            }
        }
    }

    Ok(())
}

pub async fn delete_item(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    item_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, vault_id).await?;
    client.delete_item(vault.vault_id, item_id).await?;

    let output = DeletedItemOutput {
        vault_id: vault.vault_id,
        item_id,
        deleted: true,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("Deleted item {} from vault {}", item_id, vault.name)
                    .green()
                    .bold()
            );
        }
    }

    Ok(())
}

pub async fn restore_item(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    item_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, vault_id).await?;
    client.restore_item(vault.vault_id, item_id).await?;

    let output = RestoredItemOutput {
        vault_id: vault.vault_id,
        item_id,
        restored: true,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("Restored item {} to vault {}", item_id, vault.name)
                    .green()
                    .bold()
            );
        }
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct DecryptedAttachmentMetadata {
    attachment_id: Uuid,
    item_id: Uuid,
    filename: String,
    content_type: String,
    size_bytes: i64,
    created_at: jiff::Timestamp,
}

#[derive(serde::Serialize)]
struct DownloadedAttachmentOutput {
    vault_id: Uuid,
    item_id: Uuid,
    attachment_id: Uuid,
    filename: String,
    content_type: String,
    size_bytes: usize,
    output: String,
}

#[derive(serde::Serialize)]
struct UploadedAttachmentOutput {
    vault_id: Uuid,
    item_id: Uuid,
    attachment_id: Uuid,
    filename: String,
    content_type: String,
    size_bytes: i64,
}

#[derive(serde::Serialize)]
struct PasswordsVaultExport {
    format: &'static str,
    version: u32,
    vault: PasswordsVaultExportVault,
    attachments_included: bool,
    attachment_count: usize,
    attachment_bytes: usize,
    attachments_omitted_count: usize,
    attachments_omitted_bytes: usize,
    items: Vec<PasswordsVaultExportItem>,
}

#[derive(serde::Serialize)]
struct PasswordsVaultExportVault {
    vault_id: Uuid,
    name: String,
    key_version: i32,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct PasswordsVaultExportItem {
    #[serde(default)]
    item_id: Option<Uuid>,
    title: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    sensitive: bool,
    #[serde(default)]
    favorite: bool,
    content: serde_json::Value,
    #[serde(default)]
    attachments: Vec<PasswordsVaultExportAttachment>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct PasswordsVaultExportAttachment {
    #[serde(default)]
    attachment_id: Option<Uuid>,
    filename: String,
    content_type: String,
    size_bytes: usize,
    content_base64: String,
}

struct PasswordsPreparedImportAttachment {
    attachment_id: Uuid,
    filename: String,
    content_type: String,
    size_bytes: usize,
    content_base64: String,
}

#[derive(serde::Deserialize)]
struct PasswordsVaultImport {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    attachments_included: Option<bool>,
    #[serde(default)]
    attachment_count: Option<usize>,
    #[serde(default)]
    attachment_bytes: Option<usize>,
    items: Vec<PasswordsVaultExportItem>,
}

#[derive(serde::Serialize)]
struct PasswordsVaultImportOutput {
    vault_id: Uuid,
    imported_count: usize,
    attachment_count: usize,
    items: Vec<PasswordsVaultImportedItem>,
}

#[derive(serde::Serialize)]
struct PasswordsVaultImportedItem {
    item_id: Uuid,
    title: String,
    attachment_count: usize,
}

struct AttachmentMetadataFields<'a> {
    attachment_id: Uuid,
    filename_ciphertext: &'a str,
    content_type_ciphertext: &'a str,
    response_item_id: Uuid,
    size_bytes: i64,
    created_at: jiff::Timestamp,
}

pub async fn attachment_upload(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    item_id: Uuid,
    path: std::path::PathBuf,
    filename: Option<String>,
    content_type: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let vault_client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&vault_client, vault_id).await?;
    let plaintext = Zeroizing::new(
        std::fs::read(&path).with_context(|| format!("could not read {}", path.display()))?,
    );
    if plaintext.is_empty() {
        bail!("attachment file is empty");
    }
    let filename = match filename {
        Some(value) => value,
        None => path
            .file_name()
            .and_then(|name| name.to_str())
            .context("could not infer filename from --path; pass --filename")?
            .to_string(),
    };
    let filename = filename.trim();
    if filename.is_empty() {
        bail!("attachment filename cannot be empty");
    }
    let content_type = content_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("application/octet-stream");

    let client = passwords_api_client(ctx).await?;
    let metadata = upload_plaintext_attachment(
        &client,
        &vault,
        item_id,
        None,
        filename,
        content_type,
        &plaintext,
    )
    .await?;
    let output = UploadedAttachmentOutput {
        vault_id: vault.vault_id,
        item_id,
        attachment_id: metadata.attachment_id,
        filename: metadata.filename,
        content_type: metadata.content_type,
        size_bytes: metadata.size_bytes,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => output::print_key_value_table(
            Some("Uploaded password attachment"),
            &[
                ("Attachment ID", output.attachment_id.to_string()),
                ("Filename", output.filename),
                ("Content type", output.content_type),
                ("Bytes", output.size_bytes.to_string()),
            ],
        ),
    }

    Ok(())
}

async fn upload_plaintext_attachment(
    client: &seren::Client,
    vault: &seren_secrets_resolver::vault::DecryptedVault,
    item_id: Uuid,
    attachment_id: Option<Uuid>,
    filename: &str,
    content_type: &str,
    plaintext: &[u8],
) -> Result<DecryptedAttachmentMetadata> {
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
        "failed to upload password item attachment",
    )?
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
) -> Result<seren::CreateAttachmentRequest> {
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
        bail!("encrypted attachment exceeds the 100 MiB upload limit");
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

pub async fn attachment_list(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    item_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let vault_client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&vault_client, vault_id).await?;
    let client = passwords_api_client(ctx).await?;
    let attachments = passwords_gateway_data(
        client.attachment_list(&vault.vault_id, &item_id).await,
        "failed to list password item attachments",
    )?
    .data
    .into_iter()
    .map(|attachment| decrypt_attachment_metadata(&vault.key, item_id, &attachment))
    .collect::<Result<Vec<_>>>()?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&attachments)?,
        OutputFormat::Table => {
            if attachments.is_empty() {
                println!("No password item attachments found");
            } else {
                let rows = attachments
                    .iter()
                    .map(|attachment| {
                        format!(
                            "{} | {} | {} | {} bytes",
                            attachment.attachment_id,
                            attachment.filename,
                            attachment.content_type,
                            attachment.size_bytes
                        )
                    })
                    .collect::<Vec<_>>();
                output::print_list_table(Some("Password item attachments"), "Attachment", &rows);
            }
        }
    }

    Ok(())
}

pub async fn attachment_download(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    item_id: Uuid,
    attachment_id: Uuid,
    output_path: std::path::PathBuf,
    ctx: &CommandContext,
) -> Result<()> {
    let vault_client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&vault_client, vault_id).await?;
    let client = passwords_api_client(ctx).await?;
    let attachment = passwords_gateway_data(
        client
            .attachment_get(&vault.vault_id, &item_id, &attachment_id)
            .await,
        "failed to download password item attachment",
    )?
    .data;
    let metadata = decrypt_attachment_metadata_with_blob(&vault.key, item_id, &attachment)?;
    let plaintext = decrypt_attachment_blob(&vault.key, item_id, &attachment)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .with_context(|| format!("could not create {}", output_path.display()))?;
    file.write_all(&plaintext)
        .with_context(|| format!("could not write {}", output_path.display()))?;

    let output = DownloadedAttachmentOutput {
        vault_id: vault.vault_id,
        item_id,
        attachment_id,
        filename: metadata.filename,
        content_type: metadata.content_type,
        size_bytes: plaintext.len(),
        output: output_path.display().to_string(),
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => output::print_key_value_table(
            Some("Downloaded password attachment"),
            &[
                ("Attachment ID", output.attachment_id.to_string()),
                ("Filename", output.filename),
                ("Content type", output.content_type),
                ("Bytes", output.size_bytes.to_string()),
                ("Output", output.output),
            ],
        ),
    }

    Ok(())
}

pub async fn attachment_delete(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    item_id: Uuid,
    attachment_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let vault_client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&vault_client, vault_id).await?;
    let client = passwords_api_client(ctx).await?;
    let result = passwords_gateway_data(
        client
            .attachment_delete(&vault.vault_id, &item_id, &attachment_id)
            .await,
        "failed to delete password item attachment",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => println!(
            "{}",
            format!("Deleted attachment {attachment_id} from item {item_id}")
                .green()
                .bold()
        ),
    }

    Ok(())
}

pub async fn export_vault(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    output_path: std::path::PathBuf,
    exclude_attachments: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, vault_id).await?;
    let api_client = passwords_api_client(ctx).await?;
    let listed = client.list_items(vault.vault_id, &vault.key).await?;
    let mut items = Vec::with_capacity(listed.len());
    let mut attachment_plan = Vec::new();
    let include_attachments = !exclude_attachments;
    let mut attachment_count = 0usize;
    let mut attachment_bytes = 0usize;
    let mut attachments_omitted_count = 0usize;
    let mut attachments_omitted_bytes = 0usize;
    for (item_id, _) in listed {
        let item = client.get_item(vault.vault_id, item_id, &vault.key).await?;
        let metadata = serde_json::from_str::<serde_json::Value>(&item.metadata_json).ok();
        let sensitive = metadata_bool(metadata.as_ref(), "sensitive");
        let favorite = metadata_bool(metadata.as_ref(), "favorite");
        let item_index = items.len();
        items.push(PasswordsVaultExportItem {
            item_id: Some(item.item_id),
            title: item.title,
            tags: item.tags,
            sensitive,
            favorite,
            content: serde_json::to_value(item.content)?,
            attachments: Vec::new(),
        });
        let attachments = passwords_gateway_data(
            api_client
                .attachment_list(&vault.vault_id, &item.item_id)
                .await,
            "failed to list password item attachments for export",
        )?
        .data;
        let item_attachment_bytes = attachments
            .iter()
            .map(|attachment| usize::try_from(attachment.size_bytes.max(0)).unwrap_or(0))
            .sum::<usize>();
        if include_attachments {
            attachment_count += attachments.len();
            attachment_bytes += item_attachment_bytes;
            attachment_plan.push((item_index, item.item_id, attachments));
        } else {
            attachments_omitted_count += attachments.len();
            attachments_omitted_bytes += item_attachment_bytes;
        }
    }

    if include_attachments && attachment_count > 0 && matches!(ctx.format, OutputFormat::Table) {
        eprintln!(
            "warning: export will include {} attachments totaling about {} before base64 encoding",
            attachment_count,
            format_bytes(attachment_bytes),
        );
    } else if !include_attachments
        && attachments_omitted_count > 0
        && matches!(ctx.format, OutputFormat::Table)
    {
        eprintln!(
            "warning: export will omit {} attachments totaling about {}",
            attachments_omitted_count,
            format_bytes(attachments_omitted_bytes),
        );
    }

    let mut exported_attachment_bytes = 0usize;
    for (item_index, item_id, attachments) in attachment_plan {
        let mut exported_attachments = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            let attachment = passwords_gateway_data(
                api_client
                    .attachment_get(&vault.vault_id, &item_id, &attachment.attachment_id)
                    .await,
                "failed to download password item attachment for export",
            )?
            .data;
            let metadata = decrypt_attachment_metadata_with_blob(&vault.key, item_id, &attachment)?;
            let plaintext = decrypt_attachment_blob(&vault.key, item_id, &attachment)?;
            exported_attachment_bytes += plaintext.len();
            exported_attachments.push(PasswordsVaultExportAttachment {
                attachment_id: Some(metadata.attachment_id),
                filename: metadata.filename,
                content_type: metadata.content_type,
                size_bytes: plaintext.len(),
                content_base64: BASE64.encode(&plaintext),
            });
        }
        items[item_index].attachments = exported_attachments;
    }

    let export = PasswordsVaultExport {
        format: PASSWORDS_EXPORT_FORMAT,
        version: PASSWORDS_EXPORT_VERSION,
        vault: PasswordsVaultExportVault {
            vault_id: vault.vault_id,
            name: vault.name,
            key_version: vault.key_version,
        },
        attachments_included: include_attachments,
        attachment_count,
        attachment_bytes: exported_attachment_bytes,
        attachments_omitted_count,
        attachments_omitted_bytes,
        items,
    };
    let file = create_plaintext_export_file(&output_path)?;
    let mut writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &export)
        .with_context(|| format!("could not write {}", output_path.display()))?;
    writer
        .write_all(b"\n")
        .with_context(|| format!("could not write {}", output_path.display()))?;
    writer
        .flush()
        .with_context(|| format!("could not write {}", output_path.display()))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&serde_json::json!({
            "vault_id": export.vault.vault_id,
            "exported_count": export.items.len(),
            "attachments_included": export.attachments_included,
            "attachment_count": export.attachment_count,
            "attachment_bytes": export.attachment_bytes,
            "attachments_omitted_count": export.attachments_omitted_count,
            "attachments_omitted_bytes": export.attachments_omitted_bytes,
            "output": output_path.display().to_string(),
        }))?,
        OutputFormat::Table => output::print_key_value_table(
            Some("Exported password vault"),
            &[
                ("Vault ID", export.vault.vault_id.to_string()),
                ("Items", export.items.len().to_string()),
                (
                    "Attachments included",
                    export.attachments_included.to_string(),
                ),
                ("Attachments", export.attachment_count.to_string()),
                ("Attachment bytes", format_bytes(export.attachment_bytes)),
                (
                    "Attachments omitted",
                    export.attachments_omitted_count.to_string(),
                ),
                (
                    "Omitted attachment bytes",
                    format_bytes(export.attachments_omitted_bytes),
                ),
                ("Output", output_path.display().to_string()),
            ],
        ),
    }

    Ok(())
}

pub async fn import_vault(
    options: PasswordsOptions,
    vault_id: Option<Uuid>,
    input_path: std::path::PathBuf,
    ctx: &CommandContext,
) -> Result<()> {
    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, vault_id).await?;
    let api_client = passwords_api_client(ctx).await?;
    let file = std::fs::File::open(&input_path)
        .with_context(|| format!("could not open {}", input_path.display()))?;
    let import: PasswordsVaultImport = serde_json::from_reader(file)
        .with_context(|| format!("could not parse {}", input_path.display()))?;
    validate_passwords_import_metadata(&import)?;
    if import.items.is_empty() {
        bail!("import file contains no items");
    }

    let mut imported = Vec::with_capacity(import.items.len());
    for item in import.items {
        let title = item.title.trim().to_string();
        if title.is_empty() {
            bail!("import item title cannot be empty");
        }
        let tags = item.tags;
        let sensitive = item.sensitive;
        let favorite = item.favorite;
        let (content_value, attachments) =
            prepare_passwords_import_item_content(item.content, item.attachments);
        let content: ItemContent = serde_json::from_value(content_value)
            .context("could not parse exported item content")?;
        let item_kind = item_content_kind(&content);
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
            .await?;
        let upload = async {
            if favorite {
                restore_imported_item_favorite(&api_client, &vault, item_id, item_kind, sensitive)
                    .await?;
            }
            let mut imported_attachment_count = 0usize;
            for attachment in attachments {
                let filename = attachment.filename.trim();
                if filename.is_empty() {
                    bail!("import attachment filename cannot be empty");
                }
                let content_type = attachment.content_type.trim();
                if content_type.is_empty() {
                    bail!("import attachment content_type cannot be empty");
                }
                let plaintext = Zeroizing::new(decode_passwords_b64_field(
                    "attachment.content_base64",
                    &attachment.content_base64,
                )?);
                if plaintext.len() != attachment.size_bytes {
                    bail!(
                        "import attachment {} size mismatch",
                        attachment.attachment_id
                    );
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
            Ok::<usize, anyhow::Error>(imported_attachment_count)
        }
        .await;
        let imported_attachment_count = match upload {
            Ok(count) => count,
            Err(error) => {
                cleanup_imported_item(&client, vault.vault_id, item_id).await;
                return Err(error);
            }
        };
        imported.push(PasswordsVaultImportedItem {
            item_id,
            title,
            attachment_count: imported_attachment_count,
        });
    }

    let imported_attachment_count = imported
        .iter()
        .map(|item| item.attachment_count)
        .sum::<usize>();
    let output = PasswordsVaultImportOutput {
        vault_id: vault.vault_id,
        imported_count: imported.len(),
        attachment_count: imported_attachment_count,
        items: imported,
    };
    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => output::print_key_value_table(
            Some("Imported password vault items"),
            &[
                ("Vault ID", output.vault_id.to_string()),
                ("Items", output.imported_count.to_string()),
                ("Attachments", output.attachment_count.to_string()),
            ],
        ),
    }

    Ok(())
}

fn create_plaintext_export_file(path: &std::path::Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("could not create {}", path.display()))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("could not lock down {}", path.display()))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        eprintln!(
            "warning: export file {} is protected only by default filesystem permissions on this platform; keep plaintext password exports on a single-user host",
            path.display()
        );
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("could not create {}", path.display()))
    }
}

fn prepare_passwords_import_item_content(
    content: serde_json::Value,
    attachments: Vec<PasswordsVaultExportAttachment>,
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
) -> Result<()> {
    let record = passwords_gateway_data(
        client.item_get(&vault.vault_id, &item_id).await,
        "failed to load imported password item",
    )?
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
        "failed to restore imported password item flags",
    )?;
    Ok(())
}

async fn cleanup_imported_item(client: &VaultClient, vault_id: Uuid, item_id: Uuid) {
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

fn validate_passwords_import_metadata(import: &PasswordsVaultImport) -> Result<()> {
    if let Some(format) = import.format.as_deref()
        && format != PASSWORDS_EXPORT_FORMAT
    {
        bail!("unsupported import format: {format}");
    }
    if let Some(version) = import.version
        && version != PASSWORDS_EXPORT_VERSION
    {
        bail!("unsupported import version: {version}");
    }
    if !import.attachments_included.unwrap_or(true)
        && import.items.iter().any(|item| !item.attachments.is_empty())
    {
        bail!("import metadata says attachments are excluded but attachments were found");
    }
    let exported_count = import
        .items
        .iter()
        .map(|item| item.attachments.len())
        .sum::<usize>();
    let exported_bytes = import
        .items
        .iter()
        .flat_map(|item| &item.attachments)
        .map(|attachment| attachment.size_bytes)
        .sum::<usize>();
    let mut seen_attachment_ids = HashSet::new();
    for attachment_id in import
        .items
        .iter()
        .flat_map(|item| &item.attachments)
        .filter_map(|attachment| attachment.attachment_id)
    {
        if !seen_attachment_ids.insert(attachment_id) {
            bail!("import contains duplicate attachment_id: {attachment_id}");
        }
    }
    if let Some(declared_count) = import.attachment_count
        && declared_count != exported_count
    {
        bail!("import attachment_count does not match items");
    }
    if let Some(declared_bytes) = import.attachment_bytes
        && declared_bytes != exported_bytes
    {
        bail!("import attachment_bytes does not match items");
    }
    Ok(())
}

fn format_bytes(bytes: usize) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes_f = bytes as f64;
    if bytes_f >= GIB {
        format!("{:.1} GiB", bytes_f / GIB)
    } else if bytes_f >= MIB {
        format!("{:.1} MiB", bytes_f / MIB)
    } else if bytes_f >= KIB {
        format!("{:.1} KiB", bytes_f / KIB)
    } else {
        format!("{bytes} bytes")
    }
}

pub async fn copy_item(
    options: PasswordsOptions,
    source_vault_id: Option<Uuid>,
    item_id: Uuid,
    target_vault_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let vault_client = build_vault_client(options, ctx).await?;
    let api_client = passwords_api_client(ctx).await?;
    let source = select_vault(&vault_client, source_vault_id).await?;
    let target = select_vault(&vault_client, Some(target_vault_id)).await?;
    ensure_distinct_transfer_vaults(source.vault_id, target.vault_id)?;
    let new_item_id =
        duplicate_item_via_api(&api_client, &vault_client, &source, item_id, &target).await?;

    let output = CopiedItemOutput {
        source_vault_id: source.vault_id,
        source_item_id: item_id,
        target_vault_id: target.vault_id,
        item_id: new_item_id,
        copied: true,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!(
                    "Copied item {} from vault {} to vault {} as {}",
                    item_id, source.name, target.name, new_item_id
                )
                .green()
                .bold()
            );
        }
    }

    Ok(())
}

pub async fn move_item(
    options: PasswordsOptions,
    source_vault_id: Option<Uuid>,
    item_id: Uuid,
    target_vault_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let vault_client = build_vault_client(options, ctx).await?;
    let api_client = passwords_api_client(ctx).await?;
    let source = select_vault(&vault_client, source_vault_id).await?;
    let target = select_vault(&vault_client, Some(target_vault_id)).await?;
    ensure_distinct_transfer_vaults(source.vault_id, target.vault_id)?;
    let moved_item_id =
        move_item_via_api(&api_client, &vault_client, &source, item_id, &target).await?;

    let output = MovedItemOutput {
        source_vault_id: source.vault_id,
        source_item_id: item_id,
        target_vault_id: target.vault_id,
        item_id: moved_item_id,
        moved: true,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!(
                    "Moved item {} from vault {} to vault {} as {}",
                    item_id, source.name, target.name, moved_item_id
                )
                .green()
                .bold()
            );
        }
    }

    Ok(())
}

async fn duplicate_item_via_api(
    api_client: &seren::Client,
    vault_client: &VaultClient,
    source: &seren_secrets_resolver::vault::DecryptedVault,
    item_id: Uuid,
    target: &seren_secrets_resolver::vault::DecryptedVault,
) -> Result<Uuid> {
    let item = vault_client
        .get_item(source.vault_id, item_id, &source.key)
        .await?;
    let record = fetch_password_item_record(api_client, source.vault_id, item_id).await?;
    ensure_item_record_matches(&record, source.vault_id, item_id)?;
    let content_key = unwrap_item_content_key(
        &source.key,
        item_id.as_bytes(),
        &decode_passwords_b64_field("content_key_wrap", &record.content_key_wrap)?,
    )
    .context("could not unwrap item content key")?;
    let new_item_id = Uuid::new_v4();
    let (attachments, attachment_id_map) =
        duplicate_item_attachments(api_client, source, item_id, target, new_item_id).await?;

    let mut content = item.content;
    if !attachment_id_map.is_empty() {
        let content_value =
            serde_json::to_value(&content).context("could not serialize item content")?;
        let rewritten = rewrite_attachment_references(content_value, &attachment_id_map);
        content =
            serde_json::from_value(rewritten).context("could not rewrite attachment references")?;
    }

    let request = seren::DuplicateItemRequest {
        attachments,
        content_ciphertext: BASE64.encode(
            encrypt_item_with_content_key(&content_key, new_item_id.as_bytes(), &content)
                .context("could not encrypt duplicated item content")?,
        ),
        content_key_wrap: BASE64.encode(wrap_item_content_key(
            &target.key,
            new_item_id.as_bytes(),
            &content_key,
        )),
        item_id: new_item_id,
        metadata_ciphertext: BASE64.encode(encrypt_metadata_json(
            &target.key,
            new_item_id.as_bytes(),
            &item.metadata_json,
        )),
        tags_ciphertext: encrypt_tags_for_transfer(&target.key, new_item_id, &item.tags)?,
        target_vault_id: Some(target.vault_id),
        title_blind_index: String::new(),
        title_ciphertext: BASE64.encode(encrypt_title(
            &target.key,
            new_item_id.as_bytes(),
            &item.title,
        )),
        wrapping_key_version: Some(target.key_version),
    };

    let created = passwords_gateway_data(
        api_client
            .item_duplicate(&source.vault_id, &item_id, &request)
            .await,
        "failed to duplicate password item",
    )?
    .data;
    if created.item_id != new_item_id || created.vault_id != target.vault_id {
        bail!("password item duplicate response did not match requested destination");
    }
    Ok(created.item_id)
}

async fn move_item_via_api(
    api_client: &seren::Client,
    vault_client: &VaultClient,
    source: &seren_secrets_resolver::vault::DecryptedVault,
    item_id: Uuid,
    target: &seren_secrets_resolver::vault::DecryptedVault,
) -> Result<Uuid> {
    let item = vault_client
        .get_item(source.vault_id, item_id, &source.key)
        .await?;
    let record = fetch_password_item_record(api_client, source.vault_id, item_id).await?;
    ensure_item_record_matches(&record, source.vault_id, item_id)?;
    let content_key = unwrap_item_content_key(
        &source.key,
        item_id.as_bytes(),
        &decode_passwords_b64_field("content_key_wrap", &record.content_key_wrap)?,
    )
    .context("could not unwrap item content key")?;
    let attachments = move_item_attachments(api_client, source, item_id, target).await?;

    let request = seren::MoveItemRequest {
        attachments,
        content_key_wrap: BASE64.encode(wrap_item_content_key(
            &target.key,
            item_id.as_bytes(),
            &content_key,
        )),
        metadata_ciphertext: BASE64.encode(encrypt_metadata_json(
            &target.key,
            item_id.as_bytes(),
            &item.metadata_json,
        )),
        tags_ciphertext: encrypt_tags_for_transfer(&target.key, item_id, &item.tags)?,
        target_vault_id: target.vault_id,
        title_blind_index: String::new(),
        title_ciphertext: BASE64.encode(encrypt_title(
            &target.key,
            item_id.as_bytes(),
            &item.title,
        )),
        wrapping_key_version: Some(target.key_version),
    };

    let moved = passwords_gateway_data(
        api_client
            .item_move(&source.vault_id, &item_id, &request)
            .await,
        "failed to move password item",
    )?
    .data;
    if moved.item_id != item_id || moved.vault_id != target.vault_id {
        bail!("password item move response did not match requested destination");
    }
    Ok(moved.item_id)
}

async fn fetch_password_item_record(
    api_client: &seren::Client,
    vault_id: Uuid,
    item_id: Uuid,
) -> Result<seren::ItemRecord> {
    Ok(passwords_gateway_data(
        api_client.item_get(&vault_id, &item_id).await,
        "failed to fetch password item",
    )?
    .data)
}

fn ensure_item_record_matches(
    record: &seren::ItemRecord,
    expected_vault_id: Uuid,
    expected_item_id: Uuid,
) -> Result<()> {
    if record.vault_id != expected_vault_id || record.item_id != expected_item_id {
        bail!("password item response did not match requested item");
    }
    Ok(())
}

async fn duplicate_item_attachments(
    api_client: &seren::Client,
    source: &seren_secrets_resolver::vault::DecryptedVault,
    source_item_id: Uuid,
    target: &seren_secrets_resolver::vault::DecryptedVault,
    target_item_id: Uuid,
) -> Result<(
    Vec<seren::DuplicateItemAttachmentRequest>,
    HashMap<String, String>,
)> {
    let attachments = passwords_gateway_data(
        api_client
            .attachment_list(&source.vault_id, &source_item_id)
            .await,
        "failed to list password item attachments",
    )?
    .data;
    let mut requests = Vec::with_capacity(attachments.len());
    let mut id_map = HashMap::with_capacity(attachments.len());

    for attachment in attachments {
        let source_attachment_id = attachment.attachment_id;
        let attachment_with_blob = passwords_gateway_data(
            api_client
                .attachment_get(&source.vault_id, &source_item_id, &source_attachment_id)
                .await,
            "failed to fetch password item attachment",
        )?
        .data;
        let metadata = decrypt_attachment_metadata_with_blob(
            &source.key,
            source_item_id,
            &attachment_with_blob,
        )?;
        let plaintext =
            decrypt_attachment_blob(&source.key, source_item_id, &attachment_with_blob)?;
        let target_attachment_id = Uuid::new_v4();
        let create_request = build_attachment_create_request(
            &target.key,
            target_item_id,
            target_attachment_id,
            &metadata.filename,
            &metadata.content_type,
            &plaintext,
        )?;
        id_map.insert(
            source_attachment_id.to_string(),
            target_attachment_id.to_string(),
        );
        requests.push(seren::DuplicateItemAttachmentRequest {
            attachment_id: target_attachment_id,
            blob: create_request.blob,
            content_type_ciphertext: create_request.content_type_ciphertext,
            filename_ciphertext: create_request.filename_ciphertext,
            source_attachment_id,
            wrapped_content_key: create_request.wrapped_content_key,
        });
    }

    Ok((requests, id_map))
}

async fn move_item_attachments(
    api_client: &seren::Client,
    source: &seren_secrets_resolver::vault::DecryptedVault,
    item_id: Uuid,
    target: &seren_secrets_resolver::vault::DecryptedVault,
) -> Result<Vec<seren::MoveItemAttachmentRequest>> {
    let attachments = passwords_gateway_data(
        api_client.attachment_list(&source.vault_id, &item_id).await,
        "failed to list password item attachments",
    )?
    .data;
    attachments
        .iter()
        .map(|attachment| {
            let rewrapped =
                rewrap_attachment_for_rotation(&source.key, &target.key, item_id, attachment)?;
            Ok(seren::MoveItemAttachmentRequest {
                attachment_id: rewrapped.attachment_id,
                content_type_ciphertext: rewrapped.content_type_ciphertext,
                filename_ciphertext: rewrapped.filename_ciphertext,
                wrapped_content_key: rewrapped.wrapped_content_key,
            })
        })
        .collect()
}

fn encrypt_tags_for_transfer(
    vault_key: &VaultKey,
    item_id: Uuid,
    tags: &[String],
) -> Result<Option<String>> {
    if tags.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            BASE64.encode(
                encrypt_tags(vault_key, item_id.as_bytes(), tags)
                    .context("could not encrypt password item tags")?,
            ),
        ))
    }
}

fn ensure_distinct_transfer_vaults(source_vault_id: Uuid, target_vault_id: Uuid) -> Result<()> {
    if source_vault_id == target_vault_id {
        bail!("target vault must be different from source vault");
    }
    Ok(())
}

fn optional_uuid(value: Option<Uuid>) -> String {
    value
        .map(|id| id.to_string())
        .unwrap_or_else(|| "(none)".to_string())
}

pub async fn update_item(
    options: PasswordsOptions,
    update: ItemUpdateOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let password_supplied = update.password.is_some() || update.password_stdin;
    let key_supplied = update.key.is_some() || update.key_stdin;
    let body_supplied = update.body.is_some() || update.body_stdin;

    let stdin_count = [update.password_stdin, update.key_stdin, update.body_stdin]
        .into_iter()
        .filter(|set| *set)
        .count();
    if stdin_count > 1 {
        bail!("only one secret may be read from stdin per invocation");
    }

    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, update.vault_id).await?;
    let item = client
        .get_item(vault.vault_id, update.item_id, &vault.key)
        .await?;

    let title = update.title.unwrap_or(item.title);

    let tags = update.tags.unwrap_or(item.tags);

    let sensitive = match update.sensitive {
        Some(value) => value,
        None => serde_json::from_str::<serde_json::Value>(&item.metadata_json)
            .ok()
            .and_then(|value| value.get("sensitive").and_then(serde_json::Value::as_bool))
            .unwrap_or(false),
    };

    let mut content = item.content;
    match &mut content {
        ItemContent::Login(login) => {
            if let Some(username) = update.username {
                login.username = username;
            }
            if password_supplied {
                login.password = read_secret_input(
                    update.password,
                    update.password_stdin,
                    "Password",
                    "missing password; pass --password or --password-stdin",
                )?;
            }
            if let Some(urls) = update.urls {
                login.urls = urls.into_iter().map(LoginUrl::from).collect();
            }
            if let Some(notes) = update.notes {
                let (doc, text) = prose::from_plaintext(&notes);
                login.notes = doc;
                login.notes_text = text;
            }
            if key_supplied {
                bail!("--key is only valid for api-credential items");
            }
            if body_supplied {
                bail!("--body is only valid for secure-note items");
            }
            if update.credential_kind.is_some() {
                bail!("--credential-kind is only valid for api-credential items");
            }
        }
        ItemContent::ApiCredential(cred) => {
            if key_supplied {
                cred.primary_value = read_secret_input(
                    update.key,
                    update.key_stdin,
                    "API key",
                    "missing API key; pass --key or --key-stdin",
                )?;
            }
            if let Some(kind) = update.credential_kind {
                cred.kind = api_credential_kind(&kind)?;
            }
            if let Some(notes) = update.notes {
                let (doc, text) = prose::from_plaintext(&notes);
                cred.notes = doc;
                cred.notes_text = text;
            }
            if password_supplied {
                bail!("--password is only valid for login items");
            }
            if update.username.is_some() {
                bail!("--username is only valid for login items");
            }
            if update.urls.is_some() {
                bail!("--url is only valid for login items");
            }
            if body_supplied {
                bail!("--body is only valid for secure-note items");
            }
        }
        ItemContent::SecureNote(note) => {
            if body_supplied {
                let body = read_text_input(update.body, update.body_stdin)?;
                let (doc, text) = prose::from_plaintext(&body);
                note.body = doc;
                note.body_text = text;
            }
            if password_supplied {
                bail!("--password is only valid for login items");
            }
            if update.username.is_some() {
                bail!("--username is only valid for login items");
            }
            if update.urls.is_some() {
                bail!("--url is only valid for login items");
            }
            if key_supplied {
                bail!("--key is only valid for api-credential items");
            }
            if update.credential_kind.is_some() {
                bail!("--credential-kind is only valid for api-credential items");
            }
            if update.notes.is_some() {
                bail!(
                    "--notes is only valid for login and api-credential items; use --body for secure notes"
                );
            }
        }
        _ => {
            if password_supplied
                || key_supplied
                || body_supplied
                || update.username.is_some()
                || update.urls.is_some()
                || update.credential_kind.is_some()
                || update.notes.is_some()
            {
                bail!("updating this item kind is not supported via the CLI");
            }
        }
    }

    client
        .update_item(
            vault.vault_id,
            update.item_id,
            &vault.key,
            content,
            &title,
            &tags,
            sensitive,
            vault.key_version,
        )
        .await?;

    let output = UpdatedItemOutput {
        vault_id: vault.vault_id,
        item_id: update.item_id,
        updated: true,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("Updated item {} in vault {}", update.item_id, vault.name)
                    .green()
                    .bold()
            );
        }
    }

    Ok(())
}

pub async fn create_login(
    options: PasswordsOptions,
    create: LoginCreateOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let password = read_secret_input(
        create.password,
        create.password_stdin,
        "Password",
        "missing password; pass --password, --password-stdin, or enter it at the prompt",
    )?;
    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, create.vault_id).await?;
    let (notes, notes_text) = prose::from_plaintext(create.notes.as_deref().unwrap_or_default());
    let content = ItemContent::Login(LoginContent {
        username: create.username,
        password,
        urls: create.urls.into_iter().map(LoginUrl::from).collect(),
        notes,
        notes_text,
        ..LoginContent::default()
    });

    create_item(
        &client,
        &vault,
        &create.title,
        &create.tags,
        create.sensitive,
        "login",
        "password",
        content,
        ctx,
    )
    .await
}

pub async fn create_api_credential(
    options: PasswordsOptions,
    create: ApiCredentialCreateOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let key = read_secret_input(
        create.key,
        create.key_stdin,
        "API key",
        "missing API key; pass --key, --key-stdin, or enter it at the prompt",
    )?;
    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, create.vault_id).await?;
    let (notes, notes_text) = prose::from_plaintext(create.notes.as_deref().unwrap_or_default());
    let content = ItemContent::ApiCredential(ApiCredentialContent {
        kind: api_credential_kind(&create.credential_kind)?,
        primary_value: key,
        notes,
        notes_text,
        ..ApiCredentialContent::default()
    });

    create_item(
        &client,
        &vault,
        &create.title,
        &create.tags,
        create.sensitive,
        "api_credential",
        "primary_value",
        content,
        ctx,
    )
    .await
}

pub async fn create_secure_note(
    options: PasswordsOptions,
    create: SecureNoteCreateOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let body = read_text_input(create.body, create.body_stdin)?;
    let client = build_vault_client(options, ctx).await?;
    let vault = select_vault(&client, create.vault_id).await?;
    let (body, body_text) = prose::from_plaintext(&body);
    let content = ItemContent::SecureNote(SecureNoteContent {
        body,
        body_text,
        ..SecureNoteContent::default()
    });

    create_item(
        &client,
        &vault,
        &create.title,
        &create.tags,
        create.sensitive,
        "secure_note",
        "body",
        content,
        ctx,
    )
    .await
}

#[derive(serde::Serialize)]
struct AgentProvisionOutput {
    identity_id: Uuid,
    display_name: String,
    access: String,
    granted_vaults: Vec<Uuid>,
    key_file: String,
}

#[derive(serde::Serialize)]
struct AgentKeyFileGrant {
    vault_id: Uuid,
    access: String,
}

#[derive(serde::Serialize)]
struct AgentKeyFile {
    identity_id: Uuid,
    display_name: String,
    kem_private: String,
    signing_private: String,
    api_key: String,
    granted_vaults: Vec<AgentKeyFileGrant>,
}

// These fields are long-lived credentials; scrub their heap buffers on drop.
impl Drop for AgentKeyFile {
    fn drop(&mut self) {
        self.kem_private.zeroize();
        self.signing_private.zeroize();
        self.api_key.zeroize();
    }
}

pub async fn agent_provision(
    options: PasswordsOptions,
    provision: AgentProvisionOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let master_password = read_master_password(options.master_password)?;

    let base_url = ctx.api_base();
    let passwords_base_url = passwords_api_base_url(&base_url);
    let bearer = get_bearer_token(ctx.api_key.clone()).await?;
    if bearer.starts_with("seren_") {
        bail!(
            "agent provisioning requires a signed-in user session; run 'seren auth login' with browser sign-in because an API key cannot mint another key"
        );
    }

    let key_source =
        fetch_master_password_key_source(&passwords_base_url, &bearer, master_password)
            .await
            .context("could not fetch account secrets")?;
    let owner_signing_private = match &key_source {
        seren_secrets_resolver::VaultKeySource::MasterPassword {
            secrets,
            master_password,
        } => {
            seren_secrets_crypto::protocol::account::unlock_account(master_password, secrets)?
                .signing_private
        }
        _ => bail!("agent provisioning requires master-password authentication"),
    };
    let client = VaultClient::new(VaultClientConfig {
        base_url: passwords_base_url.clone(),
        bearer_token: bearer.clone(),
        key_source,
    })
    .context("could not build vault client")?;

    let vaults = client.list_vaults().await?;
    let targets: Vec<&seren_secrets_resolver::vault::DecryptedVault> = if provision.vault == "all" {
        vaults.iter().collect()
    } else {
        let id = Uuid::parse_str(&provision.vault)
            .with_context(|| format!("invalid vault id: {}", provision.vault))?;
        let vault = vaults
            .iter()
            .find(|v| v.vault_id == id)
            .with_context(|| format!("vault {id} is not available to this account"))?;
        vec![vault]
    };
    if targets.is_empty() {
        bail!("no vaults to grant");
    }

    let kem = IdentityKemKeypair::generate();
    let sign = IdentitySigningKeypair::generate();

    let provenance = serde_json::json!({ "kind": "software", "source": "seren-cli" });
    let identity_id = create_agent_identity(
        &passwords_base_url,
        &bearer,
        &owner_signing_private,
        &provision.name,
        &kem.public,
        &sign.public,
        provenance,
    )
    .await?;

    // After identity creation, failures trigger a best-effort identity revoke.
    let result: Result<(std::path::PathBuf, Vec<Uuid>)> = async {
        for vault in &targets {
            grant_membership(
                &passwords_base_url,
                &bearer,
                &owner_signing_private,
                vault.vault_id,
                identity_id,
                &vault.key,
                &kem.public,
                provision.access.as_str(),
            )
            .await?;
        }

        let expires_in_days = match provision.expires_in_days {
            Some(days) => Some(i64::from(days)),
            None => {
                eprintln!(
                    "warning: provisioning a non-expiring agent credential; prefer --expires-in-days to bound its lifetime"
                );
                None
            }
        };
        let api_client = seren::Client::from_config(
            &seren::ClientConfig::new(bearer.clone()).with_base_url(base_url.clone()),
        )?;
        let api_key = api_client
            .create_default_org_api_key(&seren::CreateApiKeyRequest {
                name: format!("{} (seren-passwords agent)", provision.name),
                key_type: Some(seren::ApiKeyType::Agent),
                agent_identity_id: Some(identity_id),
                scopes: Some(vec!["publisher:seren-passwords".to_owned()]),
                expires_in_days,
            })
            .await
            .context("failed to mint agent API key")?
            .into_inner()
            .data
            .api_key;

        let granted_vaults: Vec<Uuid> = targets.iter().map(|v| v.vault_id).collect();
        let key_file = AgentKeyFile {
            identity_id,
            display_name: provision.name.clone(),
            kem_private: BASE64.encode(kem.private.as_bytes()),
            signing_private: BASE64.encode(sign.private.as_bytes()),
            api_key,
            granted_vaults: targets
                .iter()
                .map(|v| AgentKeyFileGrant {
                    vault_id: v.vault_id,
                    access: provision.access.clone(),
                })
                .collect(),
        };
        let key_file_path = write_agent_key_file(identity_id, &key_file)?;
        Ok((key_file_path, granted_vaults))
    }
    .await;

    let (key_file_path, granted_vaults) = match result {
        Ok(values) => values,
        Err(e) => {
            // Revoking the identity also invalidates keys minted against it.
            let guidance = match revoke_agent_identity(&passwords_base_url, &bearer, identity_id)
                .await
            {
                Ok(_) => format!(
                    "agent provisioning failed after creating identity {identity_id}; automatic rollback removed the identity"
                ),
                Err(rollback_err) => format!(
                    "agent provisioning failed after creating identity {identity_id}; automatic rollback failed ({rollback_err}) -- the identity and any minted key may still be live, run `seren passwords agent revoke {identity_id}` now"
                ),
            };
            return Err(e.context(guidance));
        }
    };

    let output = AgentProvisionOutput {
        identity_id,
        display_name: provision.name.clone(),
        access: provision.access.clone(),
        granted_vaults,
        key_file: key_file_path.display().to_string(),
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("Provisioned agent {identity_id}").green().bold()
            );
            let vault_names = targets
                .iter()
                .map(|v| v.name.clone())
                .collect::<Vec<_>>()
                .join(", ");
            output::print_key_value_table(
                None,
                &[
                    ("Identity ID", output.identity_id.to_string()),
                    ("Display name", output.display_name.clone()),
                    ("Access", output.access.clone()),
                    ("Granted vaults", vault_names),
                    ("Key file", output.key_file.clone()),
                ],
            );
        }
    }

    Ok(())
}

/// Directory holding on-disk agent key files.
fn agent_key_dir() -> Result<std::path::PathBuf> {
    let strategy = choose_base_strategy().context("could not determine config directory")?;
    Ok(strategy
        .config_dir()
        .join("seren")
        .join("passwords")
        .join("agents"))
}

/// Path of the on-disk key file for an agent identity.
fn agent_key_file_path(identity_id: Uuid) -> Result<std::path::PathBuf> {
    Ok(agent_key_dir()?.join(format!("{identity_id}.json")))
}

/// Remove an agent key file. Missing files keep revoke idempotent.
fn remove_agent_key_file(identity_id: Uuid) -> Result<()> {
    let path = agent_key_file_path(identity_id)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("could not remove {}", path.display())),
    }
}

fn write_agent_key_file(identity_id: Uuid, key_file: &AgentKeyFile) -> Result<std::path::PathBuf> {
    let dir = agent_key_dir()?;
    std::fs::create_dir_all(&dir).context("could not create agent key directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&dir)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&dir, permissions)?;
    }

    let path = dir.join(format!("{identity_id}.json"));
    let serialized = Zeroizing::new(
        serde_json::to_vec_pretty(key_file).context("could not serialize agent key file")?,
    );

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .context("could not create agent key file")?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("could not lock down agent key file")?;
        file.write_all(serialized.as_slice())
            .context("could not write agent key file")?;
    }
    #[cfg(not(unix))]
    {
        // Non-Unix platforms inherit default permissions; warn before writing
        // long-lived agent credentials.
        eprintln!(
            "warning: agent key file {} is protected only by default filesystem permissions on this platform; keep it on a single-user host",
            path.display()
        );
        std::fs::write(&path, serialized.as_slice()).context("could not write agent key file")?;
    }

    Ok(path)
}

#[derive(Debug, serde::Serialize)]
struct AgentRevokeOutput {
    agent_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_id: Option<Uuid>,
    scope: String,
    revoked: bool,
}

#[derive(Debug, serde::Serialize)]
struct AgentFreezeOutput {
    revoked: i64,
}

#[derive(Debug, serde::Serialize)]
struct AuditVerifyOutput {
    verified: bool,
    entries: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_broken_log_id: Option<Uuid>,
    checked_at: jiff::Timestamp,
}

pub async fn agent_list(ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let agents = passwords_gateway_data(
        client.agent_identity_list().await,
        "failed to list agent identities",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&agents)?,
        OutputFormat::Table => {
            if agents.is_empty() {
                println!("No provisioned agents found");
            } else {
                for agent in &agents {
                    let identity = &agent.identity;
                    println!(
                        "{}",
                        format!("{} ({})", identity.display_name, identity.identity_id)
                            .green()
                            .bold()
                    );
                    let vaults = if agent.granted_vaults.is_empty() {
                        "(none)".to_string()
                    } else {
                        agent
                            .granted_vaults
                            .iter()
                            .map(|grant| format!("{} ({})", grant.vault_id, grant.access_level))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    let status = if identity.revoked_at.is_some() {
                        "revoked"
                    } else {
                        "active"
                    };
                    output::print_key_value_table(
                        None,
                        &[
                            ("Status", status.to_string()),
                            ("Created", identity.created_at.to_string()),
                            (
                                "Last seen",
                                identity
                                    .last_seen_at
                                    .as_ref()
                                    .map(ToString::to_string)
                                    .unwrap_or_else(|| "(never)".to_string()),
                            ),
                            ("Vaults", vaults),
                        ],
                    );
                }
            }
        }
    }

    Ok(())
}

pub async fn agent_freeze(ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let active_agent_ids = passwords_gateway_data(
        client.agent_identity_list().await,
        "failed to list agent identities before freeze",
    )?
    .data
    .into_iter()
    .filter(|agent| agent.identity.revoked_at.is_none())
    .map(|agent| agent.identity.identity_id)
    .collect::<Vec<_>>();
    let response = passwords_gateway_data(
        client.agent_identity_freeze().await,
        "failed to freeze agent identities",
    )?
    .data;
    for agent_id in active_agent_ids {
        if let Err(e) = remove_agent_key_file(agent_id) {
            eprintln!("warning: could not remove local agent key file for {agent_id}: {e}");
        }
    }
    let output = AgentFreezeOutput {
        revoked: response.revoked,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("Revoked {} active agent identities", output.revoked)
                    .green()
                    .bold()
            );
        }
    }

    Ok(())
}

pub async fn audit_list(options: PasswordAuditListOptions, ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let from = parse_timestamp_arg("from", options.from.as_deref())?;
    let to = parse_timestamp_arg("to", options.to.as_deref())?;
    let events = passwords_gateway_data(
        client
            .audit_event_list(
                options.action.as_deref(),
                options.actor_identity_id.as_ref(),
                from.as_ref(),
                Some(options.limit),
                Some(options.offset),
                options.target_id.as_ref(),
                options.target_kind.as_deref(),
                to.as_ref(),
            )
            .await,
        "failed to list password audit events",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&events)?,
        OutputFormat::Table => {
            if events.is_empty() {
                println!("No password audit events found");
            } else {
                let rows = events
                    .iter()
                    .map(|event| {
                        let target = match (&event.target_kind, event.target_id) {
                            (Some(kind), Some(id)) => format!("{kind}:{id}"),
                            (Some(kind), None) => kind.clone(),
                            (None, Some(id)) => id.to_string(),
                            (None, None) => "-".to_string(),
                        };
                        format!(
                            "{} | {} | actor {} | target {}",
                            event.created_at, event.action, event.actor_identity_id, target
                        )
                    })
                    .collect::<Vec<_>>();
                output::print_list_table(Some("Password audit events"), "Event", &rows);
            }
        }
    }

    Ok(())
}

pub async fn audit_verify(ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let result = passwords_gateway_data(
        client.audit_chain_verify().await,
        "failed to verify password audit chain",
    )?
    .data;
    let output = AuditVerifyOutput {
        verified: result.verified,
        entries: result.entries,
        first_broken_log_id: result.first_broken_log_id,
        checked_at: result.checked_at,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => output::print_key_value_table(
            Some("Password audit chain"),
            &[
                ("Verified", output.verified.to_string()),
                ("Entries", output.entries.to_string()),
                (
                    "First broken log ID",
                    output
                        .first_broken_log_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "(none)".to_string()),
                ),
                ("Checked at", output.checked_at.to_string()),
            ],
        ),
    }

    Ok(())
}

pub async fn approval_request(
    target_kind: seren::ApprovalTargetKind,
    target_id: Uuid,
    timeout_seconds: Option<i32>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let approval = passwords_gateway_data(
        client
            .approval_create(&seren::CreateApprovalRequest {
                target_id,
                target_kind,
                timeout_seconds,
            })
            .await,
        "failed to request password approval",
    )?
    .data;
    print_approval_record("Password approval request", &approval, ctx)
}

pub async fn approval_list(ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let approvals = passwords_gateway_data(
        client.approval_list_pending().await,
        "failed to list password approvals",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&approvals)?,
        OutputFormat::Table => {
            if approvals.is_empty() {
                println!("No pending password approvals found");
            } else {
                let rows = approvals
                    .iter()
                    .map(|approval| {
                        format!(
                            "{} | {} {} | requester {} | expires {}",
                            approval.request_id,
                            approval.target_kind,
                            approval.target_id,
                            approval.requesting_identity_id,
                            approval.expires_at
                        )
                    })
                    .collect::<Vec<_>>();
                output::print_list_table(Some("Pending password approvals"), "Approval", &rows);
            }
        }
    }

    Ok(())
}

pub async fn approval_get(approval_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let approval = passwords_gateway_data(
        client.approval_get(&approval_id).await,
        "failed to get password approval",
    )?
    .data;
    print_approval_record("Password approval", &approval, ctx)
}

pub async fn approval_approve(
    options: PasswordsOptions,
    approval_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let (_, _, key_source) = build_vault_key_source(options, ctx).await?;
    let kem_private = key_source
        .kem_private()
        .context("could not unlock vault key source")?
        .into_owned();
    let client = passwords_api_client(ctx).await?;
    let approve_context = passwords_gateway_data(
        client.approval_approve_context(&approval_id).await,
        "failed to load password approval context",
    )?
    .data;
    let one_shot_wrapped_key = build_approval_wrapped_key(&kem_private, &approve_context)?;
    let approval = passwords_gateway_data(
        client
            .approval_approve(
                &approval_id,
                &seren::ApprovalDecisionRequest {
                    one_shot_wrapped_key: BASE64.encode(one_shot_wrapped_key),
                },
            )
            .await,
        "failed to approve password approval",
    )?
    .data;
    print_approval_record("Approved password approval", &approval, ctx)
}

pub async fn approval_deny(approval_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let approval = passwords_gateway_data(
        client.approval_deny(&approval_id).await,
        "failed to deny password approval",
    )?
    .data;
    print_approval_record("Denied password approval", &approval, ctx)
}

fn print_approval_record(
    title: &str,
    approval: &seren::ApprovalRecord,
    ctx: &CommandContext,
) -> Result<()> {
    match ctx.format {
        OutputFormat::Json => output::print_json(approval)?,
        OutputFormat::Table => output::print_key_value_table(
            Some(title),
            &[
                ("Request ID", approval.request_id.to_string()),
                ("Status", approval.status.to_string()),
                (
                    "Target",
                    format!("{} {}", approval.target_kind, approval.target_id),
                ),
                (
                    "Requester identity",
                    approval.requesting_identity_id.to_string(),
                ),
                (
                    "Approver identity",
                    optional_uuid(approval.approver_identity_id),
                ),
                ("Created", approval.created_at.to_string()),
                ("Expires", approval.expires_at.to_string()),
                (
                    "Decided",
                    approval
                        .decided_at
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "(pending)".to_string()),
                ),
            ],
        ),
    }

    Ok(())
}

fn build_approval_wrapped_key(
    kem_private: &IdentityKemPrivateKey,
    context: &seren::ApproveContext,
) -> Result<Vec<u8>> {
    let requester_public = decode_kem_public_key(&context.requester_kem_public_key)?;
    let approver_wrapped_vault_key = decode_passwords_b64_field(
        "approver_wrapped_vault_key",
        &context.approver_wrapped_vault_key,
    )?;
    let vault_key = unwrap_vault_key(kem_private, &approver_wrapped_vault_key)
        .context("could not unwrap approver vault key")?;

    match context.target_kind {
        seren::ApprovalTargetKind::Vault => {
            Ok(wrap_vault_key_for_identity(&vault_key, &requester_public))
        }
        seren::ApprovalTargetKind::Item => {
            let item_id = context
                .item_id
                .context("approval context missing item_id")?;
            let content_key_wrap = context
                .content_key_wrap
                .as_ref()
                .context("approval context missing content_key_wrap")?;
            let content_key_wrap =
                decode_passwords_b64_field("content_key_wrap", content_key_wrap)?;
            let content_key =
                unwrap_item_content_key(&vault_key, item_id.as_bytes(), &content_key_wrap)
                    .context("could not unwrap item content key")?;
            Ok(seren_secrets_crypto::kem::seal(
                &requester_public,
                content_key.as_bytes(),
            ))
        }
    }
}

fn decode_kem_public_key(encoded: &str) -> Result<IdentityKemPublicKey> {
    let bytes = decode_passwords_b64_field("requester_kem_public_key", encoded)?;
    IdentityKemPublicKey::from_slice(&bytes).context("invalid requester KEM public key")
}

fn decode_kem_public_key_field(field: &'static str, encoded: &str) -> Result<IdentityKemPublicKey> {
    let bytes = decode_passwords_b64_field(field, encoded)?;
    IdentityKemPublicKey::from_slice(&bytes).with_context(|| format!("invalid {field}"))
}

fn decode_passwords_b64_field(field: &'static str, encoded: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(encoded.as_bytes())
        .with_context(|| format!("invalid base64 field {field}"))
}

async fn build_rotation_complete_request(
    client: &seren::Client,
    vault_id: Uuid,
    rotation_token: Uuid,
    kem_private: &IdentityKemPrivateKey,
    signing_private: &IdentitySigningPrivateKey,
) -> Result<seren::RotationCompleteRequest> {
    let sync = passwords_gateway_data(
        client.sync_get().await,
        "failed to load password sync data for rotation",
    )?
    .data;
    let vault = sync
        .vaults
        .iter()
        .find(|vault| vault.vault_id == vault_id)
        .with_context(|| format!("vault {vault_id} is not available to this account"))?;
    let old_wrapped_key = vault
        .wrapped_vault_key
        .as_deref()
        .context("vault response missing wrapped_vault_key")?;
    let old_vault_key = unwrap_vault_key(
        kem_private,
        &decode_passwords_b64_field("wrapped_vault_key", old_wrapped_key)?,
    )
    .context("could not unwrap current vault key")?;
    let new_vault_key = generate_vault_key();
    let identities = sync
        .identities
        .iter()
        .map(|identity| (identity.identity_id, identity))
        .collect::<HashMap<_, _>>();

    let memberships = sync
        .memberships
        .iter()
        .filter(|membership| membership.vault_id == vault_id && membership.revoked_at.is_none())
        .map(|membership| {
            let identity = identities
                .get(&membership.identity_id)
                .with_context(|| format!("identity {} is not visible", membership.identity_id))?;
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
        .collect::<Result<Vec<_>>>()?;
    if memberships.is_empty() {
        bail!("vault has no active memberships to rotate");
    }

    let listed_invitations = passwords_gateway_data(
        client.invitation_list_for_vault(&vault_id).await,
        "failed to list password vault invitations for rotation",
    )?
    .data;
    let mut recipient_emails = HashMap::new();
    let mut invitations = Vec::with_capacity(listed_invitations.len());
    for invitation in listed_invitations {
        let email = decrypt_vault_invitation_email(
            &old_vault_key,
            vault_id.as_bytes(),
            invitation.invitation_id.as_bytes(),
            &decode_passwords_b64_field(
                "invitee_email_ciphertext",
                &invitation.invitee_email_ciphertext,
            )?,
        )
        .context("could not decrypt invitation email for rotation")?;
        if let Some(recipient_identity_id) = invitation
            .recipient_identity_id
            .or(invitation.redeemed_by_identity)
        {
            recipient_emails
                .entry(recipient_identity_id)
                .or_insert_with(|| email.clone());
        }
        invitations.push(seren::RotationInvitationDto {
            invitation_id: invitation.invitation_id,
            invitee_email_ciphertext: BASE64.encode(encrypt_vault_invitation_email(
                &new_vault_key,
                vault_id.as_bytes(),
                invitation.invitation_id.as_bytes(),
                &email,
            )),
        });
    }

    let active_foreign_memberships = sync
        .foreign_memberships
        .iter()
        .filter(|membership| membership.vault_id == vault_id && membership.revoked_at.is_none());
    let mut foreign_memberships = Vec::new();
    for membership in active_foreign_memberships {
        let email = recipient_emails
            .get(&membership.recipient_identity_id)
            .context("foreign recipient email is not available for rotation")?;
        let verified = passwords_gateway_data(
            client
                .share_recipient_lookup(&seren::ShareRecipientLookupRequest {
                    email: email.clone(),
                })
                .await,
            "failed to verify foreign recipient for rotation",
        )?
        .data;
        let verified_public_key = verified.recipient_kem_public_key.as_deref();
        if !verified.available
            || verified.recipient_organization_id != Some(membership.recipient_organization_id)
            || verified.recipient_user_id != Some(membership.recipient_user_id)
            || verified.recipient_identity_id != Some(membership.recipient_identity_id)
            || verified_public_key != Some(membership.recipient_kem_public_key.as_str())
        {
            bail!("foreign recipient public key no longer matches the verified email");
        }
        let recipient_public = decode_kem_public_key_field(
            "recipient_kem_public_key",
            verified_public_key.context("foreign recipient public key is not available")?,
        )?;
        let wrapped = wrap_vault_key_for_identity(&new_vault_key, &recipient_public);
        foreign_memberships.push(seren::RotationForeignMembershipDto {
            access_level: membership.access_level,
            granted_signature: membership_grant_signature(
                signing_private,
                vault_id,
                membership.recipient_identity_id,
                membership.access_level,
                &wrapped,
            ),
            recipient_identity_id: membership.recipient_identity_id,
            recipient_organization_id: membership.recipient_organization_id,
            recipient_user_id: membership.recipient_user_id,
            wrapped_vault_key: BASE64.encode(wrapped),
        });
    }

    let mut items = Vec::new();
    let mut attachments = Vec::new();
    for state in [
        seren::ListStateParam::Active,
        seren::ListStateParam::Trashed,
    ] {
        let summaries = passwords_gateway_data(
            client.item_list(&vault_id, Some(state), None, None).await,
            "failed to list password vault items for rotation",
        )?
        .data;
        for summary in summaries {
            let item = passwords_gateway_data(
                client.item_get(&vault_id, &summary.item_id).await,
                "failed to fetch password item for rotation",
            )?
            .data;
            let item_id = item.item_id;
            let item_id_bytes = item_id.as_bytes();
            let title = decrypt_title(
                &old_vault_key,
                item_id_bytes,
                &decode_passwords_b64_field("title_ciphertext", &item.title_ciphertext)?,
            )
            .context("could not decrypt item title for rotation")?;
            let tags_ciphertext = item
                .tags_ciphertext
                .as_deref()
                .map(|tags| {
                    let tags = decrypt_tags(
                        &old_vault_key,
                        item_id_bytes,
                        &decode_passwords_b64_field("tags_ciphertext", tags)?,
                    )
                    .context("could not decrypt item tags for rotation")?;
                    let ciphertext = encrypt_tags(&new_vault_key, item_id_bytes, &tags)
                        .context("could not encrypt item tags for rotation")?;
                    Ok::<String, anyhow::Error>(BASE64.encode(ciphertext))
                })
                .transpose()?;
            let metadata_json = decrypt_metadata_json(
                &old_vault_key,
                item_id_bytes,
                &decode_passwords_b64_field("metadata_ciphertext", &item.metadata_ciphertext)?,
            )
            .context("could not decrypt item metadata for rotation")?;
            let content_key = unwrap_item_content_key(
                &old_vault_key,
                item_id_bytes,
                &decode_passwords_b64_field("content_key_wrap", &item.content_key_wrap)?,
            )
            .context("could not unwrap item content key for rotation")?;
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

            let listed_attachments = passwords_gateway_data(
                client.attachment_list(&vault_id, &item_id).await,
                "failed to list password item attachments for rotation",
            )?
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
    .context("could not decrypt vault name for rotation")?;
    let vault_description_ciphertext = vault
        .description_ciphertext
        .as_deref()
        .map(|description| {
            let description = decrypt_vault_description(
                &old_vault_key,
                vault_id.as_bytes(),
                &decode_passwords_b64_field("description_ciphertext", description)?,
            )
            .context("could not decrypt vault description for rotation")?;
            Ok::<String, anyhow::Error>(BASE64.encode(encrypt_vault_description(
                &new_vault_key,
                vault_id.as_bytes(),
                &description,
            )))
        })
        .transpose()?;

    Ok(seren::RotationCompleteRequest {
        attachments,
        foreign_memberships,
        invitations,
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
) -> Result<DecryptedAttachmentMetadata> {
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
) -> Result<DecryptedAttachmentMetadata> {
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
) -> Result<DecryptedAttachmentMetadata> {
    let item_id_bytes = item_id.as_bytes();
    let attachment_id_bytes = fields.attachment_id.as_bytes();
    let filename = decrypt_filename(
        vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("filename_ciphertext", fields.filename_ciphertext)?,
    )
    .context("could not decrypt attachment filename")?;
    let content_type = decrypt_content_type(
        vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("content_type_ciphertext", fields.content_type_ciphertext)?,
    )
    .context("could not decrypt attachment content type")?;

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
) -> Result<Zeroizing<Vec<u8>>> {
    let attachment_id = attachment.attachment_id;
    let item_id_bytes = item_id.as_bytes();
    let attachment_id_bytes = attachment_id.as_bytes();
    let content_key = unwrap_attachment_key(
        vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("wrapped_content_key", &attachment.wrapped_content_key)?,
    )
    .context("could not unwrap attachment content key")?;
    Ok(Zeroizing::new(
        decrypt_blob(
            &content_key,
            item_id_bytes,
            attachment_id_bytes,
            &decode_passwords_b64_field("blob", &attachment.blob)?,
        )
        .context("could not decrypt attachment blob")?,
    ))
}

fn rewrap_attachment_for_rotation(
    old_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    item_id: Uuid,
    attachment: &seren::AttachmentView,
) -> Result<seren::RotationAttachmentDto> {
    let attachment_id = attachment.attachment_id;
    let item_id_bytes = item_id.as_bytes();
    let attachment_id_bytes = attachment_id.as_bytes();
    let filename = decrypt_filename(
        old_vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("filename_ciphertext", &attachment.filename_ciphertext)?,
    )
    .context("could not decrypt attachment filename for rotation")?;
    let content_type = decrypt_content_type(
        old_vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field(
            "content_type_ciphertext",
            &attachment.content_type_ciphertext,
        )?,
    )
    .context("could not decrypt attachment content type for rotation")?;
    let attachment_key = unwrap_attachment_key(
        old_vault_key,
        item_id_bytes,
        attachment_id_bytes,
        &decode_passwords_b64_field("wrapped_content_key", &attachment.wrapped_content_key)?,
    )
    .context("could not unwrap attachment content key for rotation")?;

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

fn account_signing_private_from_key_source(
    key_source: &VaultKeySource,
) -> Result<IdentitySigningPrivateKey> {
    match key_source {
        VaultKeySource::MasterPassword {
            secrets,
            master_password,
        } => Ok(
            seren_secrets_crypto::protocol::account::unlock_account(master_password, secrets)?
                .signing_private,
        ),
        _ => bail!("membership grants require master-password authentication"),
    }
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

pub async fn membership_list(vault_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let memberships = passwords_gateway_data(
        client.membership_list(&vault_id).await,
        "failed to list password vault memberships",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&memberships)?,
        OutputFormat::Table => {
            if memberships.is_empty() {
                println!("No active memberships found");
            } else {
                let rows = memberships
                    .iter()
                    .map(|membership| {
                        format!(
                            "{} | {} | granted by {} at {}",
                            membership.identity_id,
                            membership.access_level,
                            membership.granted_by_identity,
                            membership.granted_at
                        )
                    })
                    .collect::<Vec<_>>();
                output::print_list_table(Some("Password vault memberships"), "Membership", &rows);
            }
        }
    }

    Ok(())
}

pub async fn membership_grant(options: MembershipGrantOptions, ctx: &CommandContext) -> Result<()> {
    let (passwords_base_url, bearer, key_source) = build_vault_key_source(
        PasswordsOptions {
            master_password: options.master_password,
        },
        ctx,
    )
    .await?;
    let signing_private = account_signing_private_from_key_source(&key_source)?;
    let vault_client = VaultClient::new(VaultClientConfig {
        base_url: passwords_base_url,
        bearer_token: bearer,
        key_source,
    })
    .context("could not build vault client")?;
    let vault = select_vault(&vault_client, Some(options.vault_id)).await?;
    let client = passwords_api_client(ctx).await?;
    let identity = passwords_gateway_data(
        client.identity_get(&options.identity_id).await,
        "failed to load password identity",
    )?
    .data;
    let recipient_public = decode_kem_public_key_field("kem_public_key", &identity.kem_public_key)?;
    let wrapped = wrap_vault_key_for_identity(&vault.key, &recipient_public);
    let granted_signature = membership_grant_signature(
        &signing_private,
        vault.vault_id,
        options.identity_id,
        options.access_level,
        &wrapped,
    );
    let result = passwords_gateway_data(
        client
            .membership_grant(
                &vault.vault_id,
                &seren::MembershipGrantRequest {
                    access_level: options.access_level,
                    granted_signature,
                    identity_id: options.identity_id,
                    wrapped_vault_key: BASE64.encode(wrapped),
                },
            )
            .await,
        "failed to grant password vault membership",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => println!(
            "{}",
            format!(
                "Granted {} access to identity {} in vault {}",
                options.access_level, options.identity_id, vault.vault_id
            )
            .green()
            .bold()
        ),
    }

    Ok(())
}

pub async fn membership_revoke(
    vault_id: Uuid,
    identity_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let result = passwords_gateway_data(
        client.membership_revoke(&vault_id, &identity_id).await,
        "failed to revoke password vault membership",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => println!(
            "{}",
            format!("Revoked identity {identity_id} from vault {vault_id}")
                .green()
                .bold()
        ),
    }

    Ok(())
}

pub async fn membership_update_access(
    options: MembershipAccessUpdateOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let (passwords_base_url, bearer, key_source) = build_vault_key_source(
        PasswordsOptions {
            master_password: options.master_password,
        },
        ctx,
    )
    .await?;
    let signing_private = account_signing_private_from_key_source(&key_source)?;
    let vault_client = VaultClient::new(VaultClientConfig {
        base_url: passwords_base_url,
        bearer_token: bearer,
        key_source,
    })
    .context("could not build vault client")?;
    let vault = select_vault(&vault_client, Some(options.vault_id)).await?;
    let client = passwords_api_client(ctx).await?;
    let identity = passwords_gateway_data(
        client.identity_get(&options.identity_id).await,
        "failed to load password identity",
    )?
    .data;
    let recipient_public = decode_kem_public_key_field("kem_public_key", &identity.kem_public_key)?;
    let wrapped = wrap_vault_key_for_identity(&vault.key, &recipient_public);
    let granted_signature = membership_grant_signature(
        &signing_private,
        vault.vault_id,
        options.identity_id,
        options.access_level,
        &wrapped,
    );
    let result = passwords_gateway_data(
        client
            .membership_update_access(
                &vault.vault_id,
                &options.identity_id,
                &seren::MembershipGrantRequest {
                    access_level: options.access_level,
                    granted_signature,
                    identity_id: options.identity_id,
                    wrapped_vault_key: BASE64.encode(wrapped),
                },
            )
            .await,
        "failed to update password vault membership access",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => println!(
            "{}",
            format!(
                "Changed identity {} to {} access in vault {}",
                options.identity_id, options.access_level, vault.vault_id
            )
            .green()
            .bold()
        ),
    }

    Ok(())
}

pub async fn invitation_create(
    options: InvitationCreateOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let email = options.email.trim().to_ascii_lowercase();
    if !email.contains('@') {
        bail!("--email must be a valid email address");
    }
    let vault_client = build_vault_client(
        PasswordsOptions {
            master_password: options.master_password,
        },
        ctx,
    )
    .await?;
    let vault = select_vault(&vault_client, Some(options.vault_id)).await?;
    let invitation_id = Uuid::new_v4();
    let email_ciphertext = encrypt_vault_invitation_email(
        &vault.key,
        vault.vault_id.as_bytes(),
        invitation_id.as_bytes(),
        &email,
    );
    let client = passwords_api_client(ctx).await?;
    let created = passwords_gateway_data(
        client
            .invitation_create(
                &vault.vault_id,
                &seren::CreateInvitationRequest {
                    access_level: options.access_level,
                    expires_in_hours: options.expires_in_hours,
                    invitation_id,
                    invitee_email: email.clone(),
                    invitee_email_ciphertext: BASE64.encode(email_ciphertext),
                },
            )
            .await,
        "failed to create password invitation",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&created)?,
        OutputFormat::Table => output::print_key_value_table(
            Some("Created password invitation"),
            &[
                ("Invitation ID", created.invitation_id.to_string()),
                ("Vault ID", created.vault_id.to_string()),
                ("Email", email),
                ("Access", created.access_level.to_string()),
                ("Token", created.invitation_token),
            ],
        ),
    }

    Ok(())
}

pub async fn invitation_list(vault_id: Option<Uuid>, ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let invitations = if let Some(vault_id) = vault_id {
        passwords_gateway_data(
            client.invitation_list_for_vault(&vault_id).await,
            "failed to list password vault invitations",
        )?
        .data
    } else {
        passwords_gateway_data(
            client.invitation_list_pending().await,
            "failed to list pending password invitations",
        )?
        .data
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&invitations)?,
        OutputFormat::Table => {
            if invitations.is_empty() {
                println!("No password invitations found");
            } else {
                let rows = invitations
                    .iter()
                    .map(|invitation| {
                        format!(
                            "{} | vault {} | access {} | redeemed {}",
                            invitation.invitation_id,
                            invitation.vault_id,
                            invitation.access_level,
                            optional_uuid(invitation.redeemed_by_identity)
                        )
                    })
                    .collect::<Vec<_>>();
                output::print_list_table(Some("Password invitations"), "Invitation", &rows);
            }
        }
    }

    Ok(())
}

pub async fn invitation_redeem(
    token: String,
    recipient_email: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("invitation token is required");
    }
    let recipient_email = recipient_email
        .map(|email| email.trim().to_ascii_lowercase())
        .filter(|email| !email.is_empty());
    if recipient_email
        .as_deref()
        .is_some_and(|email| !email.contains('@'))
    {
        bail!("--email must be a valid email address");
    }
    let client = passwords_api_client(ctx).await?;
    let invitation = passwords_gateway_data(
        client
            .invitation_redeem(&seren::RedeemRequest {
                invitation_token: token,
                recipient_email,
            })
            .await,
        "failed to redeem password invitation",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&invitation)?,
        OutputFormat::Table => {
            print_invitation_record("Redeemed password invitation", &invitation, ctx)?
        }
    }

    Ok(())
}

pub async fn invitation_complete(
    options: InvitationCompleteOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let (passwords_base_url, bearer, key_source) = build_vault_key_source(
        PasswordsOptions {
            master_password: options.master_password,
        },
        ctx,
    )
    .await?;
    let signing_private = account_signing_private_from_key_source(&key_source)?;
    let vault_client = VaultClient::new(VaultClientConfig {
        base_url: passwords_base_url,
        bearer_token: bearer,
        key_source,
    })
    .context("could not build vault client")?;
    let vault = select_vault(&vault_client, Some(options.vault_id)).await?;
    let client = passwords_api_client(ctx).await?;
    let invitations = passwords_gateway_data(
        client.invitation_list_for_vault(&vault.vault_id).await,
        "failed to list password vault invitations",
    )?
    .data;
    let invitation = invitations
        .into_iter()
        .find(|invitation| invitation.invitation_id == options.invitation_id)
        .with_context(|| format!("invitation {} is not available", options.invitation_id))?;
    let identity_id = invitation
        .redeemed_by_identity
        .context("invitation has not been redeemed")?;
    let identity = passwords_gateway_data(
        client.identity_get(&identity_id).await,
        "failed to load invitee identity",
    )?
    .data;
    let recipient_public = decode_kem_public_key_field("kem_public_key", &identity.kem_public_key)?;
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
        "failed to complete password invitation",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => println!(
            "{}",
            format!(
                "Completed invitation {} for identity {}",
                options.invitation_id, identity_id
            )
            .green()
            .bold()
        ),
    }

    Ok(())
}

fn print_invitation_record(
    title: &str,
    invitation: &seren::InvitationView,
    ctx: &CommandContext,
) -> Result<()> {
    match ctx.format {
        OutputFormat::Json => output::print_json(invitation)?,
        OutputFormat::Table => output::print_key_value_table(
            Some(title),
            &[
                ("Invitation ID", invitation.invitation_id.to_string()),
                ("Vault ID", invitation.vault_id.to_string()),
                ("Access", invitation.access_level.to_string()),
                (
                    "Redeemed by",
                    optional_uuid(invitation.redeemed_by_identity),
                ),
            ],
        ),
    }

    Ok(())
}

pub async fn share_list_outbound(vault_id: Option<Uuid>, ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let shares = passwords_gateway_data(
        client.share_list_outbound(vault_id.as_ref()).await,
        "failed to list outbound password shares",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&shares)?,
        OutputFormat::Table => {
            if shares.is_empty() {
                println!("No outbound password shares found");
            } else {
                let rows = shares
                    .iter()
                    .map(|share| {
                        format!(
                            "{} | item {} | vault {} | status {} | recipient {}",
                            share.share_id,
                            share.owner_item_id,
                            share.owner_vault_id,
                            share.status,
                            optional_uuid(share.recipient_identity_id)
                        )
                    })
                    .collect::<Vec<_>>();
                output::print_list_table(Some("Outbound password shares"), "Share", &rows);
            }
        }
    }

    Ok(())
}

pub async fn share_list_received(ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let shares = passwords_gateway_data(
        client.share_list_received().await,
        "failed to list received password shares",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&shares)?,
        OutputFormat::Table => {
            if shares.is_empty() {
                println!("No received password shares found");
            } else {
                let rows = shares
                    .iter()
                    .map(|share| {
                        format!(
                            "{} | item {} | owner vault {} | status {}",
                            share.share_id, share.owner_item_id, share.owner_vault_id, share.status
                        )
                    })
                    .collect::<Vec<_>>();
                output::print_list_table(Some("Received password shares"), "Share", &rows);
            }
        }
    }

    Ok(())
}

pub async fn share_revoke(share_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = passwords_api_client(ctx).await?;
    let share = passwords_gateway_data(
        client.share_revoke(&share_id).await,
        "failed to revoke password share",
    )?
    .data;

    match ctx.format {
        OutputFormat::Json => output::print_json(&share)?,
        OutputFormat::Table => println!(
            "{}",
            format!("Revoked password share {share_id}").green().bold()
        ),
    }

    Ok(())
}

pub async fn agent_revoke(
    agent_id: Uuid,
    vault_id: Option<Uuid>,
    ctx: &CommandContext,
) -> Result<()> {
    let base_url = ctx.api_base();
    let passwords_base_url = passwords_api_base_url(&base_url);
    let bearer = get_bearer_token(ctx.api_key.clone()).await?;

    let (scope, message) = match vault_id {
        Some(vault_id) => {
            revoke_membership(&passwords_base_url, &bearer, vault_id, agent_id).await?;
            (
                "membership",
                format!("Revoked agent {agent_id} membership in vault {vault_id}"),
            )
        }
        None => {
            revoke_agent_identity(&passwords_base_url, &bearer, agent_id).await?;
            // Local and hosted credential cleanup is best-effort after revoke.
            if let Err(e) = remove_agent_key_file(agent_id) {
                eprintln!("warning: could not remove local agent key file: {e}");
            }
            ("identity", format!("Revoked agent identity {agent_id}"))
        }
    };

    let output = AgentRevokeOutput {
        agent_id,
        vault_id,
        scope: scope.to_string(),
        revoked: true,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => println!("{}", message.green().bold()),
    }

    Ok(())
}

pub fn generate_password(options: PasswordGenerateOptions, ctx: &CommandContext) -> Result<()> {
    let recipe = match options.mode.as_str() {
        "random" => PasswordRecipe::Random {
            length: options.length.unwrap_or(20),
            upper: options.upper,
            lower: options.lower,
            digits: options.digits,
            symbols: options.symbols,
        },
        "passphrase" => PasswordRecipe::Passphrase {
            word_count: options.word_count,
            separator: options.separator,
            capitalize_first: options.capitalize_first,
        },
        "hex" => PasswordRecipe::Hex {
            length: options.length.unwrap_or(32),
        },
        other => bail!("unknown generator mode: {other}"),
    };
    let password = seren_secrets_crypto::password_generator::generate(&recipe)
        .context("failed to generate password")?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&serde_json::json!({ "password": password }))?,
        OutputFormat::Table => println!("{password}"),
    }

    Ok(())
}

fn passwords_api_base_url(api_base_url: &str) -> String {
    publisher_api_base_url(api_base_url, SEREN_PASSWORDS_PUBLISHER_SLUG)
}

fn publisher_api_base_url(api_base_url: &str, publisher_slug: &str) -> String {
    let publisher_prefix = format!("/publishers/{publisher_slug}");
    let trimmed = api_base_url.trim_end_matches('/');
    if trimmed.ends_with(&publisher_prefix) {
        trimmed.to_string()
    } else {
        format!("{trimmed}{publisher_prefix}")
    }
}

async fn passwords_api_client(ctx: &CommandContext) -> Result<seren::Client> {
    let bearer = get_bearer_token(ctx.api_key.clone()).await?;
    seren::Client::from_config(&seren::ClientConfig::new(bearer).with_base_url(ctx.api_base()))
        .context("could not build Seren API client")
}

/// Resolve a Seren Passwords publisher response into its typed wrapper.
///
/// These ops reach Seren Passwords through the Seren publisher gateway,
/// which wraps the upstream `DataResponse<T>` in a metered envelope
/// (`{ "data": { "status", "body", ... } }`). The generated SDK methods
/// deserialize the direct `DataResponse<T>` shape, so the gateway envelope must
/// be unwrapped here when present. Upstream response bodies are never surfaced
/// in the error: a genuine failure maps to a status/generic message only.
fn passwords_gateway_data<T>(
    result: Result<seren::ResponseValue<T>, seren::Error<()>>,
    context: &'static str,
) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    match result {
        Ok(response) => Ok(response.into_inner()),
        Err(seren::Error::InvalidResponsePayload(bytes, _)) => {
            decode_passwords_gateway_body::<T>(&bytes).map_err(|e| {
                anyhow::anyhow!("{context}: unexpected response shape from gateway: {e}")
            })
        }
        Err(seren::Error::UnexpectedResponse(response)) => Err(anyhow::anyhow!(
            "{context}: API error {}",
            response.status()
        )),
        Err(seren::Error::ErrorResponse(response)) => Err(anyhow::anyhow!(
            "{context}: API error {}",
            response.status()
        )),
        Err(seren::Error::CommunicationError(_)) => {
            Err(anyhow::anyhow!("{context}: communication error"))
        }
        Err(_) => Err(anyhow::anyhow!("{context}")),
    }
}

/// Parse a Seren Passwords publisher response that may be a direct
/// `DataResponse<T>` or a metered publisher gateway envelope.
fn decode_passwords_gateway_body<T>(bytes: &[u8]) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    if let Ok(value) = serde_json::from_slice::<T>(bytes) {
        return Ok(value);
    }

    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON body: {e}"))?;
    let data = value
        .get("data")
        .ok_or_else(|| "missing data field".to_string())?;
    if data.get("status").and_then(serde_json::Value::as_u64) != Some(200) {
        let status = data
            .get("status")
            .and_then(serde_json::Value::as_u64)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        return Err(format!("gateway returned upstream status {status}"));
    }
    let body = data
        .get("body")
        .ok_or_else(|| "missing data.body field".to_string())?;
    let body = match body.as_str() {
        Some(raw) => serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|e| format!("invalid JSON in data.body: {e}"))?,
        None => body.clone(),
    };
    serde_json::from_value::<T>(body)
        .map_err(|e| format!("invalid typed response in data.body: {e}"))
}

fn parse_timestamp_arg(name: &str, value: Option<&str>) -> Result<Option<jiff::Timestamp>> {
    value
        .map(|raw| {
            raw.parse::<jiff::Timestamp>()
                .with_context(|| format!("invalid --{name} timestamp"))
        })
        .transpose()
}

async fn build_vault_client(
    options: PasswordsOptions,
    ctx: &CommandContext,
) -> Result<VaultClient> {
    let (passwords_base_url, bearer, key_source) = build_vault_key_source(options, ctx).await?;
    VaultClient::new(VaultClientConfig {
        base_url: passwords_base_url,
        bearer_token: bearer,
        key_source,
    })
    .context("could not build vault client")
}

async fn build_vault_key_source(
    options: PasswordsOptions,
    ctx: &CommandContext,
) -> Result<(String, String, VaultKeySource)> {
    let master_password = read_master_password(options.master_password)?;
    let base_url = ctx.api_base();
    let passwords_base_url = passwords_api_base_url(&base_url);
    let bearer = get_bearer_token(ctx.api_key.clone()).await?;
    let key_source =
        fetch_master_password_key_source(&passwords_base_url, &bearer, master_password)
            .await
            .context("could not fetch account secrets")?;
    Ok((passwords_base_url, bearer, key_source))
}

async fn select_vault(
    client: &VaultClient,
    vault_id: Option<Uuid>,
) -> Result<seren_secrets_resolver::vault::DecryptedVault> {
    let mut vaults = client.list_vaults().await?;
    match vault_id {
        Some(id) => vaults
            .into_iter()
            .find(|v| v.vault_id == id)
            .with_context(|| format!("vault {id} is not available to this account")),
        None => {
            if vaults.len() != 1 {
                bail!("multiple vaults found; pass --vault-id");
            }
            vaults.pop().context("no password vaults found")
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_item(
    client: &VaultClient,
    vault: &seren_secrets_resolver::vault::DecryptedVault,
    title: &str,
    tags: &[String],
    sensitive: bool,
    item_kind: &str,
    reference_field: &str,
    content: ItemContent,
    ctx: &CommandContext,
) -> Result<()> {
    let item_id = client
        .create_item(
            vault.vault_id,
            &vault.key,
            content,
            title,
            tags,
            sensitive,
            vault.key_version,
        )
        .await?;

    let output = CreatedItemOutput {
        vault_id: vault.vault_id,
        item_id,
        item_kind: item_kind.to_string(),
        reference: format!(
            "seren-secrets://{}/{}/{}",
            vault.vault_id, item_id, reference_field
        ),
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("Created {} in vault {}", item_kind, vault.name)
                    .green()
                    .bold()
            );
            output::print_key_value_table(
                None,
                &[
                    ("Vault ID", output.vault_id.to_string()),
                    ("Item ID", output.item_id.to_string()),
                    ("Reference", output.reference),
                ],
            );
        }
    }

    Ok(())
}

fn api_credential_kind(raw: &str) -> Result<ApiCredentialKind> {
    match raw.to_ascii_lowercase().as_str() {
        "api_key" | "api-key" | "key" => Ok(ApiCredentialKind::ApiKey),
        "oauth2_token" | "oauth2-token" | "oauth2" => Ok(ApiCredentialKind::Oauth2Token),
        "basic" => Ok(ApiCredentialKind::Basic),
        "mtls" => Ok(ApiCredentialKind::Mtls),
        "aws_sig_v4" | "aws-sig-v4" | "aws" => Ok(ApiCredentialKind::AwsSigV4),
        "gcp_service_account" | "gcp-service-account" | "gcp" => {
            Ok(ApiCredentialKind::GcpServiceAccount)
        }
        other => bail!("unsupported api credential kind: {other}"),
    }
}

/// Read the master password from the environment, if present.
///
/// The env var is the supported non-interactive path. The value is wrapped in
/// `Zeroizing` immediately and a warning is emitted.
pub fn master_password_from_env() -> Option<Zeroizing<String>> {
    match std::env::var("SEREN_PASSWORDS_MASTER_PASSWORD") {
        Ok(value) if !value.is_empty() => {
            eprintln!(
                "warning: using SEREN_PASSWORDS_MASTER_PASSWORD from the environment; prefer the interactive prompt where possible"
            );
            Some(Zeroizing::new(value))
        }
        _ => None,
    }
}

pub fn master_password_from_input(
    master_password_stdin: bool,
    master_password_file: Option<&Path>,
) -> Result<Option<Zeroizing<String>>> {
    if master_password_stdin && master_password_file.is_some() {
        bail!("pass only one of --master-password-stdin or --master-password-file");
    }

    if master_password_stdin {
        let value = read_stdin_trimmed()?;
        if value.is_empty() {
            bail!("master password read from stdin is empty");
        }
        return Ok(Some(Zeroizing::new(value)));
    }

    if let Some(path) = master_password_file {
        let mut value = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read master password file {}", path.display()))?;
        strip_one_terminal_newline(&mut value);
        if value.is_empty() {
            bail!("master password file {} is empty", path.display());
        }
        return Ok(Some(Zeroizing::new(value)));
    }

    Ok(master_password_from_env())
}

fn read_master_password(master_password: Option<Zeroizing<String>>) -> Result<Zeroizing<Vec<u8>>> {
    let password = match master_password {
        Some(value) => value,
        None => Zeroizing::new(
            rpassword::prompt_password("Seren Passwords master password: ")
                .context("failed to read master password")?,
        ),
    };
    validate_master_password(password.as_str())?;
    Ok(Zeroizing::new(password.as_bytes().to_vec()))
}

fn validate_master_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_MASTER_PASSWORD_LEN {
        bail!("master password must be at least {MIN_MASTER_PASSWORD_LEN} characters");
    }
    Ok(())
}

fn read_secret_input(
    value: Option<String>,
    from_stdin: bool,
    prompt: &str,
    missing_message: &str,
) -> Result<String> {
    let secret = if from_stdin {
        read_stdin_trimmed()?
    } else {
        match value {
            Some(value) => value,
            None if atty_stdin() => rpassword::prompt_password(format!("{prompt}: "))
                .with_context(|| format!("failed to read {prompt}"))?,
            None => bail!("{missing_message}"),
        }
    };
    // Empty secret values should fail at the input boundary.
    if secret.is_empty() {
        bail!("{missing_message}");
    }
    Ok(secret)
}

fn read_text_input(value: Option<String>, from_stdin: bool) -> Result<String> {
    if from_stdin {
        return read_stdin();
    }
    value.context("missing note body; pass --body or --body-stdin")
}

fn read_stdin() -> Result<String> {
    let mut value = String::new();
    io::stdin()
        .read_to_string(&mut value)
        .context("failed to read stdin")?;
    Ok(value)
}

fn read_stdin_trimmed() -> Result<String> {
    let mut s = read_stdin()?;
    strip_one_terminal_newline(&mut s);
    Ok(s)
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

fn atty_stdin() -> bool {
    std::io::IsTerminal::is_terminal(&io::stdin())
}

#[cfg(test)]
mod tests {
    use super::{
        ATTACHMENT_URI_SCHEME, BASE64, PasswordsVaultExportAttachment, PasswordsVaultImport,
        build_attachment_create_request, decode_passwords_gateway_body,
        ensure_distinct_transfer_vaults, membership_grant_signature, metadata_bool,
        passwords_api_base_url, prepare_passwords_import_item_content,
        rewrap_attachment_for_rotation, validate_passwords_import_metadata,
    };
    use base64::Engine;
    use seren_secrets_crypto::keys::{IdentitySigningKeypair, IdentitySigningPrivateKey};
    use seren_secrets_crypto::protocol::attachment::{
        decrypt_blob, decrypt_content_type, decrypt_filename, encrypt_blob, encrypt_content_type,
        encrypt_filename, generate_attachment_key, unwrap_attachment_key, wrap_attachment_key,
    };
    use seren_secrets_crypto::protocol::vault::generate_vault_key;
    use uuid::Uuid;

    #[test]
    fn master_password_from_input_rejects_both_sources() {
        let err =
            super::master_password_from_input(true, Some(std::path::Path::new("/nonexistent")))
                .unwrap_err();
        assert!(err.to_string().contains("only one of"));
    }

    #[test]
    fn master_password_from_input_reads_file_and_strips_one_newline() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "hunter2").unwrap();
        let value = super::master_password_from_input(false, Some(file.path()))
            .unwrap()
            .unwrap();
        assert_eq!(value.as_str(), "hunter2");
    }

    #[test]
    fn master_password_from_input_rejects_empty_file() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file).unwrap();
        let err = super::master_password_from_input(false, Some(file.path())).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn read_master_password_rejects_short_value() {
        let err = super::read_master_password(Some(zeroize::Zeroizing::new("short".to_string())))
            .unwrap_err();
        assert!(err.to_string().contains("at least 8"));
    }

    #[test]
    fn transfer_requires_distinct_vaults() {
        let source = Uuid::new_v4();
        let target = Uuid::new_v4();

        assert!(ensure_distinct_transfer_vaults(source, target).is_ok());
        assert!(ensure_distinct_transfer_vaults(source, source).is_err());
    }

    #[test]
    fn passwords_api_base_url_appends_publisher_prefix_once() {
        assert_eq!(
            passwords_api_base_url("https://api.serendb.com"),
            "https://api.serendb.com/publishers/seren-passwords"
        );
        assert_eq!(
            passwords_api_base_url("https://api.serendb.com/"),
            "https://api.serendb.com/publishers/seren-passwords"
        );
        assert_eq!(
            passwords_api_base_url("https://api.serendb.com/publishers/seren-passwords/"),
            "https://api.serendb.com/publishers/seren-passwords"
        );
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
    fn attachment_rotation_preserves_decryptability_under_new_key() {
        let old_vault_key = generate_vault_key();
        let new_vault_key = generate_vault_key();
        let item_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let attachment_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let attachment_key = generate_attachment_key();
        let plaintext = b"report-bytes".to_vec();
        // The blob stays under the unchanged attachment key; rotation only
        // re-encrypts the wrapped key + metadata under the new vault key.
        let blob = encrypt_blob(
            &attachment_key,
            item_id.as_bytes(),
            attachment_id.as_bytes(),
            &plaintext,
        );

        let attachment = seren::AttachmentView {
            attachment_id,
            content_type_ciphertext: BASE64.encode(encrypt_content_type(
                &old_vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                "application/pdf",
            )),
            created_at: "2030-01-01T00:00:00Z".parse().unwrap(),
            filename_ciphertext: BASE64.encode(encrypt_filename(
                &old_vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                "report.pdf",
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

        let rotated =
            rewrap_attachment_for_rotation(&old_vault_key, &new_vault_key, item_id, &attachment)
                .unwrap();

        assert_eq!(
            decrypt_filename(
                &new_vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                &BASE64.decode(rotated.filename_ciphertext).unwrap(),
            )
            .unwrap(),
            "report.pdf"
        );
        assert_eq!(
            decrypt_content_type(
                &new_vault_key,
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                &BASE64.decode(rotated.content_type_ciphertext).unwrap(),
            )
            .unwrap(),
            "application/pdf"
        );
        let recovered_key = unwrap_attachment_key(
            &new_vault_key,
            item_id.as_bytes(),
            attachment_id.as_bytes(),
            &BASE64.decode(rotated.wrapped_content_key).unwrap(),
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
    fn gateway_body_decodes_direct_data_response() {
        let direct = serde_json::to_vec(&seren::DataResponseAgentFreeze {
            data: seren::AgentFreezeResponse { revoked: 2 },
        })
        .unwrap();
        let parsed =
            decode_passwords_gateway_body::<seren::DataResponseAgentFreeze>(&direct).unwrap();
        assert_eq!(parsed.data.revoked, 2);
    }

    #[test]
    fn gateway_body_decodes_metered_envelope() {
        let envelope = serde_json::json!({
            "data": {
                "status": 200,
                "body": { "data": { "revoked": 5 } },
                "response_bytes": 12,
                "execution_time_ms": 1,
                "cost": "0",
                "asset_symbol": "USDC",
                "payment_source": "none"
            }
        });
        let parsed = decode_passwords_gateway_body::<seren::DataResponseAgentFreeze>(
            serde_json::to_string(&envelope).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(parsed.data.revoked, 5);
    }

    #[test]
    fn gateway_body_rejects_non_200_envelope() {
        let envelope = serde_json::json!({
            "data": {
                "status": 500,
                "body": { "error": "boom" }
            }
        });
        assert!(
            decode_passwords_gateway_body::<seren::DataResponseAgentFreeze>(
                serde_json::to_string(&envelope).unwrap().as_bytes(),
            )
            .is_err()
        );
    }

    #[test]
    fn import_metadata_accepts_supported_plaintext_item_exports() {
        let export = serde_json::json!({
            "format": "seren-passwords-mcp-export",
            "version": 1,
            "attachments_included": false,
            "items": [
                {
                    "item_id": "11111111-1111-1111-1111-111111111111",
                    "title": "GitHub",
                    "tags": ["work"],
                    "sensitive": true,
                    "favorite": true,
                    "content": { "type": "login" }
                }
            ]
        });
        let parsed: PasswordsVaultImport = serde_json::from_value(export).unwrap();
        assert!(parsed.items[0].favorite);
        validate_passwords_import_metadata(&parsed).unwrap();

        let export = serde_json::json!({
            "format": "seren-passwords-mcp-export",
            "version": 1,
            "attachments_included": true,
            "attachment_count": 1,
            "attachment_bytes": 7,
            "items": [
                {
                    "item_id": "11111111-1111-1111-1111-111111111111",
                    "title": "GitHub",
                    "tags": ["work"],
                    "sensitive": true,
                    "favorite": true,
                    "content": { "type": "login" },
                    "attachments": [
                        {
                            "attachment_id": "22222222-2222-2222-2222-222222222222",
                            "filename": "example.txt",
                            "content_type": "text/plain",
                            "size_bytes": 7,
                            "content_base64": "ZXhhbXBsZQ=="
                        }
                    ]
                }
            ]
        });
        let parsed: PasswordsVaultImport = serde_json::from_value(export).unwrap();
        assert!(parsed.items[0].favorite);
        validate_passwords_import_metadata(&parsed).unwrap();

        let mcp_params_shape = serde_json::json!({
            "items": [
                {
                    "title": "GitHub",
                    "content": { "type": "login" }
                }
            ]
        });
        let parsed: PasswordsVaultImport = serde_json::from_value(mcp_params_shape).unwrap();
        validate_passwords_import_metadata(&parsed).unwrap();
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
            vec![PasswordsVaultExportAttachment {
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
        let excluded_with_attachments: PasswordsVaultImport =
            serde_json::from_value(serde_json::json!({
                "format": "seren-passwords-mcp-export",
                "version": 1,
                "attachments_included": false,
                "items": [
                    {
                        "title": "GitHub",
                        "content": { "type": "login" },
                        "attachments": [
                            {
                                "filename": "example.txt",
                                "content_type": "text/plain",
                                "size_bytes": 7,
                                "content_base64": "ZXhhbXBsZQ=="
                            }
                        ]
                    }
                ]
            }))
            .unwrap();
        assert!(validate_passwords_import_metadata(&excluded_with_attachments).is_err());

        let mismatched_attachment_count: PasswordsVaultImport =
            serde_json::from_value(serde_json::json!({
                "format": "seren-passwords-mcp-export",
                "version": 1,
                "attachment_count": 1,
                "items": []
            }))
            .unwrap();
        assert!(validate_passwords_import_metadata(&mismatched_attachment_count).is_err());

        let duplicate_attachment_id: PasswordsVaultImport =
            serde_json::from_value(serde_json::json!({
                "format": "seren-passwords-mcp-export",
                "version": 1,
                "attachments_included": true,
                "attachment_count": 2,
                "attachment_bytes": 14,
                "items": [
                    {
                        "title": "GitHub",
                        "content": { "type": "login" },
                        "attachments": [
                            {
                                "attachment_id": "22222222-2222-2222-2222-222222222222",
                                "filename": "one.txt",
                                "content_type": "text/plain",
                                "size_bytes": 7,
                                "content_base64": "ZXhhbXBsZQ=="
                            },
                            {
                                "attachment_id": "22222222-2222-2222-2222-222222222222",
                                "filename": "two.txt",
                                "content_type": "text/plain",
                                "size_bytes": 7,
                                "content_base64": "ZXhhbXBsZQ=="
                            }
                        ]
                    }
                ]
            }))
            .unwrap();
        assert!(validate_passwords_import_metadata(&duplicate_attachment_id).is_err());

        let unsupported_version: PasswordsVaultImport = serde_json::from_value(serde_json::json!({
            "format": "seren-passwords-mcp-export",
            "version": 2,
            "items": [
                {
                    "title": "GitHub",
                    "content": { "type": "login" }
                }
            ]
        }))
        .unwrap();
        assert!(validate_passwords_import_metadata(&unsupported_version).is_err());
    }
}
