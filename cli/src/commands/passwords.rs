use std::collections::HashMap;
use std::io::{self, Read};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use colored::Colorize;
use etcetera::base_strategy::{BaseStrategy, choose_base_strategy};
use seren_secrets_crypto::aead::{xchacha20_decrypt_with_aad, xchacha20_encrypt_with_aad};
use seren_secrets_crypto::keys::{
    IdentityKemKeypair, IdentityKemPrivateKey, IdentityKemPublicKey, IdentitySigningKeypair,
    IdentitySigningPrivateKey, VaultKey,
};
use seren_secrets_crypto::password_generator::PasswordRecipe;
use seren_secrets_crypto::prose;
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
use seren_secrets_resolver::{
    VaultClient, VaultClientConfig, VaultKeySource, create_agent_identity,
    fetch_master_password_key_source, grant_membership, revoke_agent_identity, revoke_membership,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::commands::auth::get_bearer_token;
use crate::{CommandContext, OutputFormat, output};

const SEREN_PASSWORDS_PUBLISHER_SLUG: &str = "seren-passwords";

#[derive(Clone)]
pub struct PasswordsOptions {
    pub master_password: Option<Zeroizing<String>>,
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

pub async fn copy_item(
    options: PasswordsOptions,
    source_vault_id: Option<Uuid>,
    item_id: Uuid,
    target_vault_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = build_vault_client(options, ctx).await?;
    let source = select_vault(&client, source_vault_id).await?;
    let target = select_vault(&client, Some(target_vault_id)).await?;
    ensure_distinct_transfer_vaults(source.vault_id, target.vault_id)?;
    let new_item_id = client
        .copy_item(
            source.vault_id,
            item_id,
            &source.key,
            target.vault_id,
            &target.key,
            target.key_version,
        )
        .await?;

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
    let client = build_vault_client(options, ctx).await?;
    let source = select_vault(&client, source_vault_id).await?;
    let target = select_vault(&client, Some(target_vault_id)).await?;
    ensure_distinct_transfer_vaults(source.vault_id, target.vault_id)?;
    let new_item_id = client
        .move_item(
            source.vault_id,
            item_id,
            &source.key,
            target.vault_id,
            &target.key,
            target.key_version,
        )
        .await?;

    let output = MovedItemOutput {
        source_vault_id: source.vault_id,
        source_item_id: item_id,
        target_vault_id: target.vault_id,
        item_id: new_item_id,
        moved: true,
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!(
                    "Moved item {} from vault {} to vault {} as {}",
                    item_id, source.name, target.name, new_item_id
                )
                .green()
                .bold()
            );
        }
    }

    Ok(())
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

fn attachment_aad(label: &'static str, item_id: Uuid, attachment_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(label.len() + 1 + 16 + 1 + 16);
    aad.extend_from_slice(label.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(item_id.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(attachment_id.as_bytes());
    aad
}

fn rewrap_attachment_for_rotation(
    old_vault_key: &VaultKey,
    new_vault_key: &VaultKey,
    item_id: Uuid,
    attachment: &seren::AttachmentView,
) -> Result<seren::RotationAttachmentDto> {
    let attachment_id = attachment.attachment_id;
    let filename = xchacha20_decrypt_with_aad(
        old_vault_key.as_bytes(),
        &decode_passwords_b64_field("filename_ciphertext", &attachment.filename_ciphertext)?,
        &attachment_aad("attachment-filename", item_id, attachment_id),
    )
    .context("could not decrypt attachment filename for rotation")?;
    let content_type = xchacha20_decrypt_with_aad(
        old_vault_key.as_bytes(),
        &decode_passwords_b64_field(
            "content_type_ciphertext",
            &attachment.content_type_ciphertext,
        )?,
        &attachment_aad("attachment-content-type", item_id, attachment_id),
    )
    .context("could not decrypt attachment content type for rotation")?;
    let content_key = xchacha20_decrypt_with_aad(
        old_vault_key.as_bytes(),
        &decode_passwords_b64_field("wrapped_content_key", &attachment.wrapped_content_key)?,
        &attachment_aad("attachment-content-key", item_id, attachment_id),
    )
    .context("could not unwrap attachment content key for rotation")?;

    Ok(seren::RotationAttachmentDto {
        attachment_id,
        content_type_ciphertext: BASE64.encode(xchacha20_encrypt_with_aad(
            new_vault_key.as_bytes(),
            &content_type,
            &attachment_aad("attachment-content-type", item_id, attachment_id),
        )),
        filename_ciphertext: BASE64.encode(xchacha20_encrypt_with_aad(
            new_vault_key.as_bytes(),
            &filename,
            &attachment_aad("attachment-filename", item_id, attachment_id),
        )),
        wrapped_content_key: BASE64.encode(xchacha20_encrypt_with_aad(
            new_vault_key.as_bytes(),
            &content_key,
            &attachment_aad("attachment-content-key", item_id, attachment_id),
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
    const DOMAIN: &[u8] = b"seren-secrets/membership-grant";

    let access_level_byte = match access_level {
        seren::AccessLevel::Admin => 0,
        seren::AccessLevel::Write => 1,
        seren::AccessLevel::Read => 2,
    };
    let mut payload = Vec::with_capacity(DOMAIN.len() + 16 + 16 + 1 + wrapped_vault_key.len());
    payload.extend_from_slice(DOMAIN);
    payload.extend_from_slice(vault_id.as_bytes());
    payload.extend_from_slice(identity_id.as_bytes());
    payload.push(access_level_byte);
    payload.extend_from_slice(wrapped_vault_key);

    BASE64.encode(seren_secrets_crypto::signing::sign(
        signing_private,
        &payload,
    ))
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

pub async fn invitation_redeem(token: String, ctx: &CommandContext) -> Result<()> {
    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("invitation token is required");
    }
    let client = passwords_api_client(ctx).await?;
    let invitation = passwords_gateway_data(
        client
            .invitation_redeem(&seren::RedeemRequest {
                invitation_token: token,
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

fn read_master_password(master_password: Option<Zeroizing<String>>) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(match master_password {
        Some(value) => value.as_bytes().to_vec(),
        None => rpassword::prompt_password("Seren Passwords master password: ")
            .context("failed to read master password")?
            .into_bytes(),
    }))
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
    // Strip one terminal newline without trimming intentional secret content.
    let mut s = read_stdin()?;
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    } else if s.ends_with('\r') {
        s.pop();
    }
    Ok(s)
}

fn atty_stdin() -> bool {
    std::io::IsTerminal::is_terminal(&io::stdin())
}

#[cfg(test)]
mod tests {
    use super::{
        BASE64, attachment_aad, decode_passwords_gateway_body, ensure_distinct_transfer_vaults,
        membership_grant_signature, passwords_api_base_url, rewrap_attachment_for_rotation,
    };
    use base64::Engine;
    use seren_secrets_crypto::aead::xchacha20_decrypt_with_aad;
    use seren_secrets_crypto::keys::{IdentitySigningKeypair, IdentitySigningPrivateKey};
    use seren_secrets_crypto::protocol::vault::generate_vault_key;
    use uuid::Uuid;

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
            (seren::AccessLevel::Admin, 0),
            (seren::AccessLevel::Write, 1),
            (seren::AccessLevel::Read, 2),
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
    fn attachment_rotation_rewraps_with_expected_aad() {
        let old_vault_key = generate_vault_key();
        let new_vault_key = generate_vault_key();
        let item_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let attachment_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        let filename_aad = attachment_aad("attachment-filename", item_id, attachment_id);
        assert_eq!(&filename_aad[..20], b"attachment-filename:");
        assert_eq!(&filename_aad[20..36], item_id.as_bytes());
        assert_eq!(filename_aad[36], b':');
        assert_eq!(&filename_aad[37..], attachment_id.as_bytes());

        let filename = b"report.pdf";
        let content_type = b"application/pdf";
        let content_key = [9u8; 32];
        let attachment = seren::AttachmentView {
            attachment_id,
            content_type_ciphertext: BASE64.encode(
                seren_secrets_crypto::aead::xchacha20_encrypt_with_aad(
                    old_vault_key.as_bytes(),
                    content_type,
                    &attachment_aad("attachment-content-type", item_id, attachment_id),
                ),
            ),
            created_at: "2030-01-01T00:00:00Z".parse().unwrap(),
            filename_ciphertext: BASE64.encode(
                seren_secrets_crypto::aead::xchacha20_encrypt_with_aad(
                    old_vault_key.as_bytes(),
                    filename,
                    &filename_aad,
                ),
            ),
            item_id,
            size_bytes: 123,
            wrapped_content_key: BASE64.encode(
                seren_secrets_crypto::aead::xchacha20_encrypt_with_aad(
                    old_vault_key.as_bytes(),
                    &content_key,
                    &attachment_aad("attachment-content-key", item_id, attachment_id),
                ),
            ),
        };

        let rotated =
            rewrap_attachment_for_rotation(&old_vault_key, &new_vault_key, item_id, &attachment)
                .unwrap();

        let rotated_filename = BASE64.decode(rotated.filename_ciphertext).unwrap();
        assert!(
            xchacha20_decrypt_with_aad(old_vault_key.as_bytes(), &rotated_filename, &filename_aad)
                .is_err()
        );
        assert_eq!(
            xchacha20_decrypt_with_aad(new_vault_key.as_bytes(), &rotated_filename, &filename_aad)
                .unwrap(),
            filename
        );
        assert_eq!(
            xchacha20_decrypt_with_aad(
                new_vault_key.as_bytes(),
                &BASE64.decode(rotated.content_type_ciphertext).unwrap(),
                &attachment_aad("attachment-content-type", item_id, attachment_id),
            )
            .unwrap(),
            content_type
        );
        assert_eq!(
            xchacha20_decrypt_with_aad(
                new_vault_key.as_bytes(),
                &BASE64.decode(rotated.wrapped_content_key).unwrap(),
                &attachment_aad("attachment-content-key", item_id, attachment_id),
            )
            .unwrap(),
            content_key
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
}
