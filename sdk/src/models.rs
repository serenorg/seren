use serde::{Deserialize, Serialize};

/// Managed deployment view with any pending stop refusal.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ManagedDeploymentReadResponse {
    #[serde(flatten)]
    pub deployment: crate::ManagedDeploymentReadView,
    pub pending_stop_refusal: Option<crate::ManagedDeploymentPendingStopRefusal>,
}

/// Changes the named profile fields; omitted fields retain their stored value.
/// Text can be cleared with null, and lists can be cleared with an empty list.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PutManagedAgentTemplateProfile {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_list::<_, _, 8>"
    )]
    #[schemars(with = "Vec<crate::CapabilityLabel>", length(max = 8))]
    pub capabilities: Option<Vec<crate::CapabilityLabel>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub description: Option<Option<crate::Description>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_list::<_, _, 3>"
    )]
    #[schemars(with = "Vec<crate::ExampleTask>", length(max = 3))]
    pub example_tasks: Option<Vec<crate::ExampleTask>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub job_title: Option<Option<crate::JobTitle>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_non_null"
    )]
    #[schemars(with = "crate::Pronouns")]
    pub pronouns: Option<crate::Pronouns>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub tagline: Option<Option<crate::Tagline>>,
    /// Each tool at most once, in the order the card shows them.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_list::<_, _, 13>"
    )]
    #[schemars(with = "Vec<crate::ManagedAgentTemplateTool>", length(max = 13))]
    pub works_in: Option<Vec<crate::ManagedAgentTemplateTool>>,
}

/// A supplied non-null value is distinct from an omitted field's default.
fn deserialize_optional_non_null<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn deserialize_optional_list<'de, T, D, const MAX: usize>(
    deserializer: D,
) -> Result<Option<Vec<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.len() > MAX {
        return Err(serde::de::Error::custom(format!(
            "expected at most {MAX} items"
        )));
    }
    Ok(Some(values))
}

/// Changes to an OAuth provider. An omitted field stays unchanged.
///
/// Double-option fields distinguish omission (`None`), an explicit null reset
/// (`Some(None)`), and a supplied value (`Some(Some(value))`). Other fields treat
/// null as omitted. Ownership changes are supported only by the admin endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateOAuthProviderRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// New client secret, stored encrypted. If omitted, the existing secret is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Custom provider-specific authorization URL parameters. If omitted, left unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_auth_params: Option<serde_json::Value>,
    /// If omitted, left unchanged. If null, cleared.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    /// If omitted, left unchanged. If null, cleared.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub logo_url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Admin-only ownership change: omitted leaves it unchanged; null makes it global.
    /// Moving a sealed organization secret requires an explicit replacement secret.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub organization_id: Option<Option<uuid::Uuid>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkce_required: Option<bool>,
    /// Revocation request shape, `form_token` or `bearer`. If omitted, left
    /// unchanged. If null, reset to `form_token`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub revocation_auth: Option<Option<crate::RevocationAuth>>,
    /// If omitted, left unchanged. If null, cleared.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub revocation_url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<crate::TokenEndpointAuthMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    /// JSON Pointer (RFC 6901) to the account email in the lookup reply. If
    /// omitted, left unchanged. If null, cleared so the email is read from `email`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub userinfo_email_path: Option<Option<String>>,
    /// JSON Pointer (RFC 6901) to the account ID in the lookup reply. If omitted,
    /// left unchanged. If null, cleared so the ID is read from `sub` or `id`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub userinfo_id_path: Option<Option<String>>,
    /// Account lookup method, `get` or `post`. If omitted, left unchanged. If
    /// null, reset to `get`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub userinfo_method: Option<Option<crate::UserinfoMethod>>,
    /// If omitted, left unchanged. If null, cleared.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub userinfo_url: Option<Option<String>>,
}

/// Preserve a present null separately from an omitted field's default.
fn deserialize_double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

// ===================== Schema Diff Types (not in OpenAPI spec) =====================

/// Schema diff result comparing two branches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDiff {
    pub base_branch_id: String,
    pub compare_branch_id: String,
    pub differences: Vec<SchemaDifference>,
}

/// Types of schema differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SchemaDifference {
    TableAdded {
        table_name: String,
        schema_name: String,
    },
    TableRemoved {
        table_name: String,
        schema_name: String,
    },
    TableModified {
        table_name: String,
        schema_name: String,
        changes: Vec<TableChange>,
    },
}

/// Changes within a modified table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "change_type", rename_all = "snake_case")]
pub enum TableChange {
    ColumnAdded {
        column_name: String,
        data_type: String,
        is_nullable: bool,
    },
    ColumnRemoved {
        column_name: String,
        data_type: String,
    },
    ColumnModified {
        column_name: String,
        old_type: String,
        new_type: String,
        nullable_changed: Option<bool>,
    },
    IndexAdded {
        index_name: String,
        is_unique: bool,
        columns: Vec<String>,
    },
    IndexRemoved {
        index_name: String,
    },
    ConstraintAdded {
        constraint_name: String,
        constraint_type: String,
    },
    ConstraintRemoved {
        constraint_name: String,
        constraint_type: String,
    },
}

/// Request parameters for schema diff.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaDiffRequest {
    pub base_branch_id: String,
    pub compare_branch_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
}

impl SchemaDiffRequest {
    pub fn new(base_branch_id: impl Into<String>, compare_branch_id: impl Into<String>) -> Self {
        Self {
            base_branch_id: base_branch_id.into(),
            compare_branch_id: compare_branch_id.into(),
            database: None,
        }
    }

    pub fn with_database(mut self, database: impl Into<String>) -> Self {
        self.database = Some(database.into());
        self
    }
}

// ===================== Endpoint Types (not in OpenAPI spec) =====================

/// Health status for an endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointHealth {
    pub status: String,
    pub replicas: i32,
    pub ready_replicas: i32,
    pub available_replicas: i32,
    pub unavailable_replicas: i32,
}

/// Resource metrics for an endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointMetrics {
    pub pod_count: i32,
    pub cpu_request_millicores: i64,
    pub memory_request_bytes: i64,
}

// ===================== Session Management Types (not in OpenAPI spec) =====================

/// Response for listing user sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: uuid::Uuid,
    pub created_at: jiff::Timestamp,
    pub last_active_at: jiff::Timestamp,
    pub expires_at: jiff::Timestamp,
    pub is_current: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

/// Response when revoking sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeSessionResponse {
    pub revoked_count: i64,
}

// ===================== Webhook Types (not in OpenAPI spec) =====================

/// Webhook configuration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookResponse {
    pub id: uuid::Uuid,
    pub organization_id: uuid::Uuid,
    pub url: String,
    pub event_types: Vec<String>,
    pub is_active: bool,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

// ===================== RBAC Types (not in OpenAPI spec) =====================

/// RBAC Role response (organization-level roles, distinct from database roles)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationRoleResponse {
    pub id: uuid::Uuid,
    pub organization_id: Option<uuid::Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub is_built_in: bool,
    pub permissions: Vec<String>,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

/// Request to create an organization role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrganizationRoleRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

/// Request to update an organization role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOrganizationRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
}

/// Request to assign a role to a member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignOrganizationRoleRequest {
    pub role_id: uuid::Uuid,
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationPermission {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub action: String,
}

// ===================== Publication/Replication Types (not in OpenAPI spec) =====================

/// Publication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationResponse {
    pub id: uuid::Uuid,
    pub branch_id: uuid::Uuid,
    pub name: String,
    pub table_names: Vec<String>,
    pub all_tables: bool,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

/// Replication slot response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationSlotResponse {
    pub id: uuid::Uuid,
    pub branch_id: uuid::Uuid,
    pub name: String,
    pub plugin: String,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

#[cfg(test)]
mod template_profile_patch_tests {
    use super::PutManagedAgentTemplateProfile;
    use serde_json::json;

    #[test]
    fn profile_patch_preserves_omission_clear_and_supplied_values() {
        for wire in [
            json!({}),
            json!({"job_title": null, "tagline": null, "description": null}),
            json!({"capabilities": [], "example_tasks": [], "works_in": []}),
            json!({"job_title": "Researcher", "tagline": "Research made clear",
                "description": "Find and summarize primary sources.",
                "capabilities": ["Research"], "example_tasks": ["Summarize the latest report"],
                "works_in": ["1password", "google-drive", "slack"], "pronouns": "they/them"}),
        ] {
            let patch: PutManagedAgentTemplateProfile =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(patch).unwrap(), wire);
        }
        let omitted: PutManagedAgentTemplateProfile = serde_json::from_value(json!({})).unwrap();
        assert!(omitted.job_title.is_none());
        assert!(omitted.tagline.is_none());
        assert!(omitted.description.is_none());
        assert!(omitted.capabilities.is_none());
        assert!(omitted.example_tasks.is_none());
        assert!(omitted.works_in.is_none());
        assert!(omitted.pronouns.is_none());
        let cleared: PutManagedAgentTemplateProfile = serde_json::from_value(json!({
            "job_title": null, "tagline": null, "description": null
        }))
        .unwrap();
        assert!(matches!(cleared.job_title, Some(None)));
        assert!(matches!(cleared.tagline, Some(None)));
        assert!(matches!(cleared.description, Some(None)));
        assert_eq!(
            serde_json::to_value(PutManagedAgentTemplateProfile::default()).unwrap(),
            json!({})
        );
    }

    #[test]
    fn profile_patch_rejects_null_non_null_fields_and_closed_wire_values() {
        for wire in [
            json!({"capabilities": null}),
            json!({"example_tasks": null}),
            json!({"works_in": null}),
            json!({"pronouns": null}),
            json!({"pronouns": "unknown"}),
            json!({"works_in": ["unknown"]}),
            json!({"capabilities": [null]}),
            json!({"example_tasks": [7]}),
            json!({"avatar_url": "https://example.com/avatar.png"}),
        ] {
            assert!(
                serde_json::from_value::<PutManagedAgentTemplateProfile>(wire.clone()).is_err(),
                "{wire}"
            );
        }
    }

    #[test]
    fn profile_patch_enforces_named_text_and_list_bounds() {
        for (field, maximum) in [("capabilities", 8), ("example_tasks", 3), ("works_in", 13)] {
            let items = if field == "works_in" {
                vec![
                    "1password",
                    "canva",
                    "discord",
                    "gmail",
                    "google",
                    "google-drive",
                    "microsoft",
                    "onedrive",
                    "outlook",
                    "shopify",
                    "signal",
                    "slack",
                    "whatsapp",
                ]
            } else {
                vec!["Research"; maximum]
            };
            let at_limit = json!({field: items});
            let decoded: PutManagedAgentTemplateProfile =
                serde_json::from_value(at_limit.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), at_limit);
            let item = if field == "works_in" {
                "slack"
            } else {
                "Research"
            };
            let oversized = json!({field: vec![item; maximum + 1]});
            assert!(serde_json::from_value::<PutManagedAgentTemplateProfile>(oversized).is_err());
        }
        for (field, maximum, list) in [
            ("job_title", 60, false),
            ("tagline", 120, false),
            ("description", 2000, false),
            ("capabilities", 80, true),
            ("example_tasks", 80, true),
        ] {
            for length in [0, maximum + 1] {
                let text = "x".repeat(length);
                let value = if list { json!([text]) } else { json!(text) };
                assert!(
                    serde_json::from_value::<PutManagedAgentTemplateProfile>(json!({field: value}))
                        .is_err(),
                    "{field}: {length}"
                );
            }
            let text = "x".repeat(maximum);
            let wire = json!({field: if list { json!([text]) } else { json!(text) }});
            let decoded: PutManagedAgentTemplateProfile =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
        }
    }

    #[test]
    fn profile_patch_schema_advertises_optional_non_null_lists_and_pronouns() {
        let schema =
            serde_json::to_value(schemars::schema_for!(PutManagedAgentTemplateProfile)).unwrap();
        assert!(
            schema
                .get("required")
                .is_none_or(|required| required.as_array().unwrap().is_empty())
        );
        assert_eq!(schema["additionalProperties"], false);
        for (field, maximum) in [("capabilities", 8), ("example_tasks", 3), ("works_in", 13)] {
            assert_eq!(schema["properties"][field]["type"], "array");
            assert_eq!(schema["properties"][field]["maxItems"], maximum);
        }
        let pronouns = &schema["properties"]["pronouns"];
        let pronouns = pronouns
            .get("$ref")
            .and_then(serde_json::Value::as_str)
            .map_or(pronouns, |reference| {
                schema
                    .pointer(reference.strip_prefix('#').unwrap())
                    .unwrap()
            });
        assert_eq!(pronouns["type"], "string");
        let values = pronouns["enum"].as_array().unwrap();
        assert_eq!(values.len(), 3);
        for value in ["she/her", "he/him", "they/them"] {
            assert!(values.contains(&json!(value)));
        }
    }
}

#[cfg(test)]
mod oauth_provider_update_tests {
    use super::UpdateOAuthProviderRequest;
    use serde_json::json;

    #[test]
    fn oauth_provider_update_preserves_omission_null_and_values() {
        for wire in [
            json!({}),
            json!({"description": null, "logo_url": null, "userinfo_url": null,
                "revocation_url": null, "organization_id": null}),
            json!({"description": "", "logo_url": "", "userinfo_url": "",
                "revocation_url": "", "organization_id": "00000000-0000-0000-0000-000000000001",
                "is_active": false, "scopes": []}),
            json!({"userinfo_method": null, "userinfo_id_path": null,
                "userinfo_email_path": null, "revocation_auth": null}),
            json!({"userinfo_method": "post", "userinfo_id_path": "/account/id",
                "userinfo_email_path": "/account/email", "revocation_auth": "bearer"}),
            json!({"userinfo_method": "get", "revocation_auth": "form_token"}),
            json!({"userinfo_method": null, "userinfo_email_path": "/email", "is_active": false}),
        ] {
            let request: UpdateOAuthProviderRequest = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(request).unwrap(), wire);
        }
        assert_eq!(
            serde_json::to_value(UpdateOAuthProviderRequest::default()).unwrap(),
            json!({})
        );
    }

    #[test]
    fn oauth_provider_update_retains_outer_presence() {
        let omitted: UpdateOAuthProviderRequest = serde_json::from_value(json!({})).unwrap();
        assert!(omitted.userinfo_method.is_none());
        assert!(omitted.userinfo_id_path.is_none());
        assert!(omitted.userinfo_email_path.is_none());
        assert!(omitted.revocation_auth.is_none());
        assert!(omitted.description.is_none());
        assert!(omitted.logo_url.is_none());
        assert!(omitted.userinfo_url.is_none());
        assert!(omitted.revocation_url.is_none());
        assert!(omitted.organization_id.is_none());
        let cleared: UpdateOAuthProviderRequest = serde_json::from_value(json!({
            "userinfo_method": null, "userinfo_id_path": null,
            "userinfo_email_path": null, "revocation_auth": null,
            "description": null, "logo_url": null, "userinfo_url": null,
            "revocation_url": null, "organization_id": null
        }))
        .unwrap();
        assert!(matches!(cleared.userinfo_method, Some(None)));
        assert!(matches!(cleared.userinfo_id_path, Some(None)));
        assert!(matches!(cleared.userinfo_email_path, Some(None)));
        assert!(matches!(cleared.revocation_auth, Some(None)));
        assert!(matches!(cleared.description, Some(None)));
        assert!(matches!(cleared.logo_url, Some(None)));
        assert!(matches!(cleared.userinfo_url, Some(None)));
        assert!(matches!(cleared.revocation_url, Some(None)));
        assert!(matches!(cleared.organization_id, Some(None)));
        let supplied: UpdateOAuthProviderRequest = serde_json::from_value(json!({
            "userinfo_method": "post", "userinfo_id_path": "/account/id",
            "userinfo_email_path": "", "revocation_auth": "bearer",
            "description": "", "logo_url": "", "userinfo_url": "",
            "revocation_url": "", "organization_id": "00000000-0000-0000-0000-000000000001"
        }))
        .unwrap();
        assert!(matches!(supplied.userinfo_method, Some(Some(_))));
        assert!(matches!(supplied.revocation_auth, Some(Some(_))));
        assert_eq!(
            supplied.userinfo_id_path,
            Some(Some("/account/id".to_string()))
        );
        // An empty pointer is a supplied value, not a reset.
        assert_eq!(supplied.userinfo_email_path, Some(Some(String::new())));
        for value in [
            supplied.description,
            supplied.logo_url,
            supplied.userinfo_url,
            supplied.revocation_url,
        ] {
            assert_eq!(value, Some(Some(String::new())));
        }
        assert_eq!(
            supplied.organization_id,
            Some(Some(uuid::Uuid::from_u128(1)))
        );
    }

    /// Unchanged fields keep their single-`Option` public types: a present null
    /// decodes as omitted and re-encodes as omitted.
    #[test]
    fn oauth_provider_update_keeps_unrelated_fields_single_optional() {
        let request: UpdateOAuthProviderRequest = serde_json::from_value(json!({
            "is_active": null, "custom_auth_params": null,
            "client_secret": null, "scopes": null
        }))
        .unwrap();
        assert!(request.is_active.is_none());
        assert!(request.client_secret.is_none());
        assert!(request.scopes.is_none());
        assert!(request.custom_auth_params.is_none());
        assert_eq!(serde_json::to_value(request).unwrap(), json!({}));
    }

    #[test]
    fn oauth_provider_update_preserves_existing_field_types_and_values() {
        let wire = json!({
            "authorization_url": "https://provider.example/authorize",
            "client_id": "client", "client_secret": "test-secret",
            "custom_auth_params": {"prompt": "consent"}, "description": "Provider",
            "is_active": false, "logo_url": "https://provider.example/logo.png",
            "name": "Provider", "organization_id": "00000000-0000-0000-0000-000000000001",
            "pkce_required": false, "revocation_url": "https://provider.example/revoke",
            "scopes": [], "slug": "provider", "token_endpoint_auth_method": "client_secret_basic",
            "token_url": "https://provider.example/token", "userinfo_url": "https://provider.example/user"
        });
        let request: UpdateOAuthProviderRequest = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), wire);
    }

    #[test]
    fn oauth_provider_update_rejects_invalid_modes_and_field_types() {
        for wire in [
            json!({"userinfo_method": "put"}),
            json!({"revocation_auth": "basic"}),
            json!({"userinfo_id_path": false}),
            json!({"userinfo_email_path": 1}),
            json!({"organization_id": "not-a-uuid"}),
            json!({"unrecognized_setting": true}),
            json!({"userinfo_method": ["post"]}),
            json!({"revocation_auth": {"mode": "bearer"}}),
            json!({"is_active": "false"}),
            json!({"description": false}),
            json!({"logo_url": 1}),
            json!({"userinfo_url": []}),
            json!({"revocation_url": {}}),
            json!("userinfo_method"),
        ] {
            assert!(serde_json::from_value::<UpdateOAuthProviderRequest>(wire).is_err());
        }
    }

    #[tokio::test]
    async fn oauth_provider_update_sends_exact_patch_presence() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_json, method, path},
        };

        for wire in [
            json!({"name": "Changed name"}),
            json!({"description": null, "logo_url": null,
                "userinfo_url": null, "revocation_url": null, "organization_id": null}),
            json!({"description": "", "logo_url": "", "userinfo_url": "",
                "revocation_url": "", "is_active": false, "scopes": []}),
            json!({"userinfo_method": null, "userinfo_id_path": null,
                "userinfo_email_path": null, "revocation_auth": null}),
            json!({"userinfo_method": "post", "userinfo_id_path": "/id",
                "userinfo_email_path": "/email", "revocation_auth": "bearer", "pkce_required": false}),
        ] {
            let proxy = MockServer::start().await;
            let organization_id = uuid::Uuid::from_u128(1);
            let provider_id = uuid::Uuid::from_u128(2);
            Mock::given(method("PATCH"))
                .and(path(format!(
                    "/organizations/{organization_id}/oauth/providers/{provider_id}"
                )))
                .and(body_json(wire.clone()))
                .respond_with(ResponseTemplate::new(409))
                .expect(1)
                .mount(&proxy)
                .await;
            let request: UpdateOAuthProviderRequest = serde_json::from_value(wire.clone()).unwrap();
            let error = crate::Client::new(&proxy.uri())
                .update_org_oauth_provider(&organization_id, &provider_id, &request)
                .await
                .expect_err("the test upstream refuses the update after receiving its exact body");
            assert_eq!(error.status(), Some(reqwest::StatusCode::CONFLICT));
            let received = proxy.received_requests().await.unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].body_json::<serde_json::Value>().unwrap(), wire);
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ProviderOperation {
        Get,
        List,
        Create,
        Update,
    }

    fn oauth_provider_response_wire() -> serde_json::Value {
        json!({
            "id": "00000000-0000-0000-0000-000000000002",
            "organization_id": "00000000-0000-0000-0000-000000000001",
            "slug": "provider", "name": "Provider", "description": "Account lookup",
            "logo_url": "https://provider.example/logo.png",
            "authorization_url": "https://provider.example/authorize",
            "token_url": "https://provider.example/token",
            "userinfo_url": "https://provider.example/user",
            "revocation_url": "https://provider.example/revoke",
            "client_id": "client", "scopes": ["profile", "email"],
            "pkce_required": false, "token_endpoint_auth_method": "client_secret_basic",
            "userinfo_method": "get", "userinfo_id_path": null,
            "userinfo_email_path": null, "revocation_auth": "form_token",
            "is_active": false, "created_at": "2026-10-24T00:00:00Z",
            "updated_at": "2026-10-24T00:00:00Z"
        })
    }

    /// Calls one typed provider operation against a mock returning `wire` with the
    /// operation's success status. An error is the response decode message; any
    /// other failure, such as a transport or status mismatch, panics.
    async fn oauth_provider_http_response(
        operation: ProviderOperation,
        wire: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        let organization_id = uuid::Uuid::from_u128(1);
        let provider_id = uuid::Uuid::from_u128(2);
        let collection = format!("/organizations/{organization_id}/oauth/providers");
        let resource = format!("{collection}/{provider_id}");
        let (verb, route, status) = match operation {
            ProviderOperation::Get => ("GET", resource, 200),
            ProviderOperation::List => ("GET", collection, 200),
            ProviderOperation::Create => ("POST", collection, 201),
            ProviderOperation::Update => ("PATCH", resource, 200),
        };
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status).set_body_json(wire))
            .expect(1)
            .mount(&server)
            .await;
        let client = crate::Client::new(&server.uri());
        let result = match operation {
            ProviderOperation::Get => client
                .get_org_oauth_provider(&organization_id, &provider_id)
                .await
                .map(|response| serde_json::to_value(response.into_inner()).unwrap()),
            ProviderOperation::List => client
                .list_org_oauth_providers(&organization_id)
                .await
                .map(|response| serde_json::to_value(response.into_inner()).unwrap()),
            ProviderOperation::Create => {
                // Only required request fields: the response modes under test stay
                // independent of the closed request-mode enums.
                let request = serde_json::from_value(json!({
                    "slug": "provider", "name": "Provider",
                    "authorization_url": "https://provider.example/authorize",
                    "token_url": "https://provider.example/token", "client_id": "client",
                    "client_secret": "test-secret", "scopes": ["profile", "email"]
                }))
                .unwrap();
                client
                    .create_org_oauth_provider(&organization_id, &request)
                    .await
                    .map(|response| serde_json::to_value(response.into_inner()).unwrap())
            }
            ProviderOperation::Update => client
                .update_org_oauth_provider(
                    &organization_id,
                    &provider_id,
                    &UpdateOAuthProviderRequest::default(),
                )
                .await
                .map(|response| serde_json::to_value(response.into_inner()).unwrap()),
        };
        result.map_err(|error| match error {
            crate::Error::InvalidResponsePayload(_, error) => error.to_string(),
            other => panic!("{operation:?}: expected a response decode failure, got {other:?}"),
        })
    }

    fn normalize_optional_provider_paths(envelope: &mut serde_json::Value) {
        // The response schema permits null or omission for these optional paths.
        fn normalize(provider: &mut serde_json::Value) {
            let provider = provider.as_object_mut().unwrap();
            for field in ["userinfo_id_path", "userinfo_email_path"] {
                if provider.get(field).is_some_and(serde_json::Value::is_null) {
                    provider.remove(field);
                }
            }
        }
        if let Some(providers) = envelope["data"].as_array_mut() {
            for provider in providers {
                normalize(provider);
            }
        } else {
            normalize(&mut envelope["data"]);
        }
    }

    #[tokio::test]
    async fn oauth_provider_http_success_preserves_response_modes_and_paths() {
        for operation in [
            ProviderOperation::Get,
            ProviderOperation::List,
            ProviderOperation::Create,
            ProviderOperation::Update,
        ] {
            for (lookup, revocation, paths) in [
                (
                    "get",
                    "form_token",
                    json!({"userinfo_id_path": null, "userinfo_email_path": null}),
                ),
                (
                    "post",
                    "bearer",
                    json!({"userinfo_id_path": "/account/id", "userinfo_email_path": "/account/email"}),
                ),
                // The response schema types both modes as open strings; only requests use
                // the closed enums, so an unlisted response value still decodes verbatim.
                (
                    "provider_defined_lookup",
                    "provider_defined_revocation",
                    json!({"userinfo_id_path": "", "userinfo_email_path": ""}),
                ),
                ("get", "bearer", json!({})),
            ] {
                let mut provider = oauth_provider_response_wire();
                provider["userinfo_method"] = json!(lookup);
                provider["revocation_auth"] = json!(revocation);
                for field in ["userinfo_id_path", "userinfo_email_path"] {
                    provider.as_object_mut().unwrap().remove(field);
                }
                provider
                    .as_object_mut()
                    .unwrap()
                    .extend(paths.as_object().unwrap().clone());
                let mut expected = match operation {
                    ProviderOperation::List => json!({"data": [provider]}),
                    _ => json!({"data": provider}),
                };
                let mut actual = oauth_provider_http_response(operation, expected.clone())
                    .await
                    .unwrap();
                normalize_optional_provider_paths(&mut expected);
                normalize_optional_provider_paths(&mut actual);
                assert_eq!(actual, expected, "{operation:?}: {lookup}/{revocation}");
            }
        }
    }

    #[tokio::test]
    async fn oauth_provider_http_rejects_missing_required_response_modes() {
        for operation in [
            ProviderOperation::Get,
            ProviderOperation::List,
            ProviderOperation::Create,
            ProviderOperation::Update,
        ] {
            let envelope = |provider: serde_json::Value| match operation {
                ProviderOperation::List => json!({"data": [provider]}),
                _ => json!({"data": provider}),
            };
            // Positive control: the unmodified fixture decodes on this operation.
            oauth_provider_http_response(operation, envelope(oauth_provider_response_wire()))
                .await
                .unwrap_or_else(|error| {
                    panic!("{operation:?}: complete response rejected: {error}")
                });
            for missing in ["userinfo_method", "revocation_auth"] {
                let mut provider = oauth_provider_response_wire();
                provider.as_object_mut().unwrap().remove(missing);
                let error = oauth_provider_http_response(operation, envelope(provider))
                    .await
                    .expect_err("a response missing a required mode must not decode");
                assert!(
                    error.contains(&format!("missing field `{missing}`")),
                    "{operation:?} must reject only the missing {missing}: {error}"
                );
            }
        }
    }
}
