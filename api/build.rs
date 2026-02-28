use std::{collections::HashSet, env, fs, path::PathBuf};

use openapiv3::{
    ReferenceOr, Schema, SchemaData, SchemaKind, StringFormat, StringType, VariantOrUnknownOrEmpty,
};
use progenitor::{GenerationSettings, InterfaceStyle};

fn collect_refs(value: &serde_json::Value, acc: &mut HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(reference)) = map.get("$ref")
                && let Some(name) = reference.split('/').next_back()
            {
                acc.insert(name.to_string());
            }
            for v in map.values() {
                collect_refs(v, acc);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_refs(v, acc);
            }
        }
        _ => {}
    }
}

/// Strip content bodies from error responses that would otherwise create multiple typed
/// responses per operation during progenitor code generation.
///
/// Progenitor can only handle one typed response per operation, so we remove the
/// error content schemas while keeping them documented in the source OpenAPI spec.
fn strip_error_response_content(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Object(resp_obj)) = map.get_mut("402") {
                resp_obj.remove("content");
            }
            if let Some(serde_json::Value::Object(resp_obj)) = map.get_mut("403") {
                resp_obj.remove("content");
            }
            for v in map.values_mut() {
                strip_error_response_content(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                strip_error_response_content(v);
            }
        }
        _ => {}
    }
}

/// Normalize binary media schemas so progenitor can generate typed responses.
///
/// Some endpoints emit `application/octet-stream` with an unconstrained schema
/// (`AnySchema`). Progenitor rejects that shape, so we normalize it to
/// `{ type: "string", format: "binary" }`.
fn normalize_binary_content_schemas(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Object(content)) = map.get_mut("content")
                && let Some(serde_json::Value::Object(media)) =
                    content.get_mut("application/octet-stream")
            {
                media.insert(
                    "schema".to_string(),
                    serde_json::json!({ "type": "string", "format": "binary" }),
                );
            }

            for v in map.values_mut() {
                normalize_binary_content_schemas(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                normalize_binary_content_schemas(v);
            }
        }
        _ => {}
    }
}

fn ensure_schema(components: &mut openapiv3::Components, name: &str, schema: Schema) {
    components
        .schemas
        .entry(name.to_string())
        .or_insert_with(|| ReferenceOr::Item(schema));
}

fn default_string_schema() -> Schema {
    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(openapiv3::Type::String(StringType::default())),
    }
}

/// Convert OpenAPI 3.1 constructs to 3.0 equivalents for progenitor compatibility:
/// - `"type": ["string", "null"]` → `"type": "string", "nullable": true`
/// - `"oneOf": [{"type":"null"}, {...}]` → the non-null variant + `"nullable": true`
/// - `"items": {}` (any-type) → `"items": {"type": "object"}`
fn downconvert_31_to_30(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // Convert array-typed nullables: "type": ["string", "null"]
            if let Some(serde_json::Value::Array(types)) = map.get("type") {
                let non_null: Vec<serde_json::Value> = types
                    .iter()
                    .filter(|t| t.as_str() != Some("null"))
                    .cloned()
                    .collect();
                let has_null = types.iter().any(|t| t.as_str() == Some("null"));
                if has_null && non_null.len() == 1 {
                    map.insert("type".into(), non_null[0].clone());
                    map.insert("nullable".into(), serde_json::Value::Bool(true));
                }
            }

            // Convert oneOf nullable: "oneOf": [{"type":"null"}, {$ref or schema}]
            if let Some(serde_json::Value::Array(variants)) = map.get("oneOf") {
                let non_null: Vec<&serde_json::Value> = variants
                    .iter()
                    .filter(|v| {
                        v.as_object()
                            .and_then(|o| o.get("type"))
                            .and_then(|t| t.as_str())
                            != Some("null")
                    })
                    .collect();
                let has_null = variants.len() > non_null.len();
                if has_null && non_null.len() == 1 {
                    // Flatten: replace oneOf with the non-null variant's properties
                    let replacement = non_null[0].clone();
                    map.remove("oneOf");
                    map.insert("nullable".into(), serde_json::Value::Bool(true));
                    if let serde_json::Value::Object(inner) = replacement {
                        for (k, v) in inner {
                            map.insert(k, v);
                        }
                    }
                }
            }

            // Convert empty items (any-type) to object
            if let Some(serde_json::Value::Object(items)) = map.get("items")
                && items.is_empty()
            {
                map.insert("items".into(), serde_json::json!({"type": "object"}));
            }

            for v in map.values_mut() {
                downconvert_31_to_30(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                downconvert_31_to_30(v);
            }
        }
        _ => {}
    }
}

/// Remap publisher-specific response schema names to their monolithic spec equivalents.
/// This ensures progenitor generates consistent types across old and new endpoints.
fn remap_publisher_refs(value: &mut serde_json::Value) {
    static REMAP: &[(&str, &str)] = &[
        ("DataResponse_Vec_Project", "PaginatedProjectResponse"),
        ("DataResponse_Project", "ProjectResponse"),
        ("DataResponse_ProjectCreated", "ProjectCreatedResponse"),
        (
            "DataResponse_ProjectConnectionUri",
            "ProjectConnectionUriDataResponse",
        ),
        ("DataResponse_Vec_Branch", "BranchesResponse"),
        ("DataResponse_Branch", "BranchResponse"),
        (
            "DataResponse_BranchCreationResult",
            "BranchCreationResultResponse",
        ),
        (
            "DataResponse_Vec_DatabaseWithOwner",
            "DatabasesWithOwnerResponse",
        ),
        (
            "DataResponse_DatabaseWithOwner",
            "DatabaseWithOwnerResponse",
        ),
        ("DataResponse_DatabaseCreated", "DatabaseCreatedResponse"),
        ("DataResponse_Vec_RoleInfo", "RoleInfosResponse"),
        ("DataResponse_RoleCreated", "RoleCreatedResponse"),
        (
            "DataResponse_RolePasswordReset",
            "RolePasswordResetResponse",
        ),
        ("DataResponse_Vec_Endpoint", "EndpointsResponse"),
        ("DataResponse_Endpoint", "EndpointResponse"),
        ("DataResponse_EndpointCreated", "EndpointCreatedResponse"),
        (
            "DataResponse_EndpointStatusInfo",
            "EndpointStatusInfoResponse",
        ),
    ];

    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(r)) = map.get_mut("$ref") {
                for (from, to) in REMAP {
                    let from_ref = format!("#/components/schemas/{from}");
                    if r == &from_ref {
                        *r = format!("#/components/schemas/{to}");
                        break;
                    }
                }
            }
            for v in map.values_mut() {
                remap_publisher_refs(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                remap_publisher_refs(v);
            }
        }
        _ => {}
    }
}

/// Merge a publisher spec's paths and schemas into the main spec JSON.
fn merge_publisher_spec(main: &mut serde_json::Value, publisher_path: &str, publisher_slug: &str) {
    let Ok(publisher_str) = fs::read_to_string(publisher_path) else {
        return;
    };
    let Ok(mut publisher): Result<serde_json::Value, _> = serde_json::from_str(&publisher_str)
    else {
        return;
    };

    // Convert 3.1 nullable syntax to 3.0 for progenitor compatibility.
    downconvert_31_to_30(&mut publisher);

    // Remap publisher response types to monolithic spec equivalents.
    remap_publisher_refs(&mut publisher);

    // Merge paths.
    // Publisher specs now use relative paths; convert to absolute paths under
    // /publishers/<slug> when composing the monolithic client spec.
    if let (Some(main_paths), Some(pub_paths)) = (
        main.get_mut("paths").and_then(|v| v.as_object_mut()),
        publisher.get("paths").and_then(|v| v.as_object()),
    ) {
        for (path, item) in pub_paths {
            let absolute_path = if path.starts_with("/publishers/") {
                path.to_string()
            } else if path == "/" {
                format!("/publishers/{publisher_slug}")
            } else if path.starts_with('/') {
                format!("/publishers/{publisher_slug}{path}")
            } else {
                format!("/publishers/{publisher_slug}/{path}")
            };

            main_paths
                .entry(absolute_path)
                .or_insert_with(|| item.clone());
        }
    }

    // Merge component schemas
    if let (Some(main_schemas), Some(pub_schemas)) = (
        main.pointer_mut("/components/schemas")
            .and_then(|v| v.as_object_mut()),
        publisher
            .pointer("/components/schemas")
            .and_then(|v| v.as_object()),
    ) {
        for (name, schema) in pub_schemas {
            main_schemas.entry(name).or_insert_with(|| schema.clone());
        }
    }
}
fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../openapi/openapi.json");
    println!("cargo:rerun-if-changed=../openapi/openapi-seren-db.json");
    println!("cargo:rerun-if-changed=../openapi/openapi-seren-cloud.json");

    let spec_str = fs::read_to_string("../openapi/openapi.json")?;
    let mut raw_json: serde_json::Value = serde_json::from_str(&spec_str)?;

    // Merge per-publisher specs so the generated client includes publisher endpoints.
    merge_publisher_spec(
        &mut raw_json,
        "../openapi/openapi-seren-db.json",
        "seren-db",
    );
    merge_publisher_spec(
        &mut raw_json,
        "../openapi/openapi-seren-cloud.json",
        "seren-cloud",
    );

    // Normalize OpenAPI 3.1 nullable syntax before deserializing with openapiv3.
    downconvert_31_to_30(&mut raw_json);
    raw_json["openapi"] = serde_json::json!("3.0.3");

    // Strip 402/403 response content bodies for progenitor code generation.
    // Progenitor panics with "response_types.len() <= 1" if an operation has
    // multiple typed responses (e.g., 200 success + 402 payment required).
    // We still document error bodies in the source OpenAPI spec - this only affects codegen.
    // The generated code will use UnexpectedResponse for these statuses, preserving the raw
    // response so callers can deserialize the error body manually when needed.
    strip_error_response_content(&mut raw_json);
    normalize_binary_content_schemas(&mut raw_json);

    let mut refs = HashSet::new();
    collect_refs(&raw_json, &mut refs);

    let mut spec: openapiv3::OpenAPI = serde_json::from_value(raw_json)?;

    let components = spec.components.get_or_insert_with(Default::default);

    for reference in refs {
        match reference.as_str() {
            "OffsetDateTime" => ensure_schema(
                components,
                &reference,
                Schema {
                    schema_data: SchemaData::default(),
                    schema_kind: SchemaKind::Type(openapiv3::Type::String(StringType {
                        format: VariantOrUnknownOrEmpty::Item(StringFormat::DateTime),
                        ..Default::default()
                    })),
                },
            ),
            "Uuid" => ensure_schema(
                components,
                &reference,
                Schema {
                    schema_data: SchemaData::default(),
                    schema_kind: SchemaKind::Type(openapiv3::Type::String(StringType {
                        format: VariantOrUnknownOrEmpty::Unknown("uuid".into()),
                        ..Default::default()
                    })),
                },
            ),
            _ => {
                ensure_schema(components, &reference, default_string_schema());
            }
        }
    }

    let mut settings = GenerationSettings::default();
    settings.with_interface(InterfaceStyle::Positional);
    settings.with_derive("schemars::JsonSchema");

    // Replace chrono DateTime with jiff Timestamp for date-time format
    settings.with_replacement(
        "chrono::DateTime<chrono::offset::Utc>",
        "::jiff::Timestamp",
        std::iter::empty::<progenitor::TypeImpl>(),
    );

    settings.with_replacement(
        "OffsetDateTime",
        "::jiff::Timestamp",
        std::iter::empty::<progenitor::TypeImpl>(),
    );
    settings.with_replacement(
        "Uuid",
        "::uuid::Uuid",
        std::iter::empty::<progenitor::TypeImpl>(),
    );

    let mut generator = progenitor::Generator::new(&settings);
    let tokens = generator.generate_tokens(&spec)?;

    let syntax: syn::File = syn::parse2(tokens)?;
    // Generate full client with types - no longer filtering to types only

    let formatted = prettyplease::unparse(&syntax);

    // Replace chrono with jiff in the generated code
    // Progenitor 0.11+ uses fully qualified paths with leading ::
    let formatted = formatted
        .replace(
            "::chrono::DateTime<::chrono::offset::Utc>",
            "::jiff::Timestamp",
        )
        .replace("chrono::DateTime<chrono::offset::Utc>", "::jiff::Timestamp");

    // Convert 402 responses from ErrorResponse (which discards body) to UnexpectedResponse
    // (which preserves the raw response). This allows callers to deserialize 402 bodies
    // for payment-required flows while keeping 402 documented in the OpenAPI spec.
    let formatted = formatted.replace(
        "402u16 => Err(Error::ErrorResponse(ResponseValue::empty(response)))",
        "402u16 => Err(Error::UnexpectedResponse(response))",
    );
    let formatted = formatted.replace(
        "403u16 => Err(Error::ErrorResponse(ResponseValue::empty(response)))",
        "403u16 => Err(Error::UnexpectedResponse(response))",
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::create_dir_all(&out_dir)?;
    fs::write(out_dir.join("generated.rs"), formatted)?;

    Ok(())
}
