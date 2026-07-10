use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
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
            for (key, response) in map.iter_mut() {
                let is_error_status =
                    key == "default" || key.len() == 3 && key.starts_with(['4', '5']);
                if is_error_status && let serde_json::Value::Object(resp_obj) = response {
                    resp_obj.remove("content");
                }
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

/// Progenitor models optional nullable parameters as `Option<Option<T>>`, but
/// its header serialization path cannot render that shape. Optional parameters
/// already model absence, so strip the redundant null variant before codegen.
fn normalize_nullable_parameters(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("in").is_some()
                && map.get("required").and_then(|v| v.as_bool()) == Some(false)
                && let Some(serde_json::Value::Object(schema)) = map.get_mut("schema")
            {
                if let Some(serde_json::Value::Array(types)) = schema.get_mut("type") {
                    types.retain(|kind| kind.as_str() != Some("null"));
                    if types.len() == 1 {
                        let kind = types[0].clone();
                        schema.insert("type".to_string(), kind);
                    }
                }
                schema.remove("nullable");
            }

            for v in map.values_mut() {
                normalize_nullable_parameters(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                normalize_nullable_parameters(v);
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

fn source_wrapper_to_inner_name(source_wrapper: &str) -> Option<String> {
    if let Some(rest) = source_wrapper.strip_prefix("DataResponse_Vec_") {
        return Some(rest.to_string());
    }
    if let Some(rest) = source_wrapper.strip_prefix("DataResponse_") {
        return Some(rest.to_string());
    }
    None
}

fn expected_inner_schema_name(wrapper_name: &str) -> Option<String> {
    if let Some((from, _to)) = SCHEMA_REMAP.iter().find(|(_from, to)| *to == wrapper_name) {
        return source_wrapper_to_inner_name(from);
    }
    source_wrapper_to_inner_name(wrapper_name)
}

fn choose_ref_target(wrapper_name: &str, candidates: &[String]) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        return Some(candidates[0].clone());
    }

    if let Some(expected) = expected_inner_schema_name(wrapper_name) {
        let expected_matches: Vec<&String> = candidates
            .iter()
            .filter(|name| name.as_str() == expected.as_str())
            .collect();
        if expected_matches.len() == 1 {
            return Some(expected_matches[0].clone());
        }
    }

    None
}

fn normalize_schema_for_fingerprint(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // Drop documentation-only fields so equivalent schemas hash the same.
            const NON_STRUCTURAL_KEYS: &[&str] = &[
                "title",
                "description",
                "example",
                "examples",
                "externalDocs",
            ];

            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();

            let mut out = serde_json::Map::new();
            for key in keys {
                if NON_STRUCTURAL_KEYS.contains(&key) {
                    continue;
                }
                if let Some(v) = map.get(key) {
                    out.insert(key.to_string(), normalize_schema_for_fingerprint(v));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(normalize_schema_for_fingerprint)
                .collect::<Vec<_>>(),
        ),
        _ => value.clone(),
    }
}

fn schema_fingerprint(value: &serde_json::Value) -> Option<String> {
    serde_json::to_string(&normalize_schema_for_fingerprint(value)).ok()
}

/// Replace inline schemas in DataResponse wrappers with `$ref` to named schemas.
///
/// We intentionally use a strict schema fingerprint match instead of loose field
/// heuristics to avoid accidental cross-type deduplication.
fn dedup_data_response_schemas(raw: &mut serde_json::Value) {
    // Build lookup: normalized schema fingerprint -> candidate component names.
    let mut schema_candidates: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    if let Some(schemas) = raw
        .pointer("/components/schemas")
        .and_then(|v| v.as_object())
    {
        for (name, schema) in schemas {
            // Skip wrappers; we only want inner item/object types as ref targets.
            if schema.pointer("/properties/data").is_some() {
                continue;
            }
            if let Some(fp) = schema_fingerprint(schema) {
                schema_candidates.entry(fp).or_default().push(name.clone());
            }
        }
    }

    // Patch schemas that expose a `data` property with inline object/array item schemas.
    let wrapper_names: Vec<String> = raw
        .pointer("/components/schemas")
        .and_then(|v| v.as_object())
        .map(|schemas| {
            schemas
                .iter()
                .filter_map(|(name, schema)| {
                    schema
                        .pointer("/properties/data")
                        .is_some()
                        .then_some(name.clone())
                })
                .collect()
        })
        .unwrap_or_default();

    for wrapper_name in &wrapper_names {
        let data_path = format!("/components/schemas/{wrapper_name}/properties/data");
        let Some(data_schema) = raw.pointer(&data_path).cloned() else {
            continue;
        };

        let (inline_schema, replace_path) =
            if data_schema.get("type").and_then(|v| v.as_str()) == Some("array") {
                let Some(items) = data_schema.get("items") else {
                    continue;
                };
                if items.get("$ref").is_some() || !items.is_object() {
                    continue;
                }
                (items.clone(), format!("{data_path}/items"))
            } else if data_schema.get("type").and_then(|v| v.as_str()) == Some("object")
                && data_schema.get("$ref").is_none()
            {
                (data_schema.clone(), data_path.clone())
            } else {
                continue;
            };

        let Some(fingerprint) = schema_fingerprint(&inline_schema) else {
            continue;
        };
        let Some(candidates) = schema_candidates.get(&fingerprint) else {
            continue;
        };
        let Some(target) = choose_ref_target(wrapper_name, candidates) else {
            continue;
        };

        if let Some(slot) = raw.pointer_mut(&replace_path) {
            *slot = serde_json::json!({ "$ref": format!("#/components/schemas/{target}") });
        }
    }
}

/// Mapping from publisher-specific `DataResponse_*` schema names to the legacy
/// monolithic spec equivalents so progenitor generates the same Rust types the
/// CLI/MCP code already expects.
const SCHEMA_REMAP: &[(&str, &str)] = &[
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

/// Remap publisher-specific response schema names to their monolithic spec equivalents.
/// This ensures progenitor generates consistent types across old and new endpoints.
fn remap_publisher_refs(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(r)) = map.get_mut("$ref") {
                for (from, to) in SCHEMA_REMAP {
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

fn namespace_schema_refs(value: &mut serde_json::Value, names: &HashMap<String, String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(reference)) = map.get_mut("$ref") {
                const MARKER: &str = "#/components/schemas/";
                if let Some(name) = reference.strip_prefix(MARKER)
                    && let Some(target) = names.get(name)
                {
                    *reference = format!("{MARKER}{target}");
                }
            }
            for child in map.values_mut() {
                namespace_schema_refs(child, names);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                namespace_schema_refs(child, names);
            }
        }
        _ => {}
    }
}

fn namespace_component_schemas(publisher: &mut serde_json::Value, prefix: &str) {
    let names = publisher
        .pointer("/components/schemas")
        .and_then(serde_json::Value::as_object)
        .map(|schemas| {
            schemas
                .keys()
                .map(|name| (name.clone(), format!("{prefix}{name}")))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    if names.is_empty() {
        return;
    }

    namespace_schema_refs(publisher, &names);
    if let Some(schemas) = publisher
        .pointer_mut("/components/schemas")
        .and_then(serde_json::Value::as_object_mut)
    {
        let original = std::mem::take(schemas);
        for (name, schema) in original {
            let target = names.get(&name).cloned().unwrap_or(name);
            schemas.insert(target, schema);
        }
    }
}

fn namespace_operation_ids(publisher: &mut serde_json::Value, prefix: &str) {
    let Some(paths) = publisher
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for item in paths.values_mut() {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        for method in ["get", "post", "put", "patch", "delete"] {
            let Some(operation_id) = item
                .get_mut(method)
                .and_then(serde_json::Value::as_object_mut)
                .and_then(|operation| operation.get_mut("operationId"))
                .and_then(|value| value.as_str())
                .map(str::to_owned)
            else {
                continue;
            };
            if !operation_id.starts_with(prefix) {
                item[method]["operationId"] =
                    serde_json::Value::String(format!("{prefix}{operation_id}"));
            }
        }
    }
}

/// Merge an API spec's paths and schemas into the main spec JSON.
fn merge_api_spec(
    main: &mut serde_json::Value,
    spec_path: &Path,
    path_prefix: &str,
    schema_prefix: Option<&str>,
    operation_id_prefix: Option<&str>,
) -> anyhow::Result<()> {
    let publisher_str = fs::read_to_string(spec_path)
        .with_context(|| format!("failed to read API spec: {}", spec_path.display()))?;
    let mut publisher: serde_json::Value = serde_json::from_str(&publisher_str)
        .with_context(|| format!("failed to parse API spec JSON: {}", spec_path.display()))?;

    if let Some(prefix) = schema_prefix {
        namespace_component_schemas(&mut publisher, prefix);
    }
    if let Some(prefix) = operation_id_prefix {
        namespace_operation_ids(&mut publisher, prefix);
    }

    // Convert 3.1 nullable syntax to 3.0 for progenitor compatibility.
    downconvert_31_to_30(&mut publisher);

    // Remap publisher response types to monolithic spec equivalents.
    remap_publisher_refs(&mut publisher);

    // Merge paths.
    // Service specs use relative paths; mount them at their public gateway prefix.
    if let (Some(main_paths), Some(pub_paths)) = (
        main.get_mut("paths").and_then(|v| v.as_object_mut()),
        publisher.get("paths").and_then(|v| v.as_object()),
    ) {
        for (path, item) in pub_paths {
            let absolute_path = if path == path_prefix
                || path.starts_with(&format!("{path_prefix}/"))
                || path.starts_with("/publishers/")
            {
                path.to_string()
            } else if path == "/" {
                path_prefix.to_string()
            } else if path.starts_with('/') {
                format!("{path_prefix}{path}")
            } else {
                format!("{path_prefix}/{path}")
            };

            main_paths.insert(absolute_path, item.clone());
        }
    }

    // Merge component schemas, renaming keys that were remapped in $refs.
    if let (Some(main_schemas), Some(pub_schemas)) = (
        main.pointer_mut("/components/schemas")
            .and_then(|v| v.as_object_mut()),
        publisher
            .pointer("/components/schemas")
            .and_then(|v| v.as_object()),
    ) {
        for (name, schema) in pub_schemas {
            let target_name = SCHEMA_REMAP
                .iter()
                .find(|(from, _)| *from == name.as_str())
                .map(|(_, to)| (*to).to_string())
                .unwrap_or_else(|| name.clone());
            main_schemas
                .entry(&target_name)
                .or_insert_with(|| schema.clone());
        }
    }

    Ok(())
}

fn merge_publisher_spec(
    main: &mut serde_json::Value,
    publisher_path: &Path,
    publisher_slug: &str,
) -> anyhow::Result<()> {
    merge_api_spec(
        main,
        publisher_path,
        &format!("/publishers/{publisher_slug}"),
        None,
        None,
    )
}

fn main() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_openapi_dir = manifest_dir.join("../openapi");
    let bundled_openapi_dir = manifest_dir.join("openapi");
    let openapi_dir = if workspace_openapi_dir.join("openapi.json").is_file() {
        workspace_openapi_dir
    } else {
        bundled_openapi_dir
    };
    let spec_files = [
        "openapi.json",
        "openapi-seren-db.json",
        "openapi-seren-cloud.json",
        "openapi-seren-agent.json",
        "openapi-seren-models.json",
        "openapi-seren-private-models.json",
        "openapi-seren-passwords.json",
        "openapi-seren-skills.json",
        "openapi-seren-notes.json",
        "openapi-seren-memory.json",
    ];
    for file_name in spec_files {
        println!(
            "cargo:rerun-if-changed={}",
            openapi_dir.join(file_name).display()
        );
    }

    let spec_str = fs::read_to_string(openapi_dir.join("openapi.json"))?;
    let mut raw_json: serde_json::Value = serde_json::from_str(&spec_str)?;

    // Merge per-publisher specs so the generated client includes publisher endpoints.
    merge_publisher_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-db.json"),
        "seren-db",
    )?;
    merge_publisher_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-cloud.json"),
        "seren-cloud",
    )?;
    merge_publisher_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-agent.json"),
        "seren-agent",
    )?;
    merge_publisher_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-models.json"),
        "seren-models",
    )?;
    merge_publisher_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-private-models.json"),
        "seren-private-models",
    )?;
    merge_publisher_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-passwords.json"),
        "seren-passwords",
    )?;
    merge_publisher_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-skills.json"),
        "seren-skills",
    )?;
    merge_publisher_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-notes.json"),
        "seren-notes",
    )?;
    merge_api_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-memory.json"),
        "/publishers/seren-memory",
        Some("SerenMemory"),
        Some("seren_memory_"),
    )?;

    // Replace inline schemas in DataResponse_* wrappers with $ref to named equivalents.
    // This must run after merging publisher specs so all schemas are present.
    dedup_data_response_schemas(&mut raw_json);

    // Normalize OpenAPI 3.1 nullable syntax before deserializing with openapiv3.
    normalize_nullable_parameters(&mut raw_json);
    downconvert_31_to_30(&mut raw_json);
    raw_json["openapi"] = serde_json::json!("3.0.3");

    // Strip error response content bodies for progenitor code generation.
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
    let formatted = prettyplease::unparse(&syntax);

    // Replace chrono with jiff in the generated code
    // Progenitor 0.11+ uses fully qualified paths with leading ::
    let formatted = formatted
        .replace(
            "::chrono::DateTime<::chrono::offset::Utc>",
            "::jiff::Timestamp",
        )
        .replace("chrono::DateTime<chrono::offset::Utc>", "::jiff::Timestamp");

    // Convert 400/402/403 responses from ErrorResponse (which discards body) to UnexpectedResponse
    // (which preserves the raw response). This allows callers to read and display the actual
    // error body while keeping these status codes documented in the OpenAPI spec.
    // 400: Bad request errors include a JSON body with {error, message} that should be surfaced.
    // 402/403: Payment-required and forbidden errors may carry structured body payloads.
    let formatted = formatted.replace(
        "400u16 => Err(Error::ErrorResponse(ResponseValue::empty(response)))",
        "400u16 => Err(Error::UnexpectedResponse(response))",
    );
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
