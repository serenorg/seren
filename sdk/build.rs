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

/// Named component the SerenDB query result addresses for a single cell.
const QUERY_RESULT_CELL_SCHEMA: &str = "QueryResultCell";
const QUERY_RESULT_CELL_REFERENCE: &str = "#/components/schemas/QueryResultCell";
const DIAGNOSTIC_ERROR_OPERATION_IDS: &[&str] = &[
    "seren_db_query",
    "managed_agent_secrets_setup_initiate",
    "managed_agent_secrets_setup_status",
    "managed_agent_secrets_setup_cancel",
];

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
/// Progenitor supports one success type and one error type per operation. Other
/// operations can declare several error types, so retain their untyped handling.
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

/// Preserve raw error responses for operations that surface bounded diagnostics.
///
/// Progenitor's typed decoder loses the status and body needed by the SDK's
/// bounded error handlers. Removing declared error responses makes its
/// generated catch-all return the unconsumed response without changing the
/// bundled OpenAPI contract.
fn preserve_diagnostic_error_responses(value: &mut serde_json::Value) -> anyhow::Result<()> {
    let paths = value
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
        .context("OpenAPI document is missing paths")?;
    let mut found = HashSet::new();

    for path_item in paths.values_mut() {
        let Some(path_item) = path_item.as_object_mut() else {
            continue;
        };
        for method in [
            "get", "put", "post", "delete", "options", "head", "patch", "trace",
        ] {
            let Some(operation) = path_item
                .get_mut(method)
                .and_then(serde_json::Value::as_object_mut)
            else {
                continue;
            };
            let Some(operation_id) = operation
                .get("operationId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            if !DIAGNOSTIC_ERROR_OPERATION_IDS
                .iter()
                .any(|id| *id == operation_id)
            {
                continue;
            }
            let responses = operation
                .get_mut("responses")
                .and_then(serde_json::Value::as_object_mut)
                .with_context(|| {
                    format!("OpenAPI operation {operation_id} is missing responses")
                })?;
            responses.retain(|status, _| {
                status != "default" && !(status.len() == 3 && status.starts_with(['4', '5']))
            });
            found.insert(operation_id);
        }
    }

    for operation_id in DIAGNOSTIC_ERROR_OPERATION_IDS {
        anyhow::ensure!(
            found.contains(*operation_id),
            "OpenAPI document is missing diagnostic operation {operation_id}"
        );
    }
    Ok(())
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

/// Keep the complete public contract bundled with the SDK while omitting
/// operations that Progenitor cannot represent in its generated Rust client.
fn remove_unsupported_operations(value: &mut serde_json::Value) -> anyhow::Result<()> {
    const MULTIPART_PATHS: &[&str] = &[
        "/users/me/avatar",
        "/organizations/{organization_id}/templates/{slug}/avatar",
        "/organizations/{organization_id}/addons/{name}/thumbnail",
    ];
    // Raw uploads whose Content-Type header selects the stored file type.
    // Progenitor sends one fixed media type per operation, so a generated
    // method could not upload the other declared types.
    const MULTIPLE_MEDIA_TYPE_OPERATIONS: &[&str] = &[
        "seren_cloud_runtime_publish_run_artifact",
        "seren_cloud_upload_run_file",
        "seren_cloud_upload_folder_file",
    ];
    // Add-on revision archives travel as `application/x-tar`, a media type
    // Progenitor can't send or decode.
    const TAR_ARCHIVE_OPERATIONS: &[&str] = &[
        "seren_cloud_runtime_save_addon_revision",
        "seren_cloud_runtime_download_addon_revision",
        "seren_agent_download_managed_agent_addon_revision",
    ];
    // OpenAI- and Claude-format model passthroughs whose replies carry no
    // schema; model clients call them, not this SDK.
    const SCHEMALESS_REPLY_OPERATIONS: &[&str] =
        &["post_chat_completions_native", "post_claude_messages"];
    // Omit this operation while its path template and declared parameters disagree.
    const MISDECLARED_PATH_PARAMETER_OPERATIONS: &[&str] = &["list_managed_agent_template_bundles"];
    const METHODS: [&str; 8] = [
        "get", "put", "post", "delete", "options", "head", "patch", "trace",
    ];

    let paths = value
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
        .context("OpenAPI document is missing paths")?;

    for path in MULTIPART_PATHS {
        if let Some(path_item) = paths
            .get_mut(*path)
            .and_then(serde_json::Value::as_object_mut)
        {
            let is_multipart = path_item
                .get("post")
                .and_then(|operation| {
                    operation.pointer("/requestBody/content/multipart~1form-data")
                })
                .is_some();
            if is_multipart {
                path_item.remove("post");
            }
        }
    }

    for (path, path_item) in paths.iter_mut() {
        let Some(path_item) = path_item.as_object_mut() else {
            continue;
        };
        for method in METHODS {
            let omitted = path_item.get(method).is_some_and(|operation| {
                let id = operation["operationId"].as_str();
                id.is_some_and(|id| MULTIPLE_MEDIA_TYPE_OPERATIONS.contains(&id))
                    && request_media_type_count(operation) > 1
                    || id.is_some_and(|id| MISDECLARED_PATH_PARAMETER_OPERATIONS.contains(&id))
                        && !unmatched_path_parameters(path, operation).is_empty()
                    || id.is_some_and(|id| SCHEMALESS_REPLY_OPERATIONS.contains(&id))
                        && operation["responses"]["200"]["content"]
                            .as_object()
                            .is_some_and(|content| {
                                content.values().any(|media| media.get("schema").is_none())
                            })
                    || id.is_some_and(|id| TAR_ARCHIVE_OPERATIONS.contains(&id))
                        && operation.to_string().contains("\"application/x-tar\"")
            });
            if omitted {
                path_item.remove(method);
            }
        }
    }

    for (path, path_item) in paths.iter() {
        let Some(path_item) = path_item.as_object() else {
            continue;
        };
        for method in METHODS {
            let Some(operation) = path_item.get(method) else {
                continue;
            };
            if operation
                .pointer("/requestBody/content/multipart~1form-data")
                .is_some()
            {
                anyhow::bail!(
                    "Rust SDK generation does not support multipart operation {method} {path}"
                );
            }
            let undeclared = unmatched_path_parameters(path, operation);
            if !undeclared.is_empty() {
                anyhow::bail!(
                    "Rust SDK generation needs every path parameter of {method} {path} in its path; missing {}",
                    undeclared.join(", ")
                );
            }
            if request_media_type_count(operation) > 1 {
                anyhow::bail!(
                    "Rust SDK generation does not support multiple request media types for {method} {path}; omit it explicitly or narrow the contract"
                );
            }
        }
    }

    Ok(())
}

/// Path parameters an operation declares that its path template doesn't name.
fn unmatched_path_parameters<'a>(path: &str, operation: &'a serde_json::Value) -> Vec<&'a str> {
    operation["parameters"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|parameter| parameter["in"].as_str() == Some("path"))
        .filter_map(|parameter| parameter["name"].as_str())
        .filter(|name| !path.contains(&format!("{{{name}}}")))
        .collect()
}

fn request_media_type_count(operation: &serde_json::Value) -> usize {
    operation
        .pointer("/requestBody/content")
        .and_then(serde_json::Value::as_object)
        .map_or(0, serde_json::Map::len)
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

/// Returns the exact values of an `anyOf` whose every branch is a closed string
/// enum, or `None` when any other keyword could change what the union accepts.
fn closed_string_enum_union(
    schema: &serde_json::Map<String, serde_json::Value>,
) -> Option<Vec<serde_json::Value>> {
    const UNION_KEYS: &[&str] = &["anyOf", "title", "description"];
    const BRANCH_KEYS: &[&str] = &["type", "enum", "title", "description"];
    if !schema.keys().all(|key| UNION_KEYS.contains(&key.as_str())) {
        return None;
    }
    let branches = schema.get("anyOf")?.as_array()?;
    if branches.is_empty() {
        return None;
    }
    let mut values = Vec::new();
    for branch in branches {
        let branch = branch.as_object()?;
        if !branch.keys().all(|key| BRANCH_KEYS.contains(&key.as_str()))
            || branch.get("type")?.as_str()? != "string"
        {
            return None;
        }
        let branch_values = branch.get("enum")?.as_array()?;
        if branch_values.is_empty() || !branch_values.iter().all(serde_json::Value::is_string) {
            return None;
        }
        for value in branch_values {
            if !values.contains(value) {
                values.push(value.clone());
            }
        }
    }
    Some(values)
}

/// Rewrites an `anyOf` of closed string enums as one string enum holding the
/// union of their values, which accepts exactly the same documents.
///
/// Typify models a string `anyOf` as an object of flattened optional subtypes,
/// which cannot decode the scalar these unions carry on the wire. Nullable,
/// referenced, constrained, object, and open-string unions keep their schema.
fn normalize_string_enum_unions(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for child in map.values_mut() {
                normalize_string_enum_unions(child);
            }
            if let Some(values) = closed_string_enum_union(map) {
                map.remove("anyOf");
                map.insert("type".into(), serde_json::json!("string"));
                map.insert("enum".into(), serde_json::Value::Array(values));
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                normalize_string_enum_unions(child);
            }
        }
        _ => {}
    }
}

fn has_only_keys(schema: &serde_json::Map<String, serde_json::Value>, allowed: &[&str]) -> bool {
    schema.keys().all(|key| allowed.contains(&key.as_str()))
}

/// Component name of a schema that is nothing but a local component `$ref`.
fn component_ref_name(schema: &serde_json::Value) -> Option<&str> {
    let schema = schema.as_object()?;
    if schema.len() != 1 {
        return None;
    }
    schema
        .get("$ref")?
        .as_str()?
        .strip_prefix("#/components/schemas/")
}

/// Branches of a component that is nothing but an annotated `oneOf`.
fn component_one_of<'a>(
    components: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a [serde_json::Value]> {
    let schema = components.get(name)?.as_object()?;
    if !has_only_keys(schema, &["oneOf", "title", "description"]) {
        return None;
    }
    let branches = schema.get("oneOf")?.as_array()?;
    (!branches.is_empty()).then_some(branches.as_slice())
}

/// Splits an annotated `allOf` of one component `$ref` and one sibling schema.
fn component_and_sibling(
    schema: &serde_json::Map<String, serde_json::Value>,
) -> Option<(&str, &serde_json::Value)> {
    if !has_only_keys(schema, &["allOf", "title", "description"]) {
        return None;
    }
    match schema.get("allOf")?.as_array()?.as_slice() {
        [first, second] => match (component_ref_name(first), component_ref_name(second)) {
            (Some(name), None) => Some((name, second)),
            (None, Some(name)) => Some((name, first)),
            _ => None,
        },
        _ => None,
    }
}

/// Values of a property a branch requires and declares as a closed string enum.
fn required_string_enum<'a>(
    branch: &'a serde_json::Map<String, serde_json::Value>,
    property: &str,
) -> Option<&'a [serde_json::Value]> {
    let required = branch.get("required")?.as_array()?;
    if !required.iter().any(|name| name.as_str() == Some(property)) {
        return None;
    }
    let schema = branch.get("properties")?.get(property)?.as_object()?;
    if !has_only_keys(schema, &["type", "enum", "title", "description"])
        || schema.get("type")?.as_str()? != "string"
    {
        return None;
    }
    let values = schema.get("enum")?.as_array()?;
    (!values.is_empty() && values.iter().all(serde_json::Value::is_string))
        .then_some(values.as_slice())
}

/// Returns union branches that are plain objects kept mutually exclusive by one
/// required closed string property, so no document can match two of them.
fn exclusive_object_branches(
    branches: &[serde_json::Value],
) -> Option<Vec<&serde_json::Map<String, serde_json::Value>>> {
    const OBJECT_KEYS: &[&str] = &["type", "required", "properties", "title", "description"];
    let mut objects = Vec::new();
    for branch in branches {
        let branch = branch.as_object()?;
        if !has_only_keys(branch, OBJECT_KEYS) || branch.get("type")?.as_str()? != "object" {
            return None;
        }
        objects.push(branch);
    }
    let candidates = branches.first()?.get("required")?.as_array()?;
    let exclusive = candidates
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|property| {
            let mut seen = Vec::new();
            objects.iter().all(|branch| {
                required_string_enum(branch, property).is_some_and(|values| {
                    values.iter().all(|value| {
                        let unseen = !seen.contains(&value);
                        seen.push(value);
                        unseen
                    })
                })
            })
        });
    exclusive.then_some(objects)
}

/// One alternative per member when a `oneOf` branch is an annotated
/// `allOf: [{"$ref": union}, sibling]` over an exclusive object union.
fn exclusive_union_members(
    components: &serde_json::Map<String, serde_json::Value>,
    branch: &serde_json::Value,
    outer_sibling: &serde_json::Value,
) -> Option<Vec<serde_json::Value>> {
    let branch = branch.as_object()?;
    let (name, inner_sibling) = component_and_sibling(branch)?;
    let members = exclusive_object_branches(component_one_of(components, name)?)?;
    let annotations = branch
        .iter()
        .filter(|(key, _)| key.as_str() != "allOf")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<serde_json::Map<_, _>>();
    let alternatives = members
        .into_iter()
        .map(|member| {
            let mut alternative = annotations.clone();
            alternative.insert(
                "allOf".into(),
                serde_json::json!([member, inner_sibling, outer_sibling]),
            );
            serde_json::Value::Object(alternative)
        })
        .collect();
    Some(alternatives)
}

/// Alternatives for an annotated `allOf: [{"$ref": union}, sibling]` whose
/// union has a branch nesting another exclusive object union.
fn distributed_union_alternatives(
    schema: &serde_json::Map<String, serde_json::Value>,
    components: &serde_json::Map<String, serde_json::Value>,
) -> Option<Vec<serde_json::Value>> {
    let (name, sibling) = component_and_sibling(schema)?;
    let mut nested = false;
    let mut alternatives = Vec::new();
    for branch in component_one_of(components, name)? {
        match exclusive_union_members(components, branch, sibling) {
            Some(members) => {
                nested = true;
                alternatives.extend(members);
            }
            None => alternatives.push(serde_json::json!({ "allOf": [branch, sibling] })),
        }
    }
    nested.then_some(alternatives)
}

/// Distributes a sibling schema over a referenced `oneOf` whose branch nests an
/// exclusive object union, joining that union's members to the outer `oneOf`.
///
/// `allOf[oneOf[b..], s]` accepts exactly the documents `oneOf[allOf[b, s]..]`
/// does, and members of an exclusive union never match together, so each can
/// stand as its own outer alternative. Typify would otherwise intersect the
/// sibling with the nested union and with every excluded branch, and reduce
/// the nesting branch to an uninhabited type. The referenced components keep
/// their schemas, and schemas without such a nested union are unchanged.
fn distribute_over_nested_exclusive_unions(
    value: &mut serde_json::Value,
    components: &serde_json::Map<String, serde_json::Value>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for child in map.values_mut() {
                distribute_over_nested_exclusive_unions(child, components);
            }
            if let Some(alternatives) = distributed_union_alternatives(map, components) {
                map.remove("allOf");
                map.insert("oneOf".into(), serde_json::Value::Array(alternatives));
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                distribute_over_nested_exclusive_unions(child, components);
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

/// Wire models the SDK owns in `src/models.rs`. Deployment reads retain their
/// named view and nullable stop refusal. Provider updates distinguish omitted
/// settings from explicit null resets instead of collapsing both into None.
/// Template profile patches also preserve omitted lists and reject null lists.
const SDK_SCHEMA_REPLACEMENTS: &[(&str, &str)] = &[
    (
        "PutManagedAgentTemplateProfile",
        "crate::PutManagedAgentTemplateProfile",
    ),
    (
        "ManagedDeploymentReadResponse",
        "crate::ManagedDeploymentReadResponse",
    ),
    (
        "UpdateOAuthProviderRequest",
        "crate::UpdateOAuthProviderRequest",
    ),
];

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

    // Patch inline objects and array items in `data` properties. An inline
    // composition is patched only for an SDK-owned schema; others keep their
    // generated data types.
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
            } else if (data_schema.get("type").and_then(|v| v.as_str()) == Some("object")
                || data_schema.get("allOf").is_some())
                && data_schema.get("$ref").is_none()
            {
                (data_schema.clone(), data_path.clone())
            } else {
                continue;
            };
        let composition = data_schema.get("type").is_none() && data_schema.get("allOf").is_some();

        let Some(fingerprint) = schema_fingerprint(&inline_schema) else {
            continue;
        };
        let Some(candidates) = schema_candidates.get(&fingerprint) else {
            continue;
        };
        let Some(target) = choose_ref_target(wrapper_name, candidates) else {
            continue;
        };
        if composition
            && !SDK_SCHEMA_REPLACEMENTS
                .iter()
                .any(|(schema, _)| *schema == target)
        {
            continue;
        }

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

/// Follow transitive component schema references from the roots.
fn reachable_schemas(
    roots: &serde_json::Value,
    schemas: &serde_json::Map<String, serde_json::Value>,
) -> HashSet<String> {
    let mut reached = HashSet::new();
    let mut pending = HashSet::new();
    collect_refs(roots, &mut pending);
    while let Some(name) = pending.iter().next().cloned() {
        pending.remove(&name);
        if !reached.insert(name.clone()) {
            continue;
        }
        if let Some(schema) = schemas.get(&name) {
            let mut next = HashSet::new();
            collect_refs(schema, &mut next);
            pending.extend(next.into_iter().filter(|n| !reached.contains(n)));
        }
    }
    reached
}

/// Keep referenced union branches closed to preserve untagged decoding.
fn union_branch_schemas(value: &serde_json::Value, acc: &mut HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for keyword in ["oneOf", "anyOf"] {
                if let Some(serde_json::Value::Array(branches)) = map.get(keyword) {
                    let alternatives = branches
                        .iter()
                        .filter(|b| b.get("type").and_then(|t| t.as_str()) != Some("null"))
                        .count();
                    if alternatives > 1 {
                        for branch in branches {
                            if let Some(name) = component_ref_name(branch) {
                                acc.insert(name.to_string());
                            }
                        }
                    }
                }
            }
            for v in map.values() {
                union_branch_schemas(v, acc);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                union_branch_schemas(v, acc);
            }
        }
        _ => {}
    }
}

/// Allow unknown fields on nonempty objects outside union branches.
fn open_object_schema(value: &mut serde_json::Value, union_branch: bool) {
    match value {
        serde_json::Value::Object(map) => {
            let names_properties = map
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|p| !p.is_empty());
            if !union_branch
                && names_properties
                && map.get("additionalProperties") == Some(&serde_json::Value::Bool(false))
            {
                map.remove("additionalProperties");
            }
            for (key, v) in map.iter_mut() {
                let multi_way = matches!(key.as_str(), "oneOf" | "anyOf")
                    && v.as_array().is_some_and(|branches| {
                        branches
                            .iter()
                            .filter(|b| b.get("type").and_then(|t| t.as_str()) != Some("null"))
                            .count()
                            > 1
                    });
                if multi_way {
                    for branch in v.as_array_mut().into_iter().flatten() {
                        open_object_schema(branch, true);
                    }
                } else {
                    open_object_schema(v, false);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                open_object_schema(v, false);
            }
        }
        _ => {}
    }
}

/// Keep schemas used by hand-written requests strict.
const HAND_WRITTEN_REQUEST_SCHEMAS: &[&str] = &[
    "CapabilityLabel",
    "Description",
    "ExampleTask",
    "JobTitle",
    "ManagedAgentTemplateTool",
    "Pronouns",
    "Tagline",
];

/// Length, count and pattern limits the generator turns into decoding checks.
const VALUE_LIMITS: &[&str] = &["maxLength", "minLength", "maxItems", "minItems", "pattern"];

/// Decode allowlisted response enums as strings while keeping request values closed.
const OPEN_RESPONSE_ENUMS: &[&str] = &["ManagedAgentTemplateTool"];

/// A string enum with more than one value.
fn open_string_enum(map: &serde_json::Map<String, serde_json::Value>) -> bool {
    map.get("type").and_then(serde_json::Value::as_str) == Some("string")
        && map
            .get("enum")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| values.len() > 1)
}

/// A string or number schema with a limit and no reference inside it.
fn limited_scalar(schema: &serde_json::Value) -> bool {
    let Some(map) = schema.as_object() else {
        return false;
    };
    let scalar = matches!(
        map.get("type").and_then(serde_json::Value::as_str),
        Some("string" | "integer" | "number")
    );
    let mut refs = HashSet::new();
    collect_refs(schema, &mut refs);
    scalar && refs.is_empty() && VALUE_LIMITS.iter().any(|k| map.contains_key(*k))
}

/// Unbounded shared scalars, with closed and open enum variants.
struct SharedScalars {
    limits: HashMap<String, serde_json::Value>,
    values: HashMap<String, serde_json::Value>,
}

/// Relax response limits and inline shared scalars without changing union discrimination.
/// With `values`, also open allowlisted response enums.
fn relax_value_limits(value: &mut serde_json::Value, shared: &SharedScalars, values: bool) {
    let shared_scalars = if values {
        &shared.values
    } else {
        &shared.limits
    };
    let relaxed_copy = value
        .get("$ref")
        .and_then(serde_json::Value::as_str)
        .and_then(|r| r.strip_prefix("#/components/schemas/"))
        .and_then(|name| shared_scalars.get(name));
    if let (Some(relaxed), Some(map)) = (relaxed_copy, value.as_object()) {
        // Keeps keywords beside the reference, such as `nullable`.
        let mut copy = relaxed.as_object().cloned().unwrap_or_default();
        for (key, v) in map {
            if key != "$ref" {
                copy.insert(key.clone(), v.clone());
            }
        }
        *value = serde_json::Value::Object(copy);
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for key in VALUE_LIMITS {
                map.remove(*key);
            }
            for (key, v) in map.iter_mut() {
                let multi_way = matches!(key.as_str(), "oneOf" | "anyOf")
                    && v.as_array().is_some_and(|branches| {
                        branches
                            .iter()
                            .filter(|b| b.get("type").and_then(|t| t.as_str()) != Some("null"))
                            .count()
                            > 1
                    });
                if !multi_way {
                    relax_value_limits(v, shared, values);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                relax_value_limits(v, shared, values);
            }
        }
        _ => {}
    }
}

/// Relax response-only schemas while preserving request and union constraints.
fn open_response_only_schemas(value: &mut serde_json::Value) {
    let mut request_roots = Vec::new();
    let mut response_roots = Vec::new();
    if let Some(paths) = value.get("paths").and_then(serde_json::Value::as_object) {
        for item in paths.values() {
            let Some(item) = item.as_object() else {
                continue;
            };
            for (key, operation) in item {
                if key == "parameters" {
                    request_roots.push(operation.clone());
                    continue;
                }
                for field in ["requestBody", "parameters"] {
                    if let Some(v) = operation.get(field) {
                        request_roots.push(v.clone());
                    }
                }
                if let Some(v) = operation.get("responses") {
                    response_roots.push(v.clone());
                }
            }
        }
    }
    let schemas = value
        .pointer("/components/schemas")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    request_roots.extend(
        HAND_WRITTEN_REQUEST_SCHEMAS
            .iter()
            .map(|name| serde_json::json!({"$ref": format!("#/components/schemas/{name}")})),
    );
    let requests = reachable_schemas(&serde_json::Value::Array(request_roots), &schemas);
    // Inline relaxed copies so shared request schemas retain their limits.
    let no_shared = SharedScalars {
        limits: HashMap::new(),
        values: HashMap::new(),
    };
    let relaxed_copies = |values: bool| -> HashMap<String, serde_json::Value> {
        schemas
            .iter()
            .filter(|(name, schema)| {
                requests.contains(*name)
                    && (limited_scalar(schema)
                        || values && OPEN_RESPONSE_ENUMS.contains(&name.as_str()))
            })
            .map(|(name, schema)| {
                let mut relaxed = schema.clone();
                relax_value_limits(&mut relaxed, &no_shared, false);
                if let Some(map) = relaxed.as_object_mut()
                    && values
                    && OPEN_RESPONSE_ENUMS.contains(&name.as_str())
                    && open_string_enum(map)
                {
                    map.remove("enum");
                }
                (name.clone(), relaxed)
            })
            .collect()
    };
    let shared_scalars = SharedScalars {
        limits: relaxed_copies(false),
        values: relaxed_copies(true),
    };
    let responses = reachable_schemas(&serde_json::Value::Array(response_roots), &schemas);
    let mut union_branches = HashSet::new();
    union_branch_schemas(value, &mut union_branches);
    // Keep enums closed within union branches to preserve discrimination.
    let union_reached = reachable_schemas(
        &serde_json::Value::Array(
            union_branches
                .iter()
                .map(|name| serde_json::json!({"$ref": format!("#/components/schemas/{name}")}))
                .collect(),
        ),
        &schemas,
    );

    if let Some(paths) = value
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
    {
        for item in paths.values_mut() {
            for operation in item
                .as_object_mut()
                .into_iter()
                .flat_map(|i| i.values_mut())
            {
                if let Some(responses) = operation.get_mut("responses") {
                    open_object_schema(responses, false);
                    relax_value_limits(responses, &shared_scalars, true);
                    mark_reply_enums(responses, &[]);
                }
            }
        }
    }
    if let Some(schemas) = value
        .pointer_mut("/components/schemas")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (name, schema) in schemas.iter_mut() {
            if responses.contains(name) && !requests.contains(name) {
                open_object_schema(schema, union_branches.contains(name));
                if !union_branches.contains(name) {
                    relax_value_limits(schema, &shared_scalars, !union_reached.contains(name));
                }
                if !union_reached.contains(name) && !CLOSED_REPLY_ENUMS.contains(&name.as_str()) {
                    mark_reply_enums(schema, &[]);
                }
            }
        }
    }
}

/// Documentation token that asks the generated enum to keep unlisted values.
const OPEN_REPLY_ENUM_MARKER: &str = "seren-open-reply-enum";

/// Reply-only component enums that stay closed. Every other multi-valued
/// string enum reached only from replies decodes an unlisted value as
/// `Other(String)`. Requests, single-value tags, and enums whose value picks
/// a union branch stay closed without being listed here.
const CLOSED_REPLY_ENUMS: &[&str] = &[];

fn string_enum_values(schema: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    let map = schema.as_object()?;
    if map.get("type").and_then(serde_json::Value::as_str) != Some("string") {
        return None;
    }
    map.get("enum").and_then(serde_json::Value::as_array)
}

fn branch_property<'a>(branch: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    branch.get("properties")?.get(name)
}

/// Two union branches that require one tag property with different single values.
fn tags_distinguish(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let required = |branch: &serde_json::Value| -> Vec<String> {
        branch
            .get("required")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    };
    let b_required = required(b);
    required(a).iter().any(|name| {
        b_required.contains(name)
            && matches!(
                (
                    branch_property(a, name).and_then(string_enum_values),
                    branch_property(b, name).and_then(string_enum_values),
                ),
                (Some(x), Some(y)) if x.len() == 1 && y.len() == 1 && x != y
            )
    })
}

/// Properties of `branch` whose enum could pick between it and a sibling.
fn discriminating_properties(index: usize, branches: &[serde_json::Value]) -> Vec<String> {
    let branch = &branches[index];
    let Some(properties) = branch
        .get("properties")
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    properties
        .iter()
        .filter(|(name, schema)| {
            let Some(values) = string_enum_values(schema) else {
                return false;
            };
            branches.iter().enumerate().any(|(other_index, other)| {
                other_index != index
                    && !tags_distinguish(branch, other)
                    && branch_property(other, name)
                        .is_some_and(|other| string_enum_values(other) != Some(values))
            })
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// Marks multi-valued string enums in a reply schema so the generated enum
/// keeps unlisted values. `closed` names this object's properties that must
/// stay closed because their value picks a union branch.
fn mark_reply_enums(value: &mut serde_json::Value, closed: &[String]) {
    match value {
        serde_json::Value::Object(map) => {
            if open_string_enum(map) {
                let marked = match map.get("description").and_then(serde_json::Value::as_str) {
                    Some(text) if text.contains(OPEN_REPLY_ENUM_MARKER) => text.to_string(),
                    Some(text) if !text.is_empty() => format!("{text}\n\n{OPEN_REPLY_ENUM_MARKER}"),
                    _ => OPEN_REPLY_ENUM_MARKER.to_string(),
                };
                map.insert("description".into(), serde_json::Value::String(marked));
            }
            for (key, v) in map.iter_mut() {
                match key.as_str() {
                    "oneOf" | "anyOf" => {
                        let snapshot = v.as_array().cloned().unwrap_or_default();
                        for (index, branch) in v.as_array_mut().into_iter().flatten().enumerate() {
                            let closed = discriminating_properties(index, &snapshot);
                            mark_reply_enums(branch, &closed);
                        }
                    }
                    "properties" => {
                        for (name, property) in v.as_object_mut().into_iter().flatten() {
                            if !closed.contains(name) {
                                mark_reply_enums(property, &[]);
                            }
                        }
                    }
                    _ => mark_reply_enums(v, &[]),
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                mark_reply_enums(v, &[]);
            }
        }
        _ => {}
    }
}

/// Gives each marked reply enum an `Other(String)` variant that keeps an
/// unlisted value. Parsing a string into the enum stays strict for requests.
fn open_marked_reply_enums(syntax: &mut syn::File) -> Vec<String> {
    use syn::visit_mut::VisitMut;

    fn doc_text(attr: &syn::Attribute) -> Option<String> {
        let syn::Meta::NameValue(meta) = &attr.meta else {
            return None;
        };
        if !meta.path.is_ident("doc") {
            return None;
        }
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) = &meta.value
        else {
            return None;
        };
        Some(text.value())
    }

    fn strip_marker(attrs: &mut Vec<syn::Attribute>) -> bool {
        let mut marked = false;
        attrs.retain_mut(|attr| {
            let Some(text) = doc_text(attr) else {
                return true;
            };
            if !text.contains(OPEN_REPLY_ENUM_MARKER) {
                return true;
            }
            marked = true;
            let rest = text.replace(OPEN_REPLY_ENUM_MARKER, "");
            let rest = rest.trim_end();
            if rest.trim().is_empty() {
                return false;
            }
            *attr = syn::parse_quote!(#[doc = #rest]);
            true
        });
        marked
    }

    #[derive(Default)]
    struct Enums(HashSet<String>);
    impl VisitMut for Enums {
        fn visit_field_mut(&mut self, field: &mut syn::Field) {
            strip_marker(&mut field.attrs);
            syn::visit_mut::visit_field_mut(self, field);
        }

        fn visit_item_enum_mut(&mut self, item: &mut syn::ItemEnum) {
            syn::visit_mut::visit_item_enum_mut(self, item);
            let marked = strip_marker(&mut item.attrs);
            if !marked
                || item
                    .variants
                    .iter()
                    .any(|v| !matches!(v.fields, syn::Fields::Unit))
            {
                return;
            }
            for attr in &mut item.attrs {
                if !attr.path().is_ident("derive") {
                    continue;
                }
                if let Ok(paths) = attr.parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                ) {
                    let kept = paths.into_iter().filter(|p| !p.is_ident("Copy"));
                    *attr = syn::parse_quote!(#[derive(#(#kept),*)]);
                }
            }
            item.variants.push(syn::parse_quote!(
                /// A value this SDK doesn't list yet, kept as Core sent it.
                #[serde(untagged)]
                Other(::std::string::String)
            ));
            self.0.insert(item.ident.to_string());
        }
    }

    struct Display<'a>(&'a HashSet<String>);
    impl VisitMut for Display<'_> {
        fn visit_item_impl_mut(&mut self, item: &mut syn::ItemImpl) {
            syn::visit_mut::visit_item_impl_mut(self, item);
            let Some((trait_path, _)) = &item.trait_ else {
                return;
            };
            if trait_path
                .segments
                .last()
                .is_none_or(|s| s.ident != "Display")
            {
                return;
            }
            let syn::Type::Path(self_ty) = item.self_ty.as_ref() else {
                return;
            };
            if !self_ty
                .path
                .segments
                .last()
                .is_some_and(|s| self.0.contains(&s.ident.to_string()))
            {
                return;
            }
            for impl_item in &mut item.items {
                let syn::ImplItem::Fn(method) = impl_item else {
                    continue;
                };
                for stmt in &mut method.block.stmts {
                    if let syn::Stmt::Expr(syn::Expr::Match(expr), _) = stmt {
                        *expr.expr = syn::parse_quote!(self);
                        expr.arms
                            .push(syn::parse_quote!(Self::Other(value) => f.write_str(value),));
                    }
                }
            }
        }
    }

    let mut enums = Enums::default();
    enums.visit_file_mut(syntax);
    Display(&enums.0).visit_file_mut(syntax);
    let mut names: Vec<String> = enums.0.into_iter().collect();
    names.sort();
    names
}

/// Untagged reply unions that end in a branch for a `type` this SDK doesn't list.
const OPEN_REPLY_UNIONS: &[&str] = &["CloudRunOutputEventEnvelope"];

/// Every `type` tag the run output event union lists.
fn run_output_event_types(spec: &serde_json::Value) -> anyhow::Result<Vec<String>> {
    let branches = spec
        .pointer("/components/schemas/CloudRunOutputEvent/oneOf")
        .and_then(serde_json::Value::as_array)
        .context("Seren Cloud OpenAPI document is missing CloudRunOutputEvent")?;
    fn collect(value: &serde_json::Value, types: &mut Vec<String>) {
        if let Some(values) = value
            .pointer("/properties/type/enum")
            .and_then(serde_json::Value::as_array)
        {
            types.extend(values.iter().filter_map(|v| v.as_str().map(str::to_string)));
        }
        for member in value
            .get("allOf")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            collect(member, types);
        }
    }
    let mut types = Vec::new();
    for branch in branches {
        let before = types.len();
        collect(branch, &mut types);
        if types.len() == before {
            anyhow::bail!("a CloudRunOutputEvent branch has no type tag");
        }
    }
    Ok(types)
}

/// Ends each open reply union with an `Other` branch that keeps an event whose
/// `type` the union doesn't list. A listed `type` must still match its branch.
fn open_reply_unions(syntax: &mut syn::File) {
    use syn::visit_mut::VisitMut;
    struct Unions;
    impl VisitMut for Unions {
        fn visit_item_enum_mut(&mut self, item: &mut syn::ItemEnum) {
            if OPEN_REPLY_UNIONS.contains(&item.ident.to_string().as_str()) {
                item.variants.push(syn::parse_quote!(
                    /// An event whose `type` this SDK doesn't list, kept as Core sent it.
                    Other(crate::UnknownRunOutputEvent)
                ));
            }
            syn::visit_mut::visit_item_enum_mut(self, item);
        }
    }
    Unions.visit_file_mut(syntax);
}

/// Checks the SerenDB query-cell contract before code generation.
///
/// The generated client decodes every cell shape the server can emit only while
/// rows stay positional arrays that address a named cell component with an
/// unconstrained schema. Checking both halves here turns a server-side
/// narrowing into a build failure instead of a silently coercing client type.
fn validate_query_result_cell_schema(spec: &serde_json::Value) -> anyhow::Result<()> {
    let rows = spec
        .pointer("/components/schemas/QueryResult/properties/rows")
        .context("SerenDB OpenAPI document is missing QueryResult.rows")?;
    if rows
        .pointer("/items/type")
        .and_then(serde_json::Value::as_str)
        != Some("array")
    {
        anyhow::bail!("SerenDB QueryResult rows must stay positional arrays of cells");
    }

    let cell_reference = rows
        .pointer("/items/items/$ref")
        .and_then(serde_json::Value::as_str);
    if cell_reference != Some(QUERY_RESULT_CELL_REFERENCE) {
        anyhow::bail!(
            "SerenDB QueryResult rows must reference {QUERY_RESULT_CELL_REFERENCE} before SDK generation"
        );
    }

    let cell_schema = spec
        .pointer("/components/schemas/QueryResultCell")
        .and_then(serde_json::Value::as_object)
        .with_context(|| format!("SerenDB OpenAPI is missing {QUERY_RESULT_CELL_SCHEMA}"))?;
    // Any assertion keyword would let the generator infer a narrower type than
    // "any JSON", which is what a scalar, null, or array cell needs.
    let narrowing: Vec<&str> = cell_schema
        .keys()
        .map(String::as_str)
        .filter(|key| !matches!(*key, "description" | "title"))
        .collect();
    if !narrowing.is_empty() {
        anyhow::bail!("SerenDB QueryResultCell must allow every JSON value, found {narrowing:?}");
    }

    Ok(())
}

/// Normalize generated UTC timestamps before layout can split their type paths.
fn normalize_datetime_types(syntax: &mut syn::File) {
    use syn::visit_mut::VisitMut;

    fn plain_path(path: &syn::Path, names: &[&str]) -> bool {
        path.segments.len() == names.len()
            && path.segments.iter().zip(names).all(|(segment, name)| {
                segment.ident == *name && matches!(segment.arguments, syn::PathArguments::None)
            })
    }

    struct DateTimeNormalizer;

    impl VisitMut for DateTimeNormalizer {
        fn visit_type_mut(&mut self, ty: &mut syn::Type) {
            syn::visit_mut::visit_type_mut(self, ty);
            let syn::Type::Path(type_path) = ty else {
                return;
            };
            if type_path.qself.is_some() || type_path.path.segments.len() != 2 {
                return;
            }
            let mut segments = type_path.path.segments.iter();
            let namespace = segments.next().expect("two path segments");
            let name = segments.next().expect("two path segments");
            if namespace.ident != "chrono"
                || !matches!(namespace.arguments, syn::PathArguments::None)
                || name.ident != "DateTime"
            {
                return;
            }
            let syn::PathArguments::AngleBracketed(arguments) = &name.arguments else {
                return;
            };
            if arguments.args.len() != 1 {
                return;
            }
            let Some(syn::GenericArgument::Type(syn::Type::Path(timezone))) =
                arguments.args.first()
            else {
                return;
            };
            if timezone.qself.is_none() && plain_path(&timezone.path, &["chrono", "offset", "Utc"])
            {
                type_path.path = syn::parse_str("::jiff::Timestamp").expect("valid timestamp path");
            }
        }
    }

    DateTimeNormalizer.visit_file_mut(syntax);
}

// Skills has an unconstrained Value response. A gateway must trigger recovery
// rather than deserialize successfully as publisher data.
fn guard_publisher_value_response(syntax: &mut syn::File) {
    use syn::visit_mut::VisitMut;
    struct Guard;
    impl VisitMut for Guard {
        fn visit_item_struct_mut(&mut self, item: &mut syn::ItemStruct) {
            if item.ident == "DataResponseValue" {
                for field in &mut item.fields {
                    if field.ident.as_ref().is_some_and(|name| name == "data") {
                        field.attrs.push(syn::parse_quote!(
                            #[serde(deserialize_with = "crate::publisher_gateway::deserialize_direct_data")]
                        ));
                    }
                }
            }
            syn::visit_mut::visit_item_struct_mut(self, item);
        }
    }
    Guard.visit_file_mut(syntax);
}

fn main() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let openapi_dir = manifest_dir.join("openapi");
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
        "openapi-seren-storage.json",
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
    merge_api_spec(
        &mut raw_json,
        &openapi_dir.join("openapi-seren-storage.json"),
        "/publishers/seren-storage",
        Some("SerenStorage"),
        Some("seren_storage_"),
    )?;

    // Replace inline schemas in DataResponse_* wrappers with $ref to named equivalents.
    // This must run after merging publisher specs so all schemas are present.
    dedup_data_response_schemas(&mut raw_json);

    // Normalize OpenAPI 3.1 nullable syntax before deserializing with openapiv3.
    normalize_nullable_parameters(&mut raw_json);
    downconvert_31_to_30(&mut raw_json);
    normalize_string_enum_unions(&mut raw_json);
    let components = raw_json
        .pointer("/components/schemas")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    distribute_over_nested_exclusive_unions(&mut raw_json, &components);
    raw_json["openapi"] = serde_json::json!("3.0.3");

    strip_error_response_content(&mut raw_json);
    preserve_diagnostic_error_responses(&mut raw_json)?;
    // Notes documents binary downloads but omits content schemas. Preserve the
    // body as a stream, just as Progenitor already does for Skills' skill.md.
    for path in [
        "/publishers/seren-notes/attachments/{attachment_id}/data",
        "/publishers/seren-notes/attachments/{attachment_id}/thumbnail",
    ] {
        let response = raw_json["paths"][path]["get"]["responses"]["200"]
            .as_object_mut()
            .context("missing Notes binary response")?;
        response.insert(
            "content".into(),
            serde_json::json!({
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
            }),
        );
    }
    normalize_binary_content_schemas(&mut raw_json);
    remove_unsupported_operations(&mut raw_json)?;
    // Classify response-only schemas after unsupported operations are removed.
    open_response_only_schemas(&mut raw_json);

    // Checked on the document the generator consumes, after every normalization
    // pass. `downconvert_31_to_30` rewrites an empty `items` schema to an
    // object, so a cell that stopped being a named reference would silently
    // regenerate as a map.
    validate_query_result_cell_schema(&raw_json)?;
    let event_types = run_output_event_types(&raw_json)?;

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

    for (schema, rust_type) in SDK_SCHEMA_REPLACEMENTS {
        settings.with_replacement(
            *schema,
            *rust_type,
            std::iter::empty::<progenitor::TypeImpl>(),
        );
    }

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
    // Query cells are any JSON value. `arbitrary_precision` keeps the server's
    // exact decimal token intact through this type.
    settings.with_replacement(
        QUERY_RESULT_CELL_SCHEMA,
        "::serde_json::Value",
        std::iter::empty::<progenitor::TypeImpl>(),
    );

    let mut generator = progenitor::Generator::new(&settings);
    let tokens = generator.generate_tokens(&spec)?;

    let mut syntax: syn::File = syn::parse2(tokens)?;
    normalize_datetime_types(&mut syntax);
    guard_publisher_value_response(&mut syntax);
    let open_enums = open_marked_reply_enums(&mut syntax);
    open_reply_unions(&mut syntax);
    let formatted = prettyplease::unparse(&syntax);
    if formatted.contains(OPEN_REPLY_ENUM_MARKER) {
        anyhow::bail!("generated code still carries the open reply enum marker");
    }

    // Preserve status, headers, and body for every documented HTTP error.
    // Empty typed responses discard diagnostics before SDK consumers see them.
    let mut formatted = formatted;
    for status in 400..600 {
        formatted = formatted.replace(
            &format!("{status}u16 => Err(Error::ErrorResponse(ResponseValue::empty(response)))"),
            &format!("{status}u16 => Err(Error::UnexpectedResponse(response))"),
        );
    }
    if formatted.contains("Err(Error::ErrorResponse(ResponseValue::empty(response)))") {
        anyhow::bail!("generated response handling still discards an error body");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::create_dir_all(&out_dir)?;
    fs::write(out_dir.join("generated.rs"), formatted)?;
    // A test decodes an unlisted value into every reply enum the build opened.
    let mut checks = String::from(
        "pub(crate) fn unlisted_reply_value_refusals() -> Vec<&'static str> {\n    let mut refused = Vec::new();\n",
    );
    for name in &open_enums {
        checks.push_str(&format!(
            "    if !matches!(serde_json::from_value::<crate::{name}>(serde_json::json!(\"seren-unlisted-value\")), Ok(crate::{name}::Other(value)) if value == \"seren-unlisted-value\") {{ refused.push(\"{name}\"); }}\n"
        ));
    }
    checks.push_str("    refused\n}\n");
    checks.push_str(&format!(
        "pub(crate) const OPEN_REPLY_ENUMS: &[&str] = &{open_enums:?};\n"
    ));
    fs::write(out_dir.join("open_reply_enum_checks.rs"), checks)?;
    fs::write(
        out_dir.join("run_output_event_types.rs"),
        format!("pub(crate) const RUN_OUTPUT_EVENT_TYPES: &[&str] = &{event_types:?};\n"),
    )?;

    Ok(())
}
