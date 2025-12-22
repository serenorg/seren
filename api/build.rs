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

/// Strip content bodies from 402 responses since progenitor doesn't handle them well.
/// The 402 Payment Required response has a body in the API but progenitor treats
/// any response with content as a "success" response type, causing assertion failures.
fn strip_402_content(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // If this is a responses object with a "402" key, strip its content
            if let Some(response_402) = map.get_mut("402") {
                if let serde_json::Value::Object(resp_obj) = response_402 {
                    resp_obj.remove("content");
                }
            }
            // Recurse into all values
            for v in map.values_mut() {
                strip_402_content(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                strip_402_content(v);
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

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../openapi/openapi.json");

    let spec_str = fs::read_to_string("../openapi/openapi.json")?;
    let mut raw_json: serde_json::Value = serde_json::from_str(&spec_str)?;

    // Strip 402 response content bodies since progenitor can't handle them
    strip_402_content(&mut raw_json);

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

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::create_dir_all(&out_dir)?;
    fs::write(out_dir.join("generated.rs"), formatted)?;

    Ok(())
}
