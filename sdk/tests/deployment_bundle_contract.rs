//! Cross-repo drift guard for the content-addressed deployment-bundle contract
//! that the MCP `register_agent_bundle` / `complete_agent_bundle_upload` producer
//! tools (issue #226) ride on.
//!
//! The generated client can only call the bundle ops while the committed
//! `openapi-seren-cloud.json` snapshot keeps their route, request shape, and the
//! `agent_bundle` source-kind variant. If a future Core re-sync drops or reshapes
//! any of them, this test goes red here instead of silently breaking the producer
//! tool in production. The CI job `openapi-bundle-drift` (see
//! `openapi/scripts/check_bundle_contract_drift.py`) checks the SAME subset against
//! the deployed Core spec so the snapshot cannot fall behind Core unnoticed.

use serde_json::{Value, json};

fn cloud_spec() -> Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi/openapi-seren-cloud.json"
    ))
    .expect("committed seren-cloud OpenAPI snapshot must exist");
    serde_json::from_str(&raw).expect("seren-cloud OpenAPI snapshot must be valid JSON")
}

/// The exact contract subset the producer tools depend on. Keep this in lockstep
/// with `openapi/scripts/check_bundle_contract_drift.py::bundle_contract`.
fn bundle_contract(spec: &Value) -> Value {
    let schemas = &spec["components"]["schemas"];
    let paths = &spec["paths"];
    json!({
        "create_op": paths["/deployment-bundles"]["post"]["operationId"],
        "create_request_ref": paths["/deployment-bundles"]["post"]["requestBody"]
            ["content"]["application/json"]["schema"]["$ref"],
        "complete_op": paths["/deployment-bundles/{id}/complete"]["post"]["operationId"],
        "create_request_required": schemas["CreateCloudDeploymentBundleRequest"]["required"],
        "source_kind_enum": schemas["CloudDeploymentBundleSourceKind"]["enum"],
    })
}

fn expected_contract() -> Value {
    json!({
        "create_op": "seren_cloud_create_deployment_bundle",
        "create_request_ref": "#/components/schemas/CreateCloudDeploymentBundleRequest",
        "complete_op": "seren_cloud_complete_deployment_bundle_upload",
        "create_request_required": ["sha256", "size_bytes", "source_kind"],
        "source_kind_enum": ["tar_gz", "agent_bundle"],
    })
}

#[test]
fn committed_snapshot_pins_the_bundle_producer_contract() {
    assert_eq!(
        bundle_contract(&cloud_spec()),
        expected_contract(),
        "the committed seren-cloud snapshot no longer matches the bundle producer contract; a Core re-sync changed register/complete or the source_kind enum — update the producer tools and this pin together"
    );
}

#[test]
fn drift_guard_detects_a_stale_source_kind_enum() {
    // Prove the guard is sensitive to the field that actually matters: drop the
    // `agent_bundle` variant and the extracted contract must diverge.
    let mut mutated = cloud_spec();
    mutated["components"]["schemas"]["CloudDeploymentBundleSourceKind"]["enum"] = json!(["tar_gz"]);
    assert_ne!(
        bundle_contract(&mutated),
        expected_contract(),
        "the drift guard must flag a snapshot that has lost the agent_bundle source kind"
    );
}
