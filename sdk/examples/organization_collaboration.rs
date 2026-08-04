//! Govern an employee's organization collaboration with compare-and-swap updates.
//!
//! Employee work is individual by default. An employee reaches organization
//! knowledge, credentials, skills, and artifact writes only when the organization
//! policy, the employee assignment, and the service grant all allow it. This
//! example enables the policy, narrows one employee to read-only knowledge
//! access, and then revokes it.
//!
//! Policy and assignment writes carry the revision or generation the caller read.
//! Seren rejects the write when another administrator changed the record first,
//! so a stale console tab cannot silently widen authority or reactivate an
//! assignment that someone just revoked.

use seren::{
    Client, ClientConfig, UpdateOrganizationEmployeeCollaborationPolicyRequest,
    UpsertOrganizationEmployeeCollaborationAssignmentRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::from_env();
    if config.bearer_token.is_none() {
        eprintln!("Set SEREN_API_KEY to run this example against the Seren API.");
        std::process::exit(1);
    }

    let organization_id: uuid::Uuid = match std::env::var("SEREN_ORGANIZATION_ID") {
        Ok(value) => value.parse()?,
        Err(_) => {
            eprintln!("Set SEREN_ORGANIZATION_ID to run this example.");
            std::process::exit(1);
        }
    };
    let deployment_id: uuid::Uuid = match std::env::var("SEREN_DEPLOYMENT_ID") {
        Ok(value) => value.parse()?,
        Err(_) => {
            eprintln!("Set SEREN_DEPLOYMENT_ID to run this example.");
            std::process::exit(1);
        }
    };

    let client = Client::from_config(&config)?;

    let policy = client
        .get_employee_collaboration_policy(&organization_id)
        .await?
        .into_inner();
    // The revision read here is what makes the next write safe. Sending it back
    // tells Seren which version of the policy this decision was based on.
    let policy_revision = policy.data.policy_revision.clone();
    println!("Current policy revision: {policy_revision}");

    // The policy is the ceiling for every employee. Enable only the capabilities
    // the organization is willing to delegate at all.
    let updated_policy = client
        .update_employee_collaboration_policy(
            &organization_id,
            &UpdateOrganizationEmployeeCollaborationPolicyRequest {
                expected_policy_revision: policy_revision,
                enabled: true,
                organization_knowledge_read: Some(true),
                organization_credential_use: Some(false),
                organization_skill_use: Some(false),
                organization_artifact_write: Some(false),
            },
        )
        .await?
        .into_inner();
    println!(
        "Policy revision after update: {}",
        updated_policy.data.policy_revision
    );

    // An assignment can only narrow the policy, never widen it. Requesting a
    // capability the policy withholds does not grant it.
    let assignment = client
        .upsert_employee_collaboration_assignment(
            &organization_id,
            &deployment_id,
            &UpsertOrganizationEmployeeCollaborationAssignmentRequest {
                allowed_task_labels: vec!["research".to_string()],
                expected_assignment_generation: None,
                organization_knowledge_read: Some(true),
                organization_credential_use: Some(false),
                organization_skill_use: Some(false),
                organization_artifact_write: Some(false),
            },
        )
        .await?
        .into_inner();
    let generation = assignment.data.assignment_generation;
    println!("Assignment generation: {generation}");

    let assignments = client
        .list_employee_collaboration_assignments(&organization_id, Some(false))
        .await?
        .into_inner();
    println!("Active assignments: {}", assignments.data.len());

    // Revocation is guarded by the same generation, so it cannot silently undo
    // an assignment that changed after this example read it. Revocation applies
    // at the employee's next protected operation: a run already holding a signed
    // work context does not keep its access.
    client
        .revoke_employee_collaboration_assignment(&organization_id, &deployment_id, generation)
        .await?;
    println!("Assignment revoked; the next protected operation is denied.");

    Ok(())
}
