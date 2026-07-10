use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use seren::{
    AgentBundle, AgentInstructionFile, AgentInstructionKind, AgentSpec, Client, ClientConfig,
    CloudDeploymentMode, ManagedAgentApprovalPolicy, ManagedAgentModelPolicy,
    ManagedAgentRuntimeAdapter, ManagedAgentTemplate, ManagedAgentToolPreset,
    TestSerenAgentDraftRunRequest, WorkloadExecution, WorkloadLimits, WorkloadSpec,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstructionReference {
    kind: AgentInstructionKind,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmployeeManifest {
    name: String,
    slug: String,
    description: String,
    default_message: String,
    mode: CloudDeploymentMode,
    #[serde(default)]
    cron_schedule: Option<String>,
    #[serde(default)]
    cron_timezone: Option<String>,
    template: ManagedAgentTemplate,
    tool_presets: Vec<ManagedAgentToolPreset>,
    approval_policy: ManagedAgentApprovalPolicy,
    model_policy: ManagedAgentModelPolicy,
    visibility: String,
    limits: WorkloadLimits,
    instructions: Vec<InstructionReference>,
}

struct EmployeeBlueprint {
    directory: PathBuf,
    description: String,
    default_message: String,
    spec: AgentSpec,
}

#[derive(Clone, Copy)]
enum Action {
    Preview,
    Test,
    Deploy,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let action = parse_action(args.next().as_deref().unwrap_or("preview"))?;
    let employee_slug = args
        .next()
        .unwrap_or_else(|| "chief-financial-officer".to_string());
    let employee = load_employee(&employee_slug)?;

    if matches!(action, Action::Preview) {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "employee": employee_slug,
                "bundle_directory": employee.directory,
                "description": employee.description,
                "default_message": employee.default_message,
                "deployment": employee.spec,
            }))?
        );
        return Ok(());
    }

    let config = ClientConfig::from_env();
    if config.bearer_token.is_none() {
        return Err("Set SEREN_API_KEY to run this example against the Seren API.".into());
    }
    require_opt_in(
        "SEREN_EXAMPLE_ALLOW_PAID",
        "run a paid employee test or deployment",
    )?;
    let client = Client::from_config(&config)?;

    match action {
        Action::Preview => unreachable!(),
        Action::Test => {
            let message = {
                let override_message = args.collect::<Vec<_>>().join(" ");
                if override_message.trim().is_empty() {
                    employee.default_message
                } else {
                    override_message
                }
            };
            let result = client
                .seren_agent_test_run(&TestSerenAgentDraftRunRequest {
                    deployment: employee.spec,
                    message: Some(message),
                })
                .await?
                .into_inner()
                .data;
            println!(
                "Test status: {} ({} iteration(s), {} tool call(s))",
                result.status,
                result.iterations,
                result.tool_calls.len()
            );
            if let Some(response) = result.response.or(result.partial_response) {
                println!("\n{response}");
            }
            if let Some(error) = result.error {
                eprintln!("Employee error: {error}");
            }
            for warning in result.warnings {
                eprintln!("Warning: {warning}");
            }
        }
        Action::Deploy => {
            require_opt_in(
                "SEREN_EXAMPLE_ALLOW_DEPLOY",
                "create or update this recurring deployment",
            )?;
            let deployment = client
                .seren_agent_deploy(&employee.spec)
                .await?
                .into_inner()
                .data;
            println!(
                "Deployment accepted: {} ({}) - {}",
                deployment.name, deployment.id, deployment.status
            );
        }
    }

    Ok(())
}

fn load_employee(slug: &str) -> Result<EmployeeBlueprint, Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/employees");
    let available = employee_slugs(&root)?;
    if !available.iter().any(|candidate| candidate == slug) {
        return Err(format!(
            "Unknown employee {slug:?}. Choose: {}.",
            available.join(", ")
        )
        .into());
    }

    let directory = root.join(slug);
    let manifest_body = std::fs::read_to_string(directory.join("employee.json"))?;
    let manifest: EmployeeManifest = serde_json::from_str(&manifest_body)?;
    if manifest.slug != slug {
        return Err(format!(
            "Employee folder {slug:?} declares the mismatched slug {:?}.",
            manifest.slug
        )
        .into());
    }
    if manifest.mode == CloudDeploymentMode::Cron && manifest.cron_schedule.is_none() {
        return Err(format!("Employee {slug:?} uses cron mode without cron_schedule.").into());
    }
    if manifest.mode != CloudDeploymentMode::Cron && manifest.cron_schedule.is_some() {
        return Err(format!("Employee {slug:?} declares cron_schedule outside cron mode.").into());
    }

    let instructions = manifest
        .instructions
        .into_iter()
        .map(|reference| load_instruction(&directory, reference))
        .collect::<Result<Vec<_>, _>>()?;
    require_instruction_kinds(slug, &instructions)?;

    let spec = AgentSpec {
        agent_identity_id: None,
        agent_slug: Some(manifest.slug),
        alert_policy: None,
        allowed_remote_agent_origins: None,
        approval_policy: Some(manifest.approval_policy),
        capability_policy: None,
        credentials: None,
        cron_schedule: manifest.cron_schedule,
        cron_timezone: manifest.cron_timezone,
        dashboard_config: None,
        eval_gate: None,
        guardrails: None,
        memory_policy: None,
        mode: manifest.mode,
        model_policy: Some(manifest.model_policy),
        name: Some(manifest.name),
        private_output_policy: None,
        runtime_policy: None,
        secret_resolution_delegation: None,
        session_database: None,
        template: Some(manifest.template),
        tool_presets: Some(manifest.tool_presets),
        tool_refs: None,
        visibility: Some(manifest.visibility),
        workload: WorkloadSpec {
            compute_backend: None,
            config: None,
            execution: WorkloadExecution::Llm {
                adapter: Some(ManagedAgentRuntimeAdapter::SerenAgent),
                bundle: AgentBundle {
                    instructions,
                    ..AgentBundle::default()
                },
                fallback_models: None,
                llm_connection: None,
                model_config: None,
                model_id: None,
                tool_definitions: None,
            },
            limits: Some(manifest.limits),
            network_policy: None,
            publisher_only: Some(true),
            requirements: None,
            secrets: None,
            side_effect_policy: None,
        },
    };

    Ok(EmployeeBlueprint {
        directory,
        description: manifest.description,
        default_message: manifest.default_message,
        spec,
    })
}

fn load_instruction(
    directory: &Path,
    reference: InstructionReference,
) -> Result<AgentInstructionFile, Box<dyn std::error::Error>> {
    let path = Path::new(&reference.path);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(format!("Unsafe instruction path: {:?}.", reference.path).into());
    }
    let content = std::fs::read_to_string(directory.join(path))?;
    if content.trim().is_empty() {
        return Err(format!("Instruction file is empty: {}.", reference.path).into());
    }
    Ok(AgentInstructionFile {
        allowed_tools: None,
        content: content.trim().to_string(),
        kind: reference.kind,
        path: Some(reference.path),
        sha256: None,
        skill_name: None,
    })
}

fn employee_slugs(root: &Path) -> Result<Vec<String>, std::io::Error> {
    let mut slugs = std::fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir() && entry.path().join("employee.json").is_file())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    slugs.sort();
    Ok(slugs)
}

fn require_instruction_kinds(
    slug: &str,
    instructions: &[AgentInstructionFile],
) -> Result<(), Box<dyn std::error::Error>> {
    let kinds = instructions
        .iter()
        .map(|instruction| instruction.kind)
        .collect::<HashSet<_>>();
    for required in [
        AgentInstructionKind::Identity,
        AgentInstructionKind::Skill,
        AgentInstructionKind::Tools,
        AgentInstructionKind::Eval,
    ] {
        if !kinds.contains(&required) {
            return Err(format!("Employee {slug:?} is missing a {required} instruction.").into());
        }
    }
    Ok(())
}

fn parse_action(value: &str) -> Result<Action, Box<dyn std::error::Error>> {
    match value {
        "preview" => Ok(Action::Preview),
        "test" => Ok(Action::Test),
        "deploy" => Ok(Action::Deploy),
        _ => Err(format!("Unknown action {value:?}. Choose: preview, test, deploy.").into()),
    }
}

fn require_opt_in(name: &str, purpose: &str) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var(name).as_deref() == Ok("1") {
        Ok(())
    } else {
        Err(format!("Set {name}=1 to {purpose}.").into())
    }
}
