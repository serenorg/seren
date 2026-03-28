//! Build script to extract MCP tool metadata from server.rs
//!
//! Parses #[tool(description = "...")] attributes and generates a Rust file
//! with tool information for the documentation page.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo::rerun-if-changed=src/server.rs");

    let server_rs = fs::read_to_string("src/server.rs").expect("Failed to read src/server.rs");

    let tools = extract_tools(&server_rs);

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = Path::new(&out_dir).join("tools_generated.rs");

    let generated = generate_tools_module(&tools);
    fs::write(&dest_path, generated).expect("Failed to write generated tools file");
}

#[derive(Debug)]
struct Tool {
    name: String,
    description: String,
}

fn extract_tools(source: &str) -> Vec<Tool> {
    let mut tools = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();

        // Look for #[tool( attribute
        if line.starts_with("#[tool(") {
            // Extract description from this line or following lines
            let mut description = String::new();
            let mut j = i;

            // Collect all lines until we find the closing )]
            let mut attr_content = String::new();
            while j < lines.len() {
                attr_content.push_str(lines[j]);
                attr_content.push('\n');
                if lines[j].contains(")]") {
                    break;
                }
                j += 1;
            }

            // Extract description from the attribute
            if let Some(desc) = extract_description(&attr_content) {
                description = desc;
            }

            // Find the async fn declaration after the attribute
            // Skip any other attributes like #[instrument(...)]
            j += 1;
            while j < lines.len() {
                let fn_line = lines[j].trim();
                if fn_line.starts_with("async fn ") {
                    if let Some(name) = extract_fn_name(fn_line) {
                        tools.push(Tool { name, description });
                    }
                    break;
                }
                // Skip other attributes (may span multiple lines)
                if fn_line.starts_with('#') {
                    // Skip until we find the closing bracket or next line
                    while j < lines.len() && !lines[j].contains(")]") && !lines[j].contains(']') {
                        j += 1;
                    }
                    j += 1;
                    continue;
                }
                // Skip empty lines
                if fn_line.is_empty() {
                    j += 1;
                    continue;
                }
                // If we hit something else, stop looking
                break;
            }
        }
        i += 1;
    }

    tools
}

fn extract_description(attr: &str) -> Option<String> {
    // Look for description = "..."
    let desc_start = attr.find("description")?;
    let after_desc = &attr[desc_start..];

    // Find the opening quote
    let quote_start = after_desc.find('"')? + 1;
    let rest = &after_desc[quote_start..];

    // Find the closing quote (handle escaped quotes)
    let mut chars = rest.chars().peekable();
    let mut description = String::new();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // Escaped character
            if let Some(&next) = chars.peek()
                && (next == '"' || next == '\\')
            {
                description.push(chars.next().unwrap());
                continue;
            }
            description.push(c);
        } else if c == '"' {
            break;
        } else {
            description.push(c);
        }
    }

    Some(description)
}

fn extract_fn_name(line: &str) -> Option<String> {
    // async fn name(
    let after_fn = line.strip_prefix("async fn ")?;
    let paren_pos = after_fn.find('(')?;
    Some(after_fn[..paren_pos].to_string())
}

fn categorize_tool(name: &str) -> &'static str {
    match name {
        n if n.contains("project") => "Projects",
        n if n.contains("branch") && !n.contains("default") => "Branches",
        "set_default_branch" => "Branches",
        n if n.contains("database") || n.contains("table") => "Databases",
        n if n.contains("sql")
            || n.contains("connection_string")
            || n == "run_sql"
            || n == "run_sql_transaction"
            || n == "explain_sql_statement" =>
        {
            "SQL"
        }
        n if n.contains("role") => "Roles",
        n if n.contains("endpoint") => "Endpoints",
        n if n.contains("organization") || n.contains("api_key") || n.contains("org_oauth") => {
            "Organizations & Access"
        }
        n if n.contains("cloud_eval")
            || n.contains("eval_set")
            || n.contains("eval_case")
            || n.contains("eval_run") =>
        {
            "Cloud Evals"
        }
        "promote_cloud_run_to_eval_case" => "Cloud Evals",
        n if n == "list_mcp_tools" || n == "list_mcp_resources" => "MCP Publishers",
        n if n.contains("seren_agent") => "Managed Agents",
        n if n.contains("cloud_environment") => "Cloud Environments",
        n if n == "deploy_cloud_agent"
            || n == "list_cloud_agents"
            || n == "get_cloud_overview"
            || n == "cloud_agent_status"
            || n == "start_cloud_agent"
            || n == "stop_cloud_agent"
            || n == "run_cloud_agent"
            || n == "cloud_agent_logs"
            || n == "destroy_cloud_agent"
            || n == "update_cloud_agent_config" =>
        {
            "Cloud Deployments"
        }
        n if n.contains("cloud_run")
            || n.contains("cloud_agent_run")
            || n.contains("pending_cloud_approvals")
            || n == "list_all_cloud_runs"
            || n == "get_cloud_run_by_id"
            || n == "compare_cloud_runs"
            || n == "list_cloud_run_artifacts"
            || n == "cancel_cloud_run_by_id" =>
        {
            "Cloud Runs & Approvals"
        }
        n if n == "get_local_wallet_address"
            || n == "has_local_wallet"
            || n == "get_onchain_wallet_status"
            || n == "get_x402_deposit_requirements"
            || n == "get_supported" =>
        {
            "Local Wallet & x402"
        }
        n if n.contains("prepaid")
            || n == "get_wallet_status"
            || n == "get_transaction_history" =>
        {
            "Payments & Wallets"
        }
        n if n.contains("publisher")
            || n == "suggest_for_task"
            || n.contains("agent_template")
            || n == "run_agent_cloud"
            || n == "list_agent_tasks"
            || n == "get_agent_task"
            || n == "cancel_agent_task"
            || n == "estimate_query_cost" =>
        {
            "Agent Store & Publishers"
        }
        _ => "Other",
    }
}

fn generate_tools_module(tools: &[Tool]) -> String {
    let mut output = String::new();

    output.push_str("// Auto-generated by build.rs - DO NOT EDIT\n\n");
    output.push_str("/// Tool information for documentation\n");
    output.push_str("#[derive(Debug, Clone)]\n");
    output.push_str("pub struct Tool {\n");
    output.push_str("    pub name: &'static str,\n");
    output.push_str("    pub description: &'static str,\n");
    output.push_str("    pub category: &'static str,\n");
    output.push_str("}\n\n");

    output.push_str("/// All MCP tools extracted from server.rs\n");
    output.push_str("pub const TOOLS: &[Tool] = &[\n");

    for tool in tools {
        let category = categorize_tool(&tool.name);
        // Escape any quotes in description
        let escaped_desc = tool.description.replace('\\', "\\\\").replace('"', "\\\"");
        output.push_str(&format!(
            "    Tool {{ name: \"{}\", description: \"{}\", category: \"{}\" }},\n",
            tool.name, escaped_desc, category
        ));
    }

    output.push_str("];\n");

    output
}
