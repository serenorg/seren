//! Documentation page handler for the MCP server.
//!
//! Serves a static HTML documentation page at all routes except /mcp, /health,
//! and OAuth endpoints. This allows users to discover available MCP tools.

use axum::response::{Html, IntoResponse};

/// Tool information for documentation
struct Tool {
    name: &'static str,
    description: &'static str,
    category: &'static str,
}

/// All MCP tools organized by category
const TOOLS: &[Tool] = &[
    // Project Management
    Tool {
        name: "list_projects",
        description: "List all Seren projects accessible to the authenticated user",
        category: "Projects",
    },
    Tool {
        name: "describe_project",
        description: "Get detailed information about a specific project",
        category: "Projects",
    },
    Tool {
        name: "create_project",
        description: "Create a new Seren project",
        category: "Projects",
    },
    Tool {
        name: "delete_project",
        description: "Delete a Seren project",
        category: "Projects",
    },
    Tool {
        name: "update_project",
        description: "Update a project's settings including name, security options, and compute defaults",
        category: "Projects",
    },
    // Branch Management
    Tool {
        name: "list_branches",
        description: "List branches for a project",
        category: "Branches",
    },
    Tool {
        name: "describe_branch",
        description: "Get detailed information about a branch",
        category: "Branches",
    },
    Tool {
        name: "create_branch",
        description: "Create a new branch in a project",
        category: "Branches",
    },
    Tool {
        name: "delete_branch",
        description: "Delete a branch",
        category: "Branches",
    },
    Tool {
        name: "rename_branch",
        description: "Rename a branch",
        category: "Branches",
    },
    Tool {
        name: "set_default_branch",
        description: "Set a branch as the default branch for the project",
        category: "Branches",
    },
    Tool {
        name: "reset_branch",
        description: "Reset a branch to its parent's latest state (destroys all data)",
        category: "Branches",
    },
    Tool {
        name: "set_branch_expiration",
        description: "Set or remove branch expiration date",
        category: "Branches",
    },
    // Database Operations
    Tool {
        name: "list_databases",
        description: "List all databases in a branch",
        category: "Databases",
    },
    Tool {
        name: "create_database",
        description: "Create a new database in a branch",
        category: "Databases",
    },
    Tool {
        name: "get_database",
        description: "Get details about a specific database",
        category: "Databases",
    },
    Tool {
        name: "delete_database",
        description: "Delete a database from a branch",
        category: "Databases",
    },
    Tool {
        name: "get_database_tables",
        description: "List tables in a database schema",
        category: "Databases",
    },
    Tool {
        name: "describe_table_schema",
        description: "Get schema information for a table",
        category: "Databases",
    },
    // SQL Execution
    Tool {
        name: "run_sql",
        description: "Execute a SQL query against a database",
        category: "SQL",
    },
    Tool {
        name: "run_sql_transaction",
        description: "Execute multiple SQL statements in a single transaction",
        category: "SQL",
    },
    Tool {
        name: "explain_sql_statement",
        description: "Explain a SQL statement (FORMAT JSON)",
        category: "SQL",
    },
    Tool {
        name: "get_connection_string",
        description: "Get connection string for a branch",
        category: "SQL",
    },
    // Roles & Credentials
    Tool {
        name: "list_roles",
        description: "List all roles in a branch",
        category: "Roles",
    },
    Tool {
        name: "create_role",
        description: "Create a new database role on a branch",
        category: "Roles",
    },
    Tool {
        name: "delete_role",
        description: "Delete a database role from a branch",
        category: "Roles",
    },
    Tool {
        name: "reset_role_password",
        description: "Reset a database role's password, generating a new secure password",
        category: "Roles",
    },
    Tool {
        name: "reveal_role_password",
        description: "Reveal the current password for a database role",
        category: "Roles",
    },
    // Compute Endpoints
    Tool {
        name: "list_endpoints",
        description: "List all endpoints for a branch",
        category: "Endpoints",
    },
    Tool {
        name: "create_endpoint",
        description: "Create a new endpoint for a branch",
        category: "Endpoints",
    },
    Tool {
        name: "delete_endpoint",
        description: "Delete an endpoint",
        category: "Endpoints",
    },
    Tool {
        name: "update_endpoint",
        description: "Update an endpoint's settings including autoscaling and suspend timeout",
        category: "Endpoints",
    },
    Tool {
        name: "get_endpoint_status",
        description: "Get the current status of an endpoint (running, suspended, etc.)",
        category: "Endpoints",
    },
    Tool {
        name: "start_endpoint",
        description: "Start a suspended endpoint",
        category: "Endpoints",
    },
    Tool {
        name: "suspend_endpoint",
        description: "Suspend an endpoint",
        category: "Endpoints",
    },
    Tool {
        name: "restart_endpoint",
        description: "Restart an endpoint (rolling restart via Kubernetes)",
        category: "Endpoints",
    },
    // Organizations & API Keys
    Tool {
        name: "list_organizations",
        description: "List organizations accessible to the authenticated user",
        category: "Organizations",
    },
    Tool {
        name: "list_api_keys",
        description: "List all API keys for an organization",
        category: "Organizations",
    },
    Tool {
        name: "create_api_key",
        description: "Create a new API key for an organization",
        category: "Organizations",
    },
    Tool {
        name: "revoke_api_key",
        description: "Revoke an API key",
        category: "Organizations",
    },
    // Agent Store & Publishers
    Tool {
        name: "list_agent_publishers",
        description: "List all active publishers in the agent store. Publishers provide databases or APIs that AI agents can query with micropayments.",
        category: "Agent Store",
    },
    Tool {
        name: "get_agent_publisher",
        description: "Get details about a specific publisher including pricing info by slug",
        category: "Agent Store",
    },
    Tool {
        name: "suggest_for_task",
        description: "Get publisher and agent recommendations for a task. Call this BEFORE using WebSearch/WebFetch to check if a Seren publisher can do the task better.",
        category: "Agent Store",
    },
    Tool {
        name: "create_publisher",
        description: "Create a new publisher in the agent store. Requires API key authentication.",
        category: "Agent Store",
    },
    // Payments & Wallet
    Tool {
        name: "get_prepaid_balance",
        description: "Get your SerenBucks balance. SerenBucks are credits used to pay for API calls and database queries.",
        category: "Payments",
    },
    Tool {
        name: "get_wallet_status",
        description: "Get your complete wallet status including SerenBucks balance and on-chain USDC balance (if local wallet configured).",
        category: "Payments",
    },
    Tool {
        name: "create_prepaid_deposit",
        description: "Deposit SerenBucks with a credit card via Stripe. Returns a checkout URL to complete payment.",
        category: "Payments",
    },
    Tool {
        name: "get_transaction_history",
        description: "Get transaction history for your wallet (deposits, charges, refunds)",
        category: "Payments",
    },
    Tool {
        name: "get_local_wallet_address",
        description: "Get the local wallet address. Only available when running locally with WALLET_PRIVATE_KEY.",
        category: "Payments",
    },
    Tool {
        name: "has_local_wallet",
        description: "Check if a local wallet is configured.",
        category: "Payments",
    },
    Tool {
        name: "get_x402_deposit_requirements",
        description: "Get x402 on-chain deposit requirements for depositing USDC to a publisher.",
        category: "Payments",
    },
    Tool {
        name: "get_supported",
        description: "Get supported payment protocols and configuration.",
        category: "Payments",
    },
    // Paid Queries & APIs
    Tool {
        name: "execute_paid_query",
        description: "Execute a paid SQL query against a publisher's database. Uses SerenBucks or x402 crypto payments.",
        category: "Paid APIs",
    },
    Tool {
        name: "execute_paid_api",
        description: "Execute a paid API request against a publisher's endpoint. USE THIS for web scraping (Firecrawl), AI-powered search (Perplexity), or other publisher APIs.",
        category: "Paid APIs",
    },
    Tool {
        name: "execute_paid_api_stream",
        description: "Execute a paid streaming API request. Streaming requires x402 local wallet signing.",
        category: "Paid APIs",
    },
    Tool {
        name: "estimate_query_cost",
        description: "Estimate the cost of a SQL query against a publisher's database without executing it",
        category: "Paid APIs",
    },
];

/// Generate the HTML documentation page
fn generate_docs_html() -> String {
    let version = env!("CARGO_PKG_VERSION");

    // Group tools by category
    let categories = [
        "Projects",
        "Branches",
        "Databases",
        "SQL",
        "Roles",
        "Endpoints",
        "Organizations",
        "Agent Store",
        "Payments",
        "Paid APIs",
    ];

    let mut tools_html = String::new();

    for category in categories {
        let category_tools: Vec<_> = TOOLS.iter().filter(|t| t.category == category).collect();
        if category_tools.is_empty() {
            continue;
        }

        tools_html.push_str(&format!(
            r#"<div class="category">
                <h3>{}</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Tool</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>"#,
            category
        ));

        for tool in category_tools {
            tools_html.push_str(&format!(
                r#"<tr>
                    <td><code>{}</code></td>
                    <td>{}</td>
                </tr>"#,
                tool.name, tool.description
            ));
        }

        tools_html.push_str("</tbody></table></div>");
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Seren MCP Server Documentation</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-tertiary: #0f3460;
            --text-primary: #eaeaea;
            --text-secondary: #b8b8b8;
            --accent: #e94560;
            --accent-secondary: #533483;
            --border: #2a2a4a;
            --code-bg: #0d1117;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            text-align: center;
            padding: 3rem 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }}

        h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--accent), var(--accent-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .version {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .intro {{
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border);
        }}

        .intro h2 {{
            color: var(--accent);
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }}

        .intro p {{
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }}

        .intro code {{
            background: var(--code-bg);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
        }}

        .endpoints {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            margin: 1rem 0;
        }}

        .endpoints code {{
            display: block;
            margin: 0.5rem 0;
            color: var(--text-primary);
        }}

        .category {{
            margin-bottom: 2rem;
        }}

        .category h3 {{
            color: var(--accent);
            font-size: 1.2rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--accent-secondary);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }}

        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}

        th {{
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-weight: 600;
        }}

        td:first-child {{
            width: 280px;
        }}

        td code {{
            background: var(--code-bg);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
            color: var(--accent);
        }}

        td:last-child {{
            color: var(--text-secondary);
        }}

        tr:hover {{
            background: var(--bg-tertiary);
        }}

        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            border-top: 1px solid var(--border);
            margin-top: 2rem;
        }}

        footer a {{
            color: var(--accent);
            text-decoration: none;
        }}

        footer a:hover {{
            text-decoration: underline;
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}

            h1 {{
                font-size: 1.8rem;
            }}

            td:first-child {{
                width: auto;
            }}

            table {{
                font-size: 0.9rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Seren MCP Server</h1>
            <p class="version">Version {version}</p>
        </header>

        <div class="intro">
            <h2>Getting Started</h2>
            <p>
                The Seren MCP Server provides AI assistants with tools to manage PostgreSQL databases,
                execute queries, and access the Agent Store for paid data services.
            </p>
            <p>
                Connect your AI assistant to this server using the Model Context Protocol (MCP).
                The MCP endpoint is available at:
            </p>
            <div class="endpoints">
                <code>POST /mcp - Send JSON-RPC messages</code>
                <code>GET  /mcp - Establish SSE stream (with session)</code>
                <code>DELETE /mcp - Close session</code>
            </div>
            <p>
                For more information, visit <a href="https://serendb.com" style="color: var(--accent);">serendb.com</a>
                or check out the <a href="https://github.com/serenorg/seren" style="color: var(--accent);">GitHub repository</a>.
            </p>
        </div>

        <h2 style="margin-bottom: 1.5rem;">Available Tools</h2>

        {tools_html}

        <footer>
            <p>
                <a href="https://serendb.com">SerenDB</a> ·
                <a href="https://github.com/serenorg/seren">GitHub</a> ·
                <a href="https://docs.serendb.com">Documentation</a>
            </p>
        </footer>
    </div>
</body>
</html>"##
    )
}

/// Handler for the documentation page
pub async fn docs_handler() -> impl IntoResponse {
    Html(generate_docs_html())
}
