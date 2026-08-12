//! Documentation page handler for the MCP server.
//!
//! Serves a static HTML documentation page at all routes except /mcp, /livez,
//! and OAuth endpoints. Tool information is auto-generated from server.rs at build time.

use axum::response::{Html, IntoResponse};

// Include the generated tools module
include!(concat!(env!("OUT_DIR"), "/tools_generated.rs"));

/// Generate the HTML documentation page
fn generate_docs_html() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let total_tools = TOOLS.len();

    // Group tools by category (maintain order)
    let categories = [
        "Projects",
        "Branches",
        "Databases",
        "SQL",
        "Roles",
        "Endpoints",
        "Organizations & Access",
        "Agent Store & Publishers",
        "Payments & Wallets",
        "Local Wallet & x402",
        "MCP Publishers",
        "Managed Agents",
        "Cloud Environments",
        "Cloud Deployments",
        "Cloud Runs & Approvals",
        "Cloud Evals",
        "Other",
    ];
    let populated_category_count = categories
        .iter()
        .filter(|category| TOOLS.iter().any(|tool| tool.category == **category))
        .count();

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
    <title>Seren MCP Server</title>
    <link rel="icon" href="https://serendb.com/favicon.ico" type="image/x-icon">
    <style>
        :root {{
            /* SerenAI dark theme - Zinc palette with Cyan accent */
            --bg-primary: #09090b;
            --bg-secondary: #18181b;
            --bg-tertiary: #27272a;
            --text-primary: #fafafa;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --accent: #06b6d4;
            --accent-hover: #22d3ee;
            --accent-muted: rgba(6, 182, 212, 0.15);
            --border: #27272a;
            --code-bg: #18181b;
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

        .logo {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            margin-bottom: 0.5rem;
        }}

        .logo svg {{
            width: 48px;
            height: 48px;
        }}

        h1 {{
            font-size: 2.5rem;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .version {{
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-top: 0.25rem;
        }}

        .intro {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border);
        }}

        .intro h2 {{
            color: var(--accent);
            margin-bottom: 1rem;
            font-size: 1.25rem;
            font-weight: 600;
        }}

        .intro p {{
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }}

        .intro a {{
            color: var(--accent);
            text-decoration: none;
            transition: color 0.2s;
        }}

        .intro a:hover {{
            color: var(--accent-hover);
            text-decoration: underline;
        }}

        .endpoints {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            margin: 1rem 0;
            font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Monaco, monospace;
            font-size: 0.875rem;
        }}

        .endpoints code {{
            display: block;
            margin: 0.5rem 0;
            color: var(--text-primary);
        }}

        .endpoints .method {{
            color: var(--accent);
            font-weight: 600;
            display: inline-block;
            width: 60px;
        }}

        .meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            margin: 1rem 0 0;
        }}

        .pill {{
            border: 1px solid var(--border);
            background: var(--bg-tertiary);
            border-radius: 999px;
            padding: 0.45rem 0.8rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}

        .links-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-top: 1.25rem;
        }}

        .link-card {{
            display: block;
            background: linear-gradient(180deg, rgba(6, 182, 212, 0.08), rgba(6, 182, 212, 0.02));
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            text-decoration: none;
            transition: border-color 0.2s, transform 0.2s;
        }}

        .link-card:hover {{
            border-color: var(--accent);
            transform: translateY(-1px);
            text-decoration: none;
        }}

        .link-card strong {{
            display: block;
            color: var(--text-primary);
            margin-bottom: 0.25rem;
        }}

        .link-card span {{
            color: var(--text-secondary);
            font-size: 0.9375rem;
        }}

        h2.section-title {{
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .category {{
            margin-bottom: 2rem;
        }}

        .category h3 {{
            color: var(--accent);
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--accent-muted);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
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
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }}

        td:first-child {{
            width: 280px;
        }}

        td code {{
            background: var(--code-bg);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8125rem;
            color: var(--accent);
            font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Monaco, monospace;
            border: 1px solid var(--border);
        }}

        td:last-child {{
            color: var(--text-secondary);
            font-size: 0.9375rem;
        }}

        .note {{
            margin-top: 1rem;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        tr:hover {{
            background: var(--bg-tertiary);
        }}

        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            margin-top: 2rem;
            font-size: 0.875rem;
        }}

        footer a {{
            color: var(--text-secondary);
            text-decoration: none;
            transition: color 0.2s;
        }}

        footer a:hover {{
            color: var(--accent);
        }}

        footer .links {{
            display: flex;
            justify-content: center;
            gap: 1.5rem;
            margin-bottom: 0.5rem;
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}

            h1 {{
                font-size: 1.75rem;
            }}

            td:first-child {{
                width: auto;
            }}

            table {{
                font-size: 0.875rem;
            }}

            th, td {{
                padding: 0.5rem 0.75rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="50" cy="50" r="45" stroke="#06b6d4" stroke-width="4" fill="none"/>
                    <circle cx="50" cy="50" r="30" stroke="#06b6d4" stroke-width="3" fill="none" opacity="0.6"/>
                    <circle cx="50" cy="50" r="15" fill="#06b6d4"/>
                </svg>
                <h1>Seren MCP Server</h1>
            </div>
            <p class="version">v{version}</p>
        </header>

        <div class="intro">
            <h2>Getting Started</h2>
            <p>
                Seren MCP exposes the current tool surface for Seren projects, branches,
                databases, publishers, payments, managed agents, and seren-cloud operations
                over the Model Context Protocol (MCP).
            </p>
            <div class="endpoints">
                <code><span class="method">POST</span> /mcp — Send JSON-RPC messages</code>
                <code><span class="method">GET</span> /mcp — Not supported (405 Method Not Allowed)</code>
            </div>
            <div class="meta">
                <div class="pill">{total_tools} tools in this build</div>
                <div class="pill">{populated_category_count} documentation sections</div>
                <div class="pill">Hosted OAuth + local API key workflows</div>
            </div>
            <p>
                The inventory below is generated directly from the current Rust tool
                registrations at build time, so the page tracks the live server surface
                instead of a hand-maintained list.
            </p>
            <div class="links-grid">
                <a class="link-card" href="https://github.com/serenorg/seren/blob/main/mcp/README.md">
                    <strong>Server Setup</strong>
                    <span>Hosted connection, local CLI startup, auth, and environment variables.</span>
                </a>
                <a class="link-card" href="https://github.com/serenorg/seren">
                    <strong>Repository</strong>
                    <span>Source for the MCP server, CLI, OpenAPI specs, and supporting docs.</span>
                </a>
            </div>
            <p class="note">
                For operator workflows, start with <code>get_cloud_overview</code>,
                <code>list_cloud_agents</code>, <code>list_pending_cloud_approvals</code>,
                and the managed-agent tools before drilling into individual runs.
            </p>
        </div>

        <h2 class="section-title">Available Tools</h2>

        {tools_html}

        <footer>
            <div class="links">
                <a href="https://serendb.com">SerenAI</a>
                <a href="https://github.com/serenorg/seren">GitHub</a>
                <a href="https://github.com/serenorg/seren/blob/main/mcp/README.md">MCP README</a>
            </div>
            <p>&copy; 2024-2025 SerenAI. All rights reserved.</p>
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
