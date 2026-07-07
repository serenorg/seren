#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoMethod {
    Get,
    Post,
    Delete,
}

impl DemoMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerenDemoRequest {
    pub method: DemoMethod,
    pub path: &'static str,
    pub label: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerenProductExample {
    pub slug: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub highlights: &'static [&'static str],
    pub requests: &'static [SerenDemoRequest],
}

pub const SEREN_PRODUCT_EXAMPLES: &[SerenProductExample] = &[
    SerenProductExample {
        slug: "employees",
        title: "Seren Employees",
        description: "Managed Seren agents running in Seren Cloud with scoped tools, approvals, and auditable runtime state.",
        highlights: &[
            "Deploy and inspect managed seren-agent deployments.",
            "Review activity, health, resources, and visible tools before an agent acts.",
            "Model agent operations as authenticated API requests instead of prompt-only workflows.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-agent/deployments",
                label: "List managed agents",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-agent/deployments/{id}/health",
                label: "Inspect managed-agent health",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-agent/deployments/{id}/tools",
                label: "List visible tools",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-agent/deployments/{id}/start",
                label: "Start a managed agent",
            },
        ],
    },
    SerenProductExample {
        slug: "passwords",
        title: "Seren Passwords",
        description: "Vault-backed secret access for applications and agents without copying credentials into prompts, logs, or plaintext config.",
        highlights: &[
            "List vaults and encrypted item metadata.",
            "Route sensitive reads through approval records.",
            "Keep password access separate from general application authentication.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-passwords/vaults",
                label: "List vaults",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-passwords/vaults/{vault_id}/items",
                label: "List item metadata",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-passwords/approvals",
                label: "Review approval requests",
            },
        ],
    },
    SerenProductExample {
        slug: "database",
        title: "Branchable Postgres",
        description: "Serverless Postgres projects with database branching and connection endpoints for app and agent workflows.",
        highlights: &[
            "List projects and branches.",
            "Create isolated branches for review, migration, and agent work.",
            "Retrieve branch connection strings when a workflow needs SQL access.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-db/projects",
                label: "List projects",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-db/projects/{id}/branches",
                label: "Create a branch",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-db/projects/{id}/branches/{bid}/connection-string",
                label: "Get branch connection string",
            },
        ],
    },
    SerenProductExample {
        slug: "object_storage",
        title: "Object storage",
        description: "Bucket and object APIs for agent artifacts, generated files, and application uploads.",
        highlights: &[
            "List organization buckets.",
            "Create metadata-rich uploads.",
            "Issue short-lived download URLs by object key.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/organizations/{organization_id}/object-storage/buckets",
                label: "List buckets",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/organizations/{organization_id}/object-storage/buckets/{bucket_slug}/objects/uploads",
                label: "Create upload",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/organizations/{organization_id}/object-storage/buckets/{bucket_slug}/objects/by-key/download",
                label: "Create download URL",
            },
        ],
    },
];

pub fn get_seren_product_examples() -> &'static [SerenProductExample] {
    SEREN_PRODUCT_EXAMPLES
}

pub fn get_seren_product_example(slug: &str) -> Option<&'static SerenProductExample> {
    SEREN_PRODUCT_EXAMPLES
        .iter()
        .find(|example| example.slug == slug)
}

pub fn iter_seren_demo_requests() -> impl Iterator<Item = &'static SerenDemoRequest> {
    SEREN_PRODUCT_EXAMPLES
        .iter()
        .flat_map(|example| example.requests.iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_examples_cover_core_seren_surfaces() {
        let slugs = SEREN_PRODUCT_EXAMPLES
            .iter()
            .map(|example| example.slug)
            .collect::<Vec<_>>();

        assert_eq!(
            slugs,
            vec!["employees", "passwords", "database", "object_storage"]
        );
        assert!(
            SEREN_PRODUCT_EXAMPLES
                .iter()
                .all(|example| !example.requests.is_empty())
        );
    }

    #[test]
    fn database_example_uses_branch_connection_string_endpoint() {
        let database = get_seren_product_example("database").unwrap();

        assert!(database.requests.iter().any(|request| {
            request.path == "/publishers/seren-db/projects/{id}/branches/{bid}/connection-string"
        }));
    }
}
