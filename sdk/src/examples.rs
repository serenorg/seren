#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl DemoMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
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
                path: "/publishers/seren-agent/capabilities",
                label: "List runtime capabilities",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-agent/deployments/{id}/health",
                label: "Check agent health",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-agent/deployments/{id}/tools",
                label: "List visible tools",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-agent/test-run",
                label: "Run agent test",
            },
        ],
    },
    SerenProductExample {
        slug: "cloud_runs",
        title: "Seren Cloud",
        description: "Hosted employee, prompt, and bundle runs with streamed activity, approval gates, artifacts, and schedules.",
        highlights: &[
            "List deployments and runtime state.",
            "Stream run activity and inspect generated artifacts.",
            "Resume approval-gated work from a typed API client.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-cloud/deployments",
                label: "List cloud deployments",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-cloud/deploy",
                label: "Deploy run target",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-cloud/runs",
                label: "List runs",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-cloud/runs/{run_id}/events",
                label: "Read run events",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-cloud/runs/{run_id}/artifacts",
                label: "List run artifacts",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-cloud/pending_approvals",
                label: "List pending approvals",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-cloud/runs/{run_id}/resume",
                label: "Submit approval input",
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
                path: "/publishers/seren-passwords/identities/me",
                label: "Read current identity",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-passwords/vaults/{vault_id}",
                label: "Get vault",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-passwords/vaults/{vault_id}/items/{item_id}",
                label: "Get item metadata",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-passwords/approvals",
                label: "Review approval requests",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-passwords/approvals/{approval_id}",
                label: "Get approval",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-passwords/audit/events",
                label: "List audit events",
            },
        ],
    },
    SerenProductExample {
        slug: "skills",
        title: "Seren Skills",
        description: "Publisher-backed skill bundles, versions, files, and downloads that package instructions and resources for agents.",
        highlights: &[
            "List public or owned skills through the Seren Skills publisher.",
            "Create versions with updated instructions or files.",
            "Download skill bundles for local or hosted agent runtimes.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-skills/skills",
                label: "List published skills",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-skills/skills",
                label: "Create skill",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-skills/skills/{slug}/versions",
                label: "Create version",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-skills/skills/{slug}/download",
                label: "Download bundle",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-skills/skills/{slug}/versions",
                label: "List versions",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-skills/skills/{slug}/files",
                label: "List bundle files",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-skills/skills/{slug}/collaborators",
                label: "List collaborators",
            },
        ],
    },
    SerenProductExample {
        slug: "notes",
        title: "Seren Notes",
        description: "Hosted notes, searchable memory, shares, and attachments for workspace and agent context.",
        highlights: &[
            "List and create notes through the Seren Notes publisher.",
            "Search notes by text or semantic similarity.",
            "Create shares and attach files to notes.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-notes/notes",
                label: "List notes",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-notes/notes",
                label: "Create note",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-notes/notes/search",
                label: "Full-text search",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-notes/notes/search/semantic",
                label: "Semantic search",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-notes/shares",
                label: "Create share",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-notes/notes/{note_id}/attachments",
                label: "Upload attachment",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-notes/notes/tags",
                label: "List tags",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-notes/notes/{note_id}",
                label: "Get note",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-notes/notes/{note_id}/shares",
                label: "List shares",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-notes/notes/{note_id}/attachments",
                label: "List attachments",
            },
        ],
    },
    SerenProductExample {
        slug: "memory",
        title: "Seren Memory",
        description: "Durable private agent recall plus governed read access to organizational knowledge, with separate privacy and authorization boundaries.",
        highlights: &[
            "Bootstrap sessions from relevant private context.",
            "Remember, revise, connect, and lifecycle-manage durable private context.",
            "Read governed organizational knowledge through explicit domains and operations.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-memory/bootstrap",
                label: "Bootstrap session context",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-memory/remember",
                label: "Remember durable context",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-memory/recall",
                label: "Recall relevant memories",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-memory/memories",
                label: "List private memories",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-memory/memories/{id}/append",
                label: "Append to a memory",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-memory/memories/{id}/revisions",
                label: "List memory revisions",
            },
            SerenDemoRequest {
                method: DemoMethod::Put,
                path: "/publishers/seren-memory/memories/{id}/status",
                label: "Set memory lifecycle",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-memory/memories/connections",
                label: "Connect memories",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-memory/ingest/document",
                label: "Ingest a managed document",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-memory/learn_from_error",
                label: "Store a verified error fix",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-memory/knowledge/search",
                label: "Search organizational knowledge",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-memory/knowledge/domains",
                label: "List knowledge domains",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-memory/knowledge/operations",
                label: "List knowledge operations",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-memory/knowledge/entities/open",
                label: "Open a knowledge entity",
            },
        ],
    },
    SerenProductExample {
        slug: "models",
        title: "Seren Models",
        description: "Public model chat completions through Seren's hosted model routing surface.",
        highlights: &[
            "Call public model providers through one publisher endpoint.",
            "Keep model execution behind the same API key and billing surface as the rest of Seren.",
            "Use request previews before enabling paid model execution in an app.",
        ],
        requests: &[SerenDemoRequest {
            method: DemoMethod::Post,
            path: "/publishers/seren-models/chat/completions",
            label: "Create chat completion",
        }],
    },
    SerenProductExample {
        slug: "private_models",
        title: "Seren Private Models",
        description: "Private inference for approved models where prompts and outputs are not shared with model providers or used to train base models.",
        highlights: &[
            "List private models available to an organization.",
            "Run chat completions against private model endpoints.",
            "Review which private models are approved for use.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-private-models/models",
                label: "List private models",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-private-models/chat/completions",
                label: "Create private completion",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/organizations/{organization_id}/private-models-policy",
                label: "Read private-model policy",
            },
            SerenDemoRequest {
                method: DemoMethod::Put,
                path: "/organizations/{organization_id}/private-models-policy",
                label: "Update private-model policy",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-agent/private-models",
                label: "List agent-private models",
            },
        ],
    },
    SerenProductExample {
        slug: "database",
        title: "Seren DB",
        description: "Branchable Postgres projects with database branches and connection endpoints.",
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
                label: "Create branch",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-db/projects/{id}",
                label: "Get project",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-db/projects/{id}/branches",
                label: "List branches",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-db/projects/{id}/branches/{bid}/details",
                label: "Get branch details",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-db/projects/{id}/branches/{bid}/connection-string",
                label: "Get branch connection string",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-db/projects/{id}/branches/{bid}/roles",
                label: "List roles",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-db/query",
                label: "Run SQL",
            },
        ],
    },
    SerenProductExample {
        slug: "storage",
        title: "Seren Storage",
        description: "Publisher-backed object storage with logical buckets, user-scoped namespaces, and short-lived transfer URLs.",
        highlights: &[
            "Browse the buckets available to the authenticated organization.",
            "Create checksum-bound uploads and confirm completed transfers.",
            "List and download objects without proxying file bytes through the API.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-storage/buckets",
                label: "List buckets",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-storage/buckets/{bucket_slug}/objects/uploads",
                label: "Create upload",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-storage/buckets/{bucket_slug}/objects",
                label: "List objects",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/seren-storage/buckets/{bucket_slug}/objects/by-key/download",
                label: "Create download URL",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/seren-storage/buckets/{bucket_slug}/objects/{object_id}/confirm-upload",
                label: "Confirm upload",
            },
        ],
    },
    SerenProductExample {
        slug: "publishers_payments",
        title: "Seren Publishers",
        description: "Publisher discovery, cost estimates, wallet balance, and payment flows for paid database, API, agent, and MCP integrations.",
        highlights: &[
            "Discover publishers and suggested capabilities for a task.",
            "Estimate paid publisher calls before executing them.",
            "Inspect prepaid balance for SerenBucks and x402-backed usage.",
        ],
        requests: &[
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers",
                label: "List publishers",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/suggest",
                label: "Suggest publishers",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/publishers/{slug}",
                label: "Get publisher",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/publishers/{slug}/estimate",
                label: "Estimate cost",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/wallet/balance",
                label: "Get wallet balance",
            },
            SerenDemoRequest {
                method: DemoMethod::Get,
                path: "/wallet/transactions",
                label: "List wallet transactions",
            },
            SerenDemoRequest {
                method: DemoMethod::Post,
                path: "/billing/publishers/{slug}/charges",
                label: "Create publisher charge",
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
            vec![
                "employees",
                "cloud_runs",
                "passwords",
                "skills",
                "notes",
                "memory",
                "models",
                "private_models",
                "database",
                "storage",
                "publishers_payments"
            ]
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

    #[test]
    fn storage_example_uses_seren_storage_publisher_routes() {
        let storage = get_seren_product_example("storage").unwrap();

        assert!(
            storage
                .requests
                .iter()
                .all(|request| request.path.starts_with("/publishers/seren-storage"))
        );
        assert!(
            storage
                .requests
                .iter()
                .any(|request| request.path.ends_with("/objects/uploads"))
        );
    }

    #[test]
    fn skills_example_uses_seren_skills_publisher_routes() {
        let skills = get_seren_product_example("skills").unwrap();

        assert!(
            skills
                .requests
                .iter()
                .all(|request| request.path.starts_with("/publishers/seren-skills"))
        );
        assert!(
            skills
                .requests
                .iter()
                .any(|request| request.path == "/publishers/seren-skills/skills")
        );
        assert!(
            skills
                .requests
                .iter()
                .any(|request| request.path.contains("/versions"))
        );
        assert!(
            skills
                .requests
                .iter()
                .any(|request| request.path.contains("/download"))
        );
    }

    #[test]
    fn memory_example_uses_first_class_seren_memory_routes() {
        let memory = get_seren_product_example("memory").unwrap();

        assert!(
            memory
                .requests
                .iter()
                .all(|request| request.path.starts_with("/publishers/seren-memory"))
        );
        assert!(
            memory
                .requests
                .iter()
                .any(|request| request.path.ends_with("/remember"))
        );
        assert!(
            memory
                .requests
                .iter()
                .any(|request| request.path.contains("/knowledge/search"))
        );
        assert!(
            memory
                .requests
                .iter()
                .any(|request| request.path.ends_with("/revisions"))
        );
        assert!(
            memory
                .requests
                .iter()
                .any(|request| request.path.ends_with("/knowledge/domains"))
        );
    }

    #[test]
    fn model_examples_separate_public_and_private_surfaces() {
        let models = get_seren_product_example("models").unwrap();
        let private_models = get_seren_product_example("private_models").unwrap();

        assert!(
            models
                .requests
                .iter()
                .any(|request| { request.path == "/publishers/seren-models/chat/completions" })
        );
        assert!(
            private_models
                .requests
                .iter()
                .any(|request| { request.path == "/publishers/seren-private-models/models" })
        );
        assert!(private_models.requests.iter().any(|request| {
            request.path == "/organizations/{organization_id}/private-models-policy"
                && request.method == DemoMethod::Put
        }));
    }
}
