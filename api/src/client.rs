use crate::{
    config::ClientConfig,
    error::{Error, Result},
    models::*,
};
use reqwest::{header, Client as HttpClient, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;

/// Retry configuration matching Neon's SDK
const RETRY_COUNT: u32 = 5;
const RETRY_DELAY_MS: u64 = 3000;

/// Main client for interacting with the Seren API
#[derive(Debug, Clone)]
pub struct Client {
    http: HttpClient,
    config: ClientConfig,
}

impl Client {
    /// Create a new Seren API client
    pub fn new(config: ClientConfig) -> Result<Self> {
        config.validate()?;

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", config.api_key))
                .map_err(|_| Error::InvalidApiKey)?,
        );
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_str(&config.user_agent)
                .map_err(|e| Error::Config(e.to_string()))?,
        );

        let http = HttpClient::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()?;

        Ok(Self { http, config })
    }

    /// Get the projects API client
    pub fn projects(&self) -> ProjectsClient<'_> {
        ProjectsClient { client: self }
    }

    /// Get a branches client for a specific project
    pub fn branches(&self, project_id: impl Into<String>) -> BranchesClient<'_> {
        BranchesClient {
            client: self,
            project_id: project_id.into(),
        }
    }

    /// Get an endpoints client for a specific project and branch
    pub fn endpoints(
        &self,
        project_id: impl Into<String>,
        branch_id: impl Into<String>,
    ) -> EndpointsClient<'_> {
        EndpointsClient {
            client: self,
            project_id: project_id.into(),
            branch_id: branch_id.into(),
        }
    }

    /// Get a databases client for a specific project and branch
    pub fn databases(
        &self,
        project_id: impl Into<String>,
        branch_id: impl Into<String>,
    ) -> DatabasesClient<'_> {
        DatabasesClient {
            client: self,
            project_id: project_id.into(),
            branch_id: branch_id.into(),
        }
    }

    /// Get a roles client for a specific project and branch
    pub fn roles(
        &self,
        project_id: impl Into<String>,
        branch_id: impl Into<String>,
    ) -> RolesClient<'_> {
        RolesClient {
            client: self,
            project_id: project_id.into(),
            branch_id: branch_id.into(),
        }
    }

    /// Get an operations client for a specific project
    pub fn operations(&self, project_id: impl Into<String>) -> OperationsClient<'_> {
        OperationsClient {
            client: self,
            project_id: project_id.into(),
        }
    }

    /// Manage IP allow list entries for a project
    pub fn ip_allow(&self, project_id: impl Into<String>) -> IpAllowClient<'_> {
        IpAllowClient {
            client: self,
            project_id: project_id.into(),
        }
    }

    /// Manage organization-level VPC endpoints
    pub fn organization_vpc_endpoints(
        &self,
        organization_id: impl Into<String>,
    ) -> OrganizationVpcEndpointsClient {
        OrganizationVpcEndpointsClient::new(self.clone(), organization_id.into())
    }

    /// Manage project-level VPC endpoint restrictions
    pub fn project_vpc_endpoints(
        &self,
        project_id: impl Into<String>,
    ) -> ProjectVpcEndpointsClient {
        ProjectVpcEndpointsClient::new(self.clone(), project_id.into())
    }

    /// Get current authenticated user information
    pub async fn me(&self) -> Result<User> {
        self.get("/auth/me").await
    }

    /// List all organizations for the authenticated user
    pub async fn organizations(&self) -> Result<Vec<Organization>> {
        self.get("/organizations").await
    }

    /// List members for a specific organization.
    pub async fn organization_members(
        &self,
        organization_id: impl AsRef<str>,
    ) -> Result<Vec<OrganizationMemberWithUser>> {
        let path = format!("/organizations/{}/members", organization_id.as_ref());
        self.get(&path).await
    }

    /// List invites for a specific organization.
    pub async fn organization_invites(
        &self,
        organization_id: impl AsRef<str>,
    ) -> Result<Vec<OrganizationInviteResponse>> {
        let path = format!("/organizations/{}/invites", organization_id.as_ref());
        self.get(&path).await
    }

    /// Create an organization invite.
    pub async fn create_organization_invite(
        &self,
        organization_id: impl AsRef<str>,
        request: &CreateOrganizationInviteRequest,
    ) -> Result<OrganizationInviteResponse> {
        let path = format!("/organizations/{}/invites", organization_id.as_ref());
        self.post(&path, request).await
    }

    /// Get project-scoped endpoint client (project-level routes)
    pub fn project_endpoints(&self, project_id: impl Into<String>) -> ProjectEndpointsClient {
        ProjectEndpointsClient::new(self.clone(), project_id.into())
    }

    /// Manage organization API keys
    pub fn organization_api_keys(
        &self,
        organization_id: impl Into<String>,
    ) -> OrganizationApiKeysClient {
        OrganizationApiKeysClient::new(self.clone(), organization_id.into())
    }

    /// Manage invoices and billing
    pub fn invoices(&self) -> InvoicesClient {
        InvoicesClient::new(self.clone())
    }

    /// Get usage and billing information for an organization
    pub fn usage(&self, organization_id: impl Into<String>) -> UsageClient {
        UsageClient::new(self.clone(), organization_id.into())
    }

    /// Manage agentic database billing (x402)
    pub fn billing(&self) -> BillingClient {
        BillingClient::new(self.clone())
    }

    /// Manage user sessions
    pub fn sessions(&self) -> SessionsClient {
        SessionsClient::new(self.clone())
    }

    /// Manage webhooks for an organization
    pub fn webhooks(&self, organization_id: impl Into<String>) -> WebhooksClient {
        WebhooksClient::new(self.clone(), organization_id.into())
    }

    /// Manage audit logs for an organization
    pub fn audit_logs(&self, organization_id: impl Into<String>) -> AuditLogsClient {
        AuditLogsClient::new(self.clone(), organization_id.into())
    }

    /// Manage RBAC roles for an organization
    pub fn rbac_roles(&self, organization_id: impl Into<String>) -> RbacRolesClient {
        RbacRolesClient::new(self.clone(), organization_id.into())
    }

    /// Manage branch protection for a project
    pub fn branch_protection(&self, project_id: impl Into<String>) -> BranchProtectionClient {
        BranchProtectionClient::new(self.clone(), project_id.into())
    }

    /// Manage logical replication for a project
    pub fn replication(&self, project_id: impl Into<String>) -> ReplicationClient {
        ReplicationClient::new(self.clone(), project_id.into())
    }

    /// Internal method to make GET requests with retry logic
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.config.base_url, path);

        self.request_with_retry(|| async {
            let response = self.http.get(&url).send().await?;
            self.handle_response(response).await
        })
        .await
    }

    /// Internal helper to perform GET requests with query parameters
    async fn get_with_query<T: DeserializeOwned, Q: Serialize>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<T> {
        let url = format!("{}{}", self.config.base_url, path);

        self.request_with_retry(|| async {
            let response = self.http.get(&url).query(query).send().await?;
            self.handle_response(response).await
        })
        .await
    }

    /// Internal method to make POST requests with retry logic
    async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.config.base_url, path);
        let body_json = serde_json::to_value(body)?;

        self.request_with_retry(|| async {
            let response = self.http.post(&url).json(&body_json).send().await?;
            self.handle_response(response).await
        })
        .await
    }

    /// Internal method to make PUT requests with retry logic
    async fn put<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.config.base_url, path);
        let body_json = serde_json::to_value(body)?;

        self.request_with_retry(|| async {
            let response = self.http.put(&url).json(&body_json).send().await?;
            self.handle_response(response).await
        })
        .await
    }

    /// Internal method to make PATCH requests with retry logic
    async fn patch<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.config.base_url, path);
        let body_json = serde_json::to_value(body)?;

        self.request_with_retry(|| async {
            let response = self.http.patch(&url).json(&body_json).send().await?;
            self.handle_response(response).await
        })
        .await
    }

    /// Internal method to make DELETE requests with retry logic
    async fn delete(&self, path: &str) -> Result<()> {
        let url = format!("{}{}", self.config.base_url, path);

        self.request_with_retry(|| async {
            let response = self.http.delete(&url).send().await?;

            match response.status() {
                StatusCode::NO_CONTENT | StatusCode::OK => Ok(()),
                status => {
                    let message = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    Err(Error::Api {
                        status: status.as_u16(),
                        message,
                    })
                }
            }
        })
        .await
    }

    /// Retry logic matching Neon SDK: retry on 423 Locked, 429 Rate Limited, and 5xx errors
    async fn request_with_retry<T, F, Fut>(&self, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut last_error = None;

        for attempt in 1..=RETRY_COUNT {
            match f().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    // Only retry on retryable errors
                    if !e.is_retryable() {
                        return Err(e);
                    }

                    // If this is the last attempt, return the error
                    if attempt >= RETRY_COUNT {
                        return Err(e);
                    }

                    // Store error and retry after delay
                    last_error = Some(e);
                    tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                }
            }
        }

        // This should never be reached, but satisfy the compiler
        Err(last_error.unwrap_or_else(|| Error::Config("Retry logic error".to_string())))
    }

    /// Handle API response and deserialize
    async fn handle_response<T: DeserializeOwned>(&self, response: reqwest::Response) -> Result<T> {
        let status = response.status();

        if status.is_success() {
            // Try to unwrap from DataResponse wrapper
            let wrapper: ApiResponse<T> = response.json().await?;
            Ok(wrapper.data)
        } else {
            // Extract retry-after header if present
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());

            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            match status {
                StatusCode::LOCKED => Err(Error::Locked {
                    retry_after_ms: retry_after.unwrap_or(RETRY_DELAY_MS),
                    message,
                }),
                StatusCode::TOO_MANY_REQUESTS => Err(Error::RateLimited {
                    retry_after_secs: retry_after.unwrap_or(RETRY_DELAY_MS / 1000),
                    message,
                }),
                StatusCode::UNAUTHORIZED => Err(Error::Auth(message)),
                StatusCode::NOT_FOUND => Err(Error::NotFound(message)),
                StatusCode::BAD_REQUEST => Err(Error::Validation(message)),
                StatusCode::CONFLICT => Err(Error::Conflict(message)),
                s if s.is_server_error() => Err(Error::ServerError {
                    status: s.as_u16(),
                    message,
                }),
                _ => Err(Error::Api {
                    status: status.as_u16(),
                    message,
                }),
            }
        }
    }
}

/// Client for project-related operations
pub struct ProjectsClient<'a> {
    client: &'a Client,
}

impl ProjectsClient<'_> {
    /// List all projects
    pub async fn list(&self) -> Result<Vec<Project>> {
        self.client.get("/projects").await
    }

    /// Get a specific project by ID
    pub async fn get(&self, id: &str) -> Result<Project> {
        self.client.get(&format!("/projects/{}", id)).await
    }

    /// Create a new project
    pub async fn create(&self, request: CreateProjectRequest) -> Result<CreateProjectResponse> {
        self.client.post("/projects", &request).await
    }

    /// Update a project
    pub async fn update(&self, id: &str, request: UpdateProjectRequest) -> Result<Project> {
        self.client
            .patch(&format!("/projects/{}", id), &request)
            .await
    }

    /// Delete a project
    pub async fn delete(&self, id: &str) -> Result<()> {
        self.client.delete(&format!("/projects/{}", id)).await
    }

    /// Retrieve a project-level connection URI
    pub async fn connection_uri(
        &self,
        id: &str,
        query: ProjectConnectionUriQuery,
    ) -> Result<ProjectConnectionUriResponse> {
        self.client
            .get_with_query(&format!("/projects/{}/connection_uri", id), &query)
            .await
    }
}

/// Client for branch-related operations
pub struct BranchesClient<'a> {
    client: &'a Client,
    project_id: String,
}

impl BranchesClient<'_> {
    /// List all branches for this project
    pub async fn list(&self) -> Result<Vec<Branch>> {
        self.client
            .get(&format!("/projects/{}/branches", self.project_id))
            .await
    }

    /// Get a specific branch by ID
    pub async fn get(&self, branch_id: &str) -> Result<Branch> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}",
                self.project_id, branch_id
            ))
            .await
    }

    /// Create a new branch
    pub async fn create(&self, request: CreateBranchRequest) -> Result<BranchCreationResult> {
        self.client
            .post(&format!("/projects/{}/branches", self.project_id), &request)
            .await
    }

    /// Delete a branch
    pub async fn delete(&self, branch_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/projects/{}/branches/{}",
                self.project_id, branch_id
            ))
            .await
    }

    /// Rename a branch
    pub async fn rename(&self, branch_id: &str, request: RenameBranchRequest) -> Result<Branch> {
        self.client
            .patch(
                &format!("/projects/{}/branches/{}", self.project_id, branch_id),
                &request,
            )
            .await
    }

    /// Set a branch as the default branch for its project
    pub async fn set_default(&self, branch_id: &str) -> Result<()> {
        let url = format!(
            "/projects/{}/branches/{}/set-default",
            self.project_id, branch_id
        );
        // set_default returns a JSON message, so we need a special POST that accepts empty body
        self.client
            .post::<serde_json::Value, _>(&url, &serde_json::json!({}))
            .await?;
        Ok(())
    }

    /// Get connection string for a branch (legacy convenience wrapper).
    ///
    /// By default, returns a connection string for the default
    /// `serendb_owner` role. The backend prefers SerenDB proxy-based
    /// connection strings when proxy configuration is available.
    pub async fn connection_string(&self, branch_id: &str) -> Result<ConnectionStringResponse> {
        self.connection_string_with_options(branch_id, None, None)
            .await
    }

    /// Get connection string for a branch with explicit options.
    ///
    /// - `pooled`: when `Some(true)`, request a pooled connection string.
    /// - `role`: optional PostgreSQL role/username to embed in the DSN (defaults to `serendb_owner`).
    pub async fn connection_string_with_options(
        &self,
        branch_id: &str,
        pooled: Option<bool>,
        role: Option<&str>,
    ) -> Result<ConnectionStringResponse> {
        let mut url = format!(
            "/projects/{}/branches/{}/connection-string",
            self.project_id, branch_id
        );

        let mut sep = '?';
        if let Some(p) = pooled {
            url.push(sep);
            url.push_str(&format!("pooled={}", p));
            sep = '&';
        }
        if let Some(role_name) = role {
            url.push(sep);
            url.push_str("role=");
            url.push_str(role_name);
        }

        self.client.get(&url).await
    }

    /// Set branch expiration
    pub async fn set_expiration(
        &self,
        branch_id: &str,
        request: SetBranchExpirationRequest,
    ) -> Result<Branch> {
        self.client
            .patch(
                &format!(
                    "/projects/{}/branches/{}/expiration",
                    self.project_id, branch_id
                ),
                &request,
            )
            .await
    }

    /// Compare schemas between two branches
    pub async fn schema_diff(&self, request: SchemaDiffRequest) -> Result<SchemaDiff> {
        let url = format!(
            "/projects/{}/branches/schema-diff?base_branch_id={}&compare_branch_id={}{}",
            self.project_id,
            request.base_branch_id,
            request.compare_branch_id,
            request
                .database
                .as_ref()
                .map(|d| format!("&database={}", d))
                .unwrap_or_default()
        );
        self.client.get(&url).await
    }

    /// Reset a branch to its parent's latest state
    ///
    /// Note: This feature requires SerenDB WAL integration and will return a 501 Not Implemented error
    /// until the backend integration is complete.
    pub async fn reset(&self, branch_id: &str) -> Result<Branch> {
        let request = ResetBranchRequest { parent: true };
        self.client
            .post(
                &format!("/projects/{}/branches/{}/reset", self.project_id, branch_id),
                &request,
            )
            .await
    }

    /// Restore a branch to a point in time
    ///
    /// Note: This feature requires SerenDB WAL integration and will return a 501 Not Implemented error
    /// until the backend integration is complete.
    pub async fn restore(
        &self,
        branch_id: &str,
        request: RestoreBranchRequest,
    ) -> Result<RestoreBranchResponse> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/restore",
                    self.project_id, branch_id
                ),
                &request,
            )
            .await
    }
}

/// Client for endpoint-related operations
pub struct EndpointsClient<'a> {
    client: &'a Client,
    project_id: String,
    branch_id: String,
}

impl EndpointsClient<'_> {
    /// List all endpoints for this branch
    pub async fn list(&self) -> Result<Vec<Endpoint>> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/endpoints",
                self.project_id, self.branch_id
            ))
            .await
    }

    /// Create a new endpoint
    pub async fn create(&self, request: CreateEndpointRequest) -> Result<CreateEndpointResponse> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/endpoints",
                    self.project_id, self.branch_id
                ),
                &request,
            )
            .await
    }

    /// Update an endpoint
    pub async fn update(
        &self,
        endpoint_id: &str,
        request: UpdateEndpointRequest,
    ) -> Result<Endpoint> {
        self.client
            .patch(
                &format!(
                    "/projects/{}/branches/{}/endpoints/{}",
                    self.project_id, self.branch_id, endpoint_id
                ),
                &request,
            )
            .await
    }

    /// Delete an endpoint
    pub async fn delete(&self, endpoint_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/projects/{}/branches/{}/endpoints/{}",
                self.project_id, self.branch_id, endpoint_id
            ))
            .await
    }

    /// Suspend an endpoint
    pub async fn suspend(&self, endpoint_id: &str) -> Result<Endpoint> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/endpoints/{}/suspend",
                    self.project_id, self.branch_id, endpoint_id
                ),
                &serde_json::json!({}),
            )
            .await
    }

    /// Start an endpoint
    pub async fn start(&self, endpoint_id: &str) -> Result<Endpoint> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/endpoints/{}/start",
                    self.project_id, self.branch_id, endpoint_id
                ),
                &serde_json::json!({}),
            )
            .await
    }

    /// Get health status for an endpoint
    pub async fn health(&self, endpoint_id: &str) -> Result<EndpointHealth> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/endpoints/{}/health",
                self.project_id, self.branch_id, endpoint_id
            ))
            .await
    }

    /// Get resource metrics for an endpoint
    pub async fn metrics(&self, endpoint_id: &str) -> Result<EndpointMetrics> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/endpoints/{}/metrics",
                self.project_id, self.branch_id, endpoint_id
            ))
            .await
    }
}

/// Client for database-related operations
pub struct DatabasesClient<'a> {
    client: &'a Client,
    project_id: String,
    branch_id: String,
}

impl DatabasesClient<'_> {
    /// List all databases for this branch
    pub async fn list(&self) -> Result<Vec<DatabaseWithOwner>> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/databases",
                self.project_id, self.branch_id
            ))
            .await
    }

    /// Create a new database
    pub async fn create(&self, request: CreateDatabaseRequest) -> Result<Database> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/databases",
                    self.project_id, self.branch_id
                ),
                &request,
            )
            .await
    }

    /// Delete a database
    pub async fn delete(&self, database_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/projects/{}/branches/{}/databases/{}",
                self.project_id, self.branch_id, database_id
            ))
            .await
    }

    /// Get a database by name
    pub async fn get_by_name(&self, database_name: &str) -> Result<DatabaseWithOwner> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/databases/{}",
                self.project_id, self.branch_id, database_name
            ))
            .await
    }

    /// Update a database owner by database name
    pub async fn update_owner_by_name(
        &self,
        database_name: &str,
        request: UpdateDatabaseRequest,
    ) -> Result<DatabaseWithOwner> {
        self.client
            .patch(
                &format!(
                    "/projects/{}/branches/{}/databases/{}",
                    self.project_id, self.branch_id, database_name
                ),
                &request,
            )
            .await
    }

    /// Delete a database by name
    pub async fn delete_by_name(&self, database_name: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/projects/{}/branches/{}/databases/{}",
                self.project_id, self.branch_id, database_name
            ))
            .await
    }
}

/// Client for role-related operations
pub struct RolesClient<'a> {
    client: &'a Client,
    project_id: String,
    branch_id: String,
}

impl RolesClient<'_> {
    /// List all roles for this branch
    pub async fn list(&self) -> Result<Vec<Role>> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/roles",
                self.project_id, self.branch_id
            ))
            .await
    }

    /// Create a new role
    pub async fn create(&self, request: CreateRoleRequest) -> Result<CreateRoleResponse> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/roles",
                    self.project_id, self.branch_id
                ),
                &request,
            )
            .await
    }

    /// Delete a role
    pub async fn delete(&self, role_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/projects/{}/branches/{}/roles/{}",
                self.project_id, self.branch_id, role_id
            ))
            .await
    }

    /// Reset a role's password
    pub async fn reset_password(
        &self,
        role_id: &str,
        request: ResetRolePasswordRequest,
    ) -> Result<ResetRolePasswordResponse> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/roles/{}/reset_password",
                    self.project_id, self.branch_id, role_id
                ),
                &request,
            )
            .await
    }

    /// Get a role by name
    pub async fn get_by_name(&self, role_name: &str) -> Result<RoleInfo> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/roles/{}",
                self.project_id, self.branch_id, role_name
            ))
            .await
    }

    /// Delete a role by name
    pub async fn delete_by_name(&self, role_name: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/projects/{}/branches/{}/roles/{}",
                self.project_id, self.branch_id, role_name
            ))
            .await
    }

    /// Reset a role's password by name
    pub async fn reset_password_by_name(
        &self,
        role_name: &str,
        request: ResetRolePasswordRequest,
    ) -> Result<ResetRolePasswordResponse> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/roles/{}/reset_password",
                    self.project_id, self.branch_id, role_name
                ),
                &request,
            )
            .await
    }
}

/// Client for operation-related operations
pub struct OperationsClient<'a> {
    client: &'a Client,
    project_id: String,
}

impl OperationsClient<'_> {
    /// List all operations for this project
    pub async fn list(&self) -> Result<Vec<Operation>> {
        self.client
            .get(&format!("/projects/{}/operations", self.project_id))
            .await
    }

    /// Get a specific operation by ID
    pub async fn get(&self, operation_id: &str) -> Result<Operation> {
        self.client
            .get(&format!(
                "/projects/{}/operations/{}",
                self.project_id, operation_id
            ))
            .await
    }
}

/// Client for IP allow list operations
pub struct IpAllowClient<'a> {
    client: &'a Client,
    project_id: String,
}

impl IpAllowClient<'_> {
    /// List all IP allow list entries for this project
    pub async fn list(&self) -> Result<Vec<IpAllowList>> {
        self.client
            .get(&format!("/projects/{}/ip-allow", self.project_id))
            .await
    }

    /// Add an IP address to the allow list
    pub async fn add(&self, request: AddIpAllowListRequest) -> Result<IpAllowList> {
        self.client
            .post(&format!("/projects/{}/ip-allow", self.project_id), &request)
            .await
    }

    /// Remove an IP address from the allow list
    pub async fn remove(&self, ip_id: &str) -> Result<()> {
        self.client
            .delete(&format!("/projects/{}/ip-allow/{}", self.project_id, ip_id))
            .await
    }

    /// Replace the entire IP allow list with the provided entries
    pub async fn reset(&self, request: ResetIpAllowListRequest) -> Result<Vec<IpAllowList>> {
        self.client
            .put(
                &format!("/projects/{}/ip-allow/reset", self.project_id),
                &request,
            )
            .await
    }
}

/// Client for organization VPC endpoint operations
pub struct OrganizationVpcEndpointsClient {
    client: Client,
    organization_id: String,
}

impl OrganizationVpcEndpointsClient {
    fn new(client: Client, organization_id: String) -> Self {
        Self {
            client,
            organization_id,
        }
    }

    /// List organization VPC endpoints, optionally filtered by region
    pub async fn list(&self, region: Option<&str>) -> Result<Vec<OrganizationVpcEndpoint>> {
        let mut path = format!("/api/organizations/{}/vpc-endpoints", self.organization_id);
        if let Some(region) = region {
            path.push_str(&format!("?region={}", region));
        }
        self.client.get(&path).await
    }

    /// Register a new VPC endpoint for the organization
    pub async fn create(
        &self,
        request: CreateOrganizationVpcEndpointRequest,
    ) -> Result<OrganizationVpcEndpoint> {
        self.client
            .post(
                &format!("/api/organizations/{}/vpc-endpoints", self.organization_id),
                &request,
            )
            .await
    }

    /// Fetch details for a specific organization VPC endpoint
    pub async fn get(&self, endpoint_id: &str) -> Result<OrganizationVpcEndpoint> {
        self.client
            .get(&format!(
                "/api/organizations/{}/vpc-endpoints/{}",
                self.organization_id, endpoint_id
            ))
            .await
    }

    /// Delete an organization VPC endpoint
    pub async fn delete(&self, endpoint_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/api/organizations/{}/vpc-endpoints/{}",
                self.organization_id, endpoint_id
            ))
            .await
    }
}

/// Client for project VPC endpoint assignments
pub struct ProjectVpcEndpointsClient {
    client: Client,
    project_id: String,
}

impl ProjectVpcEndpointsClient {
    fn new(client: Client, project_id: String) -> Self {
        Self { client, project_id }
    }

    /// List VPC endpoint restrictions for the project
    pub async fn list(&self) -> Result<Vec<ProjectVpcEndpointAssignment>> {
        self.client
            .get(&format!("/api/projects/{}/vpc-endpoints", self.project_id))
            .await
    }

    /// Assign a VPC endpoint to the project
    pub async fn assign(
        &self,
        request: AssignProjectVpcEndpointRequest,
    ) -> Result<ProjectVpcEndpointAssignment> {
        self.client
            .post(
                &format!("/api/projects/{}/vpc-endpoints", self.project_id),
                &request,
            )
            .await
    }

    /// Remove a VPC endpoint assignment from the project
    pub async fn remove(&self, assignment_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/api/projects/{}/vpc-endpoints/{}",
                self.project_id, assignment_id
            ))
            .await
    }
}

/// Client for project-level endpoint operations (project-scoped routes)
pub struct ProjectEndpointsClient {
    client: Client,
    project_id: String,
}

impl ProjectEndpointsClient {
    fn new(client: Client, project_id: String) -> Self {
        Self { client, project_id }
    }

    /// List all endpoints for a project
    pub async fn list(&self) -> Result<Vec<Endpoint>> {
        self.client
            .get(&format!("/api/projects/{}/endpoints", self.project_id))
            .await
    }

    /// Update an endpoint by id
    pub async fn update(
        &self,
        endpoint_id: &str,
        request: UpdateEndpointRequest,
    ) -> Result<Endpoint> {
        self.client
            .patch(
                &format!(
                    "/api/projects/{}/endpoints/{}",
                    self.project_id, endpoint_id
                ),
                &request,
            )
            .await
    }

    /// Delete an endpoint by id
    pub async fn delete(&self, endpoint_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/api/projects/{}/endpoints/{}",
                self.project_id, endpoint_id
            ))
            .await
    }

    /// Suspend an endpoint by id
    pub async fn suspend(&self, endpoint_id: &str) -> Result<Endpoint> {
        self.client
            .post(
                &format!(
                    "/api/projects/{}/endpoints/{}/suspend",
                    self.project_id, endpoint_id
                ),
                &serde_json::json!({}),
            )
            .await
    }

    /// Start an endpoint by id
    pub async fn start(&self, endpoint_id: &str) -> Result<Endpoint> {
        self.client
            .post(
                &format!(
                    "/api/projects/{}/endpoints/{}/start",
                    self.project_id, endpoint_id
                ),
                &serde_json::json!({}),
            )
            .await
    }

    /// Restart an endpoint by id
    pub async fn restart(&self, endpoint_id: &str) -> Result<EndpointStatusResponse> {
        self.client
            .post(
                &format!(
                    "/api/projects/{}/endpoints/{}/restart",
                    self.project_id, endpoint_id
                ),
                &serde_json::json!({}),
            )
            .await
    }
}

/// Client for organization API keys
pub struct OrganizationApiKeysClient {
    client: Client,
    organization_id: String,
}

impl OrganizationApiKeysClient {
    fn new(client: Client, organization_id: String) -> Self {
        Self {
            client,
            organization_id,
        }
    }

    /// Create a new API key for an organization
    pub async fn create(&self, name: &str, expires_in_days: Option<i64>) -> Result<ApiKeyCreated> {
        let body = serde_json::json!({
            "name": name,
            "expires_in_days": expires_in_days,
        });
        self.client
            .post(
                &format!("/api/organizations/{}/api_keys", self.organization_id),
                &body,
            )
            .await
    }

    /// List API keys for an organization (current user)
    pub async fn list(&self) -> Result<Vec<ApiKeyResponse>> {
        self.client
            .get(&format!(
                "/api/organizations/{}/api_keys",
                self.organization_id
            ))
            .await
    }

    /// Revoke an API key by id
    pub async fn revoke(&self, key_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/api/organizations/{}/api_keys/{}",
                self.organization_id, key_id
            ))
            .await
    }
}

// Invoices Client

pub struct InvoicesClient {
    client: Client,
}

impl InvoicesClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    /// Generate monthly invoices for all organizations
    pub async fn generate(&self, year: i32, month: u8) -> Result<GenerateInvoicesResponse> {
        let body = GenerateInvoicesRequest { year, month };
        self.client
            .post("/api/billing/invoices/generate", &body)
            .await
    }

    /// Get invoice details with line items
    pub async fn get(&self, invoice_id: &str) -> Result<Invoice> {
        self.client
            .get(&format!("/api/billing/invoices/{}", invoice_id))
            .await
    }

    /// Issue a draft invoice
    pub async fn issue(&self, invoice_id: &str) -> Result<()> {
        self.client
            .post(&format!("/api/billing/invoices/{}/issue", invoice_id), &())
            .await
    }
}

// Usage Client

pub struct UsageClient {
    client: Client,
    organization_id: String,
}

impl UsageClient {
    fn new(client: Client, organization_id: String) -> Self {
        Self {
            client,
            organization_id,
        }
    }

    /// Get usage summary for an organization
    pub async fn summary(
        &self,
        start_date: Option<&str>,
        end_date: Option<&str>,
    ) -> Result<Vec<UsageSummary>> {
        let mut query = vec![];
        if let Some(start) = start_date {
            query.push(("start_date", start));
        }
        if let Some(end) = end_date {
            query.push(("end_date", end));
        }

        let path = format!("/api/billing/usage/{}", self.organization_id);
        if query.is_empty() {
            self.client.get(&path).await
        } else {
            self.client.get_with_query(&path, &query).await
        }
    }
}

// Billing Client (Agentic/x402)

pub struct BillingClient {
    client: Client,
}

impl BillingClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    /// Get high-level billing and metering health from the Seren control plane.
    pub async fn health(&self) -> Result<BillingHealthResponse> {
        self.client.get("/api/billing/health").await
    }

    /// Validate an x402 JWT token
    pub async fn validate_token(&self, token: &str) -> Result<ValidateTokenResponse> {
        let body = ValidateTokenRequest {
            token: token.to_string(),
        };
        self.client
            .post("/api/agentic/databases/validate-token", &body)
            .await
    }

    /// Get balance for an endpoint
    pub async fn get_balance(&self, endpoint_id: &str) -> Result<BalanceResponse> {
        self.client
            .get(&format!("/api/agentic/databases/{}/balance", endpoint_id))
            .await
    }

    /// Deduct balance for a query
    pub async fn deduct_balance(
        &self,
        endpoint_id: &str,
        amount: f64,
        query_hash: &str,
        timestamp: u64,
    ) -> Result<DeductBalanceResponse> {
        let body = DeductBalanceRequest {
            endpoint_id: endpoint_id.to_string(),
            amount,
            query_hash: query_hash.to_string(),
            timestamp,
        };
        self.client.post("/api/billing/deduct", &body).await
    }

    /// Refund a transaction
    pub async fn refund_transaction(
        &self,
        endpoint_id: &str,
        transaction_id: &str,
        amount: f64,
        reason: &str,
        timestamp: u64,
    ) -> Result<RefundTransactionResponse> {
        let body = RefundTransactionRequest {
            endpoint_id: endpoint_id.to_string(),
            transaction_id: transaction_id.to_string(),
            amount,
            reason: reason.to_string(),
            timestamp,
        };
        self.client.post("/api/billing/refund", &body).await
    }
}

/// Client for session management
pub struct SessionsClient {
    client: Client,
}

impl SessionsClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// List all active sessions for the current user
    pub async fn list(&self) -> Result<Vec<SessionResponse>> {
        self.client.get("/sessions").await
    }

    /// Revoke a specific session
    pub async fn revoke(&self, session_id: &str) -> Result<()> {
        self.client
            .delete(&format!("/sessions/{}", session_id))
            .await
    }

    /// Revoke all sessions except the specified one
    pub async fn revoke_others(&self, keep_session_id: &str) -> Result<RevokeSessionResponse> {
        self.client
            .post(&format!("/sessions/{}/revoke-others", keep_session_id), &())
            .await
    }

    /// Revoke all sessions (logout everywhere)
    pub async fn revoke_all(&self) -> Result<RevokeSessionResponse> {
        self.client.post("/sessions/revoke-all", &()).await
    }
}

/// Client for webhook management
pub struct WebhooksClient {
    client: Client,
    organization_id: String,
}

impl WebhooksClient {
    pub fn new(client: Client, organization_id: String) -> Self {
        Self {
            client,
            organization_id,
        }
    }

    /// List all webhooks for the organization
    pub async fn list(&self) -> Result<Vec<WebhookResponse>> {
        self.client
            .get(&format!("/organizations/{}/webhooks", self.organization_id))
            .await
    }

    /// Get a specific webhook
    pub async fn get(&self, webhook_id: &str) -> Result<WebhookResponse> {
        self.client
            .get(&format!(
                "/organizations/{}/webhooks/{}",
                self.organization_id, webhook_id
            ))
            .await
    }

    /// Create a new webhook
    pub async fn create(&self, request: &CreateWebhookRequest) -> Result<WebhookCreatedResponse> {
        self.client
            .post(
                &format!("/organizations/{}/webhooks", self.organization_id),
                request,
            )
            .await
    }

    /// Update a webhook
    pub async fn update(
        &self,
        webhook_id: &str,
        request: &UpdateWebhookRequest,
    ) -> Result<WebhookResponse> {
        self.client
            .patch(
                &format!(
                    "/organizations/{}/webhooks/{}",
                    self.organization_id, webhook_id
                ),
                request,
            )
            .await
    }

    /// Delete a webhook
    pub async fn delete(&self, webhook_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/organizations/{}/webhooks/{}",
                self.organization_id, webhook_id
            ))
            .await
    }

    /// Rotate webhook secret
    pub async fn rotate_secret(&self, webhook_id: &str) -> Result<WebhookCreatedResponse> {
        self.client
            .post(
                &format!(
                    "/organizations/{}/webhooks/{}/rotate-secret",
                    self.organization_id, webhook_id
                ),
                &(),
            )
            .await
    }

    /// List webhook deliveries
    pub async fn list_deliveries(&self, webhook_id: &str) -> Result<Vec<WebhookDelivery>> {
        self.client
            .get(&format!(
                "/organizations/{}/webhooks/{}/deliveries",
                self.organization_id, webhook_id
            ))
            .await
    }

    /// List available event types
    pub async fn list_event_types(&self) -> Result<Vec<String>> {
        self.client.get("/webhooks/event-types").await
    }
}

/// Client for audit log access
pub struct AuditLogsClient {
    client: Client,
    organization_id: String,
}

impl AuditLogsClient {
    pub fn new(client: Client, organization_id: String) -> Self {
        Self {
            client,
            organization_id,
        }
    }

    /// List audit logs for the organization
    pub async fn list(
        &self,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<AuditLogListResponse> {
        let mut path = format!("/organizations/{}/audit-logs", self.organization_id);
        let mut params = vec![];
        if let Some(l) = limit {
            params.push(format!("limit={}", l));
        }
        if let Some(o) = offset {
            params.push(format!("offset={}", o));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.client.get(&path).await
    }

    /// Get a specific audit log entry
    pub async fn get(&self, log_id: &str) -> Result<AuditLog> {
        self.client
            .get(&format!(
                "/organizations/{}/audit-logs/{}",
                self.organization_id, log_id
            ))
            .await
    }
}

/// Client for RBAC role management (organization-level roles, distinct from database roles)
pub struct RbacRolesClient {
    client: Client,
    organization_id: String,
}

impl RbacRolesClient {
    pub fn new(client: Client, organization_id: String) -> Self {
        Self {
            client,
            organization_id,
        }
    }

    /// List all roles for the organization
    pub async fn list(&self) -> Result<Vec<OrganizationRoleResponse>> {
        self.client
            .get(&format!("/organizations/{}/roles", self.organization_id))
            .await
    }

    /// Get a specific role
    pub async fn get(&self, role_id: &str) -> Result<OrganizationRoleResponse> {
        self.client
            .get(&format!(
                "/organizations/{}/roles/{}",
                self.organization_id, role_id
            ))
            .await
    }

    /// Create a new role
    pub async fn create(
        &self,
        request: &CreateOrganizationRoleRequest,
    ) -> Result<OrganizationRoleResponse> {
        self.client
            .post(
                &format!("/organizations/{}/roles", self.organization_id),
                request,
            )
            .await
    }

    /// Update a role
    pub async fn update(
        &self,
        role_id: &str,
        request: &UpdateOrganizationRoleRequest,
    ) -> Result<OrganizationRoleResponse> {
        self.client
            .patch(
                &format!("/organizations/{}/roles/{}", self.organization_id, role_id),
                request,
            )
            .await
    }

    /// Delete a role
    pub async fn delete(&self, role_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/organizations/{}/roles/{}",
                self.organization_id, role_id
            ))
            .await
    }

    /// Assign a role to a member
    pub async fn assign(
        &self,
        member_id: &str,
        request: &AssignOrganizationRoleRequest,
    ) -> Result<()> {
        self.client
            .put(
                &format!(
                    "/organizations/{}/members/{}/role",
                    self.organization_id, member_id
                ),
                request,
            )
            .await
    }

    /// List all available permissions
    pub async fn list_permissions(&self) -> Result<Vec<OrganizationPermission>> {
        self.client.get("/permissions").await
    }

    /// Get current user's permissions
    pub async fn my_permissions(&self) -> Result<Vec<String>> {
        self.client
            .get(&format!(
                "/organizations/{}/permissions/mine",
                self.organization_id
            ))
            .await
    }
}

/// Client for branch protection management
pub struct BranchProtectionClient {
    client: Client,
    project_id: String,
}

impl BranchProtectionClient {
    pub fn new(client: Client, project_id: String) -> Self {
        Self { client, project_id }
    }

    /// List all branch protection rules for the project
    pub async fn list(&self) -> Result<Vec<BranchProtectionResponse>> {
        self.client
            .get(&format!("/projects/{}/branch-protection", self.project_id))
            .await
    }

    /// Get branch protection for a specific branch
    pub async fn get(&self, branch_id: &str) -> Result<BranchProtectionResponse> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/protection",
                self.project_id, branch_id
            ))
            .await
    }

    /// Create branch protection for a branch
    pub async fn create(
        &self,
        branch_id: &str,
        request: &CreateBranchProtectionRequest,
    ) -> Result<BranchProtectionResponse> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/protection",
                    self.project_id, branch_id
                ),
                request,
            )
            .await
    }

    /// Update branch protection
    pub async fn update(
        &self,
        branch_id: &str,
        request: &UpdateBranchProtectionRequest,
    ) -> Result<BranchProtectionResponse> {
        self.client
            .patch(
                &format!(
                    "/projects/{}/branches/{}/protection",
                    self.project_id, branch_id
                ),
                request,
            )
            .await
    }

    /// Delete branch protection
    pub async fn delete(&self, branch_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/projects/{}/branches/{}/protection",
                self.project_id, branch_id
            ))
            .await
    }
}

/// Client for logical replication management
pub struct ReplicationClient {
    client: Client,
    project_id: String,
}

impl ReplicationClient {
    pub fn new(client: Client, project_id: String) -> Self {
        Self { client, project_id }
    }

    /// Get replication settings for the project
    pub async fn get_settings(&self) -> Result<LogicalReplicationSettings> {
        self.client
            .get(&format!("/projects/{}/replication", self.project_id))
            .await
    }

    /// Update replication settings
    pub async fn update_settings(
        &self,
        request: &UpdateLogicalReplicationRequest,
    ) -> Result<LogicalReplicationSettings> {
        self.client
            .patch(
                &format!("/projects/{}/replication", self.project_id),
                request,
            )
            .await
    }

    /// List publications for a branch
    pub async fn list_publications(&self, branch_id: &str) -> Result<Vec<PublicationResponse>> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/publications",
                self.project_id, branch_id
            ))
            .await
    }

    /// Create a publication
    pub async fn create_publication(
        &self,
        branch_id: &str,
        request: &CreatePublicationRequest,
    ) -> Result<PublicationResponse> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/publications",
                    self.project_id, branch_id
                ),
                request,
            )
            .await
    }

    /// Update a publication
    pub async fn update_publication(
        &self,
        branch_id: &str,
        publication_id: &str,
        request: &UpdatePublicationRequest,
    ) -> Result<PublicationResponse> {
        self.client
            .patch(
                &format!(
                    "/projects/{}/branches/{}/publications/{}",
                    self.project_id, branch_id, publication_id
                ),
                request,
            )
            .await
    }

    /// Delete a publication
    pub async fn delete_publication(&self, branch_id: &str, publication_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/projects/{}/branches/{}/publications/{}",
                self.project_id, branch_id, publication_id
            ))
            .await
    }

    /// List replication slots for a branch
    pub async fn list_slots(&self, branch_id: &str) -> Result<Vec<ReplicationSlotResponse>> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/replication-slots",
                self.project_id, branch_id
            ))
            .await
    }

    /// Create a replication slot
    pub async fn create_slot(
        &self,
        branch_id: &str,
        request: &CreateReplicationSlotRequest,
    ) -> Result<ReplicationSlotResponse> {
        self.client
            .post(
                &format!(
                    "/projects/{}/branches/{}/replication-slots",
                    self.project_id, branch_id
                ),
                request,
            )
            .await
    }

    /// Delete a replication slot
    pub async fn delete_slot(&self, branch_id: &str, slot_id: &str) -> Result<()> {
        self.client
            .delete(&format!(
                "/projects/{}/branches/{}/replication-slots/{}",
                self.project_id, branch_id, slot_id
            ))
            .await
    }
}
