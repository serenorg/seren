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
    pub async fn create(&self, request: CreateProjectRequest) -> Result<Project> {
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

    /// Get connection string for a branch
    pub async fn connection_string(&self, branch_id: &str) -> Result<ConnectionStringResponse> {
        self.client
            .get(&format!(
                "/projects/{}/branches/{}/connection-string",
                self.project_id, branch_id
            ))
            .await
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
    pub async fn create(&self, request: CreateEndpointRequest) -> Result<Endpoint> {
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
