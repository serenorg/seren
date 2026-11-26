//! Per-managed-agent MCP views at `/employees/{page_slug}`.
//!
//! The server keeps no state between requests (production runs several
//! replicas): the job number a task returns carries everything needed to read
//! its report back.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode,
        Extensions, JsonObject, ListToolsResult, PaginatedRequestParams, ResourceContents,
        ServerCapabilities, ServerConfig, Tool,
    },
    service::{RequestContext, RoleServer},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// Public path prefix for per-managed-agent MCP views.
pub(crate) const MANAGED_AGENT_PATH_PREFIX: &str = "/employees/";

/// JSON-RPC error code for an address with no listed managed agent.
pub(crate) const NO_MANAGED_AGENT_CODE: i32 = -32004;
const NO_MANAGED_AGENT_MESSAGE: &str = "No Employee at this address.";

const AGENT_PUBLISHER: &str = "publishers/seren-agent";
const CLOUD_PUBLISHER: &str = "publishers/seren-cloud";
/// Name of the conversation an MCP caller's tasks run in.
const MCP_CONVERSATION: &str = "mcp";

const GIVE_TASK: &str = "give_task";
const GET_REPORT: &str = "get_report";
const HIRE: &str = "hire";
const TASK_TOOL_PREFIX: &str = "task_";

#[derive(Deserialize, schemars::JsonSchema)]
struct HireArguments {
    /// True once the user has approved the Employee's prices.
    confirm: bool,
    #[serde(flatten)]
    request: seren::CreateManagedAgentTemplateDeploymentRequest,
}

#[derive(Deserialize)]
struct HireRequirements {
    owner_connection: seren::ManagedAgentTemplateOwnerConnection,
    hires_per_employer: seren::ManagedAgentTemplateHiresPerEmployer,
}

#[derive(Deserialize)]
struct ManagedAgentHire {
    deployment_id: Uuid,
    hire_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TaskSchema {
    Object {
        properties: BTreeMap<String, TaskProperty>,
        required: Vec<String>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TaskProperty {
    String,
    Number,
    Boolean,
    Array { items: TaskArrayItems },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TaskArrayItems {
    String,
}

impl TaskProperty {
    fn accepts(&self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Number => value.is_number(),
            Self::Boolean => value.is_boolean(),
            Self::Array {
                items: TaskArrayItems::String,
            } => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
        }
    }
}

fn task_schema(tool: &Value) -> Result<TaskSchema, McpError> {
    let schema = serde_json::from_value(tool.get("input_schema").cloned().unwrap_or(Value::Null))
        .map_err(|_| core_error("The Employee's tool has an unsupported input schema"))?;
    let TaskSchema::Object {
        properties,
        required,
    } = &schema;
    if properties.len() > 8 || required.iter().any(|name| !properties.contains_key(name)) {
        return Err(core_error(
            "The Employee's tool has an invalid input schema",
        ));
    }
    Ok(schema)
}

fn validate_task_arguments(tool: &Value, arguments: &JsonObject) -> Result<(), McpError> {
    let TaskSchema::Object {
        properties,
        required,
    } = task_schema(tool)?;
    for name in required {
        if !arguments.contains_key(&name) {
            return Err(McpError::invalid_params(
                format!("{name} is required"),
                None,
            ));
        }
    }
    for (name, property) in properties {
        if let Some(value) = arguments.get(&name)
            && !property.accepts(value)
        {
            return Err(McpError::invalid_params(
                format!("{name} has an invalid type"),
                None,
            ));
        }
    }
    Ok(())
}

fn deployment_selector_schema() -> Value {
    json!({"type": "string", "format": "uuid", "description": "The deployment ID of your hire. Required when you have several hires of this Employee; omitted when you have just one."})
}

fn select_hire(
    hires: &[ManagedAgentHire],
    arguments: &JsonObject,
) -> Result<Option<Uuid>, McpError> {
    if let Some(value) = arguments.get("deployment_id") {
        let deployment_id: Uuid = serde_json::from_value(value.clone())
            .map_err(|_| McpError::invalid_params("deployment_id must be a UUID", None))?;
        if !hires.iter().any(|hire| hire.deployment_id == deployment_id) {
            return Err(McpError::invalid_params(
                "deployment_id must identify one of your hires of this Employee",
                None,
            ));
        }
        return Ok(Some(deployment_id));
    }
    if hires.is_empty() {
        return Ok(None);
    }
    if let [hire] = hires {
        return Ok(Some(hire.deployment_id));
    }
    let choices: Vec<String> = hires
        .iter()
        .map(|hire| match &hire.hire_name {
            Some(name) => format!("{} ({name})", hire.deployment_id),
            None => hire.deployment_id.to_string(),
        })
        .collect();
    Err(McpError::invalid_params(
        format!(
            "You have several hires of this Employee. Supply deployment_id to choose one: {}",
            choices.join(", ")
        ),
        None,
    ))
}

#[derive(Deserialize)]
struct MessagePage {
    messages: Vec<Value>,
    has_more: bool,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "charge", rename_all = "snake_case")]
enum RunPrice {
    Fee { name: String, amount: RunFee },
    Cost,
}

#[derive(Deserialize)]
struct RunFee {
    atomic: i64,
    percent: Option<i32>,
}

/// The page slug when `path` is a single-segment managed agent address.
pub(crate) fn managed_agent_page_slug_from_path(path: &str) -> Option<&str> {
    let slug = path.strip_prefix(MANAGED_AGENT_PATH_PREFIX)?;
    let valid = !slug.is_empty()
        && slug.len() <= 128
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    valid.then_some(slug)
}

fn no_managed_agent() -> McpError {
    McpError::new(
        ErrorCode(NO_MANAGED_AGENT_CODE),
        NO_MANAGED_AGENT_MESSAGE,
        None,
    )
}

fn core_error(message: impl Into<String>) -> McpError {
    McpError::internal_error(message.into(), None)
}

fn text_result(text: impl Into<String>) -> CallToolResponse {
    CallToolResponse::Complete(CallToolResult::success(vec![ContentBlock::text(text)]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobId {
    pub deployment_id: Uuid,
    pub conversation_id: String,
    pub client_message_id: String,
}

impl JobId {
    pub(crate) fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(format!(
            "{}.{}.{}",
            self.deployment_id, self.conversation_id, self.client_message_id
        ))
    }

    pub(crate) fn decode(job_id: &str) -> Option<Self> {
        let raw = URL_SAFE_NO_PAD.decode(job_id.trim()).ok()?;
        let raw = String::from_utf8(raw).ok()?;
        let (deployment_id, rest) = raw.split_once('.')?;
        let (conversation_id, client_message_id) = rest.rsplit_once('.')?;
        if conversation_id.is_empty() || client_message_id.is_empty() {
            return None;
        }
        Some(Self {
            deployment_id: deployment_id.parse().ok()?,
            conversation_id: conversation_id.to_string(),
            client_message_id: client_message_id.to_string(),
        })
    }
}

/// Whole cents, as the website shows a rate: `$0.06`.
pub(crate) fn format_hourly_rate(atomic: i64) -> String {
    let cents = (i128::from(atomic) + 5_000) / 10_000;
    format!("${}.{:02}", cents / 100, cents % 100)
}

/// Fill each `{{property}}` placeholder with the call's argument.
pub(crate) fn render_message(template: &str, arguments: &JsonObject) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let name = after[..end].trim();
                match arguments.get(name) {
                    Some(Value::String(s)) => out.push_str(s),
                    Some(Value::Null) | None => {}
                    Some(other) => out.push_str(&other.to_string()),
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn object_schema(value: Value) -> Arc<JsonObject> {
    Arc::new(match value {
        Value::Object(map) => map,
        _ => JsonObject::new(),
    })
}

/// The text a caller sees before hiring a managed agent.
pub(crate) fn not_hired_text(listing: &Value) -> String {
    let name = listing
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or("This Employee");
    let who = match listing.get("job_title").and_then(Value::as_str) {
        Some(title) if !title.trim().is_empty() => format!("{name}, {title}"),
        _ => name.to_string(),
    };
    let rate = listing
        .pointer("/catalog/hourly_rate_atomic")
        .and_then(Value::as_i64)
        .filter(|atomic| *atomic > 0);
    let history = match rate {
        Some(atomic) => format!(
            " The catalog's historical average is {} per hour the Employee was hired, not per hour of task work or a guaranteed task price.",
            format_hourly_rate(atomic)
        ),
        None => String::new(),
    };
    let fees: Vec<String> = listing
        .get("run_kinds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|kind| serde_json::from_value::<RunPrice>(kind.clone()).ok())
        .filter_map(|kind| match kind {
            RunPrice::Fee { name, amount } => {
                let price = match amount.percent {
                    Some(percent) => format!("{percent}% of recorded running cost"),
                    None => format!(
                        "${} per task",
                        crate::money::format_usd_micros(amount.atomic)
                    ),
                };
                Some(format!("{name}: {price}"))
            }
            RunPrice::Cost => None,
        })
        .collect();
    let fees = if fees.is_empty() {
        String::new()
    } else {
        format!(" Catalog service fees: {}.", fees.join("; "))
    };
    format!(
        "You haven't hired {who}.{history} Running costs and any applicable service fees are charged according to the catalog.{fees} Review those prices before approving the hire, then call hire and ask for the task again."
    )
}

/// A managed agent's MCP view, built per request from the catalog.
#[derive(Clone)]
pub(crate) struct ManagedAgentMcpServer {
    api_base_url: String,
    http: reqwest::Client,
}

impl ManagedAgentMcpServer {
    pub(crate) fn new(api_base_url: &str, http: reqwest::Client) -> Self {
        Self {
            api_base_url: api_base_url.trim_end_matches('/').to_string(),
            http,
        }
    }

    fn bearer(extensions: &Extensions) -> Result<String, McpError> {
        extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.headers.get(axum::http::header::AUTHORIZATION))
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| McpError::invalid_request("Missing Bearer token", None))
    }

    fn page_slug(extensions: &Extensions) -> Result<String, McpError> {
        extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| managed_agent_page_slug_from_path(parts.uri.path()))
            .map(str::to_string)
            .ok_or_else(no_managed_agent)
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        bearer: &str,
    ) -> Result<(reqwest::StatusCode, Value), McpError> {
        let response = request
            .header(reqwest::header::AUTHORIZATION, bearer)
            .send()
            .await
            .map_err(|error| core_error(format!("Seren is unreachable: {error}")))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| core_error(format!("Seren's answer was cut off: {error}")))?;
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok((status, body))
    }

    async fn get_json(&self, path: &str, bearer: &str) -> Result<Value, McpError> {
        let url = format!("{}/{}", self.api_base_url, path);
        let (status, body) = self.send(self.http.get(url), bearer).await?;
        if !status.is_success() {
            return Err(core_error(format!(
                "Seren answered {status} for {path}: {}",
                error_text(&body)
            )));
        }
        Ok(body)
    }

    async fn post_json(
        &self,
        path: &str,
        payload: Value,
        bearer: &str,
    ) -> Result<(reqwest::StatusCode, Value), McpError> {
        let url = format!("{}/{}", self.api_base_url, path);
        self.send(self.http.post(url).json(&payload), bearer).await
    }

    /// The listed managed agent at this address.
    async fn listing(&self, page_slug: &str, bearer: &str) -> Result<Value, McpError> {
        let catalog = self
            .get_json(&format!("{AGENT_PUBLISHER}/templates"), bearer)
            .await?;
        catalog
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|listing| {
                let address = listing
                    .get("page_slug")
                    .and_then(Value::as_str)
                    .or_else(|| listing.get("slug").and_then(Value::as_str));
                address == Some(page_slug)
            })
            .cloned()
            .ok_or_else(no_managed_agent)
    }

    fn template_slug(listing: &Value) -> Result<&str, McpError> {
        listing
            .get("slug")
            .and_then(Value::as_str)
            .ok_or_else(no_managed_agent)
    }

    /// The caller's live hires of this managed agent in the API's oldest-first order.
    async fn my_hires(
        &self,
        listing: &Value,
        bearer: &str,
    ) -> Result<Vec<ManagedAgentHire>, McpError> {
        let slug = Self::template_slug(listing)?;
        let hires = self
            .get_json(
                &format!("{AGENT_PUBLISHER}/templates/{slug}/hires/mine"),
                bearer,
            )
            .await?;
        serde_json::from_value(hires.get("data").cloned().unwrap_or(Value::Null))
            .map_err(|error| core_error(format!("Seren returned invalid hires: {error}")))
    }

    pub(crate) fn tools(listing: &Value) -> Result<Vec<Tool>, McpError> {
        let name = listing
            .get("display_name")
            .and_then(Value::as_str)
            .unwrap_or("this Employee");
        let mut tools = vec![
            Tool::new(
                GIVE_TASK,
                format!("Give {name} a task in plain words. Returns a job ID to fetch the report with get_report."),
                object_schema(json!({
                    "type": "object",
                    "properties": {"text": {"type": "string", "description": "Describe the task for this Employee."}, "deployment_id": deployment_selector_schema()},
                    "required": ["text"],
                })),
            )
            .with_title("Give a task"),
            Tool::new(
                GET_REPORT,
                format!("Fetch {name}'s report for a job number a task returned."),
                object_schema(json!({
                    "type": "object",
                    "properties": {"job_id": {"type": "string", "description": "The job number a task returned."}},
                    "required": ["job_id"],
                })),
            )
            .with_title("Get a report"),
            Tool::new(
                HIRE,
                format!("Hire {name}. Call only after the user approves the catalog's running costs and service fees. mail_and_files requires provider and oauth_connection_id; mail_read accepts both or neither; sign_in_only accepts neither. Templates allowing several hires require hire_name."),
                object_schema(serde_json::to_value(schemars::schema_for!(HireArguments))
                    .expect("the hire argument schema is JSON")),
            )
            .with_title("Hire"),
        ];
        for tool in listing
            .get("mcp_tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(tool_name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            let description = tool
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            task_schema(tool)?;
            let schema = object_schema(json!({
                "type": "object",
                "properties": {
                    "deployment_id": deployment_selector_schema(),
                    "arguments": tool["input_schema"],
                },
                "required": ["arguments"],
                "additionalProperties": false,
            }));
            let mut built = Tool::new(
                format!("{TASK_TOOL_PREFIX}{tool_name}"),
                description,
                schema,
            );
            if let Some(title) = tool.get("title").and_then(Value::as_str) {
                built = built.with_title(title);
            }
            tools.push(built);
        }
        Ok(tools)
    }

    async fn hire(
        &self,
        listing: &Value,
        arguments: &JsonObject,
        bearer: &str,
        extensions: &Extensions,
    ) -> Result<CallToolResponse, McpError> {
        if arguments.get("confirm").and_then(Value::as_bool) != Some(true) {
            return Ok(text_result(not_hired_text(listing)));
        }
        crate::server::ensure_managed_deployment_mutation_allowed(
            extensions,
            crate::server::ManagedDeploymentMutation::Create,
        )?;
        let HireArguments {
            confirm,
            mut request,
        } = serde_json::from_value(Value::Object(arguments.clone())).map_err(|error| {
            McpError::invalid_params(format!("Invalid hire arguments: {error}"), None)
        })?;
        debug_assert!(confirm);
        request.timezone = request.timezone.trim().to_string();
        if request.timezone.is_empty() {
            return Err(McpError::invalid_params("timezone is required", None));
        }
        let requirements: HireRequirements = serde_json::from_value(listing.clone())
            .map_err(|_| core_error("The Employee's hire requirements are unsupported"))?;
        use seren::ManagedAgentTemplateOwnerConnection::{MailAndFiles, MailRead, SignInOnly};
        match requirements.owner_connection {
            MailAndFiles if request.provider.is_none() || request.oauth_connection_id.is_none() => {
                return Err(McpError::invalid_params(
                    "provider and oauth_connection_id are required for this Employee",
                    None,
                ));
            }
            MailRead if request.provider.is_some() != request.oauth_connection_id.is_some() => {
                return Err(McpError::invalid_params(
                    "Supply provider and oauth_connection_id together, or omit both",
                    None,
                ));
            }
            SignInOnly if request.provider.is_some() || request.oauth_connection_id.is_some() => {
                return Err(McpError::invalid_params(
                    "This Employee does not accept provider or oauth_connection_id",
                    None,
                ));
            }
            _ => {}
        }
        use seren::ManagedAgentTemplateHiresPerEmployer::{Many, One};
        let named_hire = match requirements.hires_per_employer {
            Many => {
                let name = request.hire_name.as_deref().unwrap_or_default().trim();
                if name.is_empty() || name.chars().count() > 60 {
                    return Err(McpError::invalid_params(
                        "hire_name must contain 1 to 60 characters for this Employee",
                        None,
                    ));
                }
                request.hire_name = Some(name.to_string());
                true
            }
            One if request.hire_name.is_some() => {
                return Err(McpError::invalid_params(
                    "This Employee does not accept hire_name",
                    None,
                ));
            }
            One => false,
        };
        if !named_hire && !self.my_hires(listing, bearer).await?.is_empty() {
            return Ok(text_result("Hired. Ask again and I'll start."));
        }
        let slug = Self::template_slug(listing)?;
        let (status, body) = self
            .post_json(
                &format!("{AGENT_PUBLISHER}/templates/{slug}/deployments"),
                serde_json::to_value(request).map_err(|error| core_error(error.to_string()))?,
                bearer,
            )
            .await?;
        if status.is_success() {
            return Ok(text_result("Hired. Ask again and I'll start."));
        }
        if error_code(&body).as_deref() == Some("owner_email_unverified") {
            return Ok(text_result(
                "Confirm your email at console.serendb.com, then ask again.",
            ));
        }
        Ok(CallToolResponse::Complete(CallToolResult::error(vec![
            ContentBlock::text(format!(
                "Seren couldn't create the hire: {}",
                error_text(&body)
            )),
        ])))
    }

    async fn start_work(
        &self,
        deployment_id: Uuid,
        message: String,
        bearer: &str,
    ) -> Result<CallToolResponse, McpError> {
        let (status, session) = self
            .post_json(
                &format!("{CLOUD_PUBLISHER}/deployments/{deployment_id}/sessions"),
                json!({ "conversation_id": MCP_CONVERSATION }),
                bearer,
            )
            .await?;
        if !status.is_success() {
            return Err(core_error(format!(
                "Seren couldn't open the conversation: {}",
                error_text(&session)
            )));
        }
        let session = session.get("data").unwrap_or(&session);
        let session_id = session
            .get("session_id")
            .and_then(Value::as_str)
            .ok_or_else(|| core_error("Seren opened no session"))?;
        let conversation_id = session
            .get("conversation_id")
            .and_then(Value::as_str)
            .unwrap_or(MCP_CONVERSATION)
            .to_string();
        let client_message_id = Uuid::new_v4().to_string();
        let (status, posted) = self
            .post_json(
                &format!(
                    "{CLOUD_PUBLISHER}/deployments/{deployment_id}/sessions/{session_id}/messages"
                ),
                json!({
                    "content": message,
                    "client_message_id": client_message_id,
                    "idempotency_key": client_message_id,
                }),
                bearer,
            )
            .await?;
        if !status.is_success() {
            return Err(core_error(format!(
                "Seren couldn't submit the task: {}",
                error_text(&posted)
            )));
        }
        let job = JobId {
            deployment_id,
            conversation_id,
            client_message_id,
        };
        Ok(text_result(format!(
            "Task submitted. Job {}. Use get_report to check its result.",
            job.encode()
        )))
    }

    async fn conversation_messages(
        &self,
        job: &JobId,
        bearer: &str,
    ) -> Result<Vec<Value>, McpError> {
        let conversation = urlencode(&job.conversation_id);
        let path = format!(
            "{CLOUD_PUBLISHER}/deployments/{}/conversations/{conversation}/messages?order=asc&limit=200&include_run=false",
            job.deployment_id
        );
        let mut cursor: Option<String> = None;
        let mut seen_cursors = BTreeSet::new();
        let mut messages = Vec::new();
        loop {
            let path = match &cursor {
                Some(cursor) => format!("{path}&cursor={}", urlencode(cursor)),
                None => path.clone(),
            };
            let envelope = self.get_json(&path, bearer).await?;
            let page: MessagePage =
                serde_json::from_value(envelope.get("data").cloned().unwrap_or(envelope)).map_err(
                    |error| core_error(format!("Seren returned an invalid message page: {error}")),
                )?;
            messages.extend(page.messages);
            if !page.has_more {
                return Ok(messages);
            }
            let next = page
                .next_cursor
                .filter(|cursor| !cursor.is_empty())
                .ok_or_else(|| core_error("Seren returned no next message cursor"))?;
            if !seen_cursors.insert(next.clone()) {
                return Err(core_error("Seren repeated a message cursor"));
            }
            cursor = Some(next);
        }
    }

    async fn dispatch_tool(
        &self,
        tool_name: &str,
        arguments: JsonObject,
        extensions: &Extensions,
    ) -> Result<CallToolResponse, McpError> {
        let page_slug = Self::page_slug(extensions)?;
        let bearer = Self::bearer(extensions)?;
        let listing = self.listing(&page_slug, &bearer).await?;
        match tool_name {
            HIRE => return self.hire(&listing, &arguments, &bearer, extensions).await,
            GET_REPORT => return self.get_report(&listing, &arguments, &bearer).await,
            _ => {}
        }
        let message = if tool_name == GIVE_TASK {
            arguments
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
                .ok_or_else(|| McpError::invalid_params("text is required", None))?
                .to_string()
        } else {
            let publisher_tool_name =
                tool_name.strip_prefix(TASK_TOOL_PREFIX).ok_or_else(|| {
                    McpError::invalid_params(format!("Unknown tool: {tool_name}"), None)
                })?;
            let tool = listing
                .get("mcp_tools")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find(|tool| tool.get("name").and_then(Value::as_str) == Some(publisher_tool_name))
                .ok_or_else(|| {
                    McpError::invalid_params(format!("Unknown tool: {tool_name}"), None)
                })?;
            for name in arguments.keys() {
                if !matches!(name.as_str(), "deployment_id" | "arguments") {
                    return Err(McpError::invalid_params(
                        format!("Unknown tool argument: {name}"),
                        None,
                    ));
                }
            }
            let publisher_arguments = arguments
                .get("arguments")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    McpError::invalid_params(
                        "arguments must be an object containing the tool's inputs",
                        None,
                    )
                })?;
            validate_task_arguments(tool, publisher_arguments)?;
            let template = tool
                .get("message")
                .and_then(Value::as_str)
                .ok_or_else(|| core_error("The Employee's tool has no task message"))?;
            render_message(template, publisher_arguments)
        };
        crate::server::ensure_writes_allowed(extensions)?;
        let hires = self.my_hires(&listing, &bearer).await?;
        let Some(deployment_id) = select_hire(&hires, &arguments)? else {
            return Ok(text_result(not_hired_text(&listing)));
        };
        self.start_work(deployment_id, message, &bearer).await
    }

    async fn attach_files(
        &self,
        job: &JobId,
        bearer: &str,
        messages: &[&Value],
        content: &mut Vec<ContentBlock>,
    ) -> Result<(), McpError> {
        let mut seen_file_ids = BTreeSet::new();
        for message in messages {
            for file in message
                .get("files")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(file_id) = file.get("file_id").and_then(Value::as_str) else {
                    continue;
                };
                if !seen_file_ids.insert(file_id) {
                    continue;
                }
                let name = file.get("name").and_then(Value::as_str).unwrap_or(file_id);
                let content_type = file
                    .get("content_type")
                    .and_then(Value::as_str)
                    .unwrap_or("application/octet-stream");
                let url = format!(
                    "{}/{CLOUD_PUBLISHER}/deployments/{}/files/{}/content",
                    self.api_base_url,
                    job.deployment_id,
                    urlencode(file_id)
                );
                let response = self
                    .http
                    .get(url)
                    .header(reqwest::header::AUTHORIZATION, bearer)
                    .send()
                    .await
                    .map_err(|error| core_error(format!("Seren is unreachable: {error}")))?;
                if !response.status().is_success() {
                    return Err(core_error(format!(
                        "Seren answered {} for file {name}",
                        response.status()
                    )));
                }
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|error| core_error(format!("File {name} was cut off: {error}")))?;
                content.push(ContentBlock::resource(
                    ResourceContents::blob(BASE64.encode(&bytes), format!("seren-file:///{name}"))
                        .with_mime_type(content_type),
                ));
            }
        }
        Ok(())
    }

    async fn get_report(
        &self,
        listing: &Value,
        arguments: &JsonObject,
        bearer: &str,
    ) -> Result<CallToolResponse, McpError> {
        let refused = || McpError::invalid_params("That job number isn't one of yours.", None);
        let job = arguments
            .get("job_id")
            .and_then(Value::as_str)
            .and_then(JobId::decode)
            .ok_or_else(refused)?;
        if !self
            .my_hires(listing, bearer)
            .await?
            .iter()
            .any(|hire| hire.deployment_id == job.deployment_id)
        {
            return Err(refused());
        }
        let messages = self.conversation_messages(&job, bearer).await?;
        let Some(asked) = messages.iter().position(|message| {
            message.get("client_message_id").and_then(Value::as_str)
                == Some(job.client_message_id.as_str())
        }) else {
            return Ok(text_result("Still working."));
        };
        let replies: Vec<&Value> = messages[asked + 1..]
            .iter()
            .take_while(|message| message.get("role").and_then(Value::as_str) != Some("user"))
            .filter(|message| message.get("role").and_then(Value::as_str) == Some("assistant"))
            .collect();
        fn failed_status_message(message: &Value) -> Option<Option<&str>> {
            let summary = message.get("run_summary")?;
            let status = summary.get("status").and_then(Value::as_str)?;
            matches!(
                status,
                "failed" | "error" | "errored" | "cancelled" | "canceled"
            )
            .then(|| {
                summary
                    .get("status_message")
                    .and_then(Value::as_str)
                    .filter(|text| !text.trim().is_empty())
            })
        }
        let latest_reply_summary = replies.iter().rev().copied().find(|message| {
            message
                .pointer("/run_summary/status")
                .and_then(Value::as_str)
                .is_some()
        });
        let asked_failure = failed_status_message(&messages[asked]);
        let reply_failure = latest_reply_summary.and_then(failed_status_message);
        if asked_failure.is_some() || reply_failure.is_some() {
            let status_message = reply_failure
                .flatten()
                .or_else(|| asked_failure.flatten())
                .unwrap_or("The task failed.");
            let mut parts: Vec<&str> = replies
                .iter()
                .filter_map(|message| message.get("content").and_then(Value::as_str))
                .filter(|text| !text.trim().is_empty())
                .collect();
            parts.push(status_message);
            let mut content = vec![ContentBlock::text(parts.join("\n\n"))];
            self.attach_files(&job, bearer, &replies, &mut content)
                .await?;
            return Ok(CallToolResponse::Complete(CallToolResult::error(content)));
        }
        let Some(reply) = replies.last() else {
            return Ok(text_result("Still working."));
        };
        let finished = reply
            .pointer("/run_summary/status")
            .and_then(Value::as_str)
            .is_none_or(|status| matches!(status, "completed" | "succeeded" | "success" | "done"));
        if !finished {
            return Ok(text_result("Still working."));
        }
        let mut content = vec![ContentBlock::text(
            reply
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        )];
        self.attach_files(&job, bearer, &[reply], &mut content)
            .await?;
        Ok(CallToolResponse::Complete(CallToolResult::success(content)))
    }
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn error_code(body: &Value) -> Option<String> {
    body.pointer("/error/code")
        .or_else(|| body.get("code"))
        .or_else(|| body.get("error"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn error_text(body: &Value) -> String {
    body.pointer("/error/message")
        .or_else(|| body.get("message"))
        .or_else(|| body.get("error_description"))
        .or_else(|| body.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("no details")
        .to_string()
}

impl ServerHandler for ManagedAgentMcpServer {
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let page_slug = Self::page_slug(&context.extensions)?;
        let bearer = Self::bearer(&context.extensions)?;
        let listing = self.listing(&page_slug, &bearer).await?;
        Ok(ListToolsResult::with_all_items(Self::tools(&listing)?))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.dispatch_tool(
            request.name.as_ref(),
            request.arguments.unwrap_or_default(),
            &context.extensions,
        )
        .await
    }

    fn get_info(&self) -> ServerConfig {
        let server_info =
            rmcp::model::Implementation::new(crate::MCP_SERVER_NAME, env!("CARGO_PKG_VERSION"))
                .with_title("Seren Employee")
                .with_website_url("https://serendb.com");
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(server_info)
            .with_instructions(
                "Give this Seren Employee a task with give_task or one of the declared tools, then fetch the report with get_report and the job ID. If you have not hired the Employee, review the prices and call hire only after the user approves.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{
        body_partial_json, method, path, query_param, query_param_is_missing,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn listing() -> Value {
        json!({
            "slug": "alina-golub", "display_name": "Alina Golub",
            "owner_connection": "sign_in_only", "hires_per_employer": "one",
            "mcp_tools": [{
                "name": "trace_wallet", "title": "Trace a wallet", "description": "Trace funds.",
                "input_schema": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]},
                "message": "Trace {{address}}."
            }],
            "run_kinds": [], "catalog": {"hourly_rate_atomic": null}
        })
    }

    fn extensions(read_only: bool) -> Extensions {
        let request = axum::http::Request::builder()
            .uri("/employees/alina-golub")
            .header(axum::http::header::AUTHORIZATION, "Bearer upstream-access")
            .header("x-read-only", read_only.to_string())
            .body(())
            .unwrap();
        let mut extensions = Extensions::default();
        extensions.insert(request.into_parts().0);
        extensions
    }

    fn arguments(value: Value) -> JsonObject {
        value.as_object().unwrap().clone()
    }

    fn response_text(response: CallToolResponse) -> String {
        let CallToolResponse::Complete(result) = response else {
            panic!("expected completed MCP result")
        };
        serde_json::to_value(result).unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn catalog(core: &MockServer, listing: &Value) {
        Mock::given(method("GET"))
            .and(path("/publishers/seren-agent/templates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [listing]})))
            .mount(core)
            .await;
    }

    async fn assert_no_posts(core: &MockServer) {
        assert!(
            core.received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() != "POST")
        );
    }

    async fn mount_hires(core: &MockServer, deployment_ids: &[Uuid]) {
        let hires: Vec<Value> = deployment_ids
            .iter()
            .map(|id| json!({"deployment_id": id}))
            .collect();
        Mock::given(method("GET"))
            .and(path(
                "/publishers/seren-agent/templates/alina-golub/hires/mine",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": hires})))
            .mount(core)
            .await;
    }

    #[tokio::test]
    async fn declared_names_cannot_shadow_builtin_tools() {
        let core = MockServer::start().await;
        let mut listing = listing();
        let mut hire_tool = listing["mcp_tools"][0].clone();
        hire_tool["name"] = json!("hire");
        hire_tool["message"] = json!("Publisher hire {{address}}.");
        let mut give_task_tool = listing["mcp_tools"][0].clone();
        give_task_tool["name"] = json!("give_task");
        give_task_tool["message"] = json!("Publisher task {{address}}.");
        listing["mcp_tools"] = json!([hire_tool, give_task_tool]);
        let tools = ManagedAgentMcpServer::tools(&listing).unwrap();
        let names: BTreeSet<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        for name in [GIVE_TASK, GET_REPORT, HIRE, "task_hire", "task_give_task"] {
            assert!(names.contains(name), "{name}");
        }
        assert_eq!(names.len(), tools.len(), "tool names must be unique");
        catalog(&core, &listing).await;
        let chosen = Uuid::new_v4();
        mount_hires(&core, &[chosen]).await;
        let session_id = Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path(format!(
                "/publishers/seren-cloud/deployments/{chosen}/sessions"
            )))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"data": {
                "session_id": session_id, "conversation_id": "mcp"
            }})))
            .expect(2)
            .mount(&core)
            .await;
        for content in ["Publisher hire 0x123.", "Publisher task 0x123."] {
            Mock::given(method("POST"))
                .and(path(format!(
                    "/publishers/seren-cloud/deployments/{chosen}/sessions/{session_id}/messages"
                )))
                .and(body_partial_json(json!({"content": content})))
                .respond_with(ResponseTemplate::new(202).set_body_json(json!({"data": {}})))
                .expect(1)
                .mount(&core)
                .await;
        }
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        for name in ["task_hire", "task_give_task"] {
            let response = server
                .dispatch_tool(
                    name,
                    arguments(json!({"arguments": {"address": "0x123"}})),
                    &extensions(false),
                )
                .await
                .unwrap();
            assert!(response_text(response).starts_with("Task submitted. Job "));
        }
        let response = server
            .dispatch_tool(
                HIRE,
                arguments(json!({"confirm": false})),
                &extensions(false),
            )
            .await
            .unwrap();
        assert!(response_text(response).starts_with("You haven't hired Alina Golub."));
    }

    #[tokio::test]
    async fn declared_names_have_no_unprefixed_or_repeated_prefix_fallback() {
        let core = MockServer::start().await;
        catalog(&core, &listing()).await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        for name in ["trace_wallet", "task_task_trace_wallet"] {
            let error = server
                .dispatch_tool(
                    name,
                    arguments(json!({"arguments": {"address": "0x123"}})),
                    &extensions(false),
                )
                .await
                .unwrap_err();
            assert!(error.message.contains("Unknown tool:"));
        }
        assert_no_posts(&core).await;
    }

    #[tokio::test]
    async fn multiple_hires_require_an_owned_explicit_deployment() {
        let core = MockServer::start().await;
        catalog(&core, &listing()).await;
        mount_hires(&core, &[Uuid::new_v4(), Uuid::new_v4()]).await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        for (tool, mut input) in [
            (GIVE_TASK, json!({"text": "Research"})),
            (
                "task_trace_wallet",
                json!({"arguments": {"address": "0x123"}}),
            ),
        ] {
            let error = server
                .dispatch_tool(tool, arguments(input.clone()), &extensions(false))
                .await
                .unwrap_err();
            assert!(error.message.contains("Supply deployment_id"));
            input["deployment_id"] = json!(Uuid::new_v4());
            let error = server
                .dispatch_tool(tool, arguments(input), &extensions(false))
                .await
                .unwrap_err();
            assert!(error.message.contains("one of your hires"));
        }
        assert_no_posts(&core).await;
    }

    #[tokio::test]
    async fn no_hires_returns_price_information_without_starting_work() {
        let core = MockServer::start().await;
        catalog(&core, &listing()).await;
        mount_hires(&core, &[]).await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        let response = server
            .dispatch_tool(
                GIVE_TASK,
                arguments(json!({"text": "Research"})),
                &extensions(false),
            )
            .await
            .unwrap();
        assert!(response_text(response).starts_with("You haven't hired Alina Golub."));
        assert_no_posts(&core).await;
    }

    #[tokio::test]
    async fn no_hires_still_rejects_explicit_invalid_selectors() {
        let core = MockServer::start().await;
        catalog(&core, &listing()).await;
        mount_hires(&core, &[]).await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        for selector in [json!("invalid"), Value::Null, json!(Uuid::new_v4())] {
            for (tool, mut input) in [
                (GIVE_TASK, json!({"text": "Research"})),
                (
                    "task_trace_wallet",
                    json!({"arguments": {"address": "0x123"}}),
                ),
            ] {
                input["deployment_id"] = selector.clone();
                let error = server
                    .dispatch_tool(tool, arguments(input), &extensions(false))
                    .await
                    .unwrap_err();
                assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
            }
        }
        assert_no_posts(&core).await;
    }

    #[tokio::test]
    async fn single_implicit_and_multiple_explicit_dispatch_to_the_selected_hire() {
        for explicit in [false, true] {
            let core = MockServer::start().await;
            catalog(&core, &listing()).await;
            let chosen = Uuid::new_v4();
            let ids = if explicit {
                vec![Uuid::new_v4(), chosen]
            } else {
                vec![chosen]
            };
            mount_hires(&core, &ids).await;
            let session_id = Uuid::new_v4();
            Mock::given(method("POST"))
                .and(path(format!(
                    "/publishers/seren-cloud/deployments/{chosen}/sessions"
                )))
                .respond_with(ResponseTemplate::new(201).set_body_json(
                    json!({"data": {"session_id": session_id, "conversation_id": "mcp"}}),
                ))
                .expect(1)
                .mount(&core)
                .await;
            Mock::given(method("POST"))
                .and(path(format!(
                    "/publishers/seren-cloud/deployments/{chosen}/sessions/{session_id}/messages"
                )))
                .respond_with(ResponseTemplate::new(202).set_body_json(json!({"data": {}})))
                .expect(1)
                .mount(&core)
                .await;
            let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
            let (tool, input) = if explicit {
                (
                    "task_trace_wallet",
                    json!({"arguments": {"address": "0x123"}, "deployment_id": chosen}),
                )
            } else {
                (GIVE_TASK, json!({"text": "Research"}))
            };
            let response = response_text(
                server
                    .dispatch_tool(tool, arguments(input), &extensions(false))
                    .await
                    .unwrap(),
            );
            let job = response
                .strip_prefix("Task submitted. Job ")
                .unwrap()
                .split('.')
                .next()
                .and_then(JobId::decode)
                .unwrap();
            assert_eq!(job.deployment_id, chosen);
        }
    }

    #[test]
    fn declared_tool_envelope_preserves_the_publisher_schema() {
        let mut listing = listing();
        listing["mcp_tools"][0]["input_schema"]["properties"]["deployment_id"] =
            json!({"type": "string", "description": "The publisher's deployment reference."});
        listing["mcp_tools"][0]["input_schema"]["required"] = json!(["address", "deployment_id"]);
        let tools = ManagedAgentMcpServer::tools(&listing).unwrap();
        let trace = serde_json::to_value(
            tools
                .iter()
                .find(|tool| tool.name == "task_trace_wallet")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            trace["inputSchema"]["properties"]["arguments"],
            listing["mcp_tools"][0]["input_schema"]
        );
        assert_eq!(trace["inputSchema"]["required"], json!(["arguments"]));
        assert_eq!(
            trace["inputSchema"]["properties"]["deployment_id"]["format"],
            "uuid"
        );
    }

    #[tokio::test]
    async fn declared_tool_renders_inner_deployment_reference_and_selects_outer_hire() {
        let core = MockServer::start().await;
        let mut listing = listing();
        listing["mcp_tools"][0]["input_schema"]["properties"]["deployment_id"] =
            json!({"type": "string"});
        listing["mcp_tools"][0]["input_schema"]["required"] = json!(["address", "deployment_id"]);
        listing["mcp_tools"][0]["message"] = json!("Trace {{address}} for {{deployment_id}}.");
        catalog(&core, &listing).await;
        let chosen = Uuid::new_v4();
        mount_hires(&core, &[Uuid::new_v4(), chosen]).await;
        let session_id = Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path(format!(
                "/publishers/seren-cloud/deployments/{chosen}/sessions"
            )))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                json!({"data": {"session_id": session_id, "conversation_id": "mcp"}}),
            ))
            .expect(1)
            .mount(&core)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/publishers/seren-cloud/deployments/{chosen}/sessions/{session_id}/messages"
            )))
            .and(body_partial_json(
                json!({"content": "Trace 0x123 for publisher-deployment."}),
            ))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"data": {}})))
            .expect(1)
            .mount(&core)
            .await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        let response = server
            .dispatch_tool(
                "task_trace_wallet",
                arguments(json!({
                    "deployment_id": chosen,
                    "arguments": {"address": "0x123", "deployment_id": "publisher-deployment"}
                })),
                &extensions(false),
            )
            .await
            .unwrap();
        assert!(response_text(response).starts_with("Task submitted. Job "));
    }

    #[tokio::test]
    async fn read_only_blocks_hiring_and_task_dispatch() {
        let core = MockServer::start().await;
        catalog(&core, &listing()).await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        for (name, input) in [
            (HIRE, json!({"confirm": true, "timezone": "UTC"})),
            (GIVE_TASK, json!({"text": "Trace a wallet"})),
            (
                "task_trace_wallet",
                json!({"arguments": {"address": "0x123"}}),
            ),
        ] {
            let error = server
                .dispatch_tool(name, arguments(input), &extensions(true))
                .await
                .unwrap_err();
            assert!(error.message.contains("Read-only mode"));
        }
        assert_no_posts(&core).await;
    }

    #[tokio::test]
    async fn hiring_uses_existing_management_authorization() {
        let core = MockServer::start().await;
        catalog(&core, &listing()).await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        let auth = crate::SerenRequestAuthContext {
            user_id: Uuid::new_v4(),
            email: None,
            credential: crate::SerenRequestCredential::UserApiKey {
                api_key_id: None,
                api_key_scopes: Some(vec![]),
            },
        };
        let request = axum::http::Request::builder()
            .uri("/employees/alina-golub")
            .header(axum::http::header::AUTHORIZATION, "Bearer upstream-access")
            .extension(auth)
            .body(())
            .unwrap();
        let mut extensions = Extensions::default();
        extensions.insert(request.into_parts().0);
        let error = server
            .dispatch_tool(
                HIRE,
                arguments(json!({"confirm": true, "timezone": "UTC"})),
                &extensions,
            )
            .await
            .unwrap_err();
        assert!(error.message.contains("managed-deployment:create"));
        assert_no_posts(&core).await;
    }

    #[tokio::test]
    async fn declared_tool_rejects_missing_or_wrong_arguments_before_mutation() {
        let core = MockServer::start().await;
        catalog(&core, &listing()).await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        for input in [
            json!({}),
            json!({"address": "0x123"}),
            json!({"arguments": null}),
            json!({"arguments": {}}),
            json!({"arguments": {"address": null}}),
            json!({"arguments": {"address": {"value": "0x123"}}}),
            json!({"arguments": {"address": "0x123"}, "address": "legacy-flat-input"}),
        ] {
            let error = server
                .dispatch_tool("task_trace_wallet", arguments(input), &extensions(false))
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
        }
        assert_no_posts(&core).await;
    }

    #[test]
    fn declared_tool_checks_each_supported_property_type() {
        let tool = json!({"input_schema": {"type": "object", "properties": {
            "text": {"type": "string"}, "count": {"type": "number"},
            "enabled": {"type": "boolean"}, "names": {"type": "array", "items": {"type": "string"}}
        }, "required": ["text", "count", "enabled", "names"]}});
        let valid =
            arguments(json!({"text": "work", "count": 2.5, "enabled": true, "names": ["one"]}));
        validate_task_arguments(&tool, &valid).unwrap();
        for (name, value) in [
            ("text", json!(2)),
            ("count", json!("2")),
            ("enabled", json!("true")),
            ("names", json!([1])),
        ] {
            let mut invalid = valid.clone();
            invalid.insert(name.to_string(), value);
            assert!(validate_task_arguments(&tool, &invalid).is_err(), "{name}");
        }
    }

    #[tokio::test]
    async fn hire_forwards_connection_and_name_fields() {
        let core = MockServer::start().await;
        let mut listing = listing();
        listing["owner_connection"] = json!("mail_and_files");
        listing["hires_per_employer"] = json!("many");
        catalog(&core, &listing).await;
        Mock::given(method("GET"))
            .and(path(
                "/publishers/seren-agent/templates/alina-golub/hires/mine",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"data": [{"deployment_id": Uuid::new_v4(), "hire_name": "Other hire"}]}),
            ))
            .mount(&core)
            .await;
        let connection = Uuid::new_v4();
        Mock::given(method("POST")).and(path("/publishers/seren-agent/templates/alina-golub/deployments"))
            .and(body_partial_json(json!({"timezone": "UTC", "provider": "google", "oauth_connection_id": connection, "hire_name": "Research"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"data": {}}))).expect(1).mount(&core).await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        let response = server.dispatch_tool(HIRE, arguments(json!({"confirm": true, "timezone": "UTC", "provider": "google", "oauth_connection_id": connection, "hire_name": "Research"})), &extensions(false)).await.unwrap();
        assert!(response_text(response).starts_with("Hired."));
        let requests = core.received_requests().await.unwrap();
        let posted = requests
            .iter()
            .find(|request| request.method.as_str() == "POST")
            .unwrap();
        let payload: Value = serde_json::from_slice(&posted.body).unwrap();
        assert!(payload.get("confirm").is_none());
    }

    #[tokio::test]
    async fn hire_rejects_incompatible_listing_inputs_without_posts() {
        let core = MockServer::start().await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        for (connection, count, input) in [
            (
                "mail_and_files",
                "one",
                json!({"confirm": true, "timezone": "UTC"}),
            ),
            (
                "mail_read",
                "one",
                json!({"confirm": true, "timezone": "UTC", "provider": "google"}),
            ),
            (
                "sign_in_only",
                "one",
                json!({"confirm": true, "timezone": "UTC", "provider": "google"}),
            ),
            (
                "sign_in_only",
                "many",
                json!({"confirm": true, "timezone": "UTC"}),
            ),
            (
                "sign_in_only",
                "one",
                json!({"confirm": true, "timezone": "UTC", "hire_name": "Research"}),
            ),
        ] {
            let mut listing = listing();
            listing["owner_connection"] = json!(connection);
            listing["hires_per_employer"] = json!(count);
            assert!(
                server
                    .hire(
                        &listing,
                        &arguments(input),
                        "Bearer upstream-access",
                        &extensions(false)
                    )
                    .await
                    .is_err()
            );
        }
        assert_no_posts(&core).await;
    }

    #[tokio::test]
    async fn report_follows_message_cursor_across_task_and_reply_boundaries() {
        for task_on_first_page in [false, true] {
            let core = MockServer::start().await;
            let deployment_id = Uuid::new_v4();
            Mock::given(method("GET"))
                .and(path(
                    "/publishers/seren-agent/templates/alina-golub/hires/mine",
                ))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"data": [{"deployment_id": deployment_id}]})),
                )
                .mount(&core)
                .await;
            let asked = json!({"role": "user", "client_message_id": "requested-job"});
            let mut first_page: Vec<Value> = (0..200).map(|_| json!({"role": "user"})).collect();
            let mut second_page = vec![];
            if task_on_first_page {
                first_page[199] = asked;
            } else {
                second_page.push(asked);
            }
            second_page.push(json!({"role": "assistant", "content": "Completed report", "files": [], "run_summary": {"status": "completed"}}));
            let message_path = format!(
                "/publishers/seren-cloud/deployments/{deployment_id}/conversations/mcp/messages"
            );
            Mock::given(method("GET")).and(path(&message_path)).and(query_param("order", "asc"))
                .and(query_param("include_run", "false")).and(query_param_is_missing("cursor"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"messages": first_page, "has_more": true, "next_cursor": "cursor+/="}}))).expect(1).mount(&core).await;
            Mock::given(method("GET")).and(path(&message_path)).and(query_param("cursor", "cursor+/="))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"messages": second_page, "has_more": false, "next_cursor": null}}))).expect(1).mount(&core).await;
            let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
            let job = JobId {
                deployment_id,
                conversation_id: "mcp".to_string(),
                client_message_id: "requested-job".to_string(),
            };
            let response = server
                .get_report(
                    &listing(),
                    &arguments(json!({"job_id": job.encode()})),
                    "Bearer upstream-access",
                )
                .await
                .unwrap();
            assert_eq!(response_text(response), "Completed report");
        }
    }

    #[tokio::test]
    async fn report_refuses_a_job_from_another_hire() {
        let core = MockServer::start().await;
        mount_hires(&core, &[Uuid::new_v4()]).await;
        let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
        let job = JobId {
            deployment_id: Uuid::new_v4(),
            conversation_id: "mcp".to_string(),
            client_message_id: "job".to_string(),
        };
        let error = server
            .get_report(
                &listing(),
                &arguments(json!({"job_id": job.encode()})),
                "Bearer upstream-access",
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
        assert!(
            core.received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| !request.url.path().contains("/seren-cloud/"))
        );
    }

    #[tokio::test]
    async fn failed_job_report_keeps_her_reply() {
        async fn fetch_failed_report(
            messages: Vec<Value>,
            file: Option<(&str, &str, &[u8])>,
        ) -> Value {
            let core = MockServer::start().await;
            let deployment_id = Uuid::new_v4();
            mount_hires(&core, &[deployment_id]).await;
            let message_path = format!(
                "/publishers/seren-cloud/deployments/{deployment_id}/conversations/mcp/messages"
            );
            Mock::given(method("GET"))
                .and(path(&message_path))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "data": {"messages": messages, "has_more": false, "next_cursor": null}
                })))
                .expect(1)
                .mount(&core)
                .await;
            if let Some((file_id, content_type, bytes)) = file {
                Mock::given(method("GET"))
                    .and(path(format!(
                        "/publishers/seren-cloud/deployments/{deployment_id}/files/{file_id}/content"
                    )))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_raw(bytes.to_vec(), content_type),
                    )
                    .expect(1)
                    .mount(&core)
                    .await;
            }
            let server = ManagedAgentMcpServer::new(&core.uri(), reqwest::Client::new());
            let job = JobId {
                deployment_id,
                conversation_id: "mcp".to_string(),
                client_message_id: "failed-job".to_string(),
            };
            let CallToolResponse::Complete(result) = server
                .get_report(
                    &listing(),
                    &arguments(json!({"job_id": job.encode()})),
                    "Bearer upstream-access",
                )
                .await
                .unwrap()
            else {
                panic!("expected completed MCP result");
            };
            serde_json::to_value(result).unwrap()
        }

        let with_reply = fetch_failed_report(
            vec![
                json!({
                    "role": "user",
                    "client_message_id": "failed-job",
                    "content": "Write the memo.",
                    "run_summary": {"status": "failed", "status_message": "Run failed."}
                }),
                json!({
                    "role": "assistant",
                    "content": "PDF export failed.\n\nHere is the full memo.",
                    "files": [{"file_id": "file-1", "name": "memo.txt", "content_type": "text/plain"}],
                    "run_summary": {"status": "failed", "status_message": "Run failed."}
                }),
                json!({
                    "role": "assistant",
                    "content": "I've told Seren's team about this (report 12345678).",
                    "files": [],
                    "run_summary": null
                }),
            ],
            Some(("file-1", "text/plain", b"draft memo bytes")),
        )
        .await;
        assert_eq!(with_reply["isError"], json!(true));
        assert_eq!(with_reply["content"].as_array().unwrap().len(), 2);
        assert_eq!(
            with_reply["content"][0]["text"],
            json!(
                "PDF export failed.\n\nHere is the full memo.\n\nI've told Seren's team about this (report 12345678).\n\nRun failed."
            )
        );
        assert_eq!(with_reply["content"][1]["type"], json!("resource"));
        assert_eq!(
            with_reply["content"][1]["resource"]["uri"],
            json!("seren-file:///memo.txt")
        );
        assert_eq!(
            with_reply["content"][1]["resource"]["mimeType"],
            json!("text/plain")
        );
        assert_eq!(
            with_reply["content"][1]["resource"]["blob"],
            json!(BASE64.encode(b"draft memo bytes"))
        );

        let without_reply = fetch_failed_report(
            vec![json!({
                "role": "user",
                "client_message_id": "failed-job",
                "content": "Write the memo.",
                "run_summary": {"status": "failed", "status_message": "Run failed."}
            })],
            None,
        )
        .await;
        assert_eq!(without_reply["isError"], json!(true));
        assert_eq!(without_reply["content"].as_array().unwrap().len(), 1);
        assert_eq!(without_reply["content"][0]["text"], json!("Run failed."));

        let cancelled_after_reply = fetch_failed_report(
            vec![
                json!({"role": "user", "client_message_id": "failed-job"}),
                json!({
                    "role": "assistant",
                    "content": "Partial analysis.",
                    "files": [],
                    "run_summary": {"status": "cancelled", "status_message": "Run cancelled."}
                }),
                json!({"role": "assistant", "content": "   ", "files": [], "run_summary": null}),
                json!({
                    "role": "assistant",
                    "content": "I've told Seren's team.",
                    "files": [],
                    "run_summary": null
                }),
            ],
            None,
        )
        .await;
        assert_eq!(cancelled_after_reply["isError"], json!(true));
        assert_eq!(
            cancelled_after_reply["content"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            cancelled_after_reply["content"][0]["text"],
            json!("Partial analysis.\n\nI've told Seren's team.\n\nRun cancelled.")
        );

        let empty_reply = fetch_failed_report(
            vec![
                json!({"role": "user", "client_message_id": "failed-job"}),
                json!({
                    "role": "assistant",
                    "content": "",
                    "files": [],
                    "run_summary": {"status": "errored", "status_message": "Tool crashed."}
                }),
            ],
            None,
        )
        .await;
        assert_eq!(empty_reply["isError"], json!(true));
        assert_eq!(empty_reply["content"].as_array().unwrap().len(), 1);
        assert_eq!(empty_reply["content"][0]["text"], json!("Tool crashed."));
    }

    #[test]
    fn hiring_prices_distinguish_history_from_service_fees() {
        let mut listing = listing();
        listing["run_kinds"] = json!([
            {"charge": "fee", "name": "Research", "amount": {"atomic": 500000, "percent": null}},
            {"charge": "fee", "name": "Analysis", "amount": {"atomic": 0, "percent": 25}},
            {"charge": "cost"}
        ]);
        let text = not_hired_text(&listing);
        assert!(text.contains("Research: $0.500000 per task"));
        assert!(text.contains("Analysis: 25% of recorded running cost"));
        assert!(!text.contains("no fee"));
        listing["catalog"]["hourly_rate_atomic"] = json!(60000);
        let text = not_hired_text(&listing);
        assert!(text.contains("historical average is $0.06 per hour the Employee was hired"));
        assert!(text.contains("not per hour of task work or a guaranteed task price"));
    }
}
