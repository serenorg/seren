//! Each listed Employee's own MCP address: `/employees/{page_slug}`.
//!
//! The server keeps no state between requests (production runs several
//! replicas): the job number a task returns carries everything needed to read
//! its report back.

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
use serde_json::{Value, json};
use uuid::Uuid;

/// Path prefix of every Employee's MCP address.
pub(crate) const EMPLOYEE_PATH_PREFIX: &str = "/employees/";

/// JSON-RPC error code for an address with no listed Employee.
pub(crate) const NO_EMPLOYEE_CODE: i32 = -32004;
const NO_EMPLOYEE_MESSAGE: &str = "No Employee at this address.";

const AGENT_PUBLISHER: &str = "publishers/seren-agent";
const CLOUD_PUBLISHER: &str = "publishers/seren-cloud";
/// Name of the conversation an MCP caller's tasks run in.
const MCP_CONVERSATION: &str = "mcp";

const GIVE_TASK: &str = "give_task";
const GET_REPORT: &str = "get_report";
const HIRE: &str = "hire";

/// The Employee's page slug when `path` is a single-segment Employee address.
pub(crate) fn employee_page_slug_from_path(path: &str) -> Option<&str> {
    let slug = path.strip_prefix(EMPLOYEE_PATH_PREFIX)?;
    let valid = !slug.is_empty()
        && slug.len() <= 128
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    valid.then_some(slug)
}

fn no_employee() -> McpError {
    McpError::new(ErrorCode(NO_EMPLOYEE_CODE), NO_EMPLOYEE_MESSAGE, None)
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
    let cents = (atomic + 5_000) / 10_000;
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

fn subject_pronoun(listing: &Value) -> &'static str {
    match listing.get("pronouns").and_then(Value::as_str) {
        Some("he/him") => "He",
        Some("they/them") => "They",
        _ => "She",
    }
}

/// The text a caller sees when they haven't hired the Employee yet.
pub(crate) fn not_hired_text(listing: &Value) -> String {
    let name = listing
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or("This Employee");
    let who = match listing.get("job_title").and_then(Value::as_str) {
        Some(title) if !title.trim().is_empty() => format!("{name}, {title}"),
        _ => name.to_string(),
    };
    let pronoun = subject_pronoun(listing);
    let costs = if pronoun == "They" { "cost" } else { "costs" };
    let rate = listing
        .pointer("/catalog/hourly_rate_atomic")
        .and_then(Value::as_i64)
        .filter(|atomic| *atomic > 0);
    let price = match rate {
        Some(atomic) => format!("{} per hour of work", format_hourly_rate(atomic)),
        None => "her running cost, with no fee, per hour of work".to_string(),
    };
    format!(
        "You haven't hired {who}. {pronoun} {costs} {price}. Say yes to hire her, and I'll start this task."
    )
}

/// One Employee's MCP server, built per request from the catalog.
#[derive(Clone)]
pub(crate) struct EmployeeMcpServer {
    api_base_url: String,
    http: reqwest::Client,
}

impl EmployeeMcpServer {
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
            .and_then(|parts| employee_page_slug_from_path(parts.uri.path()))
            .map(str::to_string)
            .ok_or_else(no_employee)
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

    /// The listed Employee at this address.
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
            .ok_or_else(no_employee)
    }

    fn template_slug(listing: &Value) -> Result<&str, McpError> {
        listing
            .get("slug")
            .and_then(Value::as_str)
            .ok_or_else(no_employee)
    }

    /// The caller's live hires of this Employee, newest first as Core lists them.
    async fn my_hires(&self, listing: &Value, bearer: &str) -> Result<Vec<Uuid>, McpError> {
        let slug = Self::template_slug(listing)?;
        let hires = self
            .get_json(
                &format!("{AGENT_PUBLISHER}/templates/{slug}/hires/mine"),
                bearer,
            )
            .await?;
        Ok(hires
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|hire| hire.get("deployment_id").and_then(Value::as_str))
            .filter_map(|id| id.parse().ok())
            .collect())
    }

    pub(crate) fn tools(listing: &Value) -> Vec<Tool> {
        let name = listing
            .get("display_name")
            .and_then(Value::as_str)
            .unwrap_or("this Employee");
        let mut tools = vec![
            Tool::new(
                GIVE_TASK,
                format!("Give {name} a task in plain words. Returns a job number to fetch her report with get_report."),
                object_schema(json!({
                    "type": "object",
                    "properties": {"text": {"type": "string", "description": "The task, as you would say it to her."}},
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
                format!("Hire {name}. Call only after the user says yes to her price."),
                object_schema(json!({
                    "type": "object",
                    "properties": {
                        "timezone": {"type": "string", "description": "The user's IANA timezone, such as America/Los_Angeles."},
                        "confirm": {"type": "boolean", "description": "True once the user has said yes to hiring her."}
                    },
                    "required": ["timezone", "confirm"],
                })),
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
            if [GIVE_TASK, GET_REPORT, HIRE].contains(&tool_name) {
                continue;
            }
            let description = tool
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let schema = object_schema(tool.get("input_schema").cloned().unwrap_or(Value::Null));
            let mut built = Tool::new(tool_name.to_string(), description, schema);
            if let Some(title) = tool.get("title").and_then(Value::as_str) {
                built = built.with_title(title);
            }
            tools.push(built);
        }
        tools
    }

    async fn hire(
        &self,
        listing: &Value,
        arguments: &JsonObject,
        bearer: &str,
    ) -> Result<CallToolResponse, McpError> {
        if arguments.get("confirm").and_then(Value::as_bool) != Some(true) {
            return Ok(text_result(not_hired_text(listing)));
        }
        let timezone = arguments
            .get("timezone")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|tz| !tz.is_empty())
            .ok_or_else(|| McpError::invalid_params("timezone is required", None))?;
        if !self.my_hires(listing, bearer).await?.is_empty() {
            return Ok(text_result("Hired. Ask again and I'll start."));
        }
        let slug = Self::template_slug(listing)?;
        let (status, body) = self
            .post_json(
                &format!("{AGENT_PUBLISHER}/templates/{slug}/deployments"),
                json!({ "timezone": timezone }),
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
            ContentBlock::text(format!("Seren couldn't hire her: {}", error_text(&body))),
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
                "Seren couldn't open her conversation: {}",
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
                "Seren couldn't send her the task: {}",
                error_text(&posted)
            )));
        }
        let job = JobId {
            deployment_id,
            conversation_id,
            client_message_id,
        };
        Ok(text_result(format!(
            "Started. Job {}. Ask for the report in a minute or two.",
            job.encode()
        )))
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
            .contains(&job.deployment_id)
        {
            return Err(refused());
        }
        let conversation = urlencode(&job.conversation_id);
        let page = self
            .get_json(
                &format!(
                    "{CLOUD_PUBLISHER}/deployments/{}/conversations/{conversation}/messages?order=asc&limit=200&include_run=false",
                    job.deployment_id
                ),
                bearer,
            )
            .await?;
        let page = page.get("data").unwrap_or(&page);
        let messages: Vec<&Value> = page
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .collect();
        let Some(asked) = messages.iter().position(|message| {
            message.get("client_message_id").and_then(Value::as_str)
                == Some(job.client_message_id.as_str())
        }) else {
            return Ok(text_result("Still working."));
        };
        let replies: Vec<&Value> = messages[asked + 1..]
            .iter()
            .copied()
            .take_while(|message| message.get("role").and_then(Value::as_str) != Some("user"))
            .filter(|message| message.get("role").and_then(Value::as_str) == Some("assistant"))
            .collect();
        let failure = |message: &Value| -> Option<String> {
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
                    .or_else(|| message.get("content").and_then(Value::as_str))
                    .filter(|text| !text.trim().is_empty())
                    .unwrap_or("The task failed.")
                    .to_string()
            })
        };
        if let Some(error) = failure(messages[asked]) {
            return Ok(CallToolResponse::Complete(CallToolResult::error(vec![
                ContentBlock::text(error),
            ])));
        }
        let Some(reply) = replies.last() else {
            return Ok(text_result("Still working."));
        };
        if let Some(error) = failure(reply) {
            return Ok(CallToolResponse::Complete(CallToolResult::error(vec![
                ContentBlock::text(error),
            ])));
        }
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
        for file in reply
            .get("files")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(file_id) = file.get("file_id").and_then(Value::as_str) else {
                continue;
            };
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
                    "Seren answered {} for her file {name}",
                    response.status()
                )));
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|error| core_error(format!("Her file {name} was cut off: {error}")))?;
            content.push(ContentBlock::resource(
                ResourceContents::blob(BASE64.encode(&bytes), format!("seren-file:///{name}"))
                    .with_mime_type(content_type),
            ));
        }
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

impl ServerHandler for EmployeeMcpServer {
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let page_slug = Self::page_slug(&context.extensions)?;
        let bearer = Self::bearer(&context.extensions)?;
        let listing = self.listing(&page_slug, &bearer).await?;
        Ok(ListToolsResult::with_all_items(Self::tools(&listing)))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let page_slug = Self::page_slug(&context.extensions)?;
        let bearer = Self::bearer(&context.extensions)?;
        let listing = self.listing(&page_slug, &bearer).await?;
        let arguments = request.arguments.clone().unwrap_or_default();
        let tool_name = request.name.as_ref();
        match tool_name {
            HIRE => return self.hire(&listing, &arguments, &bearer).await,
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
            let template = listing
                .get("mcp_tools")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find(|tool| tool.get("name").and_then(Value::as_str) == Some(tool_name))
                .and_then(|tool| tool.get("message").and_then(Value::as_str))
                .ok_or_else(|| {
                    McpError::invalid_params(format!("Unknown tool: {tool_name}"), None)
                })?;
            render_message(template, &arguments)
        };
        let Some(deployment_id) = self.my_hires(&listing, &bearer).await?.into_iter().next() else {
            return Ok(text_result(not_hired_text(&listing)));
        };
        self.start_work(deployment_id, message, &bearer).await
    }

    fn get_info(&self) -> ServerConfig {
        let server_info =
            rmcp::model::Implementation::new(crate::MCP_SERVER_NAME, env!("CARGO_PKG_VERSION"))
                .with_title("Seren Employee")
                .with_website_url("https://serendb.com");
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(server_info)
            .with_instructions(
                "Give this Seren Employee a task with give_task or one of her own tools, then fetch the report with get_report and the job number. If you haven't hired her, she tells you her price; hire her with hire once the user says yes.",
            )
    }
}
