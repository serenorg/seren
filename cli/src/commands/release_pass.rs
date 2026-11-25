use std::fmt;
use std::io::{self, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue};
use serde::Deserialize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat};

const ACTIONS_ID_TOKEN_REQUEST_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
const ACTIONS_ID_TOKEN_REQUEST_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
const SEREN_RELEASE_ID_TOKEN: &str = "SEREN_RELEASE_ID_TOKEN";
const SEREN_RELEASE_KEY: &str = "SEREN_RELEASE_KEY";

pub(crate) enum ReleaseProof {
    SignedRun(String),
    ReleaseKey(String),
    Session,
}

impl fmt::Debug for ReleaseProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignedRun(_) => f.debug_tuple("SignedRun").field(&"[redacted]").finish(),
            Self::ReleaseKey(_) => f.debug_tuple("ReleaseKey").field(&"[redacted]").finish(),
            Self::Session => f.write_str("Session"),
        }
    }
}

impl ReleaseProof {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::SignedRun(_) => "signed run",
            Self::ReleaseKey(_) => "release key",
            Self::Session => "signed-in session",
        }
    }
}

pub(crate) struct ReleasePassAnswer {
    pub(crate) response: seren::DataResponseManagedAgentReleasePass,
    pub(crate) proof_label: &'static str,
}

impl ReleasePassAnswer {
    pub(crate) fn pass(&self) -> &str {
        &self.response.data.pass
    }
}

impl fmt::Debug for ReleasePassAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleasePassAnswer")
            .field("pass", &"[redacted]")
            .field("expires_at", &self.response.data.expires_at)
            .field("release_source_id", &self.response.data.release_source_id)
            .field("templates", &self.response.data.templates)
            .field("proof_label", &self.proof_label)
            .finish()
    }
}

#[derive(Deserialize)]
struct GitHubIdTokenResponse {
    value: String,
}

#[derive(Deserialize)]
struct ErrorBody {
    message: Option<String>,
}

fn non_empty_env(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    env(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn unauthenticated_client(api_base: &str) -> Result<seren::Client> {
    let config = seren::ClientConfig::unauthenticated().with_base_url(api_base);
    seren::Client::from_config(&config)
        .map_err(|error| anyhow::anyhow!("Failed to create API client: {error}"))
}

fn truncate_body(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

pub(crate) async fn refusal_error(context: &str, error: seren::Error<()>) -> anyhow::Error {
    match error {
        seren::Error::UnexpectedResponse(response) if !response.status().is_success() => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if let Ok(parsed) = serde_json::from_str::<ErrorBody>(&body)
                && let Some(message) = parsed.message.map(|value| value.trim().to_string())
                && !message.is_empty()
            {
                return anyhow::anyhow!("{message}");
            }
            let trimmed = body.trim();
            if trimmed.is_empty() {
                anyhow::anyhow!("{context}: unexpected response {status}")
            } else {
                anyhow::anyhow!(
                    "{context}: unexpected response {status} - {}",
                    truncate_body(trimmed, 1200)
                )
            }
        }
        other => super::agent::anyhow_from_seren_error(context, other).await,
    }
}

pub(crate) async fn find_proof(
    env: &dyn Fn(&str) -> Option<String>,
    http: &reqwest::Client,
    audience: &str,
) -> Result<ReleaseProof> {
    if let (Some(request_url), Some(request_token)) = (
        non_empty_env(env, ACTIONS_ID_TOKEN_REQUEST_URL),
        non_empty_env(env, ACTIONS_ID_TOKEN_REQUEST_TOKEN),
    ) {
        let mut url =
            url::Url::parse(&request_url).context("Invalid ACTIONS_ID_TOKEN_REQUEST_URL")?;
        url.query_pairs_mut().append_pair("audience", audience);
        let auth_header = HeaderValue::from_str(&format!("bearer {request_token}"))
            .map_err(|_| anyhow::anyhow!("Invalid ACTIONS_ID_TOKEN_REQUEST_TOKEN value"))?;
        let response = http
            .get(url)
            .header(AUTHORIZATION, auth_header)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .context("Failed to request signed run token from GitHub Actions")?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!(
                "GitHub Actions did not issue a signed run token (HTTP {status}). Ensure the job grants `id-token: write`."
            );
        }
        let body: GitHubIdTokenResponse = response
            .json()
            .await
            .context("Invalid signed run token response from GitHub Actions")?;
        let token = body.value.trim().to_string();
        if token.is_empty() {
            anyhow::bail!("GitHub Actions returned an empty signed run token.");
        }
        return Ok(ReleaseProof::SignedRun(token));
    }

    if let Some(token) = non_empty_env(env, SEREN_RELEASE_ID_TOKEN) {
        return Ok(ReleaseProof::SignedRun(token));
    }

    if let Some(key) = non_empty_env(env, SEREN_RELEASE_KEY) {
        return Ok(ReleaseProof::ReleaseKey(key));
    }

    Ok(ReleaseProof::Session)
}

pub(crate) async fn release_pass(
    ctx: &CommandContext,
    organization_id: Uuid,
) -> Result<ReleasePassAnswer> {
    release_pass_with_env(ctx, organization_id, &|name| std::env::var(name).ok()).await
}

pub(crate) async fn release_pass_with_env(
    ctx: &CommandContext,
    organization_id: Uuid,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<ReleasePassAnswer> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to create HTTP client")?;
    let audience = ctx.api_base();
    let proof = find_proof(env, &http, &audience).await?;
    let proof_label = proof.label();

    let (client, request) = match proof {
        ReleaseProof::SignedRun(token) => (
            unauthenticated_client(&audience)?,
            seren::CreateManagedAgentReleasePassRequest::SignedRun { token },
        ),
        ReleaseProof::ReleaseKey(key) => (
            unauthenticated_client(&audience)?,
            seren::CreateManagedAgentReleasePassRequest::ReleaseKey { key },
        ),
        ReleaseProof::Session => {
            ctx.require_user_session("Releasing in person").await?;
            (
                ctx.client().await?,
                seren::CreateManagedAgentReleasePassRequest::Session,
            )
        }
    };

    let response = match client
        .create_managed_agent_release_pass(&organization_id, &request)
        .await
    {
        Ok(response) => response.into_inner(),
        Err(error) => return Err(refusal_error("Failed to get a release pass", error).await),
    };

    Ok(ReleasePassAnswer {
        response,
        proof_label,
    })
}

fn write_output(
    answer: &ReleasePassAnswer,
    format: OutputFormat,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<()> {
    writeln!(stderr, "Using {} proof.", answer.proof_label)?;
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&answer.response)?;
            writeln!(stdout, "{json}")?;
        }
        OutputFormat::Table => writeln!(stdout, "{}", answer.pass())?,
    }
    Ok(())
}

pub(crate) async fn execute(organization_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let answer = release_pass(ctx, organization_id).await?;
    write_output(&answer, ctx.format, &mut io::stdout(), &mut io::stderr())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use clap::Parser;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::commands::managed::ManagedAction;

    #[derive(Parser)]
    struct ManagedCli {
        #[command(subcommand)]
        action: ManagedAction,
    }

    #[tokio::test]
    async fn the_cli_presents_the_first_proof_it_finds() {
        let organization_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let pass_route = format!("/organizations/{organization_id}/release-passes");

        let parsed = ManagedCli::try_parse_from([
            "agent",
            "managed-release-pass",
            &organization_id.to_string(),
        ])
        .unwrap();
        assert!(matches!(
            parsed.action,
            ManagedAction::ManagedReleasePass { organization_id: id } if id == organization_id
        ));

        // 1. GitHub Actions variables take precedence over every other proof,
        // request GitHub's token with the API base audience, and post `signed_run`
        // without an Authorization header.
        let oidc_server = MockServer::start().await;
        let api_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/idtoken"))
            .and(query_param("api-version", "2.0"))
            .and(query_param("audience", api_server.uri()))
            .and(header("authorization", "bearer synthetic-request-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"value": "synthetic-github-jwt"})),
            )
            .expect(1)
            .mount(&oidc_server)
            .await;
        Mock::given(method("POST"))
            .and(path(&pass_route))
            .and(body_json(json!({
                "proof": "signed_run",
                "token": "synthetic-github-jwt",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "pass": "serenpass_from_github",
                    "expires_at": "2026-11-25T10:00:00Z",
                    "release_source_id": source_id,
                    "templates": ["analyst"]
                }
            })))
            .expect(1)
            .mount(&api_server)
            .await;

        let mut env = HashMap::from([
            (
                ACTIONS_ID_TOKEN_REQUEST_URL,
                format!("{}/idtoken?api-version=2.0", oidc_server.uri()),
            ),
            (
                ACTIONS_ID_TOKEN_REQUEST_TOKEN,
                "synthetic-request-token".to_string(),
            ),
            (SEREN_RELEASE_ID_TOKEN, "synthetic-ci-token".to_string()),
            (SEREN_RELEASE_KEY, "serenrk_synthetic_unused".to_string()),
        ]);
        let ctx = CommandContext::new(
            Some(api_server.uri()),
            Some("seren_unused_api_key".into()),
            OutputFormat::Table,
        );
        let github_answer =
            release_pass_with_env(&ctx, organization_id, &|name| env.get(name).cloned())
                .await
                .unwrap();
        assert_eq!(github_answer.pass(), "serenpass_from_github");
        assert_eq!(github_answer.proof_label, "signed run");
        assert_eq!(
            github_answer.response.data.release_source_id,
            Some(source_id)
        );
        assert_eq!(
            github_answer.response.data.templates,
            Some(vec!["analyst".to_string()])
        );
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        write_output(
            &github_answer,
            OutputFormat::Table,
            &mut stdout,
            &mut stderr,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            "serenpass_from_github\n"
        );
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "Using signed run proof.\n"
        );
        let requests = api_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("authorization"),
            "signed_run pass exchange must not send an Authorization header"
        );
        oidc_server.verify().await;
        api_server.verify().await;

        // 2. Without GitHub variables, SEREN_RELEASE_ID_TOKEN wins over SEREN_RELEASE_KEY
        // and sends no Authorization header.
        let id_token_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(&pass_route))
            .and(body_json(json!({
                "proof": "signed_run",
                "token": "synthetic-ci-token",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "pass": "serenpass_from_ci_env",
                    "expires_at": "2026-11-25T10:00:00Z",
                    "release_source_id": source_id,
                    "templates": ["analyst"]
                }
            })))
            .expect(1)
            .mount(&id_token_server)
            .await;
        env.remove(ACTIONS_ID_TOKEN_REQUEST_URL);
        env.remove(ACTIONS_ID_TOKEN_REQUEST_TOKEN);
        let id_token_ctx = CommandContext::new(
            Some(id_token_server.uri()),
            Some("seren_unused_api_key".into()),
            OutputFormat::Table,
        );
        let id_token_answer = release_pass_with_env(&id_token_ctx, organization_id, &|name| {
            env.get(name).cloned()
        })
        .await
        .unwrap();
        assert_eq!(id_token_answer.pass(), "serenpass_from_ci_env");
        assert_eq!(id_token_answer.proof_label, "signed run");
        let requests = id_token_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("authorization"),
            "SEREN_RELEASE_ID_TOKEN pass exchange must not send an Authorization header"
        );
        id_token_server.verify().await;

        // 3. With only SEREN_RELEASE_KEY, the CLI posts `release_key` and sends no Authorization header.
        let key_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(&pass_route))
            .and(body_json(json!({
                "proof": "release_key",
                "key": "serenrk_synthetic_key",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "pass": "serenpass_from_key",
                    "expires_at": "2026-11-25T10:00:00Z",
                    "release_source_id": source_id,
                    "templates": ["analyst"]
                }
            })))
            .expect(1)
            .mount(&key_server)
            .await;
        let key_env = HashMap::from([(SEREN_RELEASE_KEY, "serenrk_synthetic_key".to_string())]);
        let key_ctx = CommandContext::new(
            Some(key_server.uri()),
            Some("seren_unused_api_key".into()),
            OutputFormat::Json,
        );
        let key_answer = release_pass_with_env(&key_ctx, organization_id, &|name| {
            key_env.get(name).cloned()
        })
        .await
        .unwrap();
        assert_eq!(key_answer.pass(), "serenpass_from_key");
        assert_eq!(key_answer.proof_label, "release key");
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        write_output(&key_answer, OutputFormat::Json, &mut stdout, &mut stderr).unwrap();
        let json_out: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(json_out["data"]["pass"], "serenpass_from_key");
        assert_eq!(json_out["data"]["release_source_id"], source_id.to_string());
        assert_eq!(json_out["data"]["templates"], json!(["analyst"]));
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "Using release key proof.\n"
        );
        let requests = key_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("authorization"),
            "release_key pass exchange must not send an Authorization header"
        );
        key_server.verify().await;

        // 4. With no environment proof, Session rejects API keys locally and sends Bearer for a session.
        let session_server = MockServer::start().await;
        let empty_env: HashMap<&str, String> = HashMap::new();
        let api_key_ctx = CommandContext::new(
            Some(session_server.uri()),
            Some("seren_personal_api_key".into()),
            OutputFormat::Table,
        );
        let api_key_err = release_pass_with_env(&api_key_ctx, organization_id, &|name| {
            empty_env.get(name).cloned()
        })
        .await
        .unwrap_err();
        assert!(
            api_key_err
                .to_string()
                .contains("interactive OAuth user session"),
            "unexpected error: {api_key_err}"
        );
        assert!(session_server.received_requests().await.unwrap().is_empty());

        Mock::given(method("POST"))
            .and(path(&pass_route))
            .and(header("authorization", "Bearer synthetic-oauth-session"))
            .and(body_json(json!({"proof": "session"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "pass": "serenpass_in_person",
                    "expires_at": "2026-11-25T10:00:00Z"
                }
            })))
            .expect(1)
            .mount(&session_server)
            .await;
        let session_ctx = CommandContext::new(
            Some(session_server.uri()),
            Some("synthetic-oauth-session".into()),
            OutputFormat::Table,
        );
        let session_answer = release_pass_with_env(&session_ctx, organization_id, &|name| {
            empty_env.get(name).cloned()
        })
        .await
        .unwrap();
        assert_eq!(session_answer.pass(), "serenpass_in_person");
        assert_eq!(session_answer.proof_label, "signed-in session");
        assert!(session_answer.response.data.release_source_id.is_none());
        session_server.verify().await;

        // 5. A refusal surfaces the server's plain message.
        let refusal_server = MockServer::start().await;
        let expected_message =
            "This release key expired on 2026-11-20. An Owner or Admin can create a new one.";
        Mock::given(method("POST"))
            .and(path(&pass_route))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": "release_key_expired",
                "message": expected_message,
            })))
            .expect(1)
            .mount(&refusal_server)
            .await;
        let refusal_ctx =
            CommandContext::new(Some(refusal_server.uri()), None, OutputFormat::Table);
        let refusal_err = release_pass_with_env(&refusal_ctx, organization_id, &|name| {
            key_env.get(name).cloned()
        })
        .await
        .unwrap_err();
        assert_eq!(refusal_err.to_string(), expected_message);
        refusal_server.verify().await;
    }
}
