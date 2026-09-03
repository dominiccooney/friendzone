//! MCP forwarding: the broker is an MCP server toward containers and an
//! MCP client toward upstream. Terminates, never tunnels: the container
//! session is answered locally, only tools/list and tools/call are
//! reconstructed upstream, and the bearer token (from a host env var)
//! never enters the container. One resolver (`Forward::allows`) computes
//! both the filtered tools/list and each tools/call verdict.

use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::state::{AppState, Verdict};

pub const PROTOCOL_VERSION: &str = "2025-03-26";

#[derive(Clone, Debug, Deserialize)]
pub struct ForwardConfig {
    /// Path segment containers address: POST /mcp/{name}.
    pub name: String,
    /// Upstream streamable-HTTP endpoint, e.g. https://mcp.linear.app/mcp
    pub url: String,
    /// Host env var holding the bearer token (API key or OAuth token).
    pub bearer_env: String,
    /// OAuth scope to request, e.g. "read" for Linear read-only.
    #[serde(default)]
    pub scope: Option<String>,
    /// Tool allowlist; list-filtering and call-checking share it.
    pub tools: Vec<String>,
}

/// Where MCP forwards are configured, for display to the user.
pub fn forwards_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("mcp-forwards.json")
}

/// Loads mcp-forwards.json from the data dir; absent file means none.
pub fn load_forwards(data_dir: &Path) -> Result<Vec<ForwardConfig>> {
    let path = forwards_path(data_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

pub struct Forward {
    config: ForwardConfig,
    settings: crate::settings::Settings,
    /// Upstream Mcp-Session-Id once initialized.
    session: Mutex<Option<String>>,
    client: reqwest::Client,
}

impl Forward {
    pub fn new(config: ForwardConfig, settings: crate::settings::Settings) -> Self {
        Self {
            config,
            settings,
            session: Mutex::new(None),
            client: reqwest::Client::new(),
        }
    }

    /// The single policy resolver: tools/list filtering and tools/call
    /// authorization both call this, so they cannot diverge.
    pub fn allows(&self, tool: &str) -> bool {
        self.config.tools.iter().any(|t| t == tool)
    }

    /// Removes disallowed tools from an upstream tools/list result.
    pub fn filter_list_result(&self, result: &mut Value) {
        if let Some(tools) = result.get_mut("tools").and_then(Value::as_array_mut) {
            tools.retain(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| self.allows(name))
            });
        }
    }

    /// Bearer resolution: OAuth session (refreshed just-in-time when
    /// near expiry) first, plain stored secret next, env var last.
    async fn bearer(&self) -> Result<String> {
        if let Some(record) = crate::oauth::TokenRecord::load(&self.settings, &self.config.name) {
            if record.expires_soon() && record.refresh_token.is_some() {
                match crate::oauth::refresh(&self.settings, &self.config.name).await {
                    Ok(token) => return Ok(token),
                    Err(error) => {
                        tracing::warn!(%error, forward = %self.config.name, "token refresh failed");
                    }
                }
            }
            return Ok(record.access_token);
        }
        if let Some(token) = self.settings.secret(&format!("mcp:{}", self.config.name)) {
            return Ok(token);
        }
        std::env::var(&self.config.bearer_env).with_context(|| {
            format!(
                "MCP forward '{}': no OAuth session, stored token, or env var {} (connect it in settings)",
                self.config.name, self.config.bearer_env
            )
        })
    }
}

impl Forward {
    /// Sends one JSON-RPC message upstream, initializing the session on
    /// first use. Returns the parsed JSON-RPC response.
    pub async fn call_upstream(&self, message: Value) -> Result<Value> {
        let mut session = self.session.lock().await;
        if session.is_none() {
            *session = Some(self.initialize_upstream().await?);
        }
        let session_id = session.clone().expect("session just initialized");
        drop(session);
        self.post(message, Some(&session_id)).await
    }

    async fn initialize_upstream(&self) -> Result<String> {
        let init = json!({
            "jsonrpc": "2.0",
            "id": "fz-init",
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "friendzone-broker", "version": env!("CARGO_PKG_VERSION")}
            }
        });
        let response = self
            .client
            .post(&self.config.url)
            .bearer_auth(self.bearer().await?)
            .header("Accept", "application/json, text/event-stream")
            .json(&init)
            .send()
            .await
            .context("upstream initialize")?;
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        parse_body(response).await.context("initialize response")?;
        let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        self.post_raw(initialized, Some(&session_id))
            .await
            .context("upstream initialized notification")?;
        Ok(session_id)
    }

    async fn post(&self, message: Value, session_id: Option<&str>) -> Result<Value> {
        let response = self.post_raw(message, session_id).await?;
        parse_body(response).await
    }

    async fn post_raw(
        &self,
        message: Value,
        session_id: Option<&str>,
    ) -> Result<reqwest::Response> {
        let response = self
            .post_once(&message, session_id, self.bearer().await?)
            .await?;
        // Expired-token 401: refresh once and retry, so agents never
        // see a reauth seam.
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            && let Ok(token) = crate::oauth::refresh(&self.settings, &self.config.name).await
        {
            return self.post_once(&message, session_id, token).await;
        }
        Ok(response)
    }

    async fn post_once(
        &self,
        message: &Value,
        session_id: Option<&str>,
        bearer: String,
    ) -> Result<reqwest::Response> {
        let mut request = self
            .client
            .post(&self.config.url)
            .bearer_auth(bearer)
            .header("Accept", "application/json, text/event-stream")
            .json(message);
        if let Some(id) = session_id.filter(|id| !id.is_empty()) {
            request = request.header("Mcp-Session-Id", id);
        }
        request.send().await.context("upstream MCP request")
    }
}

/// Streamable HTTP responses are plain JSON or an SSE stream whose final
/// data line carries the JSON-RPC response.
async fn parse_body(response: reqwest::Response) -> Result<Value> {
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let status = response.status();
    let text = response.text().await.context("read upstream body")?;
    if !status.is_success() {
        anyhow::bail!("upstream returned {status}: {text}");
    }
    if content_type.starts_with("text/event-stream") {
        let last = text
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
            .next_back();
        last.context("no JSON-RPC message in SSE response")
    } else if text.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_str(&text).context("parse upstream JSON")
    }
}

#[derive(Clone)]
pub struct McpState {
    pub app: AppState,
    pub forwards: Arc<HashMap<String, Arc<Forward>>>,
}

impl McpState {
    pub fn new(
        app: AppState,
        configs: Vec<ForwardConfig>,
        settings: crate::settings::Settings,
    ) -> Self {
        let forwards = configs
            .into_iter()
            .map(|config| {
                (
                    config.name.clone(),
                    Arc::new(Forward::new(config, settings.clone())),
                )
            })
            .collect();
        Self {
            app,
            forwards: Arc::new(forwards),
        }
    }
}

/// Handles one container-side JSON-RPC message for the named forward.
/// The container session is terminated here: initialize is answered
/// locally, only tools/list and tools/call are reconstructed upstream.
pub async fn handle_message(state: &McpState, name: &str, container: &str, message: Value) -> Value {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(forward) = state.forwards.get(name) else {
        return error_response(id, -32601, &format!("unknown MCP forward '{name}'"));
    };
    if state.app.is_killed(container) {
        return error_response(id, -32000, "container is killed");
    }
    let (verdict, response) = dispatch(forward, &method, id, &message).await;
    state.app.record(
        container.to_owned(),
        format!("MCP {method}"),
        format!("mcp:{name}"),
        verdict,
    );
    response
}

async fn dispatch(
    forward: &Forward,
    method: &str,
    id: Value,
    message: &Value,
) -> (Verdict, Value) {
    match method {
        "initialize" => (
            Verdict::Allowed,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "friendzone", "version": env!("CARGO_PKG_VERSION")}
                }
            }),
        ),
        "notifications/initialized" | "notifications/cancelled" => (Verdict::Allowed, Value::Null),
        "ping" => (
            Verdict::Allowed,
            json!({"jsonrpc": "2.0", "id": id, "result": {}}),
        ),
        "tools/list" => match forward.call_upstream(message.clone()).await {
            Ok(mut response) => {
                if let Some(result) = response.get_mut("result") {
                    forward.filter_list_result(result);
                }
                (Verdict::Allowed, response)
            }
            Err(error) => (
                Verdict::Blocked,
                error_response(id, -32603, &format!("upstream: {error:#}")),
            ),
        },
        "tools/call" => {
            let tool = message
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !forward.allows(tool) {
                return (
                    Verdict::Blocked,
                    error_response(id, -32602, &format!("tool '{tool}' is not forwarded")),
                );
            }
            match forward.call_upstream(message.clone()).await {
                Ok(response) => (Verdict::Allowed, response),
                Err(error) => (
                    Verdict::Blocked,
                    error_response(id, -32603, &format!("upstream: {error:#}")),
                ),
            }
        }
        other => (
            Verdict::Blocked,
            error_response(id, -32601, &format!("method '{other}' is not forwarded")),
        ),
    }
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear_forward() -> Forward {
        let dir = std::env::temp_dir().join(format!("fz-mcp-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        Forward::new(
            ForwardConfig {
                name: "linear".into(),
                url: "https://mcp.example.test/mcp".into(),
                bearer_env: "FZ_TEST_UNSET".into(),
                scope: None,
                tools: vec!["list_issues".into(), "get_issue".into()],
            },
            settings,
        )
    }

    #[test]
    fn one_resolver_filters_list_and_gates_calls() {
        let forward = linear_forward();
        // Same resolver: what filter removes, allows() rejects.
        let mut result = json!({"tools": [
            {"name": "list_issues"},
            {"name": "create_issue"},
        ]});
        forward.filter_list_result(&mut result);
        let listed: Vec<&str> = result["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(listed, ["list_issues"]);
        assert!(forward.allows("list_issues"));
        assert!(!forward.allows("create_issue"));
    }

    #[tokio::test]
    async fn disallowed_tool_call_is_rejected_before_upstream() {
        // bearer_env is unset and the URL unroutable: reaching upstream
        // would fail loudly, proving rejection happens first.
        let forward = linear_forward();
        let message = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "create_issue", "arguments": {}}
        });
        let (verdict, response) =
            dispatch(&forward, "tools/call", json!(1), &message).await;
        assert!(matches!(verdict, Verdict::Blocked));
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not forwarded")
        );
    }

    #[tokio::test]
    async fn unknown_methods_are_not_forwarded() {
        let forward = linear_forward();
        let message = json!({"jsonrpc": "2.0", "id": 2, "method": "resources/list"});
        let (verdict, response) =
            dispatch(&forward, "resources/list", json!(2), &message).await;
        assert!(matches!(verdict, Verdict::Blocked));
        assert_eq!(response["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn initialize_is_answered_locally() {
        let forward = linear_forward();
        let message = json!({"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}});
        let (verdict, response) = dispatch(&forward, "initialize", json!(3), &message).await;
        assert!(matches!(verdict, Verdict::Allowed));
        assert_eq!(response["result"]["serverInfo"]["name"], "friendzone");
    }
}
