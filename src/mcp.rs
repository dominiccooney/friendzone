//! MCP forwarding: the broker is an MCP server toward containers and an
//! MCP client toward upstream. Terminates, never tunnels: the container
//! session is answered locally, only tools/list and tools/call are
//! reconstructed upstream, and the bearer token (from a host env var)
//! never enters the container. One resolver (`Forward::allows`) computes
//! both the filtered tools/list and each tools/call verdict.

use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::state::{AppState, Verdict};

pub const PROTOCOL_VERSION: &str = "2025-03-26";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// Path segment containers address: POST /mcp/{name}.
    pub name: String,
    /// Upstream streamable-HTTP endpoint, e.g. https://mcp.linear.app/mcp
    pub url: String,
    /// Host env var holding the bearer token (API key or OAuth token).
    #[serde(default)]
    pub bearer_env: String,
    /// OAuth scope to request, e.g. "read" for Linear read-only.
    #[serde(default)]
    pub scope: Option<String>,
    /// Tool allowlist; list-filtering and call-checking share it.
    pub tools: Vec<String>,
    /// None preserves legacy all-approved-guests behavior; [] denies all.
    #[serde(default)]
    pub guests: Option<Vec<String>>,
    /// Read-only link to a host Cline server; credentials are never copied.
    #[serde(default)]
    pub cline: Option<crate::mcp_import::ClineSource>,
    /// Explicit broker-owned OAuth. Cline is provenance only in this mode;
    /// its credentials are never read or used as fallback.
    #[serde(default)]
    pub oauth: bool,
}

pub fn validate_configs(configs: &[ForwardConfig]) -> Result<()> {
    let mut names = std::collections::HashSet::new();
    for config in configs {
        if config.name.is_empty()
            || !config
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            anyhow::bail!("forward names must contain only letters, digits, '-' or '_'");
        }
        if !names.insert(&config.name) {
            anyhow::bail!("duplicate MCP forward '{}'", config.name);
        }
        let url = reqwest::Url::parse(&config.url).context("invalid MCP URL")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            anyhow::bail!("MCP URL must be HTTP(S) without embedded credentials or fragment");
        }
        if config.tools.iter().any(|t| t.is_empty())
            || config
                .guests
                .as_ref()
                .is_some_and(|g| g.iter().any(|n| n.is_empty()))
        {
            anyhow::bail!("tool and guest names must not be empty");
        }
        if let Some(source) = &config.cline {
            if !Path::new(&source.path).is_absolute() || source.server.is_empty() {
                anyhow::bail!("Cline link requires an absolute host path and server name");
            }
            if !config.oauth && (!config.bearer_env.is_empty() || config.scope.is_some()) {
                anyhow::bail!(
                    "Cline-linked authentication is owned by Cline; do not also set bearer_env or scope"
                );
            }
        }
    }
    Ok(())
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
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

pub struct Forward {
    config: ForwardConfig,
    settings: crate::settings::Settings,
    /// Upstream Mcp-Session-Id once initialized.
    session: Arc<Mutex<Option<(uuid::Uuid, String)>>>,
    client: reqwest::Client,
    pub oauth_session: Arc<crate::mcp_oauth::Session>,
}

impl Forward {
    pub fn new(config: ForwardConfig, settings: crate::settings::Settings) -> Self {
        let oauth_session = Arc::new(crate::mcp_oauth::Session::new(
            config.name.clone(),
            config.url.clone(),
            settings.clone(),
        ));
        Self {
            config,
            settings,
            session: Arc::new(Mutex::new(None)),
            // Never send imported credentials to a redirect destination.
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("MCP HTTP client"),
            oauth_session,
        }
    }

    /// The single policy resolver: tools/list filtering and tools/call
    /// authorization both call this, so they cannot diverge.
    pub fn allows(&self, tool: &str) -> bool {
        self.config.tools.iter().any(|t| t == tool)
    }

    pub fn allows_guest(&self, guest: &str) -> bool {
        self.config
            .guests
            .as_ref()
            .is_none_or(|guests| guests.iter().any(|g| g == guest))
    }

    fn same_upstream(&self, config: &ForwardConfig) -> bool {
        self.config.url == config.url
            && self.config.bearer_env == config.bearer_env
            && self.config.scope == config.scope
            && self.config.cline == config.cline
            && self.config.oauth == config.oauth
    }

    async fn authenticate(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> Result<(reqwest::RequestBuilder, Option<String>)> {
        if self.config.oauth {
            let token = self.oauth_session.token(None).await?;
            return Ok((request.bearer_auth(&token), Some(token)));
        } else if let Some(source) = &self.config.cline {
            for (name, value) in crate::mcp_import::headers(source, &self.config.url)? {
                request = request.header(name, value);
            }
        } else if !self.config.bearer_env.is_empty()
            || self
                .settings
                .secret(&format!("mcp:{}", self.config.name))
                .is_some()
        {
            request = request.bearer_auth(self.bearer().await?);
        }
        Ok((request, None))
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

    /// Legacy static credential resolution; broker OAuth never falls back
    /// to these values or imported Cline credentials after disconnect.
    async fn bearer(&self) -> Result<String> {
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
        let generation = self.oauth_session.connection_epoch();
        if session
            .as_ref()
            .is_none_or(|(epoch, _)| *epoch != generation)
        {
            *session = Some((generation, self.initialize_upstream().await?));
        }
        let (_, session_id) = session.clone().expect("session just initialized");
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
            .post_raw(init, None)
            .await
            .context("upstream initialize")?;
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let initialized_result = parse_body(response).await.context("initialize response")?;
        if initialized_result.get("error").is_some() || initialized_result.get("result").is_none() {
            anyhow::bail!("upstream rejected MCP initialization");
        }
        let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        self.post_raw(initialized, Some(&session_id))
            .await
            .context("upstream initialized notification")?
            .error_for_status()
            .context("upstream rejected initialized notification")?;
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
        let (response, sent_token) = self.post_once(&message, session_id, None).await?;
        // Expired-token 401: refresh once and retry, so agents never
        // see a reauth seam.
        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            && let Some(sent_token) = sent_token
        {
            let token = self.oauth_session.token(Some(&sent_token)).await?;
            return Ok(self.post_once(&message, session_id, Some(token)).await?.0);
        }
        Ok(response)
    }

    async fn post_once(
        &self,
        message: &Value,
        session_id: Option<&str>,
        bearer: Option<String>,
    ) -> Result<(reqwest::Response, Option<String>)> {
        let mut request = self
            .client
            .post(&self.config.url)
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", PROTOCOL_VERSION)
            .json(message);
        let (authenticated, sent_token) = match bearer {
            Some(token) => (request.bearer_auth(&token), Some(token)),
            None => self.authenticate(request).await?,
        };
        request = authenticated;
        if let Some(id) = session_id.filter(|id| !id.is_empty()) {
            request = request.header("Mcp-Session-Id", id);
        }
        Ok((
            request.send().await.context("upstream MCP request")?,
            sent_token,
        ))
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
        // Upstreams may echo credentials in errors; never expose bodies
        // to the guest or host UI. Cline-linked sessions refresh in Cline.
        anyhow::bail!(
            "upstream returned {status}; authorize this forward in the host Friendzone UI, not in the guest"
        );
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

/// Shared, reloadable set of forwards: the UI edits the file and calls
/// reload; the MCP endpoint reads through it per message.
#[derive(Clone)]
pub struct ForwardRegistry {
    data_dir: std::path::PathBuf,
    settings: crate::settings::Settings,
    forwards: Arc<std::sync::RwLock<HashMap<String, Arc<Forward>>>>,
    update: Arc<std::sync::Mutex<()>>,
}

impl ForwardRegistry {
    pub fn load(data_dir: &Path, settings: crate::settings::Settings) -> Result<Self> {
        let registry = Self {
            data_dir: data_dir.to_owned(),
            settings,
            forwards: Arc::new(std::sync::RwLock::new(HashMap::new())),
            update: Arc::new(std::sync::Mutex::new(())),
        };
        registry.reload()?;
        Ok(registry)
    }

    /// Re-read and validate before publishing. Unchanged upstreams keep
    /// their sessions, including when only tool/guest permissions change.
    pub fn reload(&self) -> Result<usize> {
        let _update = self.update.lock().expect("registry update lock");
        let configs = load_forwards(&self.data_dir)?;
        validate_configs(&configs)?;
        self.publish(configs)
    }

    pub fn save(&self, configs: Vec<ForwardConfig>) -> Result<usize> {
        validate_configs(&configs)?;
        let _update = self.update.lock().expect("registry update lock");
        // Persistence and publication share one writer boundary. New
        // messages see the new snapshot; in-flight Arc holders finish.
        crate::storage::atomic_write(&self.config_path(), &serde_json::to_vec_pretty(&configs)?)?;
        self.publish(configs)
    }

    fn publish(&self, configs: Vec<ForwardConfig>) -> Result<usize> {
        let mut current = self.forwards.write().expect("forwards lock");
        let rebuilt: HashMap<String, Arc<Forward>> = configs
            .into_iter()
            .map(|config| {
                if let Some(old) = current.get(&config.name) {
                    if old.config == config {
                        return (config.name.clone(), old.clone());
                    }
                    if old.same_upstream(&config) {
                        return (
                            config.name.clone(),
                            Arc::new(Forward {
                                config,
                                settings: self.settings.clone(),
                                session: old.session.clone(),
                                client: old.client.clone(),
                                oauth_session: old.oauth_session.clone(),
                            }),
                        );
                    }
                }
                (
                    config.name.clone(),
                    Arc::new(Forward::new(config, self.settings.clone())),
                )
            })
            .collect();
        let count = rebuilt.len();
        for (name, old) in current.iter() {
            if rebuilt
                .get(name)
                .is_none_or(|new| !Arc::ptr_eq(&old.oauth_session, &new.oauth_session))
            {
                old.oauth_session.retire()?;
            }
        }
        *current = rebuilt;
        Ok(count)
    }

    pub fn get(&self, name: &str) -> Option<Arc<Forward>> {
        self.forwards
            .read()
            .expect("forwards lock")
            .get(name)
            .cloned()
    }

    pub fn enable_oauth(&self, name: &str, scope: Option<String>) -> Result<Arc<Forward>> {
        let _update = self.update.lock().expect("registry update lock");
        let mut configs = self.configs();
        let config = configs
            .iter_mut()
            .find(|config| config.name == name)
            .context("unknown MCP forward")?;
        config.oauth = true;
        config.bearer_env.clear();
        config.scope = scope;
        validate_configs(&configs)?;
        crate::storage::atomic_write(&self.config_path(), &serde_json::to_vec_pretty(&configs)?)?;
        self.publish(configs)?;
        self.get(name).context("forward disappeared")
    }

    pub fn validation_forward(&self, config: ForwardConfig) -> Result<Arc<Forward>> {
        validate_configs(std::slice::from_ref(&config))?;
        if config.oauth {
            // Validation and guest calls must share the refresh lock and
            // lifecycle. Never construct a second OAuth owner for one name.
            return self
                .get(&config.name)
                .filter(|forward| forward.config.oauth && forward.config.url == config.url)
                .context(
                    "Save this forward for OAuth and authorize it in Friendzone before validation",
                );
        }
        Ok(Arc::new(Forward::new(config, self.settings.clone())))
    }

    pub fn configs(&self) -> Vec<ForwardConfig> {
        let mut configs: Vec<ForwardConfig> = self
            .forwards
            .read()
            .expect("forwards lock")
            .values()
            .map(|forward| forward.config.clone())
            .collect();
        configs.sort_by(|a, b| a.name.cmp(&b.name));
        configs
    }

    pub fn config_path(&self) -> std::path::PathBuf {
        forwards_path(&self.data_dir)
    }
}

#[derive(Clone)]
pub struct McpState {
    pub app: AppState,
    pub registry: ForwardRegistry,
}

impl McpState {
    pub fn new(app: AppState, registry: ForwardRegistry) -> Self {
        Self { app, registry }
    }
}

/// Handles one container-side JSON-RPC message for the named forward.
/// The container session is terminated here: initialize is answered
/// locally, only tools/list and tools/call are reconstructed upstream.
pub async fn handle_message(
    state: &McpState,
    name: &str,
    container: &str,
    peer: std::net::IpAddr,
    message: Value,
) -> Value {
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(forward) = state.registry.get(name) else {
        return error_response(id, -32601, &format!("unknown MCP forward '{name}'"));
    };
    let denial = if state.app.is_killed(container) {
        Some("container is killed")
    } else if state.app.authorize(container, peer) != crate::state::Authorization::Allowed {
        Some("container is not approved for this address; check approval and IP pin in the host UI")
    } else if !forward.allows_guest(container) {
        Some("MCP forward is not shared with this guest")
    } else {
        None
    };
    if let Some(reason) = denial {
        let event = state.app.record(
            container.into(),
            format!("MCP {method}"),
            format!("mcp:{name}"),
            Verdict::Blocked,
        );
        state.app.annotate(event, None, Some(reason.into()));
        return error_response(id, -32000, reason);
    }
    let (verdict, response) = dispatch(&forward, &method, id, &message).await;
    let event = state.app.record(
        container.to_owned(),
        format!("MCP {method}"),
        format!("mcp:{name}"),
        verdict,
    );
    if let Some(reason) = response.pointer("/error/message").and_then(Value::as_str) {
        state.app.annotate(event, None, Some(reason.into()));
    }
    response
}

async fn dispatch(forward: &Forward, method: &str, id: Value, message: &Value) -> (Verdict, Value) {
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

    #[tokio::test]
    async fn live_policy_updates_preserve_sessions_and_reject_invalid_config() {
        let dir = std::env::temp_dir().join(format!("fz-live-mcp-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let registry = ForwardRegistry::load(&dir, settings).unwrap();
        let mut config = linear_forward().config;
        config.guests = Some(vec!["guest".into()]);
        registry.save(vec![config.clone()]).unwrap();
        let before = registry.get("linear").unwrap();
        *before.session.lock().await =
            Some((before.oauth_session.connection_epoch(), "session-1".into()));
        registry.reload().unwrap();
        assert!(Arc::ptr_eq(&before, &registry.get("linear").unwrap()));
        let app = AppState::default();
        let ip = "127.0.0.1".parse().unwrap();
        app.authorize("guest", ip);
        app.approve_container("guest", true).unwrap();
        let state = McpState::new(app, registry.clone());
        let init = json!({"jsonrpc":"2.0", "id":1, "method":"initialize"});
        assert!(
            handle_message(&state, "linear", "guest", ip, init.clone())
                .await
                .get("result")
                .is_some()
        );
        assert!(
            handle_message(
                &state,
                "linear",
                "guest",
                "127.0.0.2".parse().unwrap(),
                init.clone()
            )
            .await
            .get("error")
            .is_some()
        );
        config.guests = Some(vec![]);
        config.tools = vec![];
        registry.save(vec![config.clone()]).unwrap();
        let after = registry.get("linear").unwrap();
        assert!(Arc::ptr_eq(&before.session, &after.session));
        assert!(
            before.allows("get_issue"),
            "in-flight snapshot retains its policy"
        );
        assert!(!after.allows("get_issue"), "new snapshot uses new policy");
        assert!(
            handle_message(&state, "linear", "guest", ip, init.clone())
                .await
                .get("error")
                .is_some()
        );
        let saved = std::fs::read(registry.config_path()).unwrap();
        assert!(registry.save(vec![config.clone(), config.clone()]).is_err());
        assert_eq!(std::fs::read(registry.config_path()).unwrap(), saved);
        std::fs::write(registry.config_path(), b"[").unwrap();
        assert!(registry.reload().is_err());
        assert!(Arc::ptr_eq(&after, &registry.get("linear").unwrap()));
        registry.save(vec![]).unwrap();
        assert!(registry.get("linear").is_none());
        assert!(
            handle_message(&state, "linear", "guest", ip, init)
                .await
                .get("error")
                .is_some()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn cline_link_uses_current_credentials_through_real_mcp_path() {
        use axum::{Json, Router, http::HeaderMap, routing::post};
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls = seen.clone();
        let app = Router::new().route("/mcp", post(move |headers: HeaderMap, Json(message): Json<Value>| {
            let calls = calls.clone();
            async move {
                calls.lock().unwrap().push((message["method"].as_str().unwrap().to_owned(), headers["authorization"].to_str().unwrap().to_owned()));
                let result = match message["method"].as_str().unwrap() {
                    "initialize" => json!({"protocolVersion":PROTOCOL_VERSION, "capabilities":{"tools":{}}, "serverInfo":{"name":"test", "version":"1"}}),
                    "tools/list" => json!({"tools":[{"name":"read"}, {"name":"write"}]}),
                    _ => json!({}),
                };
                Json(json!({"jsonrpc":"2.0", "id":message["id"], "result":result}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = std::env::temp_dir().join(format!("fz-linked-mcp-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let path = dir.join("cline_mcp_settings.json");
        let write_token = |token: &str| {
            std::fs::write(&path, serde_json::to_vec(&json!({"mcpServers":{"test":{"transport":{"type":"streamableHttp", "url":url}, "oauth":{"tokens":{"access_token":token, "refresh_token":"never-copy"}}}}})).unwrap()).unwrap()
        };
        write_token("first");
        let registry = ForwardRegistry::load(&dir, settings).unwrap();
        registry
            .save(vec![ForwardConfig {
                name: "test".into(),
                url: url.clone(),
                bearer_env: String::new(),
                scope: None,
                tools: vec!["read".into()],
                guests: Some(vec!["guest".into()]),
                cline: Some(crate::mcp_import::ClineSource {
                    path: path.to_str().unwrap().into(),
                    server: "test".into(),
                }),
                oauth: false,
            }])
            .unwrap();
        let app = AppState::default();
        app.add_container("guest").unwrap();
        let state = McpState::new(app, registry);
        let list = json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"});
        let response = handle_message(
            &state,
            "test",
            "guest",
            "127.0.0.1".parse().unwrap(),
            list.clone(),
        )
        .await;
        assert_eq!(response["result"]["tools"], json!([{"name":"read"}]));
        write_token("rotated-by-cline");
        handle_message(&state, "test", "guest", "127.0.0.1".parse().unwrap(), list).await;
        let rejected = handle_message(
            &state,
            "test",
            "guest",
            "127.0.0.1".parse().unwrap(),
            json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":"write"}}),
        )
        .await;
        assert!(rejected.get("error").is_some());
        let calls = seen.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|(method, _)| method == "initialize")
                .count(),
            1
        );
        assert_eq!(
            calls.last().unwrap(),
            &("tools/list".into(), "Bearer rotated-by-cline".into())
        );
        assert!(
            !std::fs::read_to_string(state.registry.config_path())
                .unwrap()
                .contains("never-copy")
        );
        drop(calls);
        server.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

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
                guests: None,
                cline: None,
                oauth: false,
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
        let (verdict, response) = dispatch(&forward, "tools/call", json!(1), &message).await;
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
        let (verdict, response) = dispatch(&forward, "resources/list", json!(2), &message).await;
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
