use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;

use crate::state::{AppState, StateView};

#[derive(Clone)]
struct UiState {
    app: AppState,
    settings: crate::settings::Settings,
    registry: crate::mcp::ForwardRegistry,
    oauth: crate::mcp_oauth::OauthFlows,
    cline: crate::oauth::ClineFlows,
    ui_addr: SocketAddr,
    bootstrap_addr: SocketAddr,
}

#[derive(Clone)]
struct BootstrapState {
    cert: Arc<String>,
    /// The broker's own binary: right only for guests matching the host.
    binary: Arc<Vec<u8>>,
    /// Cross-built guest binaries dropped into `<data-dir>/guest-bin/`,
    /// keyed by file name (e.g. `fz-linux-x86_64`).
    guest_binaries: Arc<std::collections::HashMap<String, std::path::PathBuf>>,
    mcp: crate::mcp::McpState,
    settings: crate::settings::Settings,
    proxy_port: u16,
}

/// Scans `<data-dir>/guest-bin/` for cross-built `fz` binaries to serve
/// to guests whose OS/arch differ from the host's. Any regular file
/// counts; the file name is the target label.
pub fn discover_guest_binaries(
    data_dir: &std::path::Path,
) -> std::collections::HashMap<String, std::path::PathBuf> {
    let dir = data_dir.join("guest-bin");
    let mut found = std::collections::HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
            {
                found.insert(name.to_owned(), path.clone());
            }
        }
    }
    found
}

pub async fn serve_ui(
    addr: SocketAddr,
    state: AppState,
    settings: crate::settings::Settings,
    registry: crate::mcp::ForwardRegistry,
    bootstrap_addr: SocketAddr,
) -> Result<()> {
    serve(
        addr,
        ui_router(UiState {
            app: state,
            settings,
            registry,
            oauth: crate::mcp_oauth::OauthFlows::default(),
            cline: crate::oauth::ClineFlows::default(),
            ui_addr: addr,
            bootstrap_addr,
        }),
        "web UI",
    )
    .await
}

pub async fn serve_bootstrap(
    addr: SocketAddr,
    cert_pem: String,
    mcp: crate::mcp::McpState,
    settings: crate::settings::Settings,
    proxy_port: u16,
) -> Result<()> {
    let executable = std::env::current_exe().context("locate fz executable")?;
    let binary = tokio::fs::read(&executable)
        .await
        .with_context(|| format!("read {}", executable.display()))?;
    let guest_binaries = discover_guest_binaries(settings.data_dir());
    serve(
        addr,
        bootstrap_router(BootstrapState {
            cert: Arc::new(cert_pem),
            binary: Arc::new(binary),
            guest_binaries: Arc::new(guest_binaries),
            mcp,
            settings,
            proxy_port,
        }),
        "bootstrap server",
    )
    .await
}

async fn serve(addr: SocketAddr, app: Router, name: &'static str) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {name} to {addr}"))?;
    tracing::info!(%addr, "{name} listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .with_context(|| format!("serve {name}"))
}

fn ui_router(state: UiState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(css))
        .route("/app.js", get(js))
        .route("/api/state", get(api_state))
        .route("/api/log", get(api_log))
        .route("/api/events", get(state_events))
        .route("/api/requests/{id}", get(review_request))
        .route("/api/requests/{id}/decision", post(decide_request))
        .route(
            "/api/requests/{id}/github-target",
            post(resolve_github_target),
        )
        .route(
            "/api/requests/{id}/comment-permission",
            post(grant_comment_permission),
        )
        .route(
            "/api/containers/{container}/comment-permissions/{id}",
            axum::routing::delete(revoke_comment_permission),
        )
        .route("/api/containers", post(add_container))
        .route(
            "/api/containers/{id}",
            axum::routing::delete(remove_container),
        )
        .route("/api/containers/{id}/kill", post(set_killed))
        .route("/api/containers/{id}/approve", post(approve_container))
        .route("/api/containers/{id}/pin", post(set_container_pin))
        .route("/api/escrow", get(list_escrow).post(add_escrow))
        .route(
            "/api/escrow/{name}",
            axum::routing::put(update_escrow).delete(remove_escrow),
        )
        .route("/api/escrow/{name}/secret", post(set_escrow_secret))
        .route("/api/bootstrap/commands", get(guest_setup_commands))
        .route("/api/mcp", get(list_forwards))
        .route("/api/mcp/config", get(get_mcp_config).put(put_mcp_config))
        .route("/api/mcp/reload", post(reload_mcp_config))
        .route("/api/mcp/import/cline", post(preview_cline_mcp))
        .route("/api/mcp/validate", post(validate_mcp))
        .route("/api/mcp/{name}/guest-config", get(mcp_guest_config))
        .route("/api/mcp/{name}/oauth/start", post(oauth_start))
        .route("/api/mcp/{name}/oauth/status", get(mcp_oauth_status))
        .route(
            "/api/mcp/{name}/oauth",
            axum::routing::delete(oauth_disconnect),
        )
        .route("/oauth/callback", get(oauth_callback))
        .route(
            "/api/escrow/{name}/cline-oauth/start",
            post(cline_oauth_start),
        )
        .route(
            "/api/escrow/{name}/cline-oauth/status",
            get(cline_oauth_status),
        )
        .route("/health", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(
            |request: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut response = next.run(request).await;
                // Host decisions must not be clickjacked inside another site's
                // frame. No-store also avoids serving a stale review UI on upgrade.
                response
                    .headers_mut()
                    .insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
                response.headers_mut().insert(
                    header::CONTENT_SECURITY_POLICY,
                    "frame-ancestors 'none'".parse().unwrap(),
                );
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
                response
            },
        ))
        .with_state(state)
}

/// Escrow entries with fakes visible but real values reduced to a
/// present/absent flag: the UI never receives a secret.
async fn list_escrow(State(state): State<UiState>) -> Json<serde_json::Value> {
    let entries: Vec<serde_json::Value> = state
        .settings
        .entries()
        .into_iter()
        .map(|entry| {
            let connected = state.settings.real_value(&entry).is_some();
            serde_json::json!({
                "name": entry.name,
                "hosts": entry.hosts,
                "header": entry.header,
                "prefix": entry.prefix,
                "fake": entry.fake,
                "guest_env": entry.guest_env,
                "connected": connected,
            })
        })
        .collect();
    Json(serde_json::json!({ "entries": entries }))
}

/// The add form's shape: no `fake` field exists, so a client cannot
/// supply one — the broker always generates it. The real key travels
/// in `real_value`, its one designated place, straight to the secret
/// store.
#[derive(Deserialize)]
struct AddEscrowRequest {
    name: String,
    hosts: Vec<String>,
    header: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    guest_env: Option<String>,
    #[serde(default)]
    real_value: Option<String>,
}

async fn add_escrow(
    State(state): State<UiState>,
    Json(request): Json<AddEscrowRequest>,
) -> impl IntoResponse {
    let entry = crate::settings::EscrowEntry {
        name: request.name,
        hosts: request.hosts,
        header: request.header,
        prefix: request.prefix,
        fake: String::new(), // always broker-generated
        real_env: None,
        guest_env: request.guest_env,
    };
    let entry = match state.settings.add_entry(entry) {
        Ok(entry) => entry,
        Err(error) => return (StatusCode::CONFLICT, error.to_string()).into_response(),
    };
    if let Some(real) = request.real_value.filter(|v| !v.trim().is_empty())
        && let Err(error) = state.settings.set_secret(&entry.name, real.trim())
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    (StatusCode::CREATED, Json(serde_json::json!(entry))).into_response()
}

#[derive(Deserialize)]
struct UpdateEscrowRequest {
    hosts: Vec<String>,
    header: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    guest_env: Option<String>,
    /// Optionally rotate the real key in the same edit.
    #[serde(default)]
    real_value: Option<String>,
}

/// Edits an entry's routing fields; the fake never changes, so guest
/// env files stay valid.
async fn update_escrow(
    State(state): State<UiState>,
    Path(name): Path<String>,
    Json(request): Json<UpdateEscrowRequest>,
) -> impl IntoResponse {
    let updated = match state.settings.update_entry(
        &name,
        request.hosts,
        request.header,
        request.prefix,
        request.guest_env,
    ) {
        Ok(entry) => entry,
        Err(error) => return (StatusCode::NOT_FOUND, error.to_string()).into_response(),
    };
    if let Some(real) = request.real_value.filter(|v| !v.trim().is_empty())
        && let Err(error) = state.settings.set_secret(&name, real.trim())
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    Json(serde_json::json!(updated)).into_response()
}

/// Deletes an escrow entry and its stored real key together.
async fn remove_escrow(
    State(state): State<UiState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.settings.remove_entry(&name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct SecretRequest {
    value: String,
}

async fn set_escrow_secret(
    State(state): State<UiState>,
    Path(name): Path<String>,
    Json(request): Json<SecretRequest>,
) -> impl IntoResponse {
    match state.settings.set_secret(&name, &request.value) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

/// MCP forwards with connection state; tokens never leave as values.
/// `auth` distinguishes OAuth sessions (reauth/disconnect apply) from
/// static keys (managed outside).
async fn list_forwards(State(state): State<UiState>) -> Json<serde_json::Value> {
    let forwards: Vec<serde_json::Value> = state
        .registry
        .configs()
        .iter()
        .map(|f| {
            let session = crate::mcp_oauth::TokenRecord::load(&state.settings, &f.name)
                .filter(|record| record.server_url == f.url);
            let (auth, expires_at, refreshable) = match &session {
                Some(record) if f.oauth => {
                    ("oauth", record.expires_at, record.refresh_token.is_some())
                }
                _ if f.oauth => ("oauth-required", None, false),
                _ if f.cline.is_some() => ("cline-link", None, false),
                None if state.settings.secret(&format!("mcp:{}", f.name)).is_some() => {
                    ("stored-key", None, false)
                }
                None if std::env::var(&f.bearer_env).is_ok() => ("env-key", None, false),
                _ => ("none", None, false),
            };
            serde_json::json!({
                "name": f.name,
                "url": f.url,
                "guest_endpoint": guest_mcp_endpoint(state.bootstrap_addr, None, &f.name).ok(),
                "tools": f.tools,
                "scope": f.scope,
                "guests": f.guests,
                "connected": auth != "none" && auth != "oauth-required",
                "auth": auth,
                "expires_at": expires_at,
                "refreshable": refreshable,
            })
        })
        .collect();
    Json(serde_json::json!({
        "forwards": forwards,
        "config_path": state.registry.config_path().display().to_string(),
        "guest_host": (!state.bootstrap_addr.ip().is_unspecified()).then(|| state.bootstrap_addr.ip().to_string()),
        "guest_port": state.bootstrap_addr.port(),
        "guest_address_warning": if state.bootstrap_addr.ip().is_unspecified() {
            Some("The broker listens on all interfaces. Enter its host IP or DNS name reachable from the guest.")
        } else if state.bootstrap_addr.ip().is_loopback() {
            Some("The bootstrap listener is loopback-only. For a VM/container, bind it to a guest-facing interface; changing the displayed host does not change the listener.")
        } else { None },
    }))
}

/// The bootstrap listener, never the UI origin or upstream URL, owns MCP
/// endpoints. Host overrides only describe guest routing; they do not bind
/// a new listener or make a network request.
fn guest_mcp_endpoint(addr: SocketAddr, host: Option<&str>, name: &str) -> Result<String> {
    let mut url = guest_broker_url(addr, host)?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("invalid broker URL"))?
        .push("mcp")
        .push(name);
    Ok(url.into())
}

fn guest_broker_url(addr: SocketAddr, host: Option<&str>) -> Result<reqwest::Url> {
    let host = host
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| addr.ip().to_string());
    let authority = host
        .parse::<std::net::IpAddr>()
        .map(|ip| match ip {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        })
        .unwrap_or(host.clone());
    if host
        .chars()
        .any(|c| c.is_whitespace() || "/\\@?#".contains(c))
    {
        anyhow::bail!(
            "Enter only the broker host IP or DNS name, without a scheme, credentials, path or port"
        );
    }
    let mut url =
        reqwest::Url::parse(&format!("http://{authority}")).context("invalid broker host")?;
    // Check the authority too: URL parsers normalize an explicit :80 away.
    let has_port = if authority.starts_with('[') {
        !authority.ends_with(']')
    } else {
        authority.contains(':')
    };
    if has_port || url.host_str().is_none() || url.path() != "/" {
        anyhow::bail!(
            "Enter only the broker host IP or DNS name; the bootstrap port is supplied automatically"
        );
    }
    if url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_unspecified())
    {
        anyhow::bail!(
            "A wildcard bind address is not a guest endpoint; enter the broker host IP or DNS name"
        );
    }
    url.set_port(Some(addr.port()))
        .map_err(|_| anyhow::anyhow!("invalid bootstrap port"))?;
    Ok(url)
}

#[derive(Deserialize)]
struct SetupCommandsQuery {
    host: Option<String>,
    #[serde(default)]
    container: String,
}
async fn guest_setup_commands(
    State(state): State<UiState>,
    axum::extract::Query(query): axum::extract::Query<SetupCommandsQuery>,
) -> impl IntoResponse {
    match guest_broker_url(state.bootstrap_addr, query.host.as_deref())
        .and_then(|url| crate::bootstrap::commands(url.as_str(), &query.container))
    {
        Ok(commands) => Json(commands).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct GuestConfigQuery {
    guest: String,
    host: Option<String>,
}

async fn mcp_guest_config(
    State(state): State<UiState>,
    Path(name): Path<String>,
    axum::extract::Query(query): axum::extract::Query<GuestConfigQuery>,
) -> impl IntoResponse {
    // Read-only snapshot for instructions. Real admission still uses the
    // same forward's allows_guest plus approval/IP/kill gates per request.
    let Some(forward) = state.registry.get(&name) else {
        return (StatusCode::NOT_FOUND, "MCP forward no longer exists").into_response();
    };
    let Some(guest) = state
        .app
        .view()
        .containers
        .into_iter()
        .find(|guest| guest.id == query.guest)
    else {
        return (StatusCode::NOT_FOUND, "Select a guest from the Inbox first").into_response();
    };
    if guest.id.is_empty() || guest.id.contains(':') || guest.id.chars().any(char::is_control) {
        return (StatusCode::UNPROCESSABLE_ENTITY, "This guest name cannot be encoded as a Basic username; use a name without ':' or control characters").into_response();
    }
    let endpoint = match guest_mcp_endpoint(state.bootstrap_addr, query.host.as_deref(), &name) {
        Ok(endpoint) => endpoint,
        Err(error) => return (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    };
    let authorization = format!("Basic {}", STANDARD.encode(format!("{}:x", guest.id)));
    let mut warnings = Vec::new();
    if !guest.approved {
        warnings.push("Guest is awaiting approval. Approve it in the host Inbox.".to_owned());
    }
    if guest.state == "killed" {
        warnings.push("Guest is killed. Resume it in the host Inbox.".to_owned());
    }
    if !forward.allows_guest(&guest.id) {
        warnings.push("This forward is not shared with the selected guest. Add its name to the forward's allowed guests and apply.".to_owned());
    }
    if state.bootstrap_addr.ip().is_loopback() {
        warnings.push("Bootstrap listener is loopback-only; remote guests cannot reach it. Rebind it to a guest-facing interface.".to_owned());
    }
    let key = format!("{name}-via-friendzone");
    Json(serde_json::json!({
        "endpoint": endpoint,
        "authorization": authorization,
        "warnings": warnings,
        "cline_config": {"mcpServers": {key: {"transport": {
            "type": "streamableHttp", "url": endpoint,
            "headers": {"Authorization": authorization}
        }}}}
    }))
    .into_response()
}

/// The raw mcp-forwards.json for in-UI editing.
async fn get_mcp_config(State(state): State<UiState>) -> impl IntoResponse {
    Json(state.registry.configs())
}

/// Saves mcp-forwards.json (validated first) and reloads the forwards.
async fn put_mcp_config(State(state): State<UiState>, body: String) -> impl IntoResponse {
    let configs = match serde_json::from_str::<Vec<crate::mcp::ForwardConfig>>(&body) {
        Ok(configs) => configs,
        Err(error) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("not a valid forwards config: {error}"),
            )
                .into_response();
        }
    };
    match state.registry.save(configs) {
        Ok(count) => Json(serde_json::json!({ "forwards": count })).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")).into_response(),
    }
}

#[derive(Deserialize)]
struct ClineImportRequest {
    path: String,
}

async fn preview_cline_mcp(Json(request): Json<ClineImportRequest>) -> impl IntoResponse {
    // Management listener only; preview never returns headers or tokens.
    match crate::mcp_import::preview(&request.path) {
        Ok(candidates) => Json(candidates).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    }
}

async fn validate_mcp(
    State(state): State<UiState>,
    Json(config): Json<crate::mcp::ForwardConfig>,
) -> impl IntoResponse {
    if let Err(error) = crate::mcp::validate_configs(std::slice::from_ref(&config)) {
        return (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response();
    }
    // Use the real upstream path, including initialization and auth. This
    // discovers tools but does not publish a forward or call any tools.
    let forward = match state.registry.validation_forward(config) {
        Ok(forward) => forward,
        Err(error) => return (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        forward.call_upstream(
            serde_json::json!({"jsonrpc":"2.0", "id":"fz-validate", "method":"tools/list"}),
        ),
    )
    .await;
    match result {
        Ok(Ok(value))
            if value
                .pointer("/result/tools")
                .and_then(serde_json::Value::as_array)
                .is_some() =>
        {
            let tools: Vec<_> = value["result"]["tools"]
                .as_array()
                .expect("checked")
                .iter()
                .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
                .collect();
            Json(serde_json::json!({"tools":tools, "more":value.pointer("/result/nextCursor").is_some()})).into_response()
        }
        Ok(Ok(_)) => (
            StatusCode::BAD_GATEWAY,
            "upstream did not return a valid tools/list result",
        )
            .into_response(),
        Ok(Err(error)) => (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "MCP validation timed out").into_response(),
    }
}

/// Re-reads mcp-forwards.json from disk (for out-of-band edits).
async fn reload_mcp_config(State(state): State<UiState>) -> impl IntoResponse {
    match state.registry.reload() {
        Ok(count) => Json(serde_json::json!({ "forwards": count })).into_response(),
        Err(error) => (StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}")).into_response(),
    }
}

/// Forgets the OAuth session for a forward.
async fn oauth_disconnect(
    State(state): State<UiState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let Some(forward) = state.registry.get(&name) else {
        return (StatusCode::NOT_FOUND, "unknown MCP forward").into_response();
    };
    match forward.oauth_session.disconnect() {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

/// Kicks off host-side OAuth: builds the authorization URL and opens
/// the host browser. Returns the URL too, in case the browser did not
/// open.
#[derive(Default, Deserialize)]
struct OAuthStartRequest {
    scope: Option<String>,
}

async fn oauth_start(
    State(state): State<UiState>,
    Path(name): Path<String>,
    request: Option<Json<OAuthStartRequest>>,
) -> impl IntoResponse {
    let configs = state.registry.configs();
    let Some(forward) = configs.iter().find(|f| f.name == name) else {
        return (StatusCode::NOT_FOUND, format!("unknown forward '{name}'")).into_response();
    };
    let mut callback_addr = state.ui_addr;
    if callback_addr.ip().is_unspecified() {
        callback_addr.set_ip("127.0.0.1".parse().expect("loopback"));
    }
    if !callback_addr.ip().is_loopback() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Broker OAuth requires a loopback UI listener for the browser callback",
        )
            .into_response();
    }
    let scope = request
        .and_then(|r| r.0.scope)
        .or_else(|| forward.scope.clone())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let forward = match state.registry.enable_oauth(&name, scope.clone()) {
        Ok(forward) => forward,
        Err(error) => return (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response(),
    };
    let redirect_uri = format!("http://{callback_addr}/oauth/callback");
    match state
        .oauth
        .start(forward.oauth_session.clone(), &redirect_uri, scope)
        .await
    {
        Ok(url) => {
            let browser_opened = open_host_browser(&url).await;
            Json(serde_json::json!({ "authorize_url": url, "browser_opened": browser_opened }))
                .into_response()
        }
        Err(error) => (StatusCode::BAD_GATEWAY, format!("{error:#}")).into_response(),
    }
}

async fn mcp_oauth_status(
    State(state): State<UiState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let Some(forward) = state.registry.get(&name) else {
        return (StatusCode::NOT_FOUND, "unknown MCP forward").into_response();
    };
    Json(state.oauth.status(&forward.oauth_session)).into_response()
}

#[derive(Deserialize)]
struct OauthCallback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}

async fn oauth_callback(
    State(state): State<UiState>,
    axum::extract::Query(query): axum::extract::Query<OauthCallback>,
) -> impl IntoResponse {
    match state
        .oauth
        .finish(&query.state, query.code.as_deref(), query.error.as_deref())
        .await
    {
        Ok(_) => Html("<h1>Connected to Friendzone</h1><p>Upstream OAuth is now owned and refreshed by the broker. Return to Friendzone Settings to discover/select tools and guest permissions. You can close this tab.</p>").into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, format!("{error:#}")).into_response(),
    }
}

/// Starts the Cline device-code sign-in: returns the user code to show,
/// opens the verification page in the host browser, and polls WorkOS in
/// the background — no callback into this process, no editor redirect.
async fn cline_oauth_start(
    State(state): State<UiState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.cline.start(&name, &state.settings).await {
        Ok(login) => {
            if let crate::oauth::ClineLoginState::WaitingForUser {
                verification_uri, ..
            } = &login
            {
                open_host_browser(verification_uri).await;
            }
            Json(serde_json::json!(login)).into_response()
        }
        Err(error) => (StatusCode::BAD_GATEWAY, format!("{error:#}")).into_response(),
    }
}

/// The UI polls this to learn when the background login completes.
async fn cline_oauth_status(
    State(state): State<UiState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.cline.status(&name) {
        Some(login) => Json(serde_json::json!(login)).into_response(),
        None => (StatusCode::NOT_FOUND, "no sign-in in progress").into_response(),
    }
}

async fn open_host_browser(url: &str) -> bool {
    match crate::browser::open(url).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, "could not open host browser");
            false
        }
    }
}

fn bootstrap_router(state: BootstrapState) -> Router {
    Router::new()
        .route("/bootstrap/ca.pem", get(certificate))
        .route("/bootstrap/fz", get(binary))
        .route("/bootstrap/fz/{target}", get(guest_binary))
        .route("/bootstrap/targets", get(bootstrap_targets))
        .route("/bootstrap/info", get(bootstrap_info))
        .route("/bootstrap/hello", get(bootstrap_hello))
        .route("/bootstrap/env", get(bootstrap_env))
        .route("/bootstrap/setup", get(bootstrap_script))
        .route(
            "/bootstrap/friendzone.js",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    include_str!("plugin/friendzone.js"),
                )
            }),
        )
        .route("/guest/jobs", post(submit_job).get(list_jobs))
        .route("/guest/jobs/{id}", get(get_job).delete(delete_job))
        .route("/guest/jobs/{id}/cancel", post(cancel_job))
        .route("/mcp/{name}", post(mcp_message))
        .route("/health", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(
            |request: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut response = next.run(request).await;
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
                response
            },
        ))
        .with_state(state)
}

fn job_identity(
    state: &BootstrapState,
    headers: &axum::http::HeaderMap,
    peer: SocketAddr,
) -> Result<(String, uuid::Uuid)> {
    let name = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(crate::proxy::basic_username)
        .context("guest Basic authorization required")?;
    if state.mcp.app.authorize(&name, peer.ip()) != crate::state::Authorization::Allowed {
        anyhow::bail!("guest awaiting approval or IP pin mismatch");
    }
    let (instance, _) = state
        .mcp
        .app
        .async_identity(&name, peer.ip())
        .context("guest killed or unauthorized")?;
    Ok((name, instance))
}
async fn submit_job(
    State(state): State<BootstrapState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    request: axum::extract::Request,
) -> axum::response::Response {
    let (name, _) = match job_identity(&state, &headers, peer) {
        Ok(value) => value,
        Err(error) => return (StatusCode::FORBIDDEN, error.to_string()).into_response(),
    };
    let Ok(_slot) = crate::review::buffer_slots().clone().try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, "upload slots busy").into_response();
    };
    let bytes = match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        axum::body::to_bytes(request.into_body(), crate::jobs::MAX_PAYLOAD + 4096),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "job upload incomplete or exceeds 10 MiB",
            )
                .into_response();
        }
    };
    let input = match serde_json::from_slice::<crate::jobs::Submission>(&bytes) {
        Ok(value) => value,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid job submission JSON").into_response(),
    };
    match state
        .mcp
        .app
        .jobs
        .submit(&state.mcp.app, &state.settings, &name, peer.ip(), input)
    {
        Ok(value) => (StatusCode::ACCEPTED, Json(value)).into_response(),
        Err(e) => (StatusCode::CONFLICT, e.to_string()).into_response(),
    }
}
#[derive(Deserialize)]
struct JobSession {
    session_id: String,
}
async fn list_jobs(
    State(state): State<BootstrapState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<JobSession>,
) -> axum::response::Response {
    match job_identity(&state, &headers, peer) {
        Ok((name, instance)) => {
            Json(state.mcp.app.jobs.list(&name, instance, &query.session_id)).into_response()
        }
        Err(e) => (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    }
}
async fn get_job(
    State(state): State<BootstrapState>,
    Path(id): Path<uuid::Uuid>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<JobSession>,
) -> axum::response::Response {
    match job_identity(&state, &headers, peer).and_then(|(name, instance)| {
        state
            .mcp
            .app
            .jobs
            .get(&name, instance, id, &query.session_id)
    }) {
        Ok(value) => Json(value).into_response(),
        Err(e) => (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    }
}
async fn cancel_job(
    State(state): State<BootstrapState>,
    Path(id): Path<uuid::Uuid>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<JobSession>,
) -> axum::response::Response {
    match job_identity(&state, &headers, peer).and_then(|(name, instance)| {
        state
            .mcp
            .app
            .jobs
            .cancel(&name, instance, id, &query.session_id)
    }) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::CONFLICT, e.to_string()).into_response(),
    }
}
async fn delete_job(
    State(state): State<BootstrapState>,
    Path(id): Path<uuid::Uuid>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<JobSession>,
) -> axum::response::Response {
    match job_identity(&state, &headers, peer).and_then(|(name, instance)| {
        state
            .mcp
            .app
            .jobs
            .delete(&name, instance, id, &query.session_id)
    }) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::CONFLICT, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptQuery {
    shell: String,
    broker: Option<String>,
    #[serde(default)]
    container: String,
}
async fn bootstrap_script(
    State(state): State<BootstrapState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ScriptQuery>,
) -> impl IntoResponse {
    // Host describes the guest's route to this HTTP listener. Strict origin
    // validation + base64 JSON encoding prevent it becoming executable code.
    // X-Forwarded-* is deliberately ignored; fetching never approves a guest.
    let broker = query.broker.unwrap_or_else(|| {
        format!(
            "http://{}",
            headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
        )
    });
    match crate::bootstrap::Shell::parse(&query.shell).and_then(|shell| {
        crate::bootstrap::script(
            shell,
            &broker,
            &query.container,
            &state.cert,
            state.proxy_port,
            &state.settings,
        )
    }) {
        Ok(script) => (
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            script,
        )
            .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct HelloQuery {
    container: String,
}

/// The guest script announces itself: creates/updates the join request so
/// it appears in the UI immediately, with the address to pin.
async fn bootstrap_hello(
    State(state): State<BootstrapState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    axum::extract::Query(query): axum::extract::Query<HelloQuery>,
) -> Json<serde_json::Value> {
    let authorization = state.mcp.app.authorize(&query.container, peer.ip());
    Json(serde_json::json!({
        "container": query.container,
        "approved": authorization == crate::state::Authorization::Allowed,
    }))
}

/// Connection facts a guest needs to compose its environment: the
/// proxy port (the host is whatever address the guest already reached
/// us on).
async fn bootstrap_info(State(state): State<BootstrapState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "proxy_port": state.proxy_port }))
}

/// Fake credentials for the guest, as shell export lines. Serving fakes
/// over plain HTTP is sound: fakes are worthless outside the proxy.
async fn bootstrap_env(State(state): State<BootstrapState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        state.settings.guest_env_lines(),
    )
}

/// Container-facing MCP endpoint (streamable HTTP, JSON responses).
/// Identity comes from the same Basic credentials as the proxy.
async fn mcp_message(
    State(state): State<BootstrapState>,
    Path(name): Path<String>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(message): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(container) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::proxy::basic_username)
    else {
        // Cline interprets every 401 as OAuth. This endpoint uses guest
        // Basic identity, not OAuth; return a clear denial, not discovery.
        return (StatusCode::FORBIDDEN, "Friendzone guest Authorization header is missing or invalid. In host Settings → MCP servers, use Connect guest → Copy Cline configuration. Remove stale oauth/oauthClient fields from the guest entry; upstream OAuth belongs on the host.").into_response();
    };
    let response =
        crate::mcp::handle_message(&state.mcp, &name, &container, peer.ip(), message).await;
    if response.is_null() {
        // Notification: no JSON-RPC response body.
        StatusCode::ACCEPTED.into_response()
    } else {
        Json(response).into_response()
    }
}

async fn index() -> Html<String> {
    let path = crate::mcp_import::default_settings_path();
    render_index(
        &path
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
    )
}

fn render_index(cline_mcp_path: &str) -> Html<String> {
    // Fill only the initial HTML. Settings refreshes never write this
    // input, so typing (including clearing it) cannot race an async default.
    let escaped = cline_mcp_path
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&#39;");
    Html(include_str!("web/index.html").replace("{{CLINE_MCP_SETTINGS_PATH}}", &escaped))
}

async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("web/app.css"),
    )
}

async fn js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("web/app.js"),
    )
}

async fn api_state(State(state): State<UiState>) -> Json<StateView> {
    Json(permission_state_view(&state.app, &state.settings))
}

fn permission_state_view(app: &AppState, settings: &crate::settings::Settings) -> StateView {
    let mut view = app.view();
    for permission in &mut view.comment_permissions {
        permission.credential_active = Some(
            settings
                .entries()
                .iter()
                .filter_map(|entry| crate::github::Credential::from_entry(settings, entry))
                .any(|credential| {
                    app.comment_permissions(&permission.container, &credential.binding)
                        .iter()
                        .any(|grant| grant.id == permission.id)
                }),
        );
    }
    view
}

fn local_review_request(state: &UiState, headers: &axum::http::HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let Ok(url) = reqwest::Url::parse(&format!("http://{host}")) else {
        return false;
    };
    let hostname = url
        .host_str()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']');
    (hostname.eq_ignore_ascii_case("localhost")
        || hostname
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()))
        && url.port_or_known_default() == Some(state.ui_addr.port())
        && headers
            .get(header::ORIGIN)
            .is_none_or(|origin| origin.to_str().ok() == Some(format!("http://{host}").as_str()))
        && headers
            .get("sec-fetch-site")
            .is_none_or(|site| site != "cross-site")
}

async fn review_request(
    State(state): State<UiState>,
    Path(id): Path<uuid::Uuid>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !local_review_request(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            "review is only available from the host-local UI origin",
        )
            .into_response();
    }
    match state
        .app
        .reviews
        .inspect(id)
        .or_else(|| state.app.jobs.inspect(id))
    {
        Some(detail) => ([(header::CACHE_CONTROL, "no-store")], Json(detail)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "Request not retained (broker restarted or history limit reached).",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewDecision {
    fingerprint: String,
    decision: crate::review::Decision,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveTarget {
    fingerprint: String,
}
fn host_decision(state: &UiState, headers: &axum::http::HeaderMap) -> bool {
    local_review_request(state, headers)
        && headers.get("x-friendzone-review").is_some_and(|h| h == "1")
}
async fn resolve_github_target(
    State(state): State<UiState>,
    Path(id): Path<uuid::Uuid>,
    headers: axum::http::HeaderMap,
    Json(request): Json<ResolveTarget>,
) -> impl IntoResponse {
    if !host_decision(&state, &headers) {
        return (StatusCode::FORBIDDEN, "use host UI to resolve targets").into_response();
    }
    let result=async {
        let detail=state.app.reviews.detail(id).context("request no longer waiting")?;
        if detail.summary.fingerprint!=request.fingerprint {anyhow::bail!("fingerprint mismatch");}
        let context=detail.comment_context.context("request is not eligible for a narrow comment permission (shape or escrow credential unsupported)")?;
        let revision=state.app.comment_revision(&detail.summary.container).context("container removed")?;
        let credential=crate::github::Credential::current(&state.settings,&context.binding).context("credential changed; make a new request")?;
        let target=state.app.github.resolve(&context.subject_id,&credential).await?;
        if crate::github::Credential::current(&state.settings,&context.binding).is_none(){anyhow::bail!("credential changed during lookup");}
        state.app.reviews.set_resolved(id,&request.fingerprint,crate::github::Resolved{target,credential:context.binding.entry},revision)
    }.await;
    match result {
        Ok(detail) => Json(detail).into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveCommentPermission {
    fingerprint: String,
    resolution_id: uuid::Uuid,
}
async fn grant_comment_permission(
    State(state): State<UiState>,
    Path(id): Path<uuid::Uuid>,
    headers: axum::http::HeaderMap,
    Json(request): Json<SaveCommentPermission>,
) -> impl IntoResponse {
    if !host_decision(&state, &headers) {
        return (StatusCode::FORBIDDEN, "use host UI to grant permissions").into_response();
    }
    let result=async {
        let detail=state.app.reviews.detail(id).context("request no longer waiting")?;
        if detail.summary.fingerprint!=request.fingerprint || detail.resolution_id!=Some(request.resolution_id) {anyhow::bail!("review/target changed; resolve again");}
        let context=detail.comment_context.context("no supported comment command")?;
        let resolved=detail.resolved_target.context("resolve and inspect the GitHub target first")?;
        let credential=crate::github::Credential::current(&state.settings,&context.binding).context("credential changed; resolve a new request")?;
        let target=state.app.github.resolve(&context.subject_id,&credential).await?;
        if !resolved.target.same_identity(&target) || crate::github::Credential::current(&state.settings,&context.binding).is_none(){anyhow::bail!("target or credential changed; resolve again");}
        let current=state.app.reviews.detail(id).context("request no longer waiting")?;
        if current.resolution_id!=Some(request.resolution_id) || current.summary.expires_at<=chrono::Utc::now(){anyhow::bail!("target review expired or changed");}
        let grant=state.app.grant_reviewed_comment(id,&request.fingerprint,request.resolution_id,target)?;
        Ok::<_,anyhow::Error>(serde_json::json!({"id":grant,"message":"Permission saved for future requests. This pending request still needs Approve once or Deny."}))
    }.await;
    match result {
        Ok(body) => Json(body).into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}
async fn revoke_comment_permission(
    State(state): State<UiState>,
    Path((container, id)): Path<(String, uuid::Uuid)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !host_decision(&state, &headers) {
        return (StatusCode::FORBIDDEN, "use host UI to revoke permissions").into_response();
    }
    match state.app.revoke_comment_permission(&container, id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

async fn decide_request(
    State(state): State<UiState>,
    Path(id): Path<uuid::Uuid>,
    headers: axum::http::HeaderMap,
    Json(request): Json<ReviewDecision>,
) -> impl IntoResponse {
    // Custom header + no CORS blocks cross-origin form/fetch approvals.
    // This remains a privileged host-local API, not remote user auth.
    if !local_review_request(&state, &headers)
        || headers
            .get("x-friendzone-review")
            .and_then(|h| h.to_str().ok())
            != Some("1")
    {
        return (
            StatusCode::FORBIDDEN,
            "review decisions must come from the host UI",
        )
            .into_response();
    }
    let result = if state.app.jobs.contains(id) {
        state
            .app
            .jobs
            .decide(id, &request.fingerprint, request.decision)
    } else {
        state
            .app
            .reviews
            .decide(id, &request.fingerprint, request.decision)
    };
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
    }
}

async fn api_log(
    State(state): State<UiState>,
    axum::extract::Query(query): axum::extract::Query<crate::state::LogQuery>,
) -> Json<crate::state::LogPage> {
    Json(state.app.log_page(&query))
}

/// Live state over SSE: a full `StateView` snapshot on connect and on
/// every change (the watch channel coalesces bursts). Clients stay
/// dumb — render whatever arrives — and EventSource reconnects itself.
async fn state_events(State(state): State<UiState>) -> impl IntoResponse {
    let mut changes = state.app.subscribe();
    let app = state.app.clone();
    let settings = state.settings.clone();
    let stream = async_stream(move |emit| async move {
        loop {
            let view = permission_state_view(&app, &settings);
            let data = serde_json::to_string(&view).expect("serialize state view");
            if emit.send(data).await.is_err() {
                return; // client went away
            }
            if changes.changed().await.is_err() {
                return; // broker shutting down
            }
        }
    });
    axum::response::sse::Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new().interval(std::time::Duration::from_secs(15)),
    )
}

/// Adapts an emit-loop into the `Stream<Item = Result<Event, _>>` SSE
/// wants, with a small buffer so a slow client cannot back up state.
fn async_stream<F, Fut>(
    body: F,
) -> impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>
where
    F: FnOnce(tokio::sync::mpsc::Sender<String>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    tokio::spawn(body(tx));
    futures_util::stream::poll_fn(move |cx| {
        rx.poll_recv(cx)
            .map(|item| item.map(|data| Ok(axum::response::sse::Event::default().data(data))))
    })
}

#[derive(Deserialize)]
struct AddContainerRequest {
    name: String,
}

/// Registers a container ahead of traffic so its proxy credentials and
/// section exist before the VM boots.
async fn add_container(
    State(state): State<UiState>,
    Json(request): Json<AddContainerRequest>,
) -> impl IntoResponse {
    let name = request.name.trim().to_owned();
    if name.is_empty() || name.contains(':') || name.contains('@') {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "container names must be nonempty and contain no ':' or '@' (they become proxy usernames)",
        )
            .into_response();
    }
    container_policy_response(state.app.add_container(&name), StatusCode::CREATED)
}

/// Unregisters a container. Log rows remain for audit; a reconnecting
/// guest re-appears as a new container.
async fn remove_container(
    State(state): State<UiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    container_policy_response(state.app.remove_container(&id), StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ApproveRequest {
    /// Pin the container to the address it last connected from.
    #[serde(default)]
    pin_to_last_ip: bool,
}

/// Approves a pending join request (or re-approves a container).
async fn approve_container(
    State(state): State<UiState>,
    Path(id): Path<String>,
    Json(request): Json<ApproveRequest>,
) -> impl IntoResponse {
    container_policy_response(
        state.app.approve_container(&id, request.pin_to_last_ip),
        StatusCode::NO_CONTENT,
    )
}

#[derive(Deserialize)]
struct PinRequest {
    /// IP to pin to; null/empty clears the pin (any address).
    ip: Option<String>,
}

async fn set_container_pin(
    State(state): State<UiState>,
    Path(id): Path<String>,
    Json(request): Json<PinRequest>,
) -> impl IntoResponse {
    match request.ip.filter(|ip| !ip.trim().is_empty()) {
        None => {
            container_policy_response(state.app.set_pinned_ip(&id, None), StatusCode::NO_CONTENT)
        }
        Some(text) => match text.trim().parse() {
            Ok(ip) => container_policy_response(
                state.app.set_pinned_ip(&id, Some(ip)),
                StatusCode::NO_CONTENT,
            ),
            Err(_) => (StatusCode::UNPROCESSABLE_ENTITY, "not an IP address").into_response(),
        },
    }
}

#[derive(Deserialize)]
struct KillRequest {
    killed: bool,
}

async fn set_killed(
    State(state): State<UiState>,
    Path(id): Path<String>,
    Json(request): Json<KillRequest>,
) -> impl IntoResponse {
    container_policy_response(
        state.app.set_killed(id, request.killed),
        StatusCode::NO_CONTENT,
    )
}

fn container_policy_response(result: Result<()>, success: StatusCode) -> axum::response::Response {
    match result {
        Ok(()) => success.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")).into_response(),
    }
}

/// What this broker can bootstrap: the host binary's platform plus any
/// cross-built binaries in guest-bin/. Guests (and humans) check here
/// before downloading.
async fn bootstrap_targets(State(state): State<BootstrapState>) -> Json<serde_json::Value> {
    let mut targets: Vec<String> = state.guest_binaries.keys().cloned().collect();
    targets.sort();
    Json(serde_json::json!({
        "host_platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        "host_binary": "/bootstrap/fz",
        "guest_binaries": targets
            .iter()
            .map(|name| format!("/bootstrap/fz/{name}"))
            .collect::<Vec<_>>(),
    }))
}

/// Serves a cross-built guest binary by file name. The directory is
/// scanned at startup (new files need a broker restart), but content is
/// read per request, so rebuilding an already-known binary is picked up
/// live. Lookup is by exact name from the scanned map, never by a path
/// from the client.
async fn guest_binary(
    State(state): State<BootstrapState>,
    Path(target): Path<String>,
) -> impl IntoResponse {
    let Some(path) = state.guest_binaries.get(&target) else {
        return (
            StatusCode::NOT_FOUND,
            format!(
                "no guest binary '{target}'; available: {} (drop cross-built binaries into <data-dir>/guest-bin/ and restart)",
                state
                    .guest_binaries
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
            .into_response();
    };
    match tokio::fs::read(path).await {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename={target}"),
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("read {}: {error}", path.display()),
        )
            .into_response(),
    }
}

/// `/bootstrap/fz` serves the host's own binary; `/bootstrap/fz?linux`
/// (or `?win`, `?macos`, or any guest-bin prefix) picks a cross-built
/// one: bare query keys are matched as prefixes against guest-bin file
/// names, so `?linux` finds `fz-linux-x86_64`.
async fn binary(
    State(state): State<BootstrapState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let host_platform = std::env::consts::OS; // "windows" | "macos" | "linux"
    let wanted = query.unwrap_or_default().trim().to_lowercase();
    if let Some(target) = wanted.strip_prefix("target=") {
        let filename = match crate::bootstrap::target_filename(target) {
            Ok(name) => name,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
        let host = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        if target == host {
            return (
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                state.binary.as_ref().clone(),
            )
                .into_response();
        }
        // Exact platform AND architecture; no substring/fallback matching.
        let name = if state.guest_binaries.contains_key(&filename) {
            filename
        } else {
            format!("{filename}.exe")
        };
        return guest_binary(State(state), Path(name)).await.into_response();
    }
    let wanted = match wanted.as_str() {
        "" => String::new(),
        "win" | "windows" => "windows".to_owned(),
        "mac" | "macos" | "darwin" => "macos".to_owned(),
        other => other.to_owned(),
    };
    // No query, or asking for the host's own platform: serve ourselves.
    if wanted.is_empty() || wanted == host_platform {
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
                (
                    header::CONTENT_DISPOSITION,
                    if cfg!(windows) {
                        "attachment; filename=fz.exe".to_owned()
                    } else {
                        "attachment; filename=fz".to_owned()
                    },
                ),
            ],
            state.binary.as_ref().clone(),
        )
            .into_response();
    }
    // Otherwise find a guest binary whose name mentions the platform,
    // e.g. ?linux -> fz-linux-x86_64.
    let candidate = state
        .guest_binaries
        .iter()
        .find(|(name, _)| name.to_lowercase().contains(&wanted));
    match candidate {
        Some((name, path)) => match tokio::fs::read(path).await {
            Ok(bytes) => (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename={name}"),
                    ),
                ],
                bytes,
            )
                .into_response(),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("read {}: {error}", path.display()),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            format!(
                "no '{wanted}' build here (host is {host_platform}); build fz in the guest (cargo build --release) or add one to <data-dir>/guest-bin/"
            ),
        )
            .into_response(),
    }
}

async fn certificate(State(state): State<BootstrapState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=friendzone-ca.pem",
            ),
        ],
        state.cert.as_bytes().to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn async_guest_routes_return_immediately_and_host_api_controls_execution() {
        let dir = std::env::temp_dir().join(format!("fz-async-http-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "github".into(),
                hosts: vec!["api.github.com".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fake".into(),
                real_env: None,
                guest_env: None,
            })
            .unwrap();
        settings.set_secret("github", "test-host-secret").unwrap();
        let app = AppState::load(&dir).unwrap();
        app.add_container("guest").unwrap();
        app.add_container("other").unwrap();
        let registry = crate::mcp::ForwardRegistry::load(&dir, settings.clone()).unwrap();
        let guest = bootstrap_router(BootstrapState {
            cert: Arc::new("test".into()),
            binary: Arc::new(vec![]),
            guest_binaries: Arc::new(Default::default()),
            mcp: crate::mcp::McpState::new(app.clone(), registry.clone()),
            settings: settings.clone(),
            proxy_port: 8080,
        });
        let ui = ui_router(UiState {
            app: app.clone(),
            settings: settings.clone(),
            registry,
            oauth: Default::default(),
            cline: Default::default(),
            ui_addr: "127.0.0.1:8081".parse().unwrap(),
            bootstrap_addr: "127.0.0.1:8082".parse().unwrap(),
        });
        let request = |method: &str, path: &str, body: String, name: Option<&str>| {
            let mut builder = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(name) = name {
                builder = builder.header(
                    header::AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode(format!("{name}:x"))),
                );
            }
            let mut req = builder.body(Body::from(body)).unwrap();
            req.extensions_mut().insert(axum::extract::ConnectInfo(
                "127.0.0.1:23456".parse::<SocketAddr>().unwrap(),
            ));
            req
        };
        let payload=serde_json::json!({"request_key":"large","session_id":"s","query":"mutation($body:String!){addComment(input:{subjectId:\"ID\",body:$body}){clientMutationId}}","variables":{"body":"x".repeat(90000)}}).to_string();
        let denied = guest
            .clone()
            .oneshot(request("POST", "/guest/jobs", payload.clone(), None))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            guest.clone().oneshot(request(
                "POST",
                "/guest/jobs",
                payload.clone(),
                Some("guest"),
            )),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let value: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        let id = value["id"].as_str().unwrap();
        assert_eq!(value["status"], "pending");
        assert_eq!(app.view().pending_requests.len(), 1);
        let response = guest
            .clone()
            .oneshot(request(
                "GET",
                &format!("/guest/jobs/{id}?session_id=s"),
                "".into(),
                Some("other"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = guest
            .clone()
            .oneshot(request(
                "POST",
                &format!("/api/requests/{id}/decision"),
                "{}".into(),
                Some("guest"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = ui
            .clone()
            .oneshot(
                Request::get(format!("/api/requests/{id}"))
                    .header(header::HOST, "127.0.0.1:8081")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let detail: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(detail["asynchronous"].as_bool().unwrap());
        assert!(detail["body"].as_str().unwrap().len() > 65536);
        let decision =
            serde_json::json!({"fingerprint":detail["fingerprint"],"decision":"deny"}).to_string();
        let response = ui
            .oneshot(
                Request::post(format!("/api/requests/{id}/decision"))
                    .header(header::HOST, "127.0.0.1:8081")
                    .header("x-friendzone-review", "1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(decision))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = guest
            .clone()
            .oneshot(request(
                "GET",
                &format!("/guest/jobs/{id}?session_id=s"),
                "".into(),
                Some("guest"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["status"], "denied");
        assert!(value["terminal"].as_bool().unwrap());
        let response = guest
            .oneshot(request("POST", "/guest/jobs", payload, Some("guest")))
            .await
            .unwrap();
        let repeated: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_ne!(repeated["id"], id);
        assert_eq!(repeated["status"], "pending");
        assert_eq!(repeated["request_key"], "large");
        assert_eq!(app.view().pending_requests.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn github_queries_flow_and_pr_review_mutations_wait_for_host_decisions_over_real_tls() {
        use hudsucker::{Proxy, certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
        let dir = std::env::temp_dir().join(format!("fz-query-review-{}", uuid::Uuid::new_v4()));
        let files = crate::ca::AuthorityFiles::load_or_create(&dir).unwrap();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "github".into(),
                hosts: vec!["api.github.com".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fake-github".into(),
                real_env: None,
                guest_env: None,
            })
            .unwrap();
        settings.set_secret("github", "host-secret").unwrap();
        let state = AppState::default();
        state.add_container("guest").unwrap();
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let received = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let observed = received.clone();
        let upstream_task = tokio::spawn(async move {
            axum::serve(
                upstream,
                Router::new().fallback(post(
                    move |headers: axum::http::HeaderMap, body: String| {
                        let observed = observed.clone();
                        async move {
                            assert_eq!(headers["authorization"], "Bearer host-secret");
                            assert!(!headers.contains_key("proxy-authorization"));
                            let graphql_error = body.contains("OutcomeGraphqlError");
                            let http_error = body.contains("OutcomeHttpError");
                            observed.lock().unwrap().push(body);
                            (
                                if http_error { StatusCode::FORBIDDEN } else { StatusCode::OK },
                                Json(if graphql_error { serde_json::json!({"data":null,"errors":[{"message":"sensitive fixture error"}]}) } else { serde_json::json!({"data":{"ok":true}}) }),
                            )
                        }
                    },
                )),
            )
            .await
            .unwrap()
        });
        let ui_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_addr = ui_listener.local_addr().unwrap();
        let registry = crate::mcp::ForwardRegistry::load(&dir, settings.clone()).unwrap();
        let ui = ui_router(UiState {
            app: state.clone(),
            settings: settings.clone(),
            registry,
            oauth: Default::default(),
            cline: Default::default(),
            ui_addr,
            bootstrap_addr: "127.0.0.1:8082".parse().unwrap(),
        });
        let ui_task = tokio::spawn(async move { axum::serve(ui_listener, ui).await.unwrap() });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let connector = tower::service_fn(move |uri: hudsucker::hyper::Uri| {
            Box::pin(async move {
                assert_eq!(uri.host(), Some("api.github.com"));
                if uri.port_u16() == Some(444) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "fixture connection refused",
                    ));
                }
                tokio::net::TcpStream::connect(upstream_addr)
                    .await
                    .map(hudsucker::hyper_util::rt::TokioIo::new)
            })
        });
        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(RcgenAuthority::new(
                files.issuer().unwrap(),
                10,
                aws_lc_rs::default_provider(),
            ))
            .with_http_connector(connector)
            .with_http_handler(crate::proxy::EventHandler::new(
                state.clone(),
                settings.clone(),
                ui_addr.port(),
                8082,
            ))
            .build()
            .unwrap();
        let proxy_task = tokio::spawn(proxy.start());
        let guest = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(
                reqwest::Certificate::from_pem(files.cert_pem.as_bytes()).unwrap(),
            )
            .proxy(
                reqwest::Proxy::all(format!("http://{proxy_addr}"))
                    .unwrap()
                    .basic_auth("guest", "x"),
            )
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let host = reqwest::Client::builder().no_proxy().build().unwrap();
        let send = |url: &str, body: String| {
            let req = guest
                .post(url)
                // Real gh 2.100.0 wire shape: token scheme + merge queue preview.
                .header("authorization", "token fake-github")
                .header("graphql-features", "merge_queue")
                .header("x-github-api-version", "2022-11-28")
                .header("time-zone", "America/New_York")
                .header("user-agent", "GitHub CLI 2.100.0")
                .header("content-type", "application/json")
                .body(body);
            tokio::spawn(async move { req.send().await.unwrap() })
        };
        let mixed = "query Read { viewer { id } } mutation Write { createPullRequest(input:{repositoryId:\"repo\",headRefName:\"feature\",baseRefName:\"main\",title:\"new\"}){clientMutationId}}";
        let queries=vec![
            serde_json::json!({"query":"{ viewer { login } }"}).to_string(),
            serde_json::json!({"query":"query MutationInName($q:String!){search(query:$q,type:ISSUE){issueCount}}","variables":{"q":"mutation { addComment }"}}).to_string(),
            serde_json::json!({"query":"query($show:Boolean=true){...F} fragment F on Query { __schema @include(if:$show){queryType{name}} }"}).to_string(),
            serde_json::json!({"query":mixed,"operationName":"Read"}).to_string(),
            serde_json::json!({"query":format!("query Big {{ {} }}","viewer { id } ".repeat(300))}).to_string(),
        ];
        for query in &queries {
            let response = send(crate::github::ENDPOINT, query.clone()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.json::<serde_json::Value>().await.unwrap()["data"]["ok"],
                true
            );
            assert_eq!(received.lock().unwrap().last(), Some(query));
            assert!(
                state.reviews.summaries().is_empty(),
                "read creates no inbox item"
            );
            let row = &state.view().requests[0];
            assert!(matches!(row.verdict, crate::state::Verdict::Allowed));
            assert!(
                row.detail
                    .as_deref()
                    .unwrap()
                    .contains("read-only GitHub GraphQL")
            );
        }
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/github_mutations.json")).unwrap();
        let mut mutations: Vec<_> = fixtures
            .as_array()
            .unwrap()
            .iter()
            .map(|fixture| {
                (
                    crate::github::ENDPOINT.to_owned(),
                    fixture["body"].to_string(),
                    fixture["action"].as_str().map(str::to_owned),
                )
            })
            .collect();
        // REST workflows use the same one-shot gate, without special grants.
        mutations.extend([
            ("https://api.github.com/repos/owner/repo/pulls".into(),r#"{"title":"new PR","head":"feature","base":"main"}"#.into(),None),
            ("https://api.github.com/repos/owner/repo/pulls/12/comments".into(),r#"{"body":"review comment","path":"file.rs","line":4,"side":"RIGHT","commit_id":"abc"}"#.into(),None),
            (crate::github::ENDPOINT.into(),serde_json::json!({"query":mixed,"operationName":"Write"}).to_string(),Some("Create pull request".into())),
            (crate::github::ENDPOINT.into(),serde_json::json!({"query":mixed}).to_string(),None),
            (format!("{}?operationName=Write",crate::github::ENDPOINT),serde_json::json!({"query":mixed,"operationName":"Read"}).to_string(),None),
            (crate::github::ENDPOINT.into(),serde_json::json!({"query":"mutation OutcomeGraphqlError { createPullRequest(input:{repositoryId:\"id\",baseRefName:\"main\",headRefName:\"feature\",title:\"text\"}){clientMutationId} }"}).to_string(),None),
            (crate::github::ENDPOINT.into(),serde_json::json!({"query":"mutation OutcomeHttpError { createPullRequest(input:{repositoryId:\"id\",baseRefName:\"main\",headRefName:\"feature\",title:\"text\"}){clientMutationId} }"}).to_string(),None),
            ("https://api.github.com:444/graphql".into(),serde_json::json!({"query":"mutation OutcomeConnectionError { createPullRequest(input:{repositoryId:\"id\",baseRefName:\"main\",headRefName:\"feature\",title:\"text\"}){clientMutationId} }"}).to_string(),None),
        ]);
        for (url, body, action) in mutations {
            for decision in ["deny", "approve"] {
                let before = received.lock().unwrap().len();
                let pending = send(&url, body.clone());
                let summary = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                    loop {
                        if let Some(s) = state.reviews.summaries().into_iter().next() {
                            break s;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert!(!pending.is_finished());
                assert_eq!(received.lock().unwrap().len(), before);
                let endpoint = format!("http://{ui_addr}/api/requests/{}", summary.id);
                let detail: serde_json::Value = host
                    .get(&endpoint)
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert_eq!(detail["body"], body);
                assert_eq!(detail["comment_permission_supported"], false);
                if let Some(action) = &action {
                    assert_eq!(
                        detail["graphql"]["analysis"]["fields"][0]["action"],
                        *action
                    );
                }
                // A read still flows while a mutation is awaiting a decision.
                let read = send(crate::github::ENDPOINT, queries[0].clone())
                    .await
                    .unwrap();
                assert_eq!(read.status(), StatusCode::OK);
                assert_eq!(state.reviews.summaries().len(), 1);
                let response = host
                    .post(format!("{endpoint}/decision"))
                    .header("x-friendzone-review", "1")
                    .json(
                        &serde_json::json!({"fingerprint":summary.fingerprint,"decision":decision}),
                    )
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::NO_CONTENT);
                let response = pending.await.unwrap();
                let connection_error = url.contains(":444/");
                let expected_http = if connection_error {
                    StatusCode::BAD_GATEWAY
                } else if body.contains("OutcomeHttpError") {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::OK
                };
                if decision == "approve" {
                    assert_eq!(response.status(), expected_http);
                    if !connection_error {
                        assert_eq!(received.lock().unwrap().last(), Some(&body));
                    }
                } else {
                    assert_eq!(response.status(), StatusCode::FORBIDDEN);
                }
                let response_body = response.text().await.unwrap();
                if decision == "approve" && body.contains("OutcomeGraphqlError") {
                    assert!(
                        response_body.contains("sensitive fixture error"),
                        "client still receives original response"
                    );
                }
                assert_eq!(
                    received.lock().unwrap().len(),
                    before + 1 + usize::from(decision == "approve" && !connection_error)
                );
                assert!(state.reviews.summaries().is_empty());
                let outcome: serde_json::Value = host
                    .get(&endpoint)
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert_eq!(
                    outcome["status"],
                    if decision == "deny" {
                        "denied"
                    } else if connection_error {
                        "upstream_error"
                    } else if body.contains("OutcomeGraphqlError") {
                        "graphql_error"
                    } else {
                        "response_received"
                    }
                );
                assert_eq!(outcome["body"], body);
                if decision == "approve" {
                    assert_eq!(outcome["http_status"], expected_http.as_u16());
                }
                assert!(outcome["outcome"].as_str().is_some());
                assert!(!outcome.to_string().contains("host-secret"));
                assert!(
                    !outcome.to_string().contains("sensitive fixture error"),
                    "upstream error payload is not copied into review history"
                );
                assert!(
                    state.reviews.detail(summary.id).is_none(),
                    "retained detail cannot authorize a grant"
                );
                assert_eq!(host.post(format!("{endpoint}/decision")).header("x-friendzone-review","1").json(&serde_json::json!({"fingerprint":summary.fingerprint,"decision":"approve"})).send().await.unwrap().status(),StatusCode::CONFLICT);
            }
        }
        // Reproduce an enclosing client's shorter deadline: it must cancel the
        // pending review, not look like broker expiry or leave a replayable write.
        let before = received.lock().unwrap().len();
        let timed_request = guest.post(crate::github::ENDPOINT)
            .header("authorization", "token fake-github")
            .header("graphql-features", "merge_queue")
            .json(&serde_json::json!({"query":"mutation { convertPullRequestToDraft(input:{pullRequestId:\"PR_fixture\"}){clientMutationId} }"}))
            .timeout(std::time::Duration::from_millis(750));
        let timed = tokio::spawn(async move { timed_request.send().await });
        let waiting = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Some(summary) = state.reviews.summaries().into_iter().next() {
                    break summary;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(timed.await.unwrap().unwrap_err().is_timeout());
        let cancelled = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let item = state.reviews.inspect(waiting.id).unwrap();
                if item.summary.status != crate::review::Status::Pending {
                    break item;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(cancelled.summary.status, crate::review::Status::Cancelled);
        assert_eq!(
            received.lock().unwrap().len(),
            before,
            "timed-out write never forwarded"
        );
        assert!(
            state
                .reviews
                .decide(
                    waiting.id,
                    &waiting.fingerprint,
                    crate::review::Decision::Approve
                )
                .is_err()
        );
        ui_task.abort();
        proxy_task.abort();
        upstream_task.abort();
        let _ = ui_task.await;
        let _ = proxy_task.await;
        let _ = upstream_task.await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn verified_comment_permission_flows_through_host_api_and_real_mitm_proxy() {
        use hudsucker::{Proxy, certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir =
            std::env::temp_dir().join(format!("fz-comment-integration-{}", uuid::Uuid::new_v4()));
        let files = crate::ca::AuthorityFiles::load_or_create(&dir).unwrap();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "github".into(),
                hosts: vec!["api.github.com".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fake-github".into(),
                real_env: None,
                guest_env: None,
            })
            .unwrap();
        settings.set_secret("github", "host-secret").unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let lookups = Arc::new(AtomicUsize::new(0));
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let hits_seen = hits.clone();
        let lookups_seen = lookups.clone();
        let upstream_task = tokio::spawn(async move {
            axum::serve(upstream,Router::new().route("/graphql",post(move |headers:axum::http::HeaderMap,Json(json):Json<serde_json::Value>|{
            let hits=hits_seen.clone();let lookups=lookups_seen.clone(); async move {
                assert_eq!(headers["authorization"],"Bearer host-secret");
                if json["query"].as_str().unwrap().starts_with("query FriendzoneTarget") {
                    crate::github::tests::assert_lookup(&json);lookups.fetch_add(1,Ordering::SeqCst);
                    let mut response=crate::github::tests::response();
                    if json["variables"]["id"]=="wrong-target" {response["data"]["node"]["id"]="wrong-target".into();response["data"]["node"]["number"]=483.into();response["data"]["node"]["url"]="https://github.com/cline/cline/issues/483".into();}
                    Json(response)
                } else {
                    assert_eq!(json["operationName"],"FriendzoneComment");assert_eq!(json["variables"]["input"]["subjectId"],"canonical");
                    assert_eq!(json["variables"]["input"]["body"],"second comment\nmutation { deleteIssue } is just text");
                    assert_eq!(headers["user-agent"],"Friendzone comment permission");assert!(!headers.contains_key("proxy-authorization"));
                    hits.fetch_add(1,Ordering::SeqCst);Json(serde_json::json!({"data":{"alias":{"clientMutationId":null}}}))
                }
            }
        }))).await.unwrap()
        });
        let mut state = AppState::load(&dir).unwrap();
        state.github = crate::github::Client::for_test(&format!("http://{upstream_addr}/graphql"));
        state.add_container("guest").unwrap();
        state.add_container("other").unwrap();
        let registry = crate::mcp::ForwardRegistry::load(&dir, settings.clone()).unwrap();
        let ui_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_addr = ui_listener.local_addr().unwrap();
        let ui = ui_router(UiState {
            app: state.clone(),
            settings: settings.clone(),
            registry,
            oauth: Default::default(),
            cline: Default::default(),
            ui_addr,
            bootstrap_addr: "127.0.0.1:8082".parse().unwrap(),
        });
        let ui_task = tokio::spawn(async move { axum::serve(ui_listener, ui).await.unwrap() });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connector = tower::service_fn(move |uri: hudsucker::hyper::Uri| {
            Box::pin(async move {
                assert_eq!(uri.host(), Some("api.github.com"));
                tokio::net::TcpStream::connect(upstream_addr)
                    .await
                    .map(hudsucker::hyper_util::rt::TokioIo::new)
            })
        });
        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(RcgenAuthority::new(
                files.issuer().unwrap(),
                10,
                aws_lc_rs::default_provider(),
            ))
            .with_http_connector(connector)
            .with_http_handler(crate::proxy::EventHandler::new(
                state.clone(),
                settings.clone(),
                ui_addr.port(),
                8082,
            ))
            .build()
            .unwrap();
        let proxy_task = tokio::spawn(proxy.start());
        let guest = |name: &str| {
            reqwest::Client::builder()
                .use_rustls_tls()
                .add_root_certificate(
                    reqwest::Certificate::from_pem(files.cert_pem.as_bytes()).unwrap(),
                )
                .proxy(
                    reqwest::Proxy::all(format!("http://{address}"))
                        .unwrap()
                        .basic_auth(name, "x"),
                )
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap()
        };
        let client = guest("guest");
        let other = guest("other");
        let host = reqwest::Client::builder().no_proxy().build().unwrap();
        let body = |subject: &str, text: &str| serde_json::json!({"query":"mutation GuestName($target:ID!,$body:String!){alias:addComment(input:{subjectId:$target,body:$body}){clientMutationId}}","variables":{"target":subject,"body":text}});
        let send = |client: reqwest::Client, body: serde_json::Value| {
            tokio::spawn(async move {
                client
                    .post(crate::github::ENDPOINT)
                    .header("authorization", "Bearer fake-github")
                    .json(&body)
                    .send()
                    .await
                    .unwrap()
            })
        };
        async fn pending(state: &AppState) -> crate::review::Summary {
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    if let Some(summary) = state.reviews.summaries().into_iter().next() {
                        break summary;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap()
        }
        let first = send(client.clone(), body("legacy-alias", "first comment"));
        let summary = pending(&state).await;
        let url = format!("http://{ui_addr}/api/requests/{}", summary.id);
        let detail: serde_json::Value = host.get(&url).send().await.unwrap().json().await.unwrap();
        assert_eq!(detail["comment_permission_supported"], true);
        let resolve = serde_json::json!({"fingerprint":summary.fingerprint});
        assert_eq!(
            host.post(format!("{url}/github-target"))
                .json(&resolve)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
        let resolved: serde_json::Value = host
            .post(format!("{url}/github-target"))
            .header("x-friendzone-review", "1")
            .json(&resolve)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            resolved["resolved_target"]["target"]["repository"],
            "cline/cline"
        );
        assert_eq!(resolved["resolved_target"]["target"]["number"], 482);
        assert!(!resolved.to_string().contains("host-secret"));
        assert!(resolved.get("comment_context").is_none());
        let grant_body = serde_json::json!({"fingerprint":summary.fingerprint,"resolution_id":resolved["resolution_id"]});
        assert_eq!(
            host.post(format!("{url}/comment-permission"))
                .header("x-friendzone-review", "1")
                .header("origin", "https://evil.test")
                .json(&grant_body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = host
            .post(format!("{url}/comment-permission"))
            .header("x-friendzone-review", "1")
            .json(&grant_body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let id = response.json::<serde_json::Value>().await.unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(!first.is_finished());
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "grant must not release waiting request"
        );
        state
            .reviews
            .decide(
                summary.id,
                &summary.fingerprint,
                crate::review::Decision::Deny,
            )
            .unwrap();
        assert_eq!(first.await.unwrap().status(), StatusCode::FORBIDDEN);
        assert_eq!(
            AppState::load(&dir)
                .unwrap()
                .view()
                .comment_permissions
                .len(),
            1
        );
        let response = send(
            client.clone(),
            body(
                "legacy-alias",
                "second comment\nmutation { deleteIssue } is just text",
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(state.reviews.summaries().is_empty());
        assert!(state.view().requests.iter().any(|r| {
            r.detail
                .as_deref()
                .is_some_and(|d| d.contains("broker-reconstructed addComment"))
        }));
        for (client, body) in [
            (client.clone(), body("wrong-target", "no")),
            (other, body("canonical", "no")),
            (
                client.clone(),
                serde_json::json!({"query":"mutation{addComment(input:{subjectId:\"canonical\",body:\"x\"}){clientMutationId}closeIssue(input:{issueId:\"canonical\"}){clientMutationId}}"}),
            ),
        ] {
            let task = send(client, body);
            let summary = pending(&state).await;
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            state
                .reviews
                .decide(
                    summary.id,
                    &summary.fingerprint,
                    crate::review::Decision::Deny,
                )
                .unwrap();
            assert_eq!(task.await.unwrap().status(), StatusCode::FORBIDDEN);
        }
        settings.set_secret("github", "rotated").unwrap();
        let task = send(client.clone(), body("canonical", "no"));
        let summary = pending(&state).await;
        state
            .reviews
            .decide(
                summary.id,
                &summary.fingerprint,
                crate::review::Decision::Deny,
            )
            .unwrap();
        assert_eq!(task.await.unwrap().status(), StatusCode::FORBIDDEN);
        settings.set_secret("github", "host-secret").unwrap();
        assert_eq!(
            host.delete(format!(
                "http://{ui_addr}/api/containers/guest/comment-permissions/{id}"
            ))
            .header("x-friendzone-review", "1")
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::NO_CONTENT
        );
        let task = send(client, body("canonical", "no"));
        let summary = pending(&state).await;
        state
            .reviews
            .decide(
                summary.id,
                &summary.fingerprint,
                crate::review::Decision::Deny,
            )
            .unwrap();
        assert_eq!(task.await.unwrap().status(), StatusCode::FORBIDDEN);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(
            AppState::load(&dir)
                .unwrap()
                .view()
                .comment_permissions
                .is_empty()
        );
        ui_task.abort();
        proxy_task.abort();
        upstream_task.abort();
        let _ = ui_task.await;
        let _ = proxy_task.await;
        let _ = upstream_task.await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn real_mitm_graphql_review_api_releases_exact_request_once_to_local_upstream() {
        use hudsucker::{Proxy, certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir =
            std::env::temp_dir().join(format!("fz-review-integration-{}", uuid::Uuid::new_v4()));
        let files = crate::ca::AuthorityFiles::load_or_create(&dir).unwrap();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "github".into(),
                hosts: vec!["api.github.com".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fake-github".into(),
                guest_env: None,
                real_env: None,
            })
            .unwrap();
        settings.set_secret("github", "host-secret").unwrap();
        let registry = crate::mcp::ForwardRegistry::load(&dir, settings.clone()).unwrap();
        let state = AppState::default();
        state.add_container("guest").unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let payload = r#"{"query":"mutation Add($target: ID!, $text: String!) { harmless: addComment(input: {subjectId: $target, body: $text}) { clientMutationId } }","variables":{"target":"opaque-target","text":"<script>not HTML</script>"}}"#;
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            axum::serve(
                upstream,
                Router::new().route(
                    "/graphql",
                    post(move |headers: axum::http::HeaderMap, body: String| {
                        let observed = observed.clone();
                        async move {
                            assert_eq!(body, payload);
                            assert_eq!(headers["authorization"], "Bearer host-secret");
                            assert_eq!(headers["x-review-test"], "unchanged");
                            assert!(!headers.contains_key("proxy-authorization"));
                            observed.fetch_add(1, Ordering::SeqCst);
                            (
                                StatusCode::CREATED,
                                Json(serde_json::json!({"data":{"ok":true}})),
                            )
                        }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let ui_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_addr = ui_listener.local_addr().unwrap();
        let ui = ui_router(UiState {
            app: state.clone(),
            settings: settings.clone(),
            registry,
            oauth: Default::default(),
            cline: Default::default(),
            ui_addr,
            bootstrap_addr: "127.0.0.1:8082".parse().unwrap(),
        });
        let ui_task = tokio::spawn(async move {
            axum::serve(ui_listener, ui).await.unwrap();
        });
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        // Only the test connector substitutes networking: the production
        // handler sees the true GitHub HTTPS URL and TLS interception path.
        // No DNS/network access to GitHub can occur in this test.
        let connector = tower::service_fn(move |uri: hudsucker::hyper::Uri| {
            Box::pin(async move {
                assert_eq!(uri.host(), Some("api.github.com"));
                tokio::net::TcpStream::connect(upstream_addr)
                    .await
                    .map(hudsucker::hyper_util::rt::TokioIo::new)
            })
        });
        let proxy = Proxy::builder()
            .with_listener(proxy_listener)
            .with_ca(RcgenAuthority::new(
                files.issuer().unwrap(),
                10,
                aws_lc_rs::default_provider(),
            ))
            .with_http_connector(connector)
            .with_http_handler(crate::proxy::EventHandler::new(
                state.clone(),
                settings,
                ui_addr.port(),
                8082,
            ))
            .build()
            .unwrap();
        let proxy_task = tokio::spawn(proxy.start());
        let guest = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(
                reqwest::Certificate::from_pem(files.cert_pem.as_bytes()).unwrap(),
            )
            .proxy(
                reqwest::Proxy::all(format!("http://{proxy_addr}"))
                    .unwrap()
                    .basic_auth("guest", "x"),
            )
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let host = reqwest::Client::builder().no_proxy().build().unwrap();
        for decision in ["approve", "deny"] {
            let guest = guest.clone();
            let pending = tokio::spawn(async move {
                guest
                    .post("https://api.github.com/graphql")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer fake-github")
                    .header("x-review-test", "unchanged")
                    .body(payload)
                    .send()
                    .await
                    .unwrap()
            });
            let summary = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    if let Some(summary) = state.reviews.summaries().into_iter().next() {
                        break summary;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(!pending.is_finished());
            assert_eq!(
                hits.load(Ordering::SeqCst),
                if decision == "approve" { 0 } else { 1 }
            );
            let url = format!("http://{ui_addr}/api/requests/{}", summary.id);
            let snapshot = host
                .get(format!("http://{ui_addr}/api/state"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(!snapshot.contains(payload));
            assert!(!snapshot.contains("host-secret"));
            let response = host.get(&url).send().await.unwrap();
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let detail: serde_json::Value = response.json().await.unwrap();
            assert_eq!(detail["body"], payload);
            assert_eq!(detail["graphql"]["status"], "parsed");
            let analysis = &detail["graphql"]["analysis"];
            assert_eq!(analysis["operation_type"], "mutation");
            assert_eq!(analysis["fields"][0]["field"], "addComment");
            assert_eq!(analysis["fields"][0]["response_name"], "harmless");
            assert_eq!(analysis["fields"][0]["target"]["id"], "opaque-target");
            assert_eq!(
                analysis["fields"][0]["comment_body"],
                "<script>not HTML</script>"
            );
            assert!(
                analysis["formatted_document"]
                    .as_str()
                    .unwrap()
                    .contains('\n')
            );
            assert!(!detail.to_string().contains("fake-github"));
            assert!(!detail.to_string().contains("host-secret"));
            let body = serde_json::json!({"fingerprint":summary.fingerprint,"decision":decision});
            assert_eq!(
                host.post(format!("{url}/decision"))
                    .json(&body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                host.post(format!("{url}/decision"))
                    .header("x-friendzone-review", "1")
                    .header("origin", "https://evil.test")
                    .json(&body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                host.get(&url)
                    .header("host", format!("evil.test:{}", ui_addr.port()))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
            let response = host
                .post(format!("{url}/decision"))
                .header("x-friendzone-review", "1")
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                host.post(format!("{url}/decision"))
                    .header("x-friendzone-review", "1")
                    .json(&body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::CONFLICT
            );
            let response = pending.await.unwrap();
            if decision == "approve" {
                assert_eq!(response.status(), StatusCode::CREATED);
                assert_eq!(
                    response.json::<serde_json::Value>().await.unwrap()["data"]["ok"],
                    true
                );
            } else {
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert!(response.text().await.unwrap().contains("denied by host"));
            }
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            assert!(state.reviews.summaries().is_empty());
        }
        ui_task.abort();
        proxy_task.abort();
        upstream_task.abort();
        let _ = ui_task.await;
        let _ = proxy_task.await;
        let _ = upstream_task.await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn host_oauth_callback_enables_guest_forward_without_exposing_tokens() {
        let fixture = crate::mcp_oauth::tests::Fixture::new().await;
        let settings = fixture.settings.clone();
        let registry =
            crate::mcp::ForwardRegistry::load(settings.data_dir(), settings.clone()).unwrap();
        registry
            .save(
                serde_json::from_value(serde_json::json!([{
                    "name":"Linear", "url":fixture.url, "oauth":true,
                    "tools":["read"], "guests":["scratch-kali"]
                }]))
                .unwrap(),
            )
            .unwrap();
        let app = AppState::default();
        app.add_container("scratch-kali").unwrap();
        let oauth = crate::mcp_oauth::OauthFlows::default();
        let forward = registry.get("Linear").unwrap();
        let url = oauth
            .start(
                forward.oauth_session.clone(),
                "http://127.0.0.1:8081/oauth/callback",
                Some("read".into()),
            )
            .await
            .unwrap();
        let authorize = reqwest::Url::parse(&url).unwrap();
        let state_id = authorize
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let ui = ui_router(UiState {
            app: app.clone(),
            settings: settings.clone(),
            registry: registry.clone(),
            oauth,
            cline: crate::oauth::ClineFlows::default(),
            ui_addr: "127.0.0.1:8081".parse().unwrap(),
            bootstrap_addr: "172.31.208.1:8082".parse().unwrap(),
        });
        let request = |uri: String| Request::get(uri).body(Body::empty()).unwrap();
        let callback = ui
            .clone()
            .oneshot(request(format!(
                "/oauth/callback?state={state_id}&code=authorization-code"
            )))
            .await
            .unwrap();
        assert_eq!(callback.status(), StatusCode::OK);
        let callback_text = axum::body::to_bytes(callback.into_body(), 8192)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&callback_text).contains("access-1"));
        let status = ui
            .clone()
            .oneshot(request("/api/mcp/Linear/oauth/status".into()))
            .await
            .unwrap();
        let status: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(status.into_body(), 8192)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status["state"], "connected");
        let bootstrap = bootstrap_router(BootstrapState {
            cert: Arc::new(String::new()),
            binary: Arc::new(vec![]),
            guest_binaries: Arc::default(),
            mcp: crate::mcp::McpState::new(app, registry),
            settings,
            proxy_port: 8080,
        });
        let make_guest = |auth: bool| {
            let mut builder =
                Request::post("/mcp/Linear").header("content-type", "application/json");
            if auth {
                builder = builder.header("authorization", "Basic c2NyYXRjaC1rYWxpOng=");
            }
            let mut request = builder
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                ))
                .unwrap();
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                "127.0.0.1:2345".parse::<SocketAddr>().unwrap(),
            ));
            request
        };
        let guest = bootstrap.clone().oneshot(make_guest(true)).await.unwrap();
        let text = axum::body::to_bytes(guest.into_body(), 8192).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&text).unwrap()["result"]["tools"],
            serde_json::json!([{"name":"read"}])
        );
        assert!(!String::from_utf8_lossy(&text).contains("access-1"));
        let missing = bootstrap.clone().oneshot(make_guest(false)).await.unwrap();
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);
        assert!(!missing.headers().contains_key(header::WWW_AUTHENTICATE));
        let text = axum::body::to_bytes(missing.into_body(), 8192)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&text).contains("Copy Cline configuration"));
        assert_eq!(
            ui.clone()
                .oneshot(request(format!(
                    "/oauth/callback?state={state_id}&code=replay"
                )))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let disconnected = ui
            .clone()
            .oneshot(
                Request::delete("/api/mcp/Linear/oauth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disconnected.status(), StatusCode::NO_CONTENT);
        let guest = bootstrap.oneshot(make_guest(true)).await.unwrap();
        assert_eq!(
            guest.status(),
            StatusCode::OK,
            "upstream missing OAuth is a JSON-RPC error, not guest OAuth challenge"
        );
        let text = axum::body::to_bytes(guest.into_body(), 8192).await.unwrap();
        assert!(String::from_utf8_lossy(&text).contains("Authorize in Friendzone"));
        let list = ui.oneshot(request("/api/mcp".into())).await.unwrap();
        let text = axum::body::to_bytes(list.into_body(), 8192).await.unwrap();
        assert!(!String::from_utf8_lossy(&text).contains("refresh-1"));
    }

    #[test]
    fn guest_endpoints_use_bootstrap_address_and_one_path_per_forward() {
        let addr = "172.31.208.1:9092".parse().unwrap();
        assert_eq!(
            guest_mcp_endpoint(addr, None, "linear").unwrap(),
            "http://172.31.208.1:9092/mcp/linear"
        );
        assert_eq!(
            guest_mcp_endpoint(addr, None, "github").unwrap(),
            "http://172.31.208.1:9092/mcp/github"
        );
        assert_eq!(
            guest_mcp_endpoint(addr, Some("broker.local"), "linear").unwrap(),
            "http://broker.local:9092/mcp/linear"
        );
        assert_eq!(
            guest_mcp_endpoint("[fd00::1]:8082".parse().unwrap(), None, "linear").unwrap(),
            "http://[fd00::1]:8082/mcp/linear"
        );
        assert_eq!(
            guest_mcp_endpoint(addr, Some("fd00::2"), "linear").unwrap(),
            "http://[fd00::2]:9092/mcp/linear"
        );
        assert_eq!(
            guest_mcp_endpoint(addr, Some("[fd00::2]"), "linear").unwrap(),
            "http://[fd00::2]:9092/mcp/linear"
        );
        for wildcard in ["0.0.0.0:8082", "[::]:8082"] {
            let addr = wildcard.parse().unwrap();
            assert!(guest_mcp_endpoint(addr, None, "linear").is_err());
            assert_eq!(
                guest_mcp_endpoint(addr, Some("broker.local"), "linear").unwrap(),
                "http://broker.local:8082/mcp/linear"
            );
        }
        for invalid in [
            "http://broker.local",
            "broker.local:80",
            "broker.local:9999",
            "user@broker.local",
            "broker.local/path",
            "broker.local?q=1",
            "broker.local#fragment",
            "0.0.0.0",
            "[::]",
            "bad host",
        ] {
            assert!(
                guest_mcp_endpoint(addr, Some(invalid), "linear").is_err(),
                "accepted invalid host {invalid}"
            );
        }
    }

    #[test]
    fn index_escapes_default_path_in_editable_input() {
        let Html(html) = render_index("/home/a&b/\"<Cline>'/settings.json");
        let input = html
            .lines()
            .find(|line| line.contains("id=\"mcp-cline-path\""))
            .unwrap();
        assert!(input.contains("value=\"/home/a&amp;b/&quot;&lt;Cline&gt;&#39;/settings.json\""));
        assert!(!input.contains("readonly"));
        assert!(!input.contains("disabled"));
        assert!(!html.contains("{{CLINE_MCP_SETTINGS_PATH}}"));
    }

    #[tokio::test]
    async fn management_save_and_guest_auth_share_the_live_registry() {
        let settings = test_settings();
        let registry =
            crate::mcp::ForwardRegistry::load(settings.data_dir(), settings.clone()).unwrap();
        let app = AppState::default();
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        app.authorize("guest", peer.ip());
        app.approve_container("guest", true).unwrap();
        let ui = ui_router(UiState {
            app: app.clone(),
            settings: settings.clone(),
            registry: registry.clone(),
            oauth: crate::mcp_oauth::OauthFlows::default(),
            cline: crate::oauth::ClineFlows::default(),
            ui_addr: "127.0.0.1:8081".parse().unwrap(),
            bootstrap_addr: "172.31.208.1:8082".parse().unwrap(),
        });
        let page = ui
            .clone()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        let body = axum::body::to_bytes(page.into_body(), 64 * 1024)
            .await
            .unwrap();
        let default =
            crate::mcp_import::default_settings_path().expect("test host has a home directory");
        assert!(default.is_absolute());
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            render_index(&default.to_string_lossy()).0
        );
        let response = ui
            .clone()
            .oneshot(
                Request::get("/api/bootstrap/commands?host=192.0.2.44&container=scratch-kali")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 32 * 1024)
            .await
            .unwrap();
        let commands: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(commands["broker"], "http://192.0.2.44:8082");
        assert!(
            commands["sh_url"]
                .as_str()
                .unwrap()
                .contains("/bootstrap/setup?shell=sh")
        );
        assert!(
            commands["powershell_url"]
                .as_str()
                .unwrap()
                .contains("shell=powershell")
        );
        assert!(!commands.to_string().contains("8081"));
        let bootstrap = bootstrap_router(BootstrapState {
            cert: Arc::new(String::new()),
            binary: Arc::new(vec![]),
            guest_binaries: Arc::default(),
            mcp: crate::mcp::McpState::new(app.clone(), registry.clone()),
            settings: settings.clone(),
            proxy_port: 8080,
        });
        let config = serde_json::json!([{"name":"test", "url":"https://example.invalid/mcp", "tools":[], "guests":["guest"]}]);
        let saved = ui
            .clone()
            .oneshot(
                Request::put("/api/mcp/config")
                    .header("content-type", "application/json")
                    .body(Body::from(config.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(saved.status(), StatusCode::OK);
        let generated = ui
            .clone()
            .oneshot(
                Request::get("/api/mcp/test/guest-config?guest=guest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(generated.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(generated.into_body(), 8192)
            .await
            .unwrap();
        let generated: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let transport =
            &generated["cline_config"]["mcpServers"]["test-via-friendzone"]["transport"];
        assert_eq!(transport["type"], "streamableHttp");
        assert_eq!(transport["url"], "http://172.31.208.1:8082/mcp/test");
        let authorization = transport["headers"]["Authorization"].as_str().unwrap();
        assert_eq!(
            crate::proxy::basic_username(authorization).as_deref(),
            Some("guest")
        );
        assert_eq!(
            transport["headers"].as_object().unwrap().len(),
            1,
            "no upstream headers copied"
        );
        assert_eq!(generated["warnings"], serde_json::json!([]));
        let endpoint = reqwest::Url::parse(transport["url"].as_str().unwrap()).unwrap();
        let request = |auth: bool, address: SocketAddr| {
            // Consume the generated instructions through the real guest route.
            let mut builder =
                Request::post(endpoint.path()).header("content-type", "application/json");
            if auth {
                builder = builder.header("authorization", authorization);
            }
            let mut request = builder
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
                ))
                .unwrap();
            request
                .extensions_mut()
                .insert(axum::extract::ConnectInfo(address));
            request
        };
        assert_eq!(
            bootstrap
                .clone()
                .oneshot(request(false, peer))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let allowed = bootstrap
            .clone()
            .oneshot(request(true, peer))
            .await
            .unwrap();
        let body = axum::body::to_bytes(allowed.into_body(), 4096)
            .await
            .unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&body)
                .unwrap()
                .get("result")
                .is_some()
        );
        let wrong_ip = bootstrap
            .clone()
            .oneshot(request(true, "127.0.0.2:12345".parse().unwrap()))
            .await
            .unwrap();
        let body = axum::body::to_bytes(wrong_ip.into_body(), 4096)
            .await
            .unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&body)
                .unwrap()
                .get("error")
                .is_some()
        );
        let invalid = ui
            .clone()
            .oneshot(
                Request::put("/api/mcp/config")
                    .body(Body::from("[null]"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(registry.configs().len(), 1);
        let page = ui
            .oneshot(
                Request::get("/api/log?search=IP%20pin&verdict=blocked")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(page.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["requests"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            bootstrap
                .oneshot(
                    Request::get("/api/mcp/import/cline")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        std::fs::remove_dir_all(settings.data_dir()).unwrap();
    }

    #[tokio::test]
    async fn guest_instructions_warn_without_granting_access() {
        let settings = test_settings();
        let registry =
            crate::mcp::ForwardRegistry::load(settings.data_dir(), settings.clone()).unwrap();
        let app = AppState::default();
        app.authorize("scratch-kali", "10.0.0.2".parse().unwrap());
        app.set_killed("scratch-kali".into(), true).unwrap();
        app.add_container("guest-ü").unwrap();
        app.add_container("bad:name").unwrap();
        let config: Vec<crate::mcp::ForwardConfig> = serde_json::from_value(serde_json::json!([
            {"name":"linear", "url":"https://upstream.invalid/mcp", "tools":["read"], "guests":[]},
            {"name":"github", "url":"https://other.invalid/mcp", "tools":[], "guests":null}
        ]))
        .unwrap();
        registry.save(config).unwrap();
        let ui_state = UiState {
            app: app.clone(),
            settings: settings.clone(),
            registry: registry.clone(),
            oauth: crate::mcp_oauth::OauthFlows::default(),
            cline: crate::oauth::ClineFlows::default(),
            ui_addr: "127.0.0.1:8081".parse().unwrap(),
            bootstrap_addr: "0.0.0.0:9082".parse().unwrap(),
        };
        let ui = ui_router(ui_state.clone());
        let before = serde_json::to_value(app.view()).unwrap();
        let request = |uri| Request::get(uri).body(Body::empty()).unwrap();
        let list = ui.clone().oneshot(request("/api/mcp")).await.unwrap();
        let list: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(list.into_body(), 8192).await.unwrap())
                .unwrap();
        assert!(list["guest_host"].is_null());
        assert_eq!(list["guest_port"], 9082);
        assert!(list["forwards"][0]["guest_endpoint"].is_null());
        assert!(list["guest_address_warning"].is_string());
        assert_eq!(
            ui.clone()
                .oneshot(request("/api/mcp/linear/guest-config?guest=scratch-kali"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let response = ui
            .clone()
            .oneshot(request(
                "/api/mcp/linear/guest-config?guest=scratch-kali&host=broker.local",
            ))
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["endpoint"], "http://broker.local:9082/mcp/linear");
        assert_eq!(response["authorization"], "Basic c2NyYXRjaC1rYWxpOng=");
        assert_eq!(
            response["warnings"].as_array().unwrap().len(),
            3,
            "approval, kill and sharing warnings"
        );
        assert_eq!(
            serde_json::to_value(app.view()).unwrap(),
            before,
            "instructions must not change guest state"
        );
        assert_eq!(registry.configs()[1].guests, Some(vec![]));
        let loopback = ui_router(UiState {
            bootstrap_addr: "127.0.0.1:9082".parse().unwrap(),
            ..ui_state
        });
        let response = loopback
            .oneshot(request("/api/mcp/github/guest-config?guest=guest-%C3%BC"))
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            crate::proxy::basic_username(response["authorization"].as_str().unwrap()).as_deref(),
            Some("guest-ü")
        );
        assert!(
            response["warnings"][0]
                .as_str()
                .unwrap()
                .contains("loopback")
        );
        assert_eq!(
            ui.clone()
                .oneshot(request(
                    "/api/mcp/github/guest-config?guest=bad%3Aname&host=broker.local"
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            ui.clone()
                .oneshot(request(
                    "/api/mcp/linear/guest-config?guest=unknown&host=broker.local"
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        registry.save(vec![]).unwrap();
        assert_eq!(
            ui.oneshot(request(
                "/api/mcp/linear/guest-config?guest=scratch-kali&host=broker.local"
            ))
            .await
            .unwrap()
            .status(),
            StatusCode::NOT_FOUND
        );
        std::fs::remove_dir_all(settings.data_dir()).unwrap();
    }

    fn test_settings() -> crate::settings::Settings {
        let dir = std::env::temp_dir().join(format!("fz-web-{}", uuid::Uuid::new_v4()));
        crate::settings::Settings::load(&dir).unwrap()
    }

    fn bootstrap_app() -> Router {
        let settings = test_settings();
        let mut guest_binaries = std::collections::HashMap::new();
        let linux_bin = settings.data_dir().join("fz-linux-x86_64");
        std::fs::write(&linux_bin, b"\x7fELF-test").unwrap();
        guest_binaries.insert("fz-linux-x86_64".to_owned(), linux_bin);
        bootstrap_router(BootstrapState {
            cert: Arc::new("CERTIFICATE".into()),
            binary: Arc::new(vec![1, 2, 3]),
            guest_binaries: Arc::new(guest_binaries),
            mcp: crate::mcp::McpState::new(
                crate::state::AppState::default(),
                crate::mcp::ForwardRegistry::load(settings.data_dir(), settings.clone()).unwrap(),
            ),
            settings,
            proxy_port: 8080,
        })
    }

    #[tokio::test]
    async fn guest_binary_served_by_target_name() {
        let response = bootstrap_app()
            .oneshot(
                Request::get("/bootstrap/fz/fz-linux-x86_64")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=fz-linux-x86_64"
        );
    }

    #[tokio::test]
    async fn guest_scripts_and_exact_target_selection_are_public_without_management() {
        let response = bootstrap_app()
            .oneshot(
                Request::get("/bootstrap/setup?shell=sh&container=guest")
                    .header(header::HOST, "192.0.2.1:9082")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let encoded = text
            .lines()
            .find_map(|line| {
                line.strip_prefix("python3 - '")
                    .and_then(|s| s.split('\'').next())
            })
            .unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
        assert_eq!(payload["broker"], "http://192.0.2.1:9082");
        assert_eq!(payload["container"], "guest");
        assert_eq!(payload["ca"], "CERTIFICATE");
        assert_eq!(payload["proxy_port"], 8080);
        for shell in ["sh", "/bin/zsh", "powershell", "pwsh"] {
            let url = format!(
                "/bootstrap/setup?shell={shell}&broker=http%3A%2F%2F192.0.2.1%3A9082&container=guest"
            );
            let response = bootstrap_app()
                .oneshot(Request::get(url).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
                .await
                .unwrap();
            let text = String::from_utf8(body.to_vec()).unwrap();
            assert!(!text.contains("bootstrap/fz"));
            assert!(!text.contains("fz setup"));
            assert!(text.contains("Friendzone"));
            assert!(!text.contains("-addstore"));
            assert!(!text.contains("secrets.json"));
        }
        for url in [
            "/bootstrap/setup?shell=fish&broker=http://host:8082",
            "/bootstrap/setup?shell=sh&broker=http://host:8082/path",
            "/bootstrap/setup?shell=sh",
            "/bootstrap/fz?target=linux-mips",
        ] {
            assert_eq!(
                bootstrap_app()
                    .oneshot(Request::get(url).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST,
                "{url}"
            );
        }
        let response = bootstrap_app()
            .oneshot(
                Request::get("/bootstrap/fz?target=linux-x86_64")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        if std::env::consts::OS != "linux" {
            assert_eq!(
                &axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()[..],
                b"\x7fELF-test"
            );
        }
        assert_eq!(
            bootstrap_app()
                .oneshot(
                    Request::get("/bootstrap/fz?target=linux-aarch64")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            if std::env::consts::OS == "linux" && std::env::consts::ARCH == "aarch64" {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        );
    }

    #[tokio::test]
    async fn unknown_guest_target_lists_available() {
        let response = bootstrap_app()
            .oneshot(
                Request::get("/bootstrap/fz/fz-plan9-mips")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains("fz-linux-x86_64"),
            "404 names what exists: {text}"
        );
    }

    #[tokio::test]
    async fn targets_manifest_names_host_and_guests() {
        let response = bootstrap_app()
            .oneshot(
                Request::get("/bootstrap/targets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["guest_binaries"][0], "/bootstrap/fz/fz-linux-x86_64");
        assert!(json["host_platform"].as_str().unwrap().contains('-'));
    }

    #[tokio::test]
    async fn bootstrap_serves_public_ca() {
        let response = bootstrap_app()
            .oneshot(
                Request::get("/bootstrap/ca.pem")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/x-pem-file"
        );
    }

    #[tokio::test]
    async fn bootstrap_does_not_expose_management_api() {
        for uri in [
            "/api/state",
            "/api/requests/00000000-0000-0000-0000-000000000001/github-target",
            "/api/requests/00000000-0000-0000-0000-000000000001/comment-permission",
            "/api/containers/guest/comment-permissions/00000000-0000-0000-0000-000000000001",
            "/api/requests/00000000-0000-0000-0000-000000000001",
            "/api/requests/00000000-0000-0000-0000-000000000001/decision",
        ] {
            for method in ["GET", "POST", "DELETE"] {
                let response = bootstrap_app()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(uri)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }
        }
    }
}
