use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use serde::Deserialize;

use crate::state::{AppState, StateView};

#[derive(Clone)]
struct UiState {
    app: AppState,
    settings: crate::settings::Settings,
    registry: crate::mcp::ForwardRegistry,
    oauth: crate::oauth::OauthFlows,
    cline: crate::oauth::ClineFlows,
    ui_addr: SocketAddr,
    bootstrap_port: u16,
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
    bootstrap_port: u16,
) -> Result<()> {
    serve(
        addr,
        ui_router(UiState {
            app: state,
            settings,
            registry,
            oauth: crate::oauth::OauthFlows::default(),
            cline: crate::oauth::ClineFlows::default(),
            ui_addr: addr,
            bootstrap_port,
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
        .route("/api/events", get(state_events))
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
        .route("/api/guest-env", get(guest_env))
        .route("/api/mcp", get(list_forwards))
        .route("/api/mcp/config", get(get_mcp_config).put(put_mcp_config))
        .route("/api/mcp/reload", post(reload_mcp_config))
        .route("/api/mcp/{name}/oauth/start", post(oauth_start))
        .route("/api/mcp/{name}/oauth", axum::routing::delete(oauth_disconnect))
        .route("/oauth/callback", get(oauth_callback))
        .route("/api/escrow/{name}/cline-oauth/start", post(cline_oauth_start))
        .route("/api/escrow/{name}/cline-oauth/status", get(cline_oauth_status))
        .route("/health", get(|| async { "ok" }))
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

async fn guest_env(State(state): State<UiState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!(
            "# Fetch from a guest: curl http://HOST_IP:{}/bootstrap/env\n{}",
            state.bootstrap_port,
            state.settings.guest_env_lines()
        ),
    )
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
            let session = crate::oauth::TokenRecord::load(&state.settings, &f.name);
            let (auth, expires_at, refreshable) = match &session {
                Some(record) => (
                    "oauth",
                    record.expires_at,
                    record.refresh_token.is_some(),
                ),
                None if state.settings.secret(&format!("mcp:{}", f.name)).is_some() => {
                    ("stored-key", None, false)
                }
                None if std::env::var(&f.bearer_env).is_ok() => ("env-key", None, false),
                None => ("none", None, false),
            };
            serde_json::json!({
                "name": f.name,
                "url": f.url,
                "tools": f.tools,
                "scope": f.scope,
                "connected": auth != "none",
                "auth": auth,
                "expires_at": expires_at,
                "refreshable": refreshable,
            })
        })
        .collect();
    Json(serde_json::json!({
        "forwards": forwards,
        "config_path": state.registry.config_path().display().to_string(),
    }))
}

/// The raw mcp-forwards.json for in-UI editing.
async fn get_mcp_config(State(state): State<UiState>) -> impl IntoResponse {
    let path = state.registry.config_path();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| "[]".to_owned());
    ([(header::CONTENT_TYPE, "application/json; charset=utf-8")], text)
}

/// Saves mcp-forwards.json (validated first) and reloads the forwards.
async fn put_mcp_config(State(state): State<UiState>, body: String) -> impl IntoResponse {
    if let Err(error) = serde_json::from_str::<Vec<crate::mcp::ForwardConfig>>(&body) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("not a valid forwards config: {error}"),
        )
            .into_response();
    }
    let path = state.registry.config_path();
    if let Err(error) = std::fs::write(&path, &body) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write {}: {error}", path.display()),
        )
            .into_response();
    }
    match state.registry.reload() {
        Ok(count) => Json(serde_json::json!({ "forwards": count })).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")).into_response(),
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
    match crate::oauth::disconnect(&state.settings, &name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

/// Kicks off host-side OAuth: builds the authorization URL and opens
/// the host browser. Returns the URL too, in case the browser did not
/// open.
async fn oauth_start(State(state): State<UiState>, Path(name): Path<String>) -> impl IntoResponse {
    let configs = state.registry.configs();
    let Some(forward) = configs.iter().find(|f| f.name == name) else {
        return (StatusCode::NOT_FOUND, format!("unknown forward '{name}'")).into_response();
    };
    let redirect_uri = format!("http://{}/oauth/callback", state.ui_addr);
    match state
        .oauth
        .start(&name, &forward.url, &redirect_uri, forward.scope.as_deref())
        .await
    {
        Ok(url) => {
            open_host_browser(&url);
            Json(serde_json::json!({ "authorize_url": url })).into_response()
        }
        Err(error) => (StatusCode::BAD_GATEWAY, format!("{error:#}")).into_response(),
    }
}

#[derive(Deserialize)]
struct OauthCallback {
    state: String,
    code: String,
}

async fn oauth_callback(
    State(state): State<UiState>,
    axum::extract::Query(query): axum::extract::Query<OauthCallback>,
) -> impl IntoResponse {
    match state
        .oauth
        .finish(&query.state, &query.code, &state.settings)
        .await
    {
        Ok(name) => Html(format!(
            "<h1>Connected</h1><p>MCP forward '{name}' is authorized. You can close this tab.</p>"
        ))
        .into_response(),
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
                open_host_browser(verification_uri);
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

fn open_host_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    let result = std::process::Command::new("xdg-open").arg(url).spawn();
    if let Err(error) = result {
        tracing::warn!(%error, "could not open host browser");
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
        .route("/mcp/{name}", post(mcp_message))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}

#[derive(Deserialize)]
struct HelloQuery {
    container: String,
}

/// `fz setup` announces the guest: creates/updates the join request so
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
    headers: axum::http::HeaderMap,
    Json(message): Json<serde_json::Value>,
) -> impl IntoResponse {
    let container = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::proxy::basic_username)
        .unwrap_or_else(|| "unidentified".to_owned());
    let response = crate::mcp::handle_message(&state.mcp, &name, &container, message).await;
    if response.is_null() {
        // Notification: no JSON-RPC response body.
        StatusCode::ACCEPTED.into_response()
    } else {
        Json(response).into_response()
    }
}

async fn index() -> Html<&'static str> {
    Html(include_str!("web/index.html"))
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
    Json(state.app.view())
}

/// Live state over SSE: a full `StateView` snapshot on connect and on
/// every change (the watch channel coalesces bursts). Clients stay
/// dumb — render whatever arrives — and EventSource reconnects itself.
async fn state_events(State(state): State<UiState>) -> impl IntoResponse {
    let mut changes = state.app.subscribe();
    let app = state.app.clone();
    let stream = async_stream(move |emit| async move {
        loop {
            let view = app.view();
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
    state.app.add_container(&name);
    StatusCode::CREATED.into_response()
}

/// Unregisters a container. Log rows remain for audit; a reconnecting
/// guest re-appears as a new container.
async fn remove_container(
    State(state): State<UiState>,
    Path(id): Path<String>,
) -> StatusCode {
    state.app.remove_container(&id);
    StatusCode::NO_CONTENT
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
) -> StatusCode {
    state.app.approve_container(&id, request.pin_to_last_ip);
    StatusCode::NO_CONTENT
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
            state.app.set_pinned_ip(&id, None);
            StatusCode::NO_CONTENT.into_response()
        }
        Some(text) => match text.trim().parse() {
            Ok(ip) => {
                state.app.set_pinned_ip(&id, Some(ip));
                StatusCode::NO_CONTENT.into_response()
            }
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
) -> StatusCode {
    state.app.set_killed(id, request.killed);
    StatusCode::NO_CONTENT
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
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("fz-linux-x86_64"), "404 names what exists: {text}");
    }

    #[tokio::test]
    async fn targets_manifest_names_host_and_guests() {
        let response = bootstrap_app()
            .oneshot(Request::get("/bootstrap/targets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
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
        let response = bootstrap_app()
            .oneshot(Request::get("/api/state").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
