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
    forwards: Arc<Vec<crate::mcp::ForwardConfig>>,
    oauth: crate::oauth::OauthFlows,
    ui_addr: SocketAddr,
}

#[derive(Clone)]
struct BootstrapState {
    cert: Arc<String>,
    binary: Arc<Vec<u8>>,
    mcp: crate::mcp::McpState,
    settings: crate::settings::Settings,
}

pub async fn serve_ui(
    addr: SocketAddr,
    state: AppState,
    settings: crate::settings::Settings,
    forwards: Vec<crate::mcp::ForwardConfig>,
) -> Result<()> {
    serve(
        addr,
        ui_router(UiState {
            app: state,
            settings,
            forwards: Arc::new(forwards),
            oauth: crate::oauth::OauthFlows::default(),
            ui_addr: addr,
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
) -> Result<()> {
    let executable = std::env::current_exe().context("locate fz executable")?;
    let binary = tokio::fs::read(&executable)
        .await
        .with_context(|| format!("read {}", executable.display()))?;
    serve(
        addr,
        bootstrap_router(BootstrapState {
            cert: Arc::new(cert_pem),
            binary: Arc::new(binary),
            mcp,
            settings,
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
    axum::serve(listener, app)
        .await
        .with_context(|| format!("serve {name}"))
}

fn ui_router(state: UiState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(css))
        .route("/app.js", get(js))
        .route("/api/state", get(api_state))
        .route("/api/containers/{id}/kill", post(set_killed))
        .route("/api/escrow", get(list_escrow).post(add_escrow))
        .route("/api/escrow/{name}/secret", post(set_escrow_secret))
        .route("/api/guest-env", get(guest_env))
        .route("/api/mcp", get(list_forwards))
        .route("/api/mcp/{name}/oauth/start", post(oauth_start))
        .route("/oauth/callback", get(oauth_callback))
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

async fn add_escrow(
    State(state): State<UiState>,
    Json(entry): Json<crate::settings::EscrowEntry>,
) -> impl IntoResponse {
    match state.settings.add_entry(entry) {
        Ok(entry) => (StatusCode::CREATED, Json(serde_json::json!(entry))).into_response(),
        Err(error) => (StatusCode::CONFLICT, error.to_string()).into_response(),
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
        state.settings.guest_env_lines(),
    )
}

/// MCP forwards with connection state; tokens never leave as values.
async fn list_forwards(State(state): State<UiState>) -> Json<serde_json::Value> {
    let forwards: Vec<serde_json::Value> = state
        .forwards
        .iter()
        .map(|f| {
            let connected = state.settings.secret(&format!("mcp:{}", f.name)).is_some()
                || std::env::var(&f.bearer_env).is_ok();
            serde_json::json!({
                "name": f.name,
                "url": f.url,
                "tools": f.tools,
                "connected": connected,
            })
        })
        .collect();
    Json(serde_json::json!({ "forwards": forwards }))
}

/// Kicks off host-side OAuth: builds the authorization URL and opens
/// the host browser. Returns the URL too, in case the browser did not
/// open.
async fn oauth_start(State(state): State<UiState>, Path(name): Path<String>) -> impl IntoResponse {
    let Some(forward) = state.forwards.iter().find(|f| f.name == name) else {
        return (StatusCode::NOT_FOUND, format!("unknown forward '{name}'")).into_response();
    };
    let redirect_uri = format!("http://{}/oauth/callback", state.ui_addr);
    match state.oauth.start(&name, &forward.url, &redirect_uri).await {
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
        .route("/bootstrap/env", get(bootstrap_env))
        .route("/mcp/{name}", post(mcp_message))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
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

async fn binary(State(state): State<BootstrapState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                if cfg!(windows) {
                    "attachment; filename=fz.exe"
                } else {
                    "attachment; filename=fz"
                },
            ),
        ],
        state.binary.as_ref().clone(),
    )
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
        bootstrap_router(BootstrapState {
            cert: Arc::new("CERTIFICATE".into()),
            binary: Arc::new(vec![1, 2, 3]),
            mcp: crate::mcp::McpState::new(
                crate::state::AppState::default(),
                Vec::new(),
                settings.clone(),
            ),
            settings,
        })
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
