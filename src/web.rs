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
}

#[derive(Clone)]
struct BootstrapState {
    cert: Arc<String>,
    binary: Arc<Vec<u8>>,
}

pub async fn serve_ui(addr: SocketAddr, state: AppState) -> Result<()> {
    serve(addr, ui_router(UiState { app: state }), "web UI").await
}

pub async fn serve_bootstrap(addr: SocketAddr, cert_pem: String) -> Result<()> {
    let executable = std::env::current_exe().context("locate fz executable")?;
    let binary = tokio::fs::read(&executable)
        .await
        .with_context(|| format!("read {}", executable.display()))?;
    serve(
        addr,
        bootstrap_router(BootstrapState {
            cert: Arc::new(cert_pem),
            binary: Arc::new(binary),
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
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}

fn bootstrap_router(state: BootstrapState) -> Router {
    Router::new()
        .route("/bootstrap/ca.pem", get(certificate))
        .route("/bootstrap/fz", get(binary))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
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

    fn bootstrap_app() -> Router {
        bootstrap_router(BootstrapState {
            cert: Arc::new("CERTIFICATE".into()),
            binary: Arc::new(vec![1, 2, 3]),
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
