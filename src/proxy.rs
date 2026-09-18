use base64::{Engine, engine::general_purpose::STANDARD};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{
        Request, Response, StatusCode,
        header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    },
};
use std::{
    collections::HashMap,
    error::Error as _,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use crate::state::{AppState, Verdict};

#[derive(Clone)]
struct PendingUpstream {
    id: uuid::Uuid,
    host: String,
    method: String,
    path: String,
    forwarding_at: std::time::Instant,
    server_span: tracing::Span,
    lifecycle: Option<Arc<UpstreamLifecycle>>,
}

static ACTIVE_UPSTREAM: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_BY_HOST: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn active_by_host() -> &'static Mutex<HashMap<String, usize>> {
    ACTIVE_BY_HOST.get_or_init(|| Mutex::new(HashMap::new()))
}

fn host_active(host: &str, delta: isize) -> usize {
    let mut hosts = active_by_host().lock().expect("upstream counter lock");
    let active = hosts.entry(host.to_owned()).or_default();
    if delta > 0 {
        *active = active.saturating_add(delta as usize);
    } else {
        *active = active.saturating_sub(delta.unsigned_abs());
    }
    let result = *active;
    if result == 0 {
        hosts.remove(host);
    }
    result
}

struct UpstreamLifecycle {
    id: uuid::Uuid,
    host: String,
    method: String,
    path: String,
    started: std::time::Instant,
    finished: AtomicBool,
    spans: Mutex<Option<TraceSpans>>,
}

struct TraceSpans {
    client: tracing::Span,
    server: tracing::Span,
}

impl UpstreamLifecycle {
    fn start(pending: &PendingUpstream) -> Arc<Self> {
        let active_total = ACTIVE_UPSTREAM.fetch_add(1, Ordering::AcqRel) + 1;
        let active_host = host_active(&pending.host, 1);
        let client = tracing::info_span!(
            parent: &pending.server_span,
            "friendzone.proxy.upstream",
            otel.kind = "client",
            otel.name = %format!("{} {}", pending.method, pending.host),
            "friendzone.request.id" = %pending.id,
            "http.request.method" = %pending.method,
            "server.address" = %pending.host,
            "url.path" = %pending.path,
            "http.response.status_code" = tracing::field::Empty,
            "network.protocol.name" = tracing::field::Empty,
            "http.response.body.size" = tracing::field::Empty,
            "friendzone.outcome" = tracing::field::Empty,
            "friendzone.active.total" = active_total,
            "friendzone.active.host" = active_host,
            "friendzone.transport.detail" = tracing::field::Empty,
            "error.type" = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
            otel.status_description = tracing::field::Empty,
        );
        tracing::info!(
            parent: &client,
            request_id = %pending.id,
            upstream_host = %pending.host,
            method = %pending.method,
            path = %pending.path,
            active_total,
            active_host,
            "upstream request forwarding"
        );
        Arc::new(Self {
            id: pending.id,
            host: pending.host.clone(),
            method: pending.method.clone(),
            path: pending.path.clone(),
            started: pending.forwarding_at,
            finished: AtomicBool::new(false),
            spans: Mutex::new(Some(TraceSpans {
                server: pending.server_span.clone(),
                client,
            })),
        })
    }

    fn client_span(&self) -> tracing::Span {
        self.spans
            .lock()
            .expect("trace span lock")
            .as_ref()
            .map_or_else(tracing::Span::none, |spans| spans.client.clone())
    }

    fn server_span(&self) -> tracing::Span {
        self.spans
            .lock()
            .expect("trace span lock")
            .as_ref()
            .map_or_else(tracing::Span::none, |spans| spans.server.clone())
    }

    fn context(&self) -> opentelemetry::Context {
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;
        self.client_span().context()
    }

    fn finish(
        &self,
        outcome: &'static str,
        status: Option<u16>,
        protocol: Option<&'static str>,
        bytes: u64,
    ) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        let active_total = ACTIVE_UPSTREAM
            .fetch_sub(1, Ordering::AcqRel)
            .saturating_sub(1);
        let active_host = host_active(&self.host, -1);
        let spans = self.spans.lock().expect("trace span lock").take();
        let parent = spans
            .as_ref()
            .map_or_else(tracing::Span::none, |spans| spans.client.clone());
        tracing::info!(
            parent: &parent,
            request_id = %self.id,
            upstream_host = %self.host,
            method = %self.method,
            path = %self.path,
            outcome,
            http_status = status.unwrap_or_default(),
            protocol = protocol.unwrap_or("unknown"),
            response_bytes = bytes,
            elapsed_ms = self.started.elapsed().as_millis() as u64,
            active_total,
            active_host,
            "upstream request finished"
        );
        if let Some(spans) = &spans {
            let elapsed_ms = self.started.elapsed().as_millis() as u64;
            spans.client.record("friendzone.outcome", outcome);
            spans.client.record("friendzone.active.total", active_total);
            spans.client.record("friendzone.active.host", active_host);
            spans.client.record("http.response.body.size", bytes);
            spans.server.record("friendzone.outcome", outcome);
            spans
                .server
                .record("friendzone.upstream.elapsed_ms", elapsed_ms);
            if let Some(status) = status {
                spans.client.record("http.response.status_code", status);
                spans.server.record("http.response.status_code", status);
            }
            if let Some(protocol) = protocol {
                spans.client.record("network.protocol.name", protocol);
            }
            let error_type = if outcome == "response_complete" {
                "http_status_error"
            } else {
                outcome
            };
            if outcome != "response_complete" || status.is_some_and(|status| status >= 400) {
                spans.client.record("error.type", error_type);
                spans.client.record("otel.status_code", "ERROR");
                spans.client.record("otel.status_description", error_type);
            }
            if outcome != "response_complete" || status.is_some_and(|status| status >= 500) {
                spans.server.record("error.type", error_type);
                spans.server.record("otel.status_code", "ERROR");
                spans.server.record("otel.status_description", error_type);
            }
        }
    }
}

impl Drop for UpstreamLifecycle {
    fn drop(&mut self) {
        self.finish("handler_dropped", None, None, 0);
    }
}

struct ObservedResponseBody {
    inner: Body,
    lifecycle: Arc<UpstreamLifecycle>,
    status: u16,
    protocol: &'static str,
    bytes: u64,
    first_byte: bool,
    ended: bool,
}

struct ObservedRequestBody {
    inner: Body,
    lifecycle: Arc<UpstreamLifecycle>,
    bytes: u64,
    first_byte: bool,
    ended: bool,
}

impl hudsucker::hyper::body::Body for ObservedRequestBody {
    type Data = hudsucker::hyper::body::Bytes;
    type Error = hudsucker::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hudsucker::hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        use std::task::Poll;

        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes = this.bytes.saturating_add(data.len() as u64);
                    if !this.first_byte && !data.is_empty() {
                        this.first_byte = true;
                        tracing::info!(
                            parent: &this.lifecycle.client_span(),
                            request_id = %this.lifecycle.id,
                            upstream_host = %this.lifecycle.host,
                            method = %this.lifecycle.method,
                            path = %this.lifecycle.path,
                            time_to_request_body_first_byte_ms = this.lifecycle.started.elapsed().as_millis() as u64,
                            "upstream request body first byte"
                        );
                    }
                }
                if this.inner.is_end_stream() {
                    this.ended = true;
                    tracing::info!(
                        parent: &this.lifecycle.client_span(),
                        request_id = %this.lifecycle.id,
                        upstream_host = %this.lifecycle.host,
                        method = %this.lifecycle.method,
                        path = %this.lifecycle.path,
                        request_bytes = this.bytes,
                        request_body_complete_ms = this.lifecycle.started.elapsed().as_millis() as u64,
                        "upstream request body complete"
                    );
                }
            }
            Poll::Ready(None) => {
                this.ended = true;
                tracing::info!(
                    parent: &this.lifecycle.client_span(),
                    request_id = %this.lifecycle.id,
                    upstream_host = %this.lifecycle.host,
                    method = %this.lifecycle.method,
                    path = %this.lifecycle.path,
                    request_bytes = this.bytes,
                    request_body_complete_ms = this.lifecycle.started.elapsed().as_millis() as u64,
                    "upstream request body complete"
                );
            }
            Poll::Ready(Some(Err(_))) => {
                this.ended = true;
                tracing::info!(
                    parent: &this.lifecycle.client_span(),
                    request_id = %this.lifecycle.id,
                    upstream_host = %this.lifecycle.host,
                    method = %this.lifecycle.method,
                    path = %this.lifecycle.path,
                    request_bytes = this.bytes,
                    request_body_error_ms = this.lifecycle.started.elapsed().as_millis() as u64,
                    "upstream request body error"
                );
            }
            Poll::Pending => {}
        }
        result
    }
}

impl Drop for ObservedRequestBody {
    fn drop(&mut self) {
        if !self.ended {
            tracing::info!(
                parent: &self.lifecycle.client_span(),
                request_id = %self.lifecycle.id,
                upstream_host = %self.lifecycle.host,
                method = %self.lifecycle.method,
                path = %self.lifecycle.path,
                request_bytes = self.bytes,
                request_body_dropped_ms = self.lifecycle.started.elapsed().as_millis() as u64,
                "upstream request body dropped"
            );
        }
    }
}

impl hudsucker::hyper::body::Body for ObservedResponseBody {
    type Data = hudsucker::hyper::body::Bytes;
    type Error = hudsucker::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hudsucker::hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        use std::task::Poll;

        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes = this.bytes.saturating_add(data.len() as u64);
                    if !this.first_byte && !data.is_empty() {
                        this.first_byte = true;
                        tracing::info!(
                            parent: &this.lifecycle.client_span(),
                            request_id = %this.lifecycle.id,
                            upstream_host = %this.lifecycle.host,
                            method = %this.lifecycle.method,
                            path = %this.lifecycle.path,
                            protocol = this.protocol,
                            time_to_first_body_byte_ms = this.lifecycle.started.elapsed().as_millis() as u64,
                            "upstream response first body byte"
                        );
                    }
                }
                if this.inner.is_end_stream() {
                    this.ended = true;
                    this.lifecycle.finish(
                        "response_complete",
                        Some(this.status),
                        Some(this.protocol),
                        this.bytes,
                    );
                }
            }
            Poll::Ready(None) => {
                this.ended = true;
                this.lifecycle.finish(
                    "response_complete",
                    Some(this.status),
                    Some(this.protocol),
                    this.bytes,
                );
            }
            Poll::Ready(Some(Err(_))) => {
                this.ended = true;
                this.lifecycle.finish(
                    "response_body_error",
                    Some(this.status),
                    Some(this.protocol),
                    this.bytes,
                );
            }
            Poll::Pending => {}
        }
        result
    }
}

impl Drop for ObservedResponseBody {
    fn drop(&mut self) {
        if !self.ended {
            self.lifecycle.finish(
                "downstream_body_dropped",
                Some(self.status),
                Some(self.protocol),
                self.bytes,
            );
        }
    }
}

#[cfg(test)]
mod basic_auth_tests;

/// A cancelled HTTP handler must not leave an apparently live review in
/// the log. Ticket drop independently removes the queue item.
struct ReviewLogGuard {
    state: AppState,
    event: uuid::Uuid,
    finished: bool,
}
impl Drop for ReviewLogGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.state.reviews.observe(
                self.event,
                crate::review::Status::Cancelled,
                None,
                "Review cancelled before forwarding. Not sent.",
            );
            self.state.mark_blocked(
                self.event,
                403,
                "review cancelled; waiting proxy handler ended without forwarding".into(),
            );
        }
    }
}

/// Last handler owner disappearing without a response is not evidence that a
/// remote write failed. Preserve that uncertainty rather than imply safe retry.
struct ResponseWatch {
    state: AppState,
    id: uuid::Uuid,
}
impl Drop for ResponseWatch {
    fn drop(&mut self) {
        self.state.reviews.observe(self.id, crate::review::Status::Unknown, None, "Proxy request ended without a response. The operation may have executed; check upstream before retrying.");
    }
}

/// Observe a bounded JSON copy without delaying, truncating or rewriting the
/// response stream. Large/invalid bodies remain HTTP-only outcomes.
struct ReviewResponseBody {
    inner: Body,
    state: AppState,
    id: uuid::Uuid,
    bytes: Option<Vec<u8>>,
    content_type: Option<String>,
    response_headers: Vec<(String, String)>,
    ended: bool,
}
impl ReviewResponseBody {
    fn finish(&mut self) {
        if self.ended {
            return;
        }
        self.ended = true;
        if let Some(bytes) = &self.bytes
            && let Some(diagnostics) = crate::review::graphql_response_diagnostics(
                bytes,
                self.content_type.clone(),
                self.response_headers.clone(),
            )
        {
            self.state
                .reviews
                .graphql_response_detail(self.id, diagnostics);
        }
    }
}
impl hudsucker::hyper::body::Body for ReviewResponseBody {
    type Data = hudsucker::hyper::body::Bytes;
    type Error = hudsucker::Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hudsucker::hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        use std::task::Poll;
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && let Some(bytes) = &mut this.bytes
                {
                    if bytes.len() + data.len() <= crate::review::MAX_BODY {
                        bytes.extend_from_slice(data);
                    } else {
                        this.bytes = None;
                    }
                }
                // A transport can stop polling after the last declared byte.
                // Do not require an extra poll returning None to record EOF.
                if this.inner.is_end_stream() {
                    this.finish();
                }
            }
            Poll::Ready(None) => {
                this.finish();
            }
            Poll::Ready(Some(Err(_))) => {
                this.ended = true;
                this.state.reviews.response_detail(this.id, crate::review::Status::Unknown, "HTTP headers received, but reading the response failed. Check upstream before retrying.");
            }
            Poll::Pending => {}
        }
        result
    }
}
impl Drop for ReviewResponseBody {
    fn drop(&mut self) {
        if !self.ended {
            self.state.reviews.response_detail(
                self.id,
                crate::review::Status::Unknown,
                "HTTP response was not fully observed. Check upstream before retrying.",
            );
        }
    }
}

#[derive(Clone)]
pub struct EventHandler {
    state: AppState,
    settings: crate::settings::Settings,
    /// The in-flight request on this connection, for response
    /// annotation and bounded transport timing.
    pending: Option<PendingUpstream>,
    /// Hudsucker clones the CONNECT handler into intercepted requests.
    /// Identity travels with that tunnel, never in an IP/port cache that
    /// could outlive a socket and authenticate a different connection.
    tunnel_identity: Option<String>,
    /// Credential-free tunnels must continue resolving by their explicit IP
    /// pin; their carried display label must never become legacy identity.
    tunnel_requires_pin: bool,
    /// Block this destination port globally, not by hostname: aliases and
    /// DNS rebinding must not let guests reach the host's management API.
    management_port: u16,
    /// Listener policy is fixed at broker startup; the bootstrap exception
    /// and actual listener use the same configured port, including in clones.
    bootstrap_port: u16,
    response_watch: Option<std::sync::Arc<ResponseWatch>>,
}

impl EventHandler {
    pub fn new(
        state: AppState,
        settings: crate::settings::Settings,
        management_port: u16,
        bootstrap_port: u16,
    ) -> Self {
        Self {
            state,
            settings,
            pending: None,
            tunnel_identity: None,
            tunnel_requires_pin: false,
            management_port,
            bootstrap_port,
            response_watch: None,
        }
    }

    fn container(
        &self,
        req: &Request<Body>,
        peer: std::net::IpAddr,
    ) -> anyhow::Result<(String, crate::state::Authorization)> {
        if let Some(container) = &self.tunnel_identity {
            if self.tunnel_requires_pin {
                let identity = self.state.authorize_proxy_peer(peer, None)?;
                if identity.0 != *container {
                    anyhow::bail!("source address no longer owns the intercepted tunnel");
                }
                Ok(identity)
            } else {
                self.state.authorize_proxy_peer(peer, Some(container))
            }
        } else {
            let presented = req
                .headers()
                .get(PROXY_AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(basic_username);
            self.state.authorize_proxy_peer(peer, presented.as_deref())
        }
    }

    /// This is the diagnostics consistency boundary: count only requests that
    /// passed every local gate and are about to be handed to Hyper.
    fn begin_forwarding(&mut self, req: Request<Body>) -> Request<Body> {
        use hudsucker::hyper::body::Body as _;

        if let Some(pending) = &mut self.pending {
            pending.forwarding_at = std::time::Instant::now();
            let lifecycle = UpstreamLifecycle::start(pending);
            pending.lifecycle = Some(lifecycle.clone());
            let (mut parts, body) = req.into_parts();
            crate::telemetry::inject(&lifecycle.context(), &mut parts.headers);
            if body.is_end_stream() {
                tracing::info!(
                    parent: &lifecycle.client_span(),
                    request_id = %lifecycle.id,
                    upstream_host = %lifecycle.host,
                    method = %lifecycle.method,
                    path = %lifecycle.path,
                    request_bytes = 0,
                    request_body_complete_ms = 0_u64,
                    "upstream request body complete"
                );
                return Request::from_parts(parts, body);
            }
            use http_body_util::BodyExt;
            return Request::from_parts(
                parts,
                Body::from(
                    ObservedRequestBody {
                        inner: body,
                        lifecycle,
                        bytes: 0,
                        first_byte: false,
                        ended: false,
                    }
                    .boxed(),
                ),
            );
        }
        req
    }

    async fn handle_from_peer(
        &mut self,
        peer: std::net::SocketAddr,
        req: Request<Body>,
    ) -> RequestOrResponse {
        use tracing::Instrument as _;
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;

        let method = req.method().to_string();
        let host = req.uri().host().unwrap_or_default();
        let path = req.uri().path();
        let server_span = tracing::info_span!(
            "friendzone.proxy.request",
            otel.kind = "server",
            otel.name = %format!("{method} {host}"),
            "http.request.method" = %method,
            "server.address" = %host,
            "url.path" = %path,
            "client.address" = %peer.ip(),
            "friendzone.container" = tracing::field::Empty,
            "friendzone.request.id" = tracing::field::Empty,
            "http.response.status_code" = tracing::field::Empty,
            "friendzone.outcome" = tracing::field::Empty,
            "friendzone.upstream.elapsed_ms" = tracing::field::Empty,
            "error.type" = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
            otel.status_description = tracing::field::Empty,
        );
        let _ = server_span.set_parent(crate::telemetry::extract(req.headers()));
        self.handle_from_peer_traced(peer, req, server_span.clone())
            .instrument(server_span)
            .await
    }

    async fn handle_from_peer_traced(
        &mut self,
        peer: std::net::SocketAddr,
        mut req: Request<Body>,
        server_span: tracing::Span,
    ) -> RequestOrResponse {
        self.pending = None;
        self.response_watch = None;
        let credential_free_connect =
            self.tunnel_identity.is_none() && !req.headers().contains_key(PROXY_AUTHORIZATION);
        let has_presented_identity =
            self.tunnel_identity.is_some() || req.headers().contains_key(PROXY_AUTHORIZATION);
        let container = match self.container(&req, peer.ip()) {
            Ok(identity) => identity,
            Err(error) if !has_presented_identity => {
                // Git/libcurl's anyauth mode waits for this challenge before
                // sending a legacy username. New clients use a unique IP pin.
                server_span.record("http.response.status_code", 407_u16);
                server_span.record("friendzone.outcome", "proxy_authentication_required");
                return Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header(PROXY_AUTHENTICATE, "Basic realm=\"Friendzone\"")
                    .body(Body::from(format!(
                        "friendzone: {error}; credential-free proxy use requires a unique IP pin"
                    )))
                    .expect("static challenge")
                    .into();
            }
            Err(error) => {
                server_span.record("http.response.status_code", 403_u16);
                server_span.record("friendzone.outcome", "identity_denied");
                server_span.record("error.type", "identity_denied");
                server_span.record("otel.status_code", "error");
                server_span.record("otel.status_description", "guest identity denied");
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from(format!("friendzone: {error}")))
                    .expect("static identity denial")
                    .into();
            }
        };
        let (container, authorization) = container;
        server_span.record("friendzone.container", &container);
        // Legacy proxy identity hints must never reach the upstream host.
        req.headers_mut().remove(PROXY_AUTHORIZATION);
        // The container gate comes before any policy: unknown names are
        // join requests (approve them in the UI), and a known name from
        // the wrong address is denied.
        if authorization != crate::state::Authorization::Allowed {
            let reason = match authorization {
                crate::state::Authorization::Pending => {
                    "friendzone: container awaiting approval; use Approve + pin IP in the UI inbox"
                }
                _ => "friendzone: container name is pinned to a different address",
            };
            let id = self.state.record(
                container,
                req.method().to_string(),
                req.uri().to_string(),
                Verdict::Blocked,
            );
            server_span.record("friendzone.request.id", id.to_string());
            server_span.record("http.response.status_code", 403_u16);
            server_span.record("friendzone.outcome", "authorization_denied");
            server_span.record("error.type", "authorization_denied");
            server_span.record("otel.status_code", "error");
            server_span.record("otel.status_description", reason);
            self.state.annotate(id, Some(403), Some(reason.into()));
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(reason))
                .expect("static blocked response")
                .into();
        }
        let killed = self.state.is_killed(&container);
        if let Some(reason) =
            destination_denial(req.uri(), self.management_port, self.bootstrap_port)
        {
            let id = self.state.record(
                container,
                req.method().to_string(),
                req.uri().to_string(),
                Verdict::Blocked,
            );
            server_span.record("friendzone.request.id", id.to_string());
            server_span.record("http.response.status_code", 403_u16);
            server_span.record("friendzone.outcome", "destination_denied");
            server_span.record("error.type", "destination_denied");
            server_span.record("otel.status_code", "error");
            server_span.record("otel.status_description", reason);
            self.state.annotate(id, Some(403), Some(reason.into()));
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(reason))
                .expect("static denial")
                .into();
        }
        if req.method() == hudsucker::hyper::Method::CONNECT && !killed {
            self.tunnel_identity = Some(container);
            self.tunnel_requires_pin = credential_free_connect;
            // Successful CONNECTs are transport setup, not application
            // requests. Do not bury the useful log under these rows.
            return req.into();
        }
        let decision = crate::policy::classify(&req);
        let needs_review = decision == crate::policy::Decision::RequireReview;
        let blocked = killed;
        let host = req.uri().host().unwrap_or_default().to_owned();
        let method = req.method().to_string();
        let path = req.uri().path().to_owned();
        let id = self.state.record(
            container.clone(),
            method.clone(),
            req.uri().to_string(),
            if blocked {
                Verdict::Blocked
            } else if needs_review {
                Verdict::Pending
            } else {
                Verdict::Allowed
            },
        );
        server_span.record("friendzone.request.id", id.to_string());
        if !blocked {
            self.pending = Some(PendingUpstream {
                id,
                host: host.clone(),
                method,
                path,
                forwarding_at: std::time::Instant::now(),
                server_span: server_span.clone(),
                lifecycle: None,
            });
        }
        if killed {
            server_span.record("http.response.status_code", 403_u16);
            server_span.record("friendzone.outcome", "container_killed");
            server_span.record("error.type", "container_killed");
            server_span.record("otel.status_code", "error");
            server_span.record("otel.status_description", "container is killed");
            self.state
                .annotate(id, Some(403), Some("container is killed".into()));
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("container is killed"))
                .expect("static blocked response")
                .into()
        } else {
            if needs_review {
                match self.await_review(&container, peer.ip(), req, id).await {
                    Ok(reviewed) => {
                        req = reviewed;
                        self.response_watch = Some(std::sync::Arc::new(ResponseWatch {
                            state: self.state.clone(),
                            id,
                        }));
                    }
                    Err(reason) => {
                        self.pending = None;
                        server_span.record("http.response.status_code", 403_u16);
                        server_span.record("friendzone.outcome", "review_denied");
                        server_span.record("error.type", "review_denied");
                        server_span.record("otel.status_code", "error");
                        server_span.record("otel.status_description", &reason);
                        self.state.mark_blocked(id, 403, reason.clone());
                        return Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(reason))
                            .expect("review denial")
                            .into();
                    }
                }
            }
            let host = req.uri().host().unwrap_or_default().to_owned();
            let substitution = self.settings.substitute(&host, |name| {
                req.headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            });
            match substitution {
                crate::settings::Substitution::None => self.begin_forwarding(req).into(),
                crate::settings::Substitution::Replace { header, value } => {
                    if let Ok(header_value) = value.parse() {
                        req.headers_mut().insert(
                            hudsucker::hyper::header::HeaderName::try_from(header.as_str())
                                .expect("escrow header name"),
                            header_value,
                        );
                    }
                    self.begin_forwarding(req).into()
                }
                crate::settings::Substitution::Block(reason) => {
                    self.pending = None;
                    server_span.record("http.response.status_code", 403_u16);
                    server_span.record("friendzone.outcome", "credential_denied");
                    server_span.record("error.type", "credential_denied");
                    server_span.record("otel.status_code", "error");
                    server_span.record("otel.status_description", &reason);
                    self.state.mark_blocked(id, 403, reason.clone());
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from(reason))
                        .expect("static blocked response")
                        .into()
                }
            }
        }
    }

    async fn await_review(
        &self,
        container: &str,
        peer: std::net::IpAddr,
        req: Request<Body>,
        event: uuid::Uuid,
    ) -> Result<Request<Body>, String> {
        use http_body_util::BodyExt;
        let mut guard = ReviewLogGuard {
            state: self.state.clone(),
            event,
            finished: false,
        };
        let error = |reason: String| format!("friendzone: GitHub request not forwarded: {reason}");
        let epoch = self
            .state
            .review_epoch(container, peer)
            .ok_or_else(|| error("container is no longer authorized".into()))?;
        // Escrow leak/missing-secret denials are not permissions the user
        // may override. Check before collecting or advertising the request.
        if let crate::settings::Substitution::Block(reason) =
            self.settings
                .substitute(req.uri().host().unwrap_or_default(), |name| {
                    req.headers()
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned)
                })
        {
            return Err(error(reason));
        }
        if req.headers().contains_key("content-encoding")
            || req.uri().path().ends_with("/git-receive-pack")
        {
            return Err(error(
                crate::policy::note(crate::policy::Decision::RequireReview)
                    .unwrap_or("unreviewable request")
                    .into(),
            ));
        }
        let _slot = crate::review::buffer_slots()
            .clone()
            .try_acquire_owned()
            .map_err(|_| error("review buffer capacity exceeded".into()))?;
        let (parts, body) = req.into_parts();
        let collected = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            http_body_util::Limited::new(body, crate::review::MAX_BODY).collect(),
        )
        .await
        .map_err(|_| error("request body upload timed out".into()))?
        .map_err(|_| error("request body exceeds 64 KiB or could not be read".into()))?;
        if collected.trailers().is_some() {
            return Err(error("HTTP trailers are not reviewable".into()));
        }
        let bytes = collected.to_bytes();
        let req = Request::from_parts(parts, Body::from(bytes.clone()));
        if crate::lfs::is_batch_route(&req) {
            if !crate::lfs::is_download(&req, &bytes) {
                return Err(error(
                    "Git LFS uploads and malformed/unsupported batch requests remain blocked"
                        .into(),
                ));
            }
            if !self.state.admit_lfs_download(event, container, peer, epoch) {
                return Err(error(
                    "container policy changed while reading the Git LFS batch body".into(),
                ));
            }
            guard.finished = true;
            return Ok(req); // Existing escrow substitution/response logging still run.
        }
        let mut detail = crate::review::Detail::from_request(container, &req, &bytes)
            .map_err(|e| error(e.to_string()))?;
        // Keep the review ID searchable/correlatable with its single audit row.
        detail.summary.id = event;
        if detail.graphql_read {
            if !self.state.admit_graphql_read(event, container, peer, epoch) {
                return Err(error(
                    "container policy changed while reading the GraphQL body".into(),
                ));
            }
            guard.finished = true;
            return Ok(req); // Existing escrow substitution/response logging still run.
        }
        if let Some(credential) = crate::github::comment_credential(&self.settings, &req)
            && let Some(crate::graphql::Review::Parsed { analysis }) = &detail.graphql
            && let Some(plan) = &analysis.comment
        {
            detail.comment_permission_supported = true;
            detail.comment_context = Some(crate::github::CommentContext {
                binding: credential.binding.clone(),
                subject_id: plan.subject_id.clone(),
                epoch,
                revision: self
                    .state
                    .comment_revision(container)
                    .ok_or_else(|| error("container was removed".into()))?,
            });
            let grants = self
                .state
                .comment_permissions(container, &credential.binding);
            if !grants.is_empty()
                && let Ok(target) = self
                    .state
                    .github
                    .resolve(&plan.subject_id, &credential)
                    .await
                && let Some(grant) = grants.iter().find(|g| g.target.same_identity(&target))
                && crate::github::Credential::current(&self.settings, &credential.binding).is_some()
            {
                // Canonical command + clean headers, not guest GraphQL. Freeze
                // the credential used to verify the target for this admission;
                // subsequent rotation affects subsequent commands.
                let mut canonical_plan = plan.clone();
                canonical_plan.subject_id = target.node_id.clone();
                let reconstructed = Request::builder()
                    .method("POST")
                    .uri(crate::github::ENDPOINT)
                    .header("content-type", "application/json")
                    .header("accept", "application/json")
                    .header("user-agent", "Friendzone comment permission")
                    .header("authorization", &credential.header_value)
                    .body(Body::from(canonical_plan.request_body()))
                    .expect("validated comment request");
                if self
                    .state
                    .admit_comment(event, container, peer, epoch, grant, &target)
                {
                    guard.finished = true;
                    return Ok(reconstructed);
                }
            }
        }
        for entry in self.settings.entries() {
            for (name, value) in &mut detail.headers {
                if name.eq_ignore_ascii_case(&entry.header) {
                    *value = "[redacted]".into();
                }
            }
        }
        self.state.annotate(
            event,
            None,
            Some(format!(
                "awaiting host review {} (120s limit)",
                detail.summary.id
            )),
        );
        let ticket = self
            .state
            .enqueue_review(detail, peer, epoch)
            .map_err(|e| error(e.to_string()))?;
        match ticket.wait().await.map_err(|e| error(e.to_string()))? {
            crate::review::Decision::Deny => return Err(error("denied by host reviewer".into())),
            crate::review::Decision::Approve => {}
        }
        if !self.state.admit_review(event, container, peer, epoch) {
            return Err(error(
                "container policy changed while awaiting approval".into(),
            ));
        }
        guard.finished = true;
        Ok(req)
    }
}

/// Applies to absolute HTTP(S) URLs, CONNECT authorities, and requests
/// decrypted inside a tunnel, before any upstream connection or escrow work.
/// This checks literal/normalized loopback names, not resolved DNS addresses.
fn destination_denial(
    uri: &hudsucker::hyper::Uri,
    management_port: u16,
    bootstrap_port: u16,
) -> Option<&'static str> {
    let destination_port = uri.port_u16().or_else(|| match uri.scheme_str() {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    });
    // The management denial always wins, even with conflicting configuration.
    if destination_port == Some(management_port) {
        return Some("friendzone: proxy access to the management UI port is forbidden");
    }
    if uri.host().is_some_and(is_loopback_host)
        && (bootstrap_port == 0 || destination_port != Some(bootstrap_port))
    {
        return Some(
            "friendzone: proxy access to host loopback is forbidden except on the configured bootstrap port; configure NO_PROXY/no_proxy for localhost,127.0.0.1,::1,[::1] and restart the guest client",
        );
    }
    None
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    // Reuse the existing URL parser for numeric aliases (127.1, octal/hex,
    // decimal IPv4). Do not resolve DNS here: a preflight DNS lookup without
    // pinning the connector's chosen address would not stop DNS rebinding.
    let Ok(url) = reqwest::Url::parse(&format!("http://{host}/")) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.to_ipv4().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

impl HttpHandler for EventHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        self.handle_from_peer(ctx.client_addr, req).await
    }

    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        error: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        let pending = self.pending.take();
        let elapsed = pending
            .as_ref()
            .map_or(std::time::Duration::ZERO, |pending| {
                pending.forwarding_at.elapsed()
            });
        let detail = upstream_failure_detail(&error, elapsed);
        if let Some(pending) = pending {
            let protocol = error.connect_info().map(|connection| {
                if connection.is_negotiated_h2() {
                    "h2"
                } else {
                    "http/1.1"
                }
            });
            if let Some(lifecycle) = &pending.lifecycle {
                let client_span = lifecycle.client_span();
                lifecycle
                    .server_span()
                    .record("http.response.status_code", 502_u16);
                client_span.record("friendzone.transport.detail", &detail);
                client_span.record("otel.status_code", "error");
                client_span.record("otel.status_description", &detail);
                tracing::warn!(
                    parent: &client_span,
                    request_id = %pending.id,
                    upstream_host = %pending.host,
                    diagnostic = %detail,
                    "upstream request failed"
                );
                lifecycle.finish("transport_error", None, protocol, 0);
            }
            self.state.reviews.observe(
                pending.id,
                crate::review::Status::UpstreamError,
                Some(502),
                if error.is_connect() {
                    "Upstream connection could not be established. No request was sent."
                } else {
                    "Upstream request failed while sending. Delivery is uncertain; check upstream before retrying."
                },
            );
            self.state
                .annotate(pending.id, Some(502), Some(detail.clone()));
            if pending.lifecycle.is_none() {
                tracing::warn!(
                    parent: &pending.server_span,
                    request_id = %pending.id,
                    upstream_host = %pending.host,
                    diagnostic = %detail,
                    "upstream request failed before lifecycle start"
                );
                pending
                    .server_span
                    .record("http.response.status_code", 502_u16);
                pending
                    .server_span
                    .record("friendzone.outcome", "transport_error");
                pending.server_span.record("error.type", "transport_error");
                pending.server_span.record("otel.status_code", "error");
                pending
                    .server_span
                    .record("otel.status_description", &detail);
            }
        }
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(format!("friendzone: {detail}")))
            .expect("static error")
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let Some(mut pending) = self.pending.take() else {
            return res;
        };
        let lifecycle = pending
            .lifecycle
            .take()
            .unwrap_or_else(|| UpstreamLifecycle::start(&pending));
        let id = pending.id;
        let host = pending.host;
        let status = res.status().as_u16();
        let protocol = match res.version() {
            hudsucker::hyper::Version::HTTP_2 => "h2",
            hudsucker::hyper::Version::HTTP_11 => "http/1.1",
            hudsucker::hyper::Version::HTTP_10 => "http/1.0",
            _ => "other",
        };
        let content_type = res
            .headers()
            .get(hudsucker::hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or_default().trim())
            .map(|value| match value {
                "application/json" => "application/json",
                "text/event-stream" => "text/event-stream",
                "application/x-ndjson" => "application/x-ndjson",
                _ => "other",
            })
            .unwrap_or("absent");
        let socket = res
            .extensions()
            .get::<hudsucker::hyper_util::client::legacy::connect::HttpInfo>();
        let upstream_remote = socket
            .map(|info| info.remote_addr().to_string())
            .unwrap_or_else(|| "unavailable".into());
        let upstream_local = socket
            .map(|info| info.local_addr().to_string())
            .unwrap_or_else(|| "unavailable".into());
        tracing::info!(
            parent: &lifecycle.client_span(),
            request_id = %id,
            upstream_host = %host,
            method = %pending.method,
            path = %pending.path,
            protocol,
            http_status = status,
            content_type,
            time_to_headers_ms = lifecycle.started.elapsed().as_millis() as u64,
            active_total = ACTIVE_UPSTREAM.load(Ordering::Acquire),
            active_host = host_active(&host, 0),
            upstream_remote,
            upstream_local,
            h2_connection = "unavailable_with_stock_hyper_connector",
            "upstream response headers"
        );
        self.state.reviews.observe(id, crate::review::Status::ResponseReceived, Some(status),
                                   if status >= 400 { "Upstream returned an HTTP error." } else { "Upstream response received. HTTP status alone does not confirm the operation succeeded." });
        let is_json = res
            .headers()
            .get(hudsucker::hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/json"));
        let reviewed_graphql =
            host.eq_ignore_ascii_case("api.github.com") && self.state.reviews.tracks_response(id);
        let response_headers = crate::review::diagnostic_response_headers(res.headers());
        let content_type = response_headers
            .iter()
            .find(|(name, _)| name == "content-type")
            .map(|(_, value)| value.clone());
        use http_body_util::BodyExt;
        let (parts, body) = res.into_parts();
        let observed = Body::from(
            ObservedResponseBody {
                inner: body,
                lifecycle,
                status,
                protocol,
                bytes: 0,
                first_byte: false,
                ended: false,
            }
            .boxed(),
        );
        if reviewed_graphql && is_json {
            self.state.annotate(id, Some(status), None);
            return Response::from_parts(
                parts,
                Body::from(
                    ReviewResponseBody {
                        inner: observed,
                        state: self.state.clone(),
                        id,
                        bytes: Some(Vec::new()),
                        content_type,
                        response_headers,
                        ended: false,
                    }
                    .boxed(),
                ),
            );
        }
        // Ordinary provider responses are never collected for optional usage
        // summaries. Returning the original body preserves first-byte delivery,
        // streaming, flow control, trailers, and connection reuse.
        self.state.annotate(id, Some(status), None);
        Response::from_parts(parts, observed)
    }
}

fn upstream_failure_detail(
    error: &hudsucker::hyper_util::client::legacy::Error,
    elapsed: std::time::Duration,
) -> String {
    let phase = if error.is_connect() {
        "connect"
    } else {
        "send"
    };
    let protocol = error.connect_info().map(|connection| {
        if connection.is_negotiated_h2() {
            "h2"
        } else {
            "http/1.1"
        }
    });
    let mut facts = vec![format!(
        "upstream {phase} failed after {} ms",
        elapsed.as_millis()
    )];
    if let Some(protocol) = protocol {
        facts.push(format!("protocol={protocol}"));
    }

    let mut source = error.source();
    let mut depth = 0;
    let mut classified = false;
    while let Some(cause) = source.filter(|_| depth < 12) {
        if let Some(hyper) = cause.downcast_ref::<hudsucker::hyper::Error>() {
            classified = true;
            let class = if hyper.is_timeout() {
                "timeout"
            } else if hyper.is_canceled() {
                "canceled"
            } else if hyper.is_closed() {
                "channel_closed"
            } else if hyper.is_incomplete_message() {
                "incomplete_message"
            } else if hyper.is_body_write_aborted() {
                "body_write_aborted"
            } else if hyper.is_shutdown() {
                "shutdown"
            } else if hyper.is_parse() {
                "parse"
            } else if hyper.is_user() {
                "request_body"
            } else {
                "transport"
            };
            facts.push(format!("hyper={class}"));
        }
        if let Some(h2) = cause.downcast_ref::<h2::Error>() {
            classified = true;
            let kind = if h2.is_reset() {
                "stream_reset"
            } else if h2.is_go_away() {
                "goaway"
            } else if h2.is_io() {
                "io"
            } else {
                "protocol"
            };
            let origin = if h2.is_remote() {
                "remote"
            } else if h2.is_library() {
                "library"
            } else {
                "local"
            };
            facts.push(format!("h2={origin}_{kind}"));
            if let Some(reason) = h2.reason() {
                facts.push(format!(
                    "h2_reason={}({})",
                    h2_reason_name(reason),
                    u32::from(reason)
                ));
            }
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            classified = true;
            let mut value = format!("io={:?}", io.kind());
            if let Some(code) = io.raw_os_error() {
                value.push_str(&format!("({code})"));
            }
            facts.push(value);
        }
        if let Some(tls) = cause.downcast_ref::<hudsucker::rustls::Error>() {
            classified = true;
            let class = match tls {
                hudsucker::rustls::Error::InvalidCertificate(_) => "invalid_certificate",
                hudsucker::rustls::Error::NoCertificatesPresented => "no_certificate",
                hudsucker::rustls::Error::AlertReceived(_) => "peer_alert",
                hudsucker::rustls::Error::PeerIncompatible(_) => "peer_incompatible",
                hudsucker::rustls::Error::NoApplicationProtocol => "no_application_protocol",
                _ => "protocol",
            };
            facts.push(format!("tls={class}"));
        }
        source = cause.source();
        depth += 1;
    }
    if !classified {
        facts.push("cause=unclassified".into());
    }
    facts.push(if error.is_connect() {
        "delivery=not_started".into()
    } else {
        "delivery=uncertain".into()
    });
    facts.push("friendzone_retry=disabled".into());
    let mut unique = Vec::with_capacity(facts.len());
    for fact in facts {
        if !unique.contains(&fact) {
            unique.push(fact);
        }
    }
    // All values are broker-generated enums, numeric codes, and elapsed time;
    // no arbitrary error text, URL, header, body, or credential is copied.
    unique.join("; ")
}

fn h2_reason_name(reason: h2::Reason) -> &'static str {
    match reason {
        h2::Reason::NO_ERROR => "NO_ERROR",
        h2::Reason::PROTOCOL_ERROR => "PROTOCOL_ERROR",
        h2::Reason::INTERNAL_ERROR => "INTERNAL_ERROR",
        h2::Reason::FLOW_CONTROL_ERROR => "FLOW_CONTROL_ERROR",
        h2::Reason::SETTINGS_TIMEOUT => "SETTINGS_TIMEOUT",
        h2::Reason::STREAM_CLOSED => "STREAM_CLOSED",
        h2::Reason::FRAME_SIZE_ERROR => "FRAME_SIZE_ERROR",
        h2::Reason::REFUSED_STREAM => "REFUSED_STREAM",
        h2::Reason::CANCEL => "CANCEL",
        h2::Reason::COMPRESSION_ERROR => "COMPRESSION_ERROR",
        h2::Reason::CONNECT_ERROR => "CONNECT_ERROR",
        h2::Reason::ENHANCE_YOUR_CALM => "ENHANCE_YOUR_CALM",
        h2::Reason::INADEQUATE_SECURITY => "INADEQUATE_SECURITY",
        h2::Reason::HTTP_1_1_REQUIRED => "HTTP_1_1_REQUIRED",
        _ => "UNKNOWN",
    }
}

pub fn basic_username(value: &str) -> Option<String> {
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let value = String::from_utf8(decoded).ok()?;
    let (username, _) = value.split_once(':')?;
    (!username.is_empty()).then(|| username.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn proxy_spans_continue_cline_trace_and_parent_the_upstream_lifecycle() {
        use opentelemetry::trace::{SpanKind, TracerProvider as _};
        use opentelemetry_sdk::testing::trace::new_test_exporter;
        use tracing_subscriber::layer::SubscriberExt as _;

        let (exporter, mut exported, _shutdown) = new_test_exporter();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let subscriber = tracing_subscriber::registry().with(
            tracing_opentelemetry::layer().with_tracer(provider.tracer("friendzone-proxy-test")),
        );
        let _guard = tracing::subscriber::set_default(subscriber);

        let dir = std::env::temp_dir().join(format!("fz-otel-{}", uuid::Uuid::new_v4()));
        let state = AppState::default();
        state.add_container("guest").unwrap();
        state
            .set_pinned_ip("guest", Some("127.0.0.1".parse().unwrap()))
            .unwrap();
        let mut handler = EventHandler::new(
            state,
            crate::settings::Settings::load(&dir).unwrap(),
            8081,
            8082,
        );
        let mut request = Request::builder()
            .method("POST")
            .uri("https://api.cline.bot/v1/chat?secret=query")
            .header(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )
            .body(Body::empty())
            .unwrap();
        request
            .headers_mut()
            .insert("authorization", "Bearer must-not-export".parse().unwrap());
        let RequestOrResponse::Request(forwarded) = handler
            .handle_from_peer("127.0.0.1:12345".parse().unwrap(), request)
            .await
        else {
            panic!("approved request was not forwarded")
        };

        let propagated = forwarded.headers()["traceparent"].to_str().unwrap();
        let fields: Vec<_> = propagated.split('-').collect();
        assert_eq!(fields[1], "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_ne!(fields[2], "00f067aa0ba902b7");
        let client_span_id = fields[2].to_owned();
        drop(forwarded);
        handler
            .pending
            .as_ref()
            .unwrap()
            .lifecycle
            .as_ref()
            .unwrap()
            .finish("response_complete", Some(200), Some("h2"), 37);
        handler.pending = None;
        drop(handler);
        provider.force_flush().unwrap();

        let mut spans = Vec::new();
        while let Ok(span) = exported.try_recv() {
            spans.push(span);
        }
        assert_eq!(spans.len(), 2, "{spans:#?}");
        let server = spans
            .iter()
            .find(|span| span.span_kind == SpanKind::Server)
            .unwrap();
        let client = spans
            .iter()
            .find(|span| span.span_kind == SpanKind::Client)
            .unwrap();
        assert_eq!(
            server.span_context.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(server.parent_span_id.to_string(), "00f067aa0ba902b7");
        assert!(server.parent_span_is_remote);
        assert_eq!(
            client.span_context.trace_id(),
            server.span_context.trace_id()
        );
        assert_eq!(client.parent_span_id, server.span_context.span_id());
        assert_eq!(client.span_context.span_id().to_string(), client_span_id);
        let attributes = client
            .attributes
            .iter()
            .map(|attribute| (attribute.key.as_str(), attribute.value.to_string()))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(attributes["http.response.status_code"], "200");
        assert_eq!(attributes["http.response.body.size"], "37");
        assert_eq!(attributes["network.protocol.name"], "h2");
        let rendered = format!("{spans:#?}");
        assert!(!rendered.contains("must-not-export"));
        assert!(!rendered.contains("secret=query"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn response_final_frame_does_not_need_an_extra_poll_to_record_completion() {
        use crate::review::{Decision, Detail, Status};
        use http_body_util::BodyExt;
        let state = AppState::default();
        for (payload, expected) in [
            (r#"{"data":{"ok":true}}"#, Status::ResponseReceived),
            (
                r#"{"errors":[{"message":"private"}]}"#,
                Status::GraphqlError,
            ),
        ] {
            let req = request("POST", "https://api.github.com/graphql", Some("guest"));
            let detail = Detail::from_request("guest", &req, b"").unwrap();
            let id = detail.summary.id;
            let ticket = state.reviews.enqueue(detail.clone()).unwrap();
            state
                .reviews
                .decide(id, &detail.summary.fingerprint, Decision::Approve)
                .unwrap();
            ticket.wait().await.unwrap();
            state.reviews.observe(
                id,
                Status::ResponseReceived,
                Some(200),
                "HTTP response received",
            );
            let mut body = ReviewResponseBody {
                inner: Body::from(payload),
                state: state.clone(),
                id,
                bytes: Some(Vec::new()),
                content_type: Some("application/json".into()),
                response_headers: vec![],
                ended: false,
            };
            assert_eq!(
                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                payload
            );
            drop(body); // HTTP implementations may not ask for a trailing None.
            let detail = state.reviews.inspect(id).unwrap();
            assert_eq!(detail.summary.status, expected);
            assert!(!detail.summary.outcome.unwrap().contains("private"));
            if expected == Status::GraphqlError {
                let diagnostics = detail.graphql_response.unwrap();
                assert_eq!(diagnostics.error_count, 1);
                assert_eq!(diagnostics.errors[0].message, "private");
                assert_eq!(diagnostics.response_bytes, payload.len());
            } else {
                assert!(detail.graphql_response.is_none());
            }
        }
    }

    #[tokio::test]
    async fn response_observation_is_bounded_keeps_bytes_and_reports_uncertainty() {
        use crate::review::{Decision, Detail, Status};
        use http_body_util::BodyExt;
        let state = AppState::default();
        let queued = || {
            let req = request("POST", "https://api.github.com/graphql", Some("guest"));
            let detail = Detail::from_request("guest", &req, b"").unwrap();
            let id = detail.summary.id;
            let ticket = state.reviews.enqueue(detail.clone()).unwrap();
            state
                .reviews
                .decide(id, &detail.summary.fingerprint, Decision::Approve)
                .unwrap();
            (id, ticket)
        };
        let (unknown, ticket) = queued();
        assert_eq!(ticket.wait().await.unwrap(), Decision::Approve);
        state
            .reviews
            .observe(unknown, Status::Sending, None, "sending");
        drop(ResponseWatch {
            state: state.clone(),
            id: unknown,
        });
        assert_eq!(
            state.reviews.inspect(unknown).unwrap().summary.status,
            Status::Unknown
        );
        for payload in [
            br#"{"errors":[{"message":"private"}]}"#.to_vec(),
            vec![b'x'; crate::review::MAX_BODY + 1],
            br#"{"data":{"ok":true}}"#.to_vec(),
        ] {
            let (id, ticket) = queued();
            assert_eq!(ticket.wait().await.unwrap(), Decision::Approve);
            state.reviews.observe(
                id,
                Status::ResponseReceived,
                Some(200),
                "HTTP response received",
            );
            let body = ReviewResponseBody {
                inner: Body::from(payload.clone()),
                state: state.clone(),
                id,
                bytes: Some(Vec::new()),
                content_type: Some("application/json".into()),
                response_headers: vec![],
                ended: false,
            };
            assert_eq!(
                body.collect().await.unwrap().to_bytes().as_ref(),
                payload.as_slice()
            );
            let summary = state.reviews.inspect(id).unwrap().summary;
            assert_eq!(
                summary.status,
                if payload.starts_with(b"{\"errors\"") {
                    Status::GraphqlError
                } else {
                    Status::ResponseReceived
                }
            );
            assert!(!summary.outcome.unwrap().contains("private"));
        }
        let (id, ticket) = queued();
        ticket.wait().await.unwrap();
        state.reviews.observe(
            id,
            Status::ResponseReceived,
            Some(201),
            "HTTP response received",
        );
        drop(ReviewResponseBody {
            inner: Body::from("incomplete"),
            state: state.clone(),
            id,
            bytes: Some(Vec::new()),
            content_type: Some("application/json".into()),
            response_headers: vec![],
            ended: false,
        });
        let summary = state.reviews.inspect(id).unwrap().summary;
        assert_eq!(summary.status, Status::Unknown);
        assert_eq!(summary.http_status, Some(201));
    }

    #[tokio::test]
    async fn graphql_reads_keep_identity_kill_pin_escrow_and_buffered_policy_gates() {
        let dir = std::env::temp_dir().join(format!("fz-read-gates-{}", uuid::Uuid::new_v4()));
        let state = AppState::default();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let query = r#"{"query":"query { viewer { login } }"}"#;
        let read = |user: Option<&str>| {
            let mut req = request("POST", crate::github::ENDPOINT, user);
            req.headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            *req.body_mut() = Body::from(query);
            req
        };
        let mut handler = EventHandler::new(state.clone(), settings.clone(), 8081, 8082);
        assert_eq!(
            status(handler.handle_from_peer(peer, read(None)).await),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED
        );
        assert_eq!(
            status(handler.handle_from_peer(peer, read(Some("guest"))).await),
            StatusCode::FORBIDDEN
        );
        state.approve_container("guest", true).unwrap();
        assert!(matches!(
            handler.handle_from_peer(peer, read(Some("guest"))).await,
            RequestOrResponse::Request(_)
        ));
        assert_eq!(
            status(
                handler
                    .handle_from_peer("127.0.0.2:12345".parse().unwrap(), read(Some("guest")))
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        state.set_killed("guest".into(), true).unwrap();
        assert_eq!(
            status(handler.handle_from_peer(peer, read(Some("guest"))).await),
            StatusCode::FORBIDDEN
        );
        state.set_killed("guest".into(), false).unwrap();
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
        let mut no_secret = read(Some("guest"));
        no_secret
            .headers_mut()
            .insert("authorization", "Bearer fake".parse().unwrap());
        assert_eq!(
            status(handler.handle_from_peer(peer, no_secret).await),
            StatusCode::FORBIDDEN
        );
        settings.set_secret("github", "secret").unwrap();
        let mut with_secret = read(Some("guest"));
        with_secret
            .headers_mut()
            .insert("authorization", "Bearer fake".parse().unwrap());
        let RequestOrResponse::Request(forwarded) =
            handler.handle_from_peer(peer, with_secret).await
        else {
            panic!("approved read")
        };
        assert_eq!(forwarded.headers()["authorization"], "Bearer secret");
        assert!(!forwarded.headers().contains_key(PROXY_AUTHORIZATION));
        assert!(state.reviews.summaries().is_empty());
        for action in ["kill", "pin", "remove"] {
            state.add_container("guest").unwrap();
            state.set_killed("guest".into(), false).unwrap();
            state.set_pinned_ip("guest", None).unwrap();
            let changed = state.clone();
            let mut req = read(Some("guest"));
            *req.body_mut() = Body::from_stream(futures_util::stream::once(async move {
                match action {
                    "kill" => {
                        changed.set_killed("guest".into(), true).unwrap();
                        changed.set_killed("guest".into(), false).unwrap();
                    }
                    "pin" => changed
                        .set_pinned_ip("guest", Some("127.0.0.2".parse().unwrap()))
                        .unwrap(),
                    _ => {
                        changed.remove_container("guest").unwrap();
                        changed.add_container("guest").unwrap();
                    }
                }
                Ok::<_, std::io::Error>(query)
            }));
            assert_eq!(
                status(handler.handle_from_peer(peer, req).await),
                StatusCode::FORBIDDEN,
                "{action} during buffering"
            );
            assert!(state.reviews.summaries().is_empty());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn lfs_download_is_a_buffered_read_but_upload_and_policy_races_fail_closed() {
        let dir = std::env::temp_dir().join(format!("fz-lfs-gates-{}", uuid::Uuid::new_v4()));
        let state = AppState::default();
        state.add_container("guest").unwrap();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let oid = "a".repeat(64);
        let body = |operation: &str| {
            format!(
                r#"{{"operation":"{operation}","transfers":["ssh","lfs-standalone-file","basic"],"objects":[{{"oid":"{oid}","size":12}}],"hash_algo":"sha256"}}"#
            )
        };
        let request = |operation: &str| {
            let mut request = request(
                "POST",
                "https://github.com/cline/cline.git/info/lfs/objects/batch",
                Some("guest"),
            );
            request.headers_mut().insert(
                "content-type",
                "application/vnd.git-lfs+json; charset=utf-8"
                    .parse()
                    .unwrap(),
            );
            request
                .headers_mut()
                .insert("accept", "application/vnd.git-lfs+json".parse().unwrap());
            *request.body_mut() = Body::from(body(operation));
            request
        };
        let mut handler = EventHandler::new(state.clone(), settings.clone(), 8081, 8082);
        assert!(matches!(
            handler.handle_from_peer(peer, request("download")).await,
            RequestOrResponse::Request(_)
        ));
        assert!(state.reviews.summaries().is_empty());
        assert!(matches!(state.view().requests[0].verdict, Verdict::Allowed));

        assert_eq!(
            status(handler.handle_from_peer(peer, request("upload")).await),
            StatusCode::FORBIDDEN
        );
        assert!(state.reviews.summaries().is_empty());

        let changed = state.clone();
        let raced_body = body("download");
        let mut raced = request("download");
        *raced.body_mut() = Body::from_stream(futures_util::stream::once(async move {
            changed.set_killed("guest".into(), true).unwrap();
            changed.set_killed("guest".into(), false).unwrap();
            Ok::<_, std::io::Error>(raced_body)
        }));
        assert_eq!(
            status(handler.handle_from_peer(peer, raced).await),
            StatusCode::FORBIDDEN
        );
        assert!(state.reviews.summaries().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    async fn wait_for_review(state: &AppState) -> crate::review::Summary {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(summary) = state.reviews.summaries().into_iter().next() {
                    break summary;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("request entered review")
    }

    #[tokio::test]
    async fn kill_resume_pin_removal_and_cancellation_invalidate_waiting_writes() {
        let dir = std::env::temp_dir().join(format!("fz-review-gates-{}", uuid::Uuid::new_v4()));
        let state = AppState::default();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
        for action in ["kill", "pin", "remove", "cancel"] {
            state.add_container("guest").unwrap();
            state.set_killed("guest".into(), false).unwrap();
            state.set_pinned_ip("guest", None).unwrap();
            let mut handler = EventHandler::new(state.clone(), settings.clone(), 8081, 8082);
            let task = tokio::spawn(async move {
                handler
                    .handle_from_peer(
                        peer,
                        request("POST", "https://api.github.com/graphql", Some("guest")),
                    )
                    .await
            });
            let summary = wait_for_review(&state).await;
            match action {
                "kill" => {
                    state.set_killed("guest".into(), true).unwrap();
                    state.set_killed("guest".into(), false).unwrap();
                }
                "pin" => state
                    .set_pinned_ip("guest", Some("127.0.0.2".parse().unwrap()))
                    .unwrap(),
                "remove" => {
                    state.remove_container("guest").unwrap();
                    state.add_container("guest").unwrap();
                }
                _ => {
                    task.abort();
                }
            }
            if action != "cancel" {
                assert_eq!(status(task.await.unwrap()), StatusCode::FORBIDDEN);
            } else {
                assert!(task.await.unwrap_err().is_cancelled());
            }
            assert!(state.reviews.summaries().is_empty());
            assert!(
                state
                    .reviews
                    .decide(
                        summary.id,
                        &summary.fingerprint,
                        crate::review::Decision::Approve
                    )
                    .is_err()
            );
            assert!(matches!(state.view().requests[0].verdict, Verdict::Blocked));
            assert_eq!(
                state.reviews.inspect(summary.id).unwrap().summary.status,
                crate::review::Status::Cancelled
            );
        }
        // Approval racing with a later kill cannot slip through a resume.
        state.set_pinned_ip("guest", None).unwrap();
        let epoch = state.review_epoch("guest", peer.ip()).unwrap();
        state.set_killed("guest".into(), true).unwrap();
        state.set_killed("guest".into(), false).unwrap();
        assert!(!state.admit_review(uuid::Uuid::new_v4(), "guest", peer.ip(), epoch));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn oversized_encoded_binary_and_escrow_denials_never_enter_inbox() {
        let dir = std::env::temp_dir().join(format!("fz-review-body-{}", uuid::Uuid::new_v4()));
        let state = AppState::default();
        state.add_container("guest").unwrap();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let mut handler = EventHandler::new(state.clone(), settings.clone(), 8081, 8082);
        for (body, encoding) in [
            (vec![b'x'; crate::review::MAX_BODY + 1], None),
            (vec![255], None),
            (vec![b'x'], Some("gzip")),
        ] {
            let mut req = request("POST", "https://api.github.com/graphql", Some("guest"));
            req.headers_mut()
                .insert("content-type", "application/json".parse().unwrap());
            if let Some(encoding) = encoding {
                req.headers_mut()
                    .insert("content-encoding", encoding.parse().unwrap());
            }
            *req.body_mut() = Body::from(body);
            assert_eq!(
                status(
                    handler
                        .handle_from_peer("127.0.0.1:12345".parse().unwrap(), req)
                        .await
                ),
                StatusCode::FORBIDDEN
            );
            assert!(state.reviews.summaries().is_empty());
        }
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "wrong-host".into(),
                hosts: vec!["example.test".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fake".into(),
                guest_env: None,
                real_env: None,
            })
            .unwrap();
        let mut req = request("POST", "https://api.github.com/graphql", Some("guest"));
        req.headers_mut()
            .insert("authorization", "Bearer fake".parse().unwrap());
        assert_eq!(
            status(
                handler
                    .handle_from_peer("127.0.0.1:12345".parse().unwrap(), req)
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        assert!(state.reviews.summaries().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn loopback_destination_forms_and_bootstrap_exception() {
        let check =
            |url: &str, bootstrap| destination_denial(&url.parse().unwrap(), 8081, bootstrap);
        for host in [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.254",
            "127.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "127.0.0.1.",
            "localhost",
            "LOCALHOST",
            "localhost.",
            "app.localhost",
            "[::1]",
            "[0:0:0:0:0:0:0:1]",
            "[::ffff:127.0.0.1]",
            "[::ffff:7f00:1]",
            "[::127.0.0.1]",
        ] {
            for url in [
                format!("http://{host}:25463/health"),
                format!("{host}:25463"),
            ] {
                assert!(
                    check(&url, 9082).unwrap().contains("host loopback"),
                    "{url}"
                );
            }
            for url in [format!("http://{host}:9082/health"), format!("{host}:9082")] {
                assert!(check(&url, 9082).is_none(), "bootstrap: {url}");
            }
        }
        // Default HTTP/HTTPS ports must participate in the same decision.
        for (url, port) in [
            ("http://127.0.0.1/health", 80),
            ("https://[::1]/health", 443),
        ] {
            assert!(check(url, 9082).is_some());
            assert!(check(url, port).is_none());
        }
        assert!(
            check("http://127.0.0.1:8082/health", 9082).is_some(),
            "no hardcoded 8082 exception"
        );
        assert!(
            check("http://127.0.0.1:0/health", 0).is_some(),
            "port zero cannot grant access"
        );
        assert!(
            check("http://127.0.0.1:8081/health", 8081)
                .unwrap()
                .contains("management UI")
        );
        for url in [
            "http://192.0.2.1:25463/health",
            "https://example.com/",
            "example.com:443",
            "http://localhost.example.com/",
            "http://notlocalhost/",
            "http://[2001:db8::1]/",
        ] {
            assert!(
                check(url, 9082).is_none(),
                "not a loopback destination: {url}"
            );
        }
    }

    #[tokio::test]
    async fn loopback_guard_precedes_review_and_applies_inside_tunnels() {
        let dir = std::env::temp_dir().join(format!("fz-loopback-{}", uuid::Uuid::new_v4()));
        let state = AppState::default();
        state.add_container("guest").unwrap();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let mut handler = EventHandler::new(state.clone(), settings, 8081, 9082);
        let peer = "10.0.0.2:12345".parse().unwrap();
        for (method, url) in [
            ("GET", "http://127.0.0.1:25463/health"),
            ("POST", "http://localhost:25463/graphql"),
            ("DELETE", "https://[::1]/resource"),
            ("CONNECT", "127.0.0.1:25463"),
        ] {
            let mut req = request(method, url, Some("guest"));
            req.headers_mut()
                .insert("host", "127.0.0.1:9082".parse().unwrap());
            assert_eq!(
                status(handler.handle_from_peer(peer, req).await),
                StatusCode::FORBIDDEN
            );
            let view = state.view();
            assert_eq!(view.requests[0].url, url);
            assert_eq!(view.requests[0].status, Some(403));
            assert!(
                view.requests[0]
                    .detail
                    .as_deref()
                    .unwrap()
                    .contains("NO_PROXY")
            );
            assert!(matches!(view.requests[0].verdict, Verdict::Blocked));
            assert!(view.pending_requests.is_empty());
            assert!(handler.pending.is_none());
        }
        assert!(matches!(
            handler
                .handle_from_peer(peer, request("CONNECT", "127.0.0.1:9082", Some("guest")))
                .await,
            RequestOrResponse::Request(_)
        ));
        let mut intercepted = handler.clone();
        assert_eq!(
            status(
                intercepted
                    .handle_from_peer(peer, request("GET", "http://127.0.0.1:25463/health", None))
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        assert!(matches!(
            intercepted
                .handle_from_peer(peer, request("GET", "http://127.0.0.1:9082/health", None))
                .await,
            RequestOrResponse::Request(_)
        ));
        // The exception bypasses only the loopback destination rule, not
        // container authorization, IP pins, or the reversible kill switch.
        state.set_killed("guest".into(), true).unwrap();
        assert_eq!(
            status(
                intercepted
                    .handle_from_peer(peer, request("GET", "http://127.0.0.1:9082/health", None))
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        state.set_killed("guest".into(), false).unwrap();
        state
            .set_pinned_ip("guest", Some("10.0.0.3".parse().unwrap()))
            .unwrap();
        assert_eq!(
            status(
                intercepted
                    .handle_from_peer(peer, request("GET", "http://127.0.0.1:9082/health", None))
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        let mut fresh = EventHandler::new(state.clone(), handler.settings.clone(), 8081, 9082);
        assert_eq!(
            status(
                fresh
                    .handle_from_peer(
                        peer,
                        request("GET", "http://127.0.0.1:9082/health", Some("unknown"))
                    )
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        state.set_pinned_ip("guest", None).unwrap();
        assert_eq!(
            status(
                fresh
                    .handle_from_peer(peer, request("GET", "https://github.com/", None))
                    .await
            ),
            StatusCode::FORBIDDEN,
            "clearing an IP pin must invalidate an existing credential-free tunnel"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn management_port_is_denied_before_http_forwarding_or_connect() {
        let dir = std::env::temp_dir().join(format!("fz-ui-gate-{}", uuid::Uuid::new_v4()));
        let state = AppState::default();
        state.add_container("guest").unwrap();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let mut handler = EventHandler::new(state.clone(), settings.clone(), 8081, 8082);
        let peer = "10.0.0.2:12345".parse().unwrap();
        for host in [
            "127.0.0.1",
            "localhost",
            "[::1]",
            "[::ffff:127.0.0.1]",
            "host-alias.example",
            "2130706433",
        ] {
            for method in ["GET", "POST", "CONNECT"] {
                let url = if method == "CONNECT" {
                    format!("{host}:8081")
                } else {
                    format!("http://{host}:8081/api/containers")
                };
                assert_eq!(
                    status(
                        handler
                            .handle_from_peer(peer, request(method, &url, Some("guest")))
                            .await
                    ),
                    StatusCode::FORBIDDEN
                );
                assert!(
                    state.view().requests[0]
                        .detail
                        .as_deref()
                        .unwrap()
                        .contains("management UI")
                );
            }
        }
        for (port, url) in [
            (80, "http://localhost/api/state"),
            (443, "https://localhost/api/state"),
        ] {
            let mut handler = EventHandler::new(state.clone(), settings.clone(), port, 8082);
            assert_eq!(
                status(
                    handler
                        .handle_from_peer(peer, request("GET", url, Some("guest")))
                        .await
                ),
                StatusCode::FORBIDDEN
            );
        }
        // This guard must not break recovery/bootstrap or direct MCP access.
        assert!(matches!(
            handler
                .handle_from_peer(
                    peer,
                    request("GET", "http://10.0.0.1:8082/health", Some("guest"))
                )
                .await,
            RequestOrResponse::Request(_)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn real_proxy_cannot_reach_management_listener() {
        use hudsucker::{Proxy, certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let dir = std::env::temp_dir().join(format!("fz-ui-isolation-{}", uuid::Uuid::new_v4()));
        let files = crate::ca::AuthorityFiles::load_or_create(&dir).unwrap();
        let state = AppState::default();
        state.add_container("guest").unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let ui_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_addr = ui_listener.local_addr().unwrap();
        let ui = tokio::spawn(async move {
            axum::serve(
                ui_listener,
                axum::Router::new().fallback(move || {
                    observed.fetch_add(1, Ordering::SeqCst);
                    async { "management" }
                }),
            )
            .await
            .unwrap()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(RcgenAuthority::new(
                files.issuer().unwrap(),
                10,
                aws_lc_rs::default_provider(),
            ))
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(EventHandler::new(
                state,
                crate::settings::Settings::load(&dir).unwrap(),
                ui_addr.port(),
                8082,
            ))
            .build()
            .unwrap();
        let task = tokio::spawn(proxy.start());
        let client = reqwest::Client::builder()
            .proxy(
                reqwest::Proxy::all(format!("http://{address}"))
                    .unwrap()
                    .basic_auth("guest", "x"),
            )
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let response = client
            .post(format!("http://{ui_addr}/api/containers"))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.text().await.unwrap().contains("management UI"));
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket.write_all(format!("CONNECT {ui_addr} HTTP/1.1\r\nHost: {ui_addr}\r\nProxy-Authorization: Basic Z3Vlc3Q6eA==\r\n\r\n").as_bytes()).await.unwrap();
        let mut bytes = [0; 1024];
        let count =
            tokio::time::timeout(std::time::Duration::from_secs(5), socket.read(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert!(String::from_utf8_lossy(&bytes[..count]).starts_with("HTTP/1.1 403"));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "no request reached the management listener"
        );
        task.abort();
        ui.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn request(method: &str, url: &str, user: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(url);
        if let Some(user) = user {
            builder = builder.header(
                PROXY_AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(format!("{user}:x"))),
            );
        }
        builder.body(Body::empty()).unwrap()
    }

    fn status(result: RequestOrResponse) -> StatusCode {
        match result {
            RequestOrResponse::Response(response) => response.status(),
            _ => panic!("expected response"),
        }
    }

    #[tokio::test]
    async fn connect_identity_and_policy_gates() {
        let dir = std::env::temp_dir().join(format!("fz-proxy-{}", uuid::Uuid::new_v4()));
        let state = AppState::default();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let mut handler = EventHandler::new(state.clone(), settings, 8081, 8082);
        let peer = "127.0.0.1:12345".parse().unwrap();
        let challenge = handler
            .handle_from_peer(peer, request("CONNECT", "github.com:443", None))
            .await;
        match challenge {
            RequestOrResponse::Response(response) => {
                assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
                assert_eq!(
                    response.headers()[PROXY_AUTHENTICATE],
                    "Basic realm=\"Friendzone\""
                );
            }
            _ => panic!("expected challenge"),
        }
        assert!(
            state.view().containers.is_empty(),
            "challenge must not create an IP-named guest"
        );
        assert_eq!(
            status(
                handler
                    .handle_from_peer(peer, request("CONNECT", "github.com:443", Some("guest")))
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        assert!(
            state.view().requests[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("awaiting approval")
        );
        state.approve_container("guest", true).unwrap();
        let connect = handler
            .handle_from_peer(peer, request("CONNECT", "github.com:443", Some("guest")))
            .await;
        assert!(matches!(connect, RequestOrResponse::Request(_)));
        let mut intercepted = handler.clone();
        let read = intercepted
            .handle_from_peer(
                peer,
                request(
                    "POST",
                    "https://github.com/cline/cline.git/git-upload-pack",
                    None,
                ),
            )
            .await;
        assert!(matches!(read, RequestOrResponse::Request(_)));
        assert_eq!(state.view().requests[0].container, "guest");
        assert_eq!(
            status(
                intercepted
                    .handle_from_peer(
                        peer,
                        request(
                            "POST",
                            "https://github.com/cline/cline.git/git-receive-pack",
                            None
                        )
                    )
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        state.set_killed("guest".into(), true).unwrap();
        assert_eq!(
            status(
                intercepted
                    .handle_from_peer(peer, request("GET", "https://github.com/", None))
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        state.set_killed("guest".into(), false).unwrap();
        let mut fresh = EventHandler::new(state.clone(), handler.settings.clone(), 8081, 8082);
        assert!(matches!(
            fresh
                .handle_from_peer(peer, request("CONNECT", "github.com:443", None))
                .await,
            RequestOrResponse::Request(_)
        ));
        let mut spoofed = EventHandler::new(state.clone(), handler.settings.clone(), 8081, 8082);
        assert_eq!(
            status(
                spoofed
                    .handle_from_peer(
                        peer,
                        request("CONNECT", "github.com:443", Some("different-guest"))
                    )
                    .await
            ),
            StatusCode::FORBIDDEN,
            "legacy name cannot override the IP-pin owner"
        );
        assert_eq!(
            status(
                fresh
                    .handle_from_peer(
                        "127.0.0.2:12345".parse().unwrap(),
                        request("CONNECT", "github.com:443", Some("guest"))
                    )
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn real_mitm_tunnel_keeps_identity_and_blocks_decrypted_write() {
        use hudsucker::{Proxy, certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
        let dir = std::env::temp_dir().join(format!("fz-mitm-{}", uuid::Uuid::new_v4()));
        let files = crate::ca::AuthorityFiles::load_or_create(&dir).unwrap();
        let state = AppState::default();
        state.add_container("guest").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(RcgenAuthority::new(
                files.issuer().unwrap(),
                10,
                aws_lc_rs::default_provider(),
            ))
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(EventHandler::new(
                state.clone(),
                crate::settings::Settings::load(&dir).unwrap(),
                8081,
                8082,
            ))
            .build()
            .unwrap();
        let task = tokio::spawn(proxy.start());
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(
                reqwest::Certificate::from_pem(files.cert_pem.as_bytes()).unwrap(),
            )
            .proxy(
                reqwest::Proxy::all(format!("http://{address}"))
                    .unwrap()
                    .basic_auth("guest", "x"),
            )
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        // No external network: the decrypted write is blocked locally.
        let response = client
            .post("https://github.com/cline/cline.git/git-receive-pack")
            .send()
            .await;
        task.abort();
        let response = response.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.text().await.unwrap().contains("GitHub writes"));
        let events = state.view().requests;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].container, "guest");
        assert_eq!(events[0].method, "POST");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn proxy_identity_exposes_only_username() {
        assert_eq!(
            basic_username("Basic cmV2aWV3ZXI6c2VjcmV0"),
            Some("reviewer".into())
        );
        assert_eq!(basic_username("Bearer secret"), None);
    }
}
