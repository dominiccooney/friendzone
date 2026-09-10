use base64::{Engine, engine::general_purpose::STANDARD};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{
        Request, Response, StatusCode,
        header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    },
};

use crate::state::{AppState, Verdict};

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
    ended: bool,
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
            }
            Poll::Ready(None) => {
                this.ended = true;
                if let Some(bytes) = &this.bytes
                    && let Ok(json) = serde_json::from_slice::<serde_json::Value>(bytes)
                    && json
                        .get("errors")
                        .and_then(|errors| errors.as_array())
                        .is_some_and(|errors| !errors.is_empty())
                {
                    this.state.reviews.response_detail(this.id, crate::review::Status::GraphqlError, "GitHub returned GraphQL errors; the operation may have partially executed. Check upstream before retrying.");
                }
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
    /// annotation: (log id, upstream host).
    pending: Option<(uuid::Uuid, String)>,
    /// Hudsucker clones the CONNECT handler into intercepted requests.
    /// Identity travels with that tunnel, never in an IP/port cache that
    /// could outlive a socket and authenticate a different connection.
    tunnel_identity: Option<String>,
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
            management_port,
            bootstrap_port,
            response_watch: None,
        }
    }

    fn container(&self, req: &Request<Body>) -> Option<String> {
        self.tunnel_identity.clone().or_else(|| {
            req.headers()
                .get(PROXY_AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(basic_username)
        })
    }

    async fn handle_from_peer(
        &mut self,
        peer: std::net::SocketAddr,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        self.pending = None;
        self.response_watch = None;
        let Some(container) = self.container(&req) else {
            // Git/libcurl's anyauth mode waits for this challenge before
            // sending the username from its proxy URL. 403 cannot do that.
            return Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(PROXY_AUTHENTICATE, "Basic realm=\"Friendzone\"")
                .body(Body::from(
                    "friendzone: proxy credentials required; use http://CONTAINER:x@HOST:PORT",
                ))
                .expect("static challenge")
                .into();
        };
        // Proxy credentials identify a container and must never reach the upstream host.
        req.headers_mut().remove(PROXY_AUTHORIZATION);
        // The container gate comes before any policy: unknown names are
        // join requests (approve them in the UI), and a known name from
        // the wrong address is denied.
        let authorization = self.state.authorize(&container, peer.ip());
        if authorization != crate::state::Authorization::Allowed {
            let reason = match authorization {
                crate::state::Authorization::Pending => {
                    "friendzone: container awaiting approval; approve it in the UI inbox"
                }
                _ => "friendzone: container name is pinned to a different address",
            };
            let id = self.state.record(
                container,
                req.method().to_string(),
                req.uri().to_string(),
                Verdict::Blocked,
            );
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
            self.state.annotate(id, Some(403), Some(reason.into()));
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(reason))
                .expect("static denial")
                .into();
        }
        if req.method() == hudsucker::hyper::Method::CONNECT && !killed {
            self.tunnel_identity = Some(container);
            // Successful CONNECTs are transport setup, not application
            // requests. Do not bury the useful log under these rows.
            return req.into();
        }
        let decision = crate::policy::classify(&req);
        let needs_review = decision == crate::policy::Decision::RequireReview;
        let blocked = killed;
        let host = req.uri().host().unwrap_or_default().to_owned();
        let id = self.state.record(
            container.clone(),
            req.method().to_string(),
            req.uri().to_string(),
            if blocked {
                Verdict::Blocked
            } else if needs_review {
                Verdict::Pending
            } else {
                Verdict::Allowed
            },
        );
        if !blocked {
            self.pending = Some((id, host.clone()));
        }
        if killed {
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
                crate::settings::Substitution::None => req.into(),
                crate::settings::Substitution::Replace { header, value } => {
                    if let Ok(header_value) = value.parse() {
                        req.headers_mut().insert(
                            hudsucker::hyper::header::HeaderName::try_from(header.as_str())
                                .expect("escrow header name"),
                            header_value,
                        );
                    }
                    req.into()
                }
                crate::settings::Substitution::Block(reason) => {
                    self.pending = None;
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
        if let Some((id, _)) = self.pending.take() {
            self.state.reviews.observe(id, crate::review::Status::UpstreamError, Some(502), "Upstream connection failed. Delivery is uncertain; check upstream before retrying.");
            self.state.annotate(
                id,
                Some(502),
                Some(format!("upstream connection failed: {error}")),
            );
        }
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(
                "friendzone: upstream connection failed (see broker log)",
            ))
            .expect("static error")
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let Some((id, host)) = self.pending.take() else {
            return res;
        };
        let status = res.status().as_u16();
        self.state.reviews.observe(id, crate::review::Status::ResponseReceived, Some(status),
            if status >= 400 { "Upstream returned an HTTP error." } else { "Upstream response received. HTTP status alone does not confirm the operation succeeded." });
        // Only inspect bodies for escrow-pinned hosts (our known
        // providers), and only JSON: streaming stays untouched.
        let is_known_host = self
            .settings
            .entries()
            .iter()
            .any(|entry| entry.hosts.iter().any(|h| h == &host));
        let is_json = res
            .headers()
            .get(hudsucker::hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/json"));
        let reviewed_graphql =
            host.eq_ignore_ascii_case("api.github.com") && self.state.reviews.tracks_response(id);
        if reviewed_graphql && is_json {
            use http_body_util::BodyExt;
            self.state.annotate(id, Some(status), None);
            let (parts, body) = res.into_parts();
            return Response::from_parts(
                parts,
                Body::from(
                    ReviewResponseBody {
                        inner: body,
                        state: self.state.clone(),
                        id,
                        bytes: Some(Vec::new()),
                        ended: false,
                    }
                    .boxed(),
                ),
            );
        }
        if !(is_known_host && is_json) {
            self.state.annotate(id, Some(status), None);
            return res;
        }
        let (parts, body) = res.into_parts();
        match http_body_util::BodyExt::collect(body).await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                let parsed = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
                let detail = parsed.as_ref().and_then(inference_detail);
                self.state.annotate(id, Some(status), detail);
                Response::from_parts(parts, Body::from(bytes.to_vec()))
            }
            Err(_) => {
                self.state.reviews.response_detail(id, crate::review::Status::Unknown, "HTTP headers received, but reading the response failed. Check upstream before retrying.");
                self.state.annotate(id, Some(status), None);
                Response::from_parts(parts, Body::empty())
            }
        }
    }
}

/// Summarizes a JSON inference response: model and token counts.
/// Handles Anthropic (`usage.input_tokens`) and OpenAI-style
/// (`usage.prompt_tokens`) shapes; unknown shapes yield None.
fn inference_detail(json: &serde_json::Value) -> Option<String> {
    let usage = json.get("usage")?;
    let (input, output) = match (
        usage.get("input_tokens").and_then(|v| v.as_u64()),
        usage.get("output_tokens").and_then(|v| v.as_u64()),
    ) {
        (Some(i), Some(o)) => (i, o),
        _ => (
            usage.get("prompt_tokens").and_then(|v| v.as_u64())?,
            usage
                .get("completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        ),
    };
    let model = json.get("model").and_then(|v| v.as_str()).unwrap_or("?");
    Some(format!("{model}: {input} in / {output} out tokens"))
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
        assert_eq!(
            status(
                fresh
                    .handle_from_peer(peer, request("CONNECT", "github.com:443", None))
                    .await
            ),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "socket address reuse must not inherit identity"
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
