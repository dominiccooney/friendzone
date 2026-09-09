use base64::{Engine, engine::general_purpose::STANDARD};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{
        Request, Response, StatusCode,
        header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    },
};

use crate::state::{AppState, Verdict};

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
}

impl EventHandler {
    pub fn new(state: AppState, settings: crate::settings::Settings) -> Self {
        Self {
            state,
            settings,
            pending: None,
            tunnel_identity: None,
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
        if req.method() == hudsucker::hyper::Method::CONNECT && !killed {
            self.tunnel_identity = Some(container);
            // Successful CONNECTs are transport setup, not application
            // requests. Do not bury the useful log under these rows.
            return req.into();
        }
        let decision = crate::policy::classify(&req);
        let blocked = killed || decision == crate::policy::Decision::BlockWrite;
        let host = req.uri().host().unwrap_or_default().to_owned();
        let id = self.state.record(
            container,
            req.method().to_string(),
            req.uri().to_string(),
            if blocked {
                Verdict::Blocked
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
        } else if blocked {
            let note = crate::policy::note(decision).unwrap_or("friendzone: blocked");
            self.state.annotate(id, Some(403), Some(note.into()));
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(note))
                .expect("static blocked response")
                .into()
        } else {
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
        if !(is_known_host && is_json) {
            self.state.annotate(id, Some(status), None);
            return res;
        }
        let (parts, body) = res.into_parts();
        match http_body_util::BodyExt::collect(body).await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                let detail = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .and_then(|json| inference_detail(&json));
                self.state.annotate(id, Some(status), detail);
                Response::from_parts(parts, Body::from(bytes.to_vec()))
            }
            Err(_) => {
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
        let mut handler = EventHandler::new(state.clone(), settings);
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
        state.approve_container("guest", true);
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
        state.set_killed("guest".into(), true);
        assert_eq!(
            status(
                intercepted
                    .handle_from_peer(peer, request("GET", "https://github.com/", None))
                    .await
            ),
            StatusCode::FORBIDDEN
        );
        state.set_killed("guest".into(), false);
        let mut fresh = EventHandler::new(state.clone(), handler.settings.clone());
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
        state.add_container("guest");
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
