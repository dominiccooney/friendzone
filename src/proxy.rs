use base64::{Engine, engine::general_purpose::STANDARD};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{Request, Response, StatusCode, header::PROXY_AUTHORIZATION},
};

use crate::state::{AppState, Verdict};

#[derive(Clone)]
pub struct EventHandler {
    state: AppState,
    settings: crate::settings::Settings,
    /// The in-flight request on this connection, for response
    /// annotation: (log id, upstream host).
    pending: Option<(uuid::Uuid, String)>,
}

impl EventHandler {
    pub fn new(state: AppState, settings: crate::settings::Settings) -> Self {
        Self {
            state,
            settings,
            pending: None,
        }
    }

    fn container(&self, req: &Request<Body>, ctx: &HttpContext) -> String {
        let username = req
            .headers()
            .get(PROXY_AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(basic_username);
        self.state.identify_connection(ctx.client_addr, username)
    }
}

impl HttpHandler for EventHandler {
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        let container = self.container(&req, ctx);
        // Proxy credentials identify a container and must never reach the upstream host.
        req.headers_mut().remove(PROXY_AUTHORIZATION);
        // The container gate comes before any policy: unknown names are
        // join requests (approve them in the UI), and a known name from
        // the wrong address is denied.
        let authorization = self.state.authorize(&container, ctx.client_addr.ip());
        if authorization != crate::state::Authorization::Allowed {
            let reason = match authorization {
                crate::state::Authorization::Pending => {
                    "friendzone: container awaiting approval; approve it in the UI inbox"
                }
                _ => "friendzone: container name is pinned to a different address",
            };
            self.state.record(
                container,
                req.method().to_string(),
                req.uri().to_string(),
                Verdict::Blocked,
            );
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(reason))
                .expect("static blocked response")
                .into();
        }
        let killed = self.state.is_killed(&container);
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
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("container is killed"))
                .expect("static blocked response")
                .into()
        } else if blocked {
            let note = crate::policy::note(decision).unwrap_or("friendzone: blocked");
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
                crate::settings::Substitution::Block(reason) => Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from(reason))
                    .expect("static blocked response")
                    .into(),
            }
        }
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

    #[test]
    fn proxy_identity_exposes_only_username() {
        assert_eq!(
            basic_username("Basic cmV2aWV3ZXI6c2VjcmV0"),
            Some("reviewer".into())
        );
        assert_eq!(basic_username("Bearer secret"), None);
    }
}
