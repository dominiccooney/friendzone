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
}

impl EventHandler {
    pub fn new(state: AppState, settings: crate::settings::Settings) -> Self {
        Self { state, settings }
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
        let killed = self.state.is_killed(&container);
        let decision = crate::policy::classify(&req);
        let blocked = killed || decision == crate::policy::Decision::BlockWrite;
        self.state.record(
            container,
            req.method().to_string(),
            req.uri().to_string(),
            if blocked {
                Verdict::Blocked
            } else {
                Verdict::Allowed
            },
        );
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
        res
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

    #[test]
    fn proxy_identity_exposes_only_username() {
        assert_eq!(
            basic_username("Basic cmV2aWV3ZXI6c2VjcmV0"),
            Some("reviewer".into())
        );
        assert_eq!(basic_username("Bearer secret"), None);
    }
}
