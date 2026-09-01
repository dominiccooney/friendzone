use base64::{Engine, engine::general_purpose::STANDARD};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{Request, Response, StatusCode, header::PROXY_AUTHORIZATION},
};

use crate::state::{AppState, Verdict};

#[derive(Clone)]
pub struct EventHandler {
    state: AppState,
}

impl EventHandler {
    pub fn new(state: AppState) -> Self {
        Self { state }
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
        self.state.record(
            container,
            req.method().to_string(),
            req.uri().to_string(),
            if killed {
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
        } else {
            req.into()
        }
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}

fn basic_username(value: &str) -> Option<String> {
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
