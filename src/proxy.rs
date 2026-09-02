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
            substitute_inference_key(&mut req);
            req.into()
        }
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}

/// Escrow-style substitution for inference hosts: whatever (fake) key
/// the container sent is replaced with the real one from the host env.
/// Host-pinned by construction: the route table is keyed by host, so
/// the real key can only ever be attached to its named host.
fn substitute_inference_key(req: &mut Request<Body>) {
    let Some(route) = req
        .uri()
        .host()
        .and_then(crate::policy::inference_route)
    else {
        return;
    };
    let Ok(real_key) = std::env::var(route.env) else {
        return; // No real key on the host: pass through unchanged.
    };
    let value = format!("{}{}", route.prefix, real_key);
    if let Ok(header_value) = value.parse() {
        req.headers_mut().insert(route.header, header_value);
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
    fn inference_key_substitutes_only_for_pinned_host() {
        // SAFETY: test-scoped variable name, no concurrent reader.
        unsafe { std::env::set_var("FZ_ANTHROPIC_API_KEY", "sk-real") };
        let mut req = Request::builder()
            .method("POST")
            .uri("https://api.anthropic.com/v1/messages")
            .header("x-api-key", "sk-fake")
            .body(Body::empty())
            .unwrap();
        substitute_inference_key(&mut req);
        assert_eq!(req.headers()["x-api-key"], "sk-real");

        // Same fake key toward any other host stays fake.
        let mut other = Request::builder()
            .method("POST")
            .uri("https://evil.example.com/v1/messages")
            .header("x-api-key", "sk-fake")
            .body(Body::empty())
            .unwrap();
        substitute_inference_key(&mut other);
        assert_eq!(other.headers()["x-api-key"], "sk-fake");
        unsafe { std::env::remove_var("FZ_ANTHROPIC_API_KEY") };
    }

    #[test]
    fn substitution_touches_only_the_credential_header() {
        // Feature headers like Anthropic's beta flags must pass through:
        // substitution replaces exactly one header, nothing else.
        unsafe { std::env::set_var("FZ_CLINE_API_KEY", "cline-real") };
        let mut req = Request::builder()
            .method("POST")
            .uri("https://api.cline.bot/v1/chat/completions")
            .header("authorization", "Bearer fake")
            .header("anthropic-beta", "computer-use-2025-01-24")
            .header("anthropic-version", "2023-06-01")
            .header("x-task-id", "task-123")
            .body(Body::empty())
            .unwrap();
        substitute_inference_key(&mut req);
        assert_eq!(req.headers()["authorization"], "Bearer cline-real");
        assert_eq!(req.headers()["anthropic-beta"], "computer-use-2025-01-24");
        assert_eq!(req.headers()["anthropic-version"], "2023-06-01");
        assert_eq!(req.headers()["x-task-id"], "task-123");
        unsafe { std::env::remove_var("FZ_CLINE_API_KEY") };
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
