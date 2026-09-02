//! Request classification: reads flow, writes queue (blocked for now).
//!
//! Read vs write is semantic, not the HTTP method: git-upload-pack and
//! GraphQL queries are reads despite being POSTs. This slice classifies
//! GitHub origins conservatively; unknown origins keep flowing so the
//! proxy stays useful while policy grows.

use hudsucker::{Body, hyper::Request};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Not a policed origin; current behavior (flow, log).
    Unpoliced,
    /// Policed origin, read-class: flows.
    AllowRead,
    /// Policed origin, write-class: blocked with a note until the
    /// pending-request inbox exists.
    BlockWrite,
}

const GITHUB_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
];

pub fn classify(req: &Request<Body>) -> Decision {
    let Some(host) = req.uri().host() else {
        return Decision::Unpoliced;
    };
    if !GITHUB_HOSTS.contains(&host) {
        return Decision::Unpoliced;
    }
    match github_access(req) {
        Access::Read => Decision::AllowRead,
        Access::Write => Decision::BlockWrite,
    }
}

/// Inference hosts get escrow-style key substitution: the container
/// holds a fake key, the broker swaps in the real one from a host env
/// var. Host-pinned: the real key is attached only for its named host.
pub struct InferenceRoute {
    pub host: &'static str,
    /// Header carrying the credential.
    pub header: &'static str,
    /// Header value prefix, e.g. "Bearer " (empty for x-api-key).
    pub prefix: &'static str,
    /// Host env var with the real key.
    pub env: &'static str,
}

pub const INFERENCE_ROUTES: &[InferenceRoute] = &[
    InferenceRoute {
        host: "api.anthropic.com",
        header: "x-api-key",
        prefix: "",
        env: "FZ_ANTHROPIC_API_KEY",
    },
    InferenceRoute {
        host: "api.openai.com",
        header: "authorization",
        prefix: "Bearer ",
        env: "FZ_OPENAI_API_KEY",
    },
    // Cline: OpenAI-compatible, Bearer auth (cline/cline
    // src/api/providers/cline.ts).
    InferenceRoute {
        host: "api.cline.bot",
        header: "authorization",
        prefix: "Bearer ",
        env: "FZ_CLINE_API_KEY",
    },
];

pub fn inference_route(host: &str) -> Option<&'static InferenceRoute> {
    INFERENCE_ROUTES.iter().find(|route| route.host == host)
}

pub fn note(decision: Decision) -> Option<&'static str> {
    match decision {
        Decision::BlockWrite => Some(
            "friendzone: GitHub writes are gated; this slice blocks them (pending-request inbox not built yet)",
        ),
        _ => None,
    }
}

fn github_access(req: &Request<Body>) -> Access {
    let method = req.method().as_str();
    let path = req.uri().path();
    match method {
        "GET" | "HEAD" | "OPTIONS" => Access::Read,
        // git smart-HTTP fetch: POST to .../git-upload-pack is a read.
        "POST" if path.ends_with("/git-upload-pack") => Access::Read,
        _ => Access::Write,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn github_reads_flow() {
        assert_eq!(
            classify(&req("GET", "https://api.github.com/repos/x/y/pulls/1")),
            Decision::AllowRead
        );
        assert_eq!(
            classify(&req("POST", "https://github.com/x/y.git/git-upload-pack")),
            Decision::AllowRead
        );
    }

    #[test]
    fn github_writes_block() {
        assert_eq!(
            classify(&req(
                "POST",
                "https://api.github.com/repos/x/y/issues/1/comments"
            )),
            Decision::BlockWrite
        );
        assert_eq!(
            classify(&req("POST", "https://github.com/x/y.git/git-receive-pack")),
            Decision::BlockWrite
        );
        assert_eq!(
            classify(&req("DELETE", "https://api.github.com/repos/x/y")),
            Decision::BlockWrite
        );
    }

    #[test]
    fn other_origins_unpoliced() {
        assert_eq!(
            classify(&req("POST", "https://example.com/anything")),
            Decision::Unpoliced
        );
    }
}
