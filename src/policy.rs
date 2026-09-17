//! Request classification: reads flow, potential writes require review.
//!
//! Read vs write is semantic, not the HTTP method: git-upload-pack, Git LFS
//! download batches, and GraphQL POSTs enter policy/body inspection. Selected
//! GraphQL queries and strict LFS `operation: download` envelopes flow
//! automatically; mutations queue for one-shot review unless an explicitly
//! saved comment permission admits a reconstructed addComment.
//! Unknown origins remain unpoliced while policy grows.

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
    /// Policed origin, potential write: explicit one-shot host review.
    RequireReview,
}

const GITHUB_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
];

pub fn classify(req: &Request<Body>) -> Decision {
    // CONNECT admits interception, not an upstream operation. The proxy
    // still applies identity/approval/IP/kill gates before this, and this
    // classifier runs again on every decrypted request inside the tunnel.
    if req.method() == hudsucker::hyper::Method::CONNECT {
        return Decision::Unpoliced;
    }
    let Some(host) = req.uri().host() else {
        return Decision::Unpoliced;
    };
    if !GITHUB_HOSTS
        .iter()
        .any(|github| host.eq_ignore_ascii_case(github))
    {
        return Decision::Unpoliced;
    }
    match github_access(req) {
        Access::Read => Decision::AllowRead,
        Access::Write => Decision::RequireReview,
    }
}

pub fn note(decision: Decision) -> Option<&'static str> {
    match decision {
        Decision::RequireReview => {
            Some("friendzone: GitHub writes require review; this request format is not reviewable")
        }
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
            classify(&req("CONNECT", "github.com:443")),
            Decision::Unpoliced
        );
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
            classify(&req("POST", "https://API.GITHUB.COM/graphql")),
            Decision::RequireReview
        );
        assert_eq!(
            classify(&req(
                "POST",
                "https://api.github.com/repos/x/y/issues/1/comments"
            )),
            Decision::RequireReview
        );
        assert_eq!(
            classify(&req("POST", "https://github.com/x/y.git/git-receive-pack")),
            Decision::RequireReview
        );
        assert_eq!(
            classify(&req("DELETE", "https://api.github.com/repos/x/y")),
            Decision::RequireReview
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
