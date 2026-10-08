//! Request classification: reads flow, potential writes require review.
//!
//! Read vs write is semantic, not the HTTP method: git-upload-pack, Git LFS
//! download batches, and GraphQL POSTs enter policy/body inspection. Selected
//! GraphQL queries and strict LFS `operation: download` envelopes flow
//! automatically; mutations queue for one-shot review unless an explicitly
//! saved comment permission admits a reconstructed addComment.
//! Explicit allow-all mode streams GitHub operations without body inspection
//! or review; identity, destination, and credential gates remain in the proxy.
//! Unknown origins remain unpoliced while policy grows.

use hudsucker::{Body, hyper::Request};

use crate::state::ClineAccess;

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
    /// GitHub review is explicitly disabled for this broker session.
    AllowAll,
    /// Policed origin, potential write: explicit one-shot host review.
    RequireReview,
}

/// Fixed at broker startup and shared by every GitHub admission path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GithubPolicy {
    #[default]
    Review,
    AllowAll,
}

impl GithubPolicy {
    pub fn allows_all(self) -> bool {
        self == Self::AllowAll
    }
}

const GITHUB_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "uploads.github.com",
];

pub fn classify(req: &Request<Body>, github_policy: GithubPolicy) -> Decision {
    // CONNECT admits interception, not an upstream operation. The proxy
    // still applies identity/approval/IP/kill gates before this, and this
    // classifier runs again on every decrypted request inside the tunnel.
    if req.method() == hudsucker::hyper::Method::CONNECT {
        return Decision::Unpoliced;
    }
    let Some(host) = req.uri().host() else {
        return Decision::Unpoliced;
    };
    // Linear file-upload credentials must not grant unreviewed arbitrary API
    // mutations through the general proxy. Text writes keep the one-shot gate.
    if crate::settings::host_matches(host, "api.linear.app") {
        return if matches!(req.method().as_str(), "GET" | "HEAD" | "OPTIONS") {
            Decision::AllowRead
        } else {
            Decision::RequireReview
        };
    }
    if !GITHUB_HOSTS
        .iter()
        .any(|github| crate::settings::host_matches(host, github))
    {
        return Decision::Unpoliced;
    }
    if github_policy.allows_all() {
        return Decision::AllowAll;
    }
    match github_access(req) {
        Access::Read => Decision::AllowRead,
        Access::Write => Decision::RequireReview,
    }
}

pub fn note(decision: Decision) -> Option<&'static str> {
    match decision {
        Decision::RequireReview => {
            Some("friendzone: this write requires review; this request format is not reviewable")
        }
        _ => None,
    }
}

/// Cline's production API origin. Always governed by the per-container gate,
/// whatever token a request carries: a guest-supplied token here cannot be
/// told apart from a leaked one, and this is where the broker's account lives.
pub const CLINE_API_HOST: &str = "api.cline.bot";

/// Verdict of the per-container Cline API gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClineVerdict {
    /// Not the Cline API host, or the request is allowed in this mode.
    Allow,
    /// Never forwarded in any mode (API key management).
    Deny(&'static str),
    /// Basic mode: answer locally with this JSON body instead of forwarding,
    /// so cloud-session lists look empty rather than erroring.
    Synthetic(&'static str),
}

/// Paths that no guest may reach in any mode. A prompt-injected agent must
/// not mint or list long-lived credentials: `/api/v1/api-keys` (user) and
/// `/api/v1/organizations/{id}/api-keys` (organization).
fn is_api_key_management(path: &str) -> bool {
    matches!(path, "/api/v1/api-keys" | "/api/v1/api-keys/")
        || path.starts_with("/api/v1/api-keys/")
        || (path.starts_with("/api/v1/organizations/") && {
            let rest = &path["/api/v1/organizations/".len()..];
            match rest.split_once('/') {
                Some((_, tail)) => tail == "api-keys" || tail.starts_with("api-keys/"),
                None => false,
            }
        })
}

/// Basic mode allowlist: inference, the model catalog, and account basics
/// (who am I, which organizations, switch the active one, balance/usage),
/// desktop banners/configuration and a root content-type probe.
/// Derived from cline/cline's SDK/CLI/desktop clients; everything else on
/// the host (cloud sessions, connectors, integrations, auth, plans) is denied.
fn basic_allows(method: &str, path: &str) -> bool {
    let read = matches!(method, "GET" | "HEAD" | "OPTIONS");
    match path {
        // Link previews probe content type with HEAD, not a CORS preflight.
        "/" => method == "HEAD",
        "/banners/v2/messages" | "/api/v1/users/me/remote-config" => method == "GET",
        // Inference and model-backed tools.
        "/api/v1/chat/completions" | "/api/v1/images" => method == "POST",
        "/api/v1/search/websearch" | "/api/v1/search/webfetch" => method == "POST",
        // Model catalog.
        "/api/v1/ai/cline/recommended-models" => read,
        // Account basics.
        "/api/v1/users/me" | "/api/v1/users/me/plan" => read,
        "/api/v1/users/active-account" => method == "PUT",
        _ => {
            if let Some(rest) = path.strip_prefix("/api/v1/users/") {
                // /users/{id}/balance|usages|payments — one id segment, then a
                // known read-only suffix. Reject nested paths and empty ids.
                return read
                    && matches!(
                        rest.split_once('/'),
                        Some((id, "balance" | "usages" | "payments")) if !id.is_empty() && id != "me"
                    );
            }
            if let Some(rest) = path.strip_prefix("/api/v1/organizations/") {
                let Some((id, tail)) = rest.split_once('/') else {
                    // GET /organizations/{id}
                    return read && !rest.is_empty();
                };
                if id.is_empty() {
                    return false;
                }
                if tail == "balance" {
                    return read;
                }
                // /organizations/{id}/members/{memberId}/usages
                if let Some(member_rest) = tail.strip_prefix("members/") {
                    return read
                        && matches!(
                            member_rest.split_once('/'),
                            Some((member, "usages")) if !member.is_empty()
                        );
                }
            }
            false
        }
    }
}

/// Applies the per-container Cline API gate. Runs on every decrypted
/// request; CONNECT is transport setup and is judged again inside the tunnel.
///
/// The gate follows the credential: `is_cline_host` must answer true for every
/// host the broker would substitute its Cline account token toward (the hosts
/// pinned by Cline credential entries, which the administrator may edit).
/// The production host is governed regardless, so a caller cannot un-gate it.
pub fn cline_verdict(
    req: &Request<Body>,
    access: ClineAccess,
    is_cline_host: impl Fn(&str) -> bool,
) -> ClineVerdict {
    if req.method() == hudsucker::hyper::Method::CONNECT {
        return ClineVerdict::Allow;
    }
    let Some(host) = req.uri().host() else {
        return ClineVerdict::Allow;
    };
    if !crate::settings::host_matches(host, CLINE_API_HOST) && !is_cline_host(host) {
        return ClineVerdict::Allow;
    }
    let path = req.uri().path();
    if is_api_key_management(path) {
        return ClineVerdict::Deny(
            "friendzone: Cline API key management is never available to guests",
        );
    }
    if access == ClineAccess::Full {
        return ClineVerdict::Allow;
    }
    // WebSocket upgrades (the cloud-session Hub) are never part of the basic
    // allowlist, whatever path they claim.
    let upgrade = req
        .headers()
        .get(hudsucker::hyper::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if upgrade {
        return ClineVerdict::Deny(
            "friendzone: Cline cloud-session connections are not allowed for this guest (basic Cline access)",
        );
    }
    let method = req.method().as_str();
    if matches!(path, "/api/v1/session" | "/api/v1/session/") && matches!(method, "GET" | "HEAD") {
        return ClineVerdict::Synthetic(r#"{"success":true,"data":[]}"#);
    }
    if basic_allows(method, path) {
        ClineVerdict::Allow
    } else {
        ClineVerdict::Deny(
            "friendzone: this Cline API operation is not allowed for this guest (basic Cline access: inference and account basics only)",
        )
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

    fn classify(req: &Request<Body>) -> Decision {
        super::classify(req, GithubPolicy::Review)
    }

    #[test]
    fn allow_all_covers_every_github_method_but_not_other_policy_hosts() {
        for host in GITHUB_HOSTS.iter().copied().chain(["API.GITHUB.COM."]) {
            for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
                let request = req(method, &format!("https://{host}/arbitrary/path"));
                assert_eq!(
                    super::classify(&request, GithubPolicy::AllowAll),
                    Decision::AllowAll
                );
            }
        }
        assert_eq!(
            super::classify(
                &req("POST", "https://api.linear.app/graphql"),
                GithubPolicy::AllowAll
            ),
            Decision::RequireReview
        );
        assert_eq!(
            super::classify(
                &req("POST", "https://api.github.com.evil.test/graphql"),
                GithubPolicy::AllowAll
            ),
            Decision::Unpoliced
        );
        assert_eq!(
            super::classify(&req("CONNECT", "github.com:443"), GithubPolicy::AllowAll),
            Decision::Unpoliced
        );
    }

    fn req(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn canonical_hosts_cannot_bypass_write_or_cline_gates() {
        assert_eq!(classify(&req("POST", "https://API.GITHUB.COM./graphql")), Decision::RequireReview);
        assert_eq!(classify(&req("POST", "https://API.LINEAR.APP./graphql")), Decision::RequireReview);
        assert!(matches!(cline_verdict(&req("POST", "https://API.CLINE.BOT./api/v1/api-keys"), ClineAccess::Full, |_| false), ClineVerdict::Deny(_)));
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
        assert_eq!(classify(&req("POST", "https://api.linear.app/graphql")), Decision::RequireReview);
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

    fn cline(method: &str, path: &str, access: ClineAccess) -> ClineVerdict {
        // The production host needs no help from the credential predicate.
        cline_verdict(
            &req(method, &format!("https://api.cline.bot{path}")),
            access,
            |_| false,
        )
    }

    #[test]
    fn api_key_management_is_denied_in_every_mode() {
        for access in [ClineAccess::Basic, ClineAccess::Full] {
            for (method, path) in [
                ("GET", "/api/v1/api-keys"),
                ("POST", "/api/v1/api-keys"),
                ("POST", "/api/v1/api-keys/"),
                ("DELETE", "/api/v1/api-keys/key-123"),
                ("GET", "/api/v1/organizations/org-1/api-keys"),
                ("POST", "/api/v1/organizations/org-1/api-keys"),
                ("DELETE", "/api/v1/organizations/org-1/api-keys/key-9"),
            ] {
                assert!(
                    matches!(cline(method, path, access), ClineVerdict::Deny(reason) if reason.contains("API key")),
                    "{access:?} {method} {path}"
                );
            }
        }
        // Host matching is case-insensitive; a query string does not change the path.
        assert!(matches!(
            cline_verdict(
                &req("POST", "https://API.CLINE.BOT/api/v1/api-keys?x=1"),
                ClineAccess::Full,
                |_| false
            ),
            ClineVerdict::Deny(_)
        ));
    }

    #[test]
    fn full_access_forwards_everything_else_on_the_cline_host() {
        for (method, path) in [
            ("POST", "/api/v1/session"),
            ("GET", "/api/v1/session"),
            ("POST", "/api/v1/session/ses-1/history"),
            ("GET", "/api/v1/integrations/github/repositories"),
            ("POST", "/api/v1/connectors/tools/GMAIL_SEND_EMAIL/execute"),
            ("POST", "/api/v1/chat/completions"),
            ("PUT", "/api/v1/users/active-account"),
        ] {
            assert_eq!(
                cline(method, path, ClineAccess::Full),
                ClineVerdict::Allow,
                "{method} {path}"
            );
        }
    }

    #[test]
    fn basic_access_allows_inference_catalog_and_account_basics() {
        for (method, path) in [
            ("POST", "/api/v1/chat/completions"),
            ("POST", "/api/v1/images"),
            ("POST", "/api/v1/search/websearch"),
            ("POST", "/api/v1/search/webfetch"),
            ("GET", "/api/v1/ai/cline/recommended-models"),
            ("GET", "/api/v1/users/me"),
            ("GET", "/api/v1/users/me/plan"),
            ("PUT", "/api/v1/users/active-account"),
            ("GET", "/api/v1/users/user-1/balance"),
            ("GET", "/api/v1/users/user-1/usages"),
            ("GET", "/api/v1/users/user-1/payments"),
            ("GET", "/api/v1/organizations/org-1"),
            ("GET", "/api/v1/organizations/org-1/balance"),
            ("GET", "/api/v1/organizations/org-1/members/member-9/usages"),
        ] {
            assert_eq!(
                cline(method, path, ClineAccess::Basic),
                ClineVerdict::Allow,
                "{method} {path}"
            );
        }
    }

    #[test]
    fn client_metadata_reads_are_narrow_and_query_independent() {
        for query in [
            "",
            "?ide=vscode&extension_version=4.1.22&os=windows",
            "?os=linux&ide=jetbrains&extension_version=9",
            "?extra=x",
        ] {
            for path in ["/banners/v2/messages", "/api/v1/users/me/remote-config"] {
                assert_eq!(
                    cline("GET", &format!("{path}{query}"), ClineAccess::Basic),
                    ClineVerdict::Allow
                );
                for method in ["POST", "PUT", "DELETE"] {
                    assert!(matches!(
                        cline(method, &format!("{path}{query}"), ClineAccess::Basic),
                        ClineVerdict::Deny(_)
                    ));
                }
            }
        }
        assert_eq!(cline("HEAD", "/", ClineAccess::Basic), ClineVerdict::Allow);
        for (method, path) in [
            ("GET", "/"),
            ("OPTIONS", "/"),
            ("HEAD", "/other"),
            ("GET", "/banners/v2/messages/extra"),
            ("GET", "/api/v1/users/me/remote-config/extra"),
        ] {
            assert!(matches!(
                cline(method, path, ClineAccess::Basic),
                ClineVerdict::Deny(_)
            ));
        }
        assert_eq!(
            classify(&req(
                "POST",
                "https://uploads.github.com/user-attachments/assets"
            )),
            Decision::RequireReview
        );
    }

    #[test]
    fn basic_access_hides_cloud_sessions_and_denies_everything_else() {
        // Listing looks empty rather than failing; nothing else about sessions flows.
        for path in ["/api/v1/session", "/api/v1/session/"] {
            assert_eq!(
                cline("GET", path, ClineAccess::Basic),
                ClineVerdict::Synthetic(r#"{"success":true,"data":[]}"#)
            );
        }
        assert!(matches!(
            cline_verdict(
                &req(
                    "GET",
                    "https://api.cline.bot/api/v1/session?organizationId=org-1"
                ),
                ClineAccess::Basic,
                |_| false
            ),
            ClineVerdict::Synthetic(_)
        ));
        for (method, path) in [
            ("POST", "/api/v1/session"),
            ("GET", "/api/v1/session/ses-1"),
            ("DELETE", "/api/v1/session/ses-1"),
            ("GET", "/api/v1/session/ses-1/history"),
            ("GET", "/api/v1/session/ses-1/status"),
            ("GET", "/api/v1/integrations"),
            ("GET", "/api/v1/integrations/github/repositories"),
            ("GET", "/api/v1/connectors"),
            ("POST", "/api/v1/connectors/tools/GMAIL_SEND_EMAIL/execute"),
            ("POST", "/api/v1/auth/refresh"),
            ("POST", "/api/v1/auth/register"),
            ("GET", "/api/v1/plans"),
            ("POST", "/api/v1/users/me/budget/request"),
            ("GET", "/api/v1/users/me/featurebase-token"),
            ("GET", "/api/v1/organizations/org-1/remote-config"),
            (
                "GET",
                "/api/v1/organizations/org-1/integrations/github/repositories",
            ),
            ("GET", "/api/v1/organizations/org-1/members/member-9"),
            ("GET", "/api/v1/organizations/"),
            ("GET", "/api/v1/users//balance"),
            ("GET", "/api/v1/users/me/balance/extra"),
            ("DELETE", "/api/v1/users/me"),
            ("POST", "/api/v1/users/me"),
            ("GET", "/api/v1/chat/completions"),
            ("GET", "/"),
            ("GET", "/v1/mcp/anything"),
        ] {
            assert!(
                matches!(
                    cline(method, path, ClineAccess::Basic),
                    ClineVerdict::Deny(_)
                ),
                "{method} {path} should be denied"
            );
        }
    }

    #[test]
    fn basic_access_denies_websocket_upgrades_even_on_allowed_paths() {
        let request = Request::builder()
            .method("GET")
            .uri("https://api.cline.bot/api/v1/users/me")
            .header("upgrade", "WebSocket")
            .header("connection", "Upgrade")
            .body(Body::empty())
            .unwrap();
        assert!(matches!(
            cline_verdict(&request, ClineAccess::Basic, |_| false),
            ClineVerdict::Deny(reason) if reason.contains("cloud-session")
        ));
        let request = Request::builder()
            .method("GET")
            .uri("https://api.cline.bot/api/v1/session/ses-1")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();
        assert!(matches!(
            cline_verdict(&request, ClineAccess::Basic, |_| false),
            ClineVerdict::Deny(_)
        ));
        assert_eq!(
            cline_verdict(&request, ClineAccess::Full, |_| false),
            ClineVerdict::Allow
        );
    }

    #[test]
    fn cline_gate_ignores_other_hosts_and_connect() {
        assert_eq!(
            cline_verdict(
                &req("POST", "https://api.github.com/api/v1/api-keys"),
                ClineAccess::Basic,
                |_| false
            ),
            ClineVerdict::Allow
        );
        assert_eq!(
            cline_verdict(
                &req("POST", "https://evil.api.cline.bot/api/v1/session"),
                ClineAccess::Basic,
                |_| false
            ),
            ClineVerdict::Allow,
            "an unpinned subdomain is another origin: no token is substituted there, so nothing to gate"
        );
        assert_eq!(
            cline_verdict(
                &req("CONNECT", "api.cline.bot:443"),
                ClineAccess::Basic,
                |_| true
            ),
            ClineVerdict::Allow
        );
    }

    #[test]
    fn cline_gate_follows_the_credential_to_every_pinned_host() {
        // An administrator pinned the Cline entry to a second origin, so the
        // broker would substitute the account token there: the same allowlist
        // must apply there, in every mode.
        let pinned = |host: &str| host == "core-api.staging.int.cline.bot";
        let staging = |method: &str, path: &str| {
            req(
                method,
                &format!("https://core-api.staging.int.cline.bot{path}"),
            )
        };
        for access in [ClineAccess::Basic, ClineAccess::Full] {
            assert!(matches!(
                cline_verdict(&staging("POST", "/api/v1/api-keys"), access, pinned),
                ClineVerdict::Deny(reason) if reason.contains("API key")
            ));
        }
        assert_eq!(
            cline_verdict(
                &staging("GET", "/api/v1/session"),
                ClineAccess::Basic,
                pinned
            ),
            ClineVerdict::Synthetic(r#"{"success":true,"data":[]}"#)
        );
        assert!(matches!(
            cline_verdict(
                &staging("POST", "/api/v1/session"),
                ClineAccess::Basic,
                pinned
            ),
            ClineVerdict::Deny(_)
        ));
        assert_eq!(
            cline_verdict(
                &staging("POST", "/api/v1/chat/completions"),
                ClineAccess::Basic,
                pinned
            ),
            ClineVerdict::Allow
        );
        assert_eq!(
            cline_verdict(
                &staging("POST", "/api/v1/session"),
                ClineAccess::Full,
                pinned
            ),
            ClineVerdict::Allow
        );
        // Hosts the predicate does not claim stay ungoverned; production stays
        // governed even when the predicate claims nothing.
        assert_eq!(
            cline_verdict(
                &req("POST", "https://evil.example/api/v1/session"),
                ClineAccess::Basic,
                pinned
            ),
            ClineVerdict::Allow
        );
        assert!(matches!(
            cline_verdict(
                &req("POST", "https://api.cline.bot/api/v1/session"),
                ClineAccess::Basic,
                |_| false
            ),
            ClineVerdict::Deny(_)
        ));
    }
}
