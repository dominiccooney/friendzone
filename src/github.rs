//! Fixed GitHub target reads and credential-bound comment permissions.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const ENDPOINT: &str = "https://api.github.com/graphql";

/// Query admission relies on GitHub's Query root contract, not on arbitrary
/// GraphQL services. Do not let URL/Host/header overrides change that meaning.
pub fn read_transport(request: &hudsucker::hyper::Request<hudsucker::Body>) -> bool {
    let uri = request.uri();
    if request.method() != hudsucker::hyper::Method::POST
        || uri.scheme_str() != Some("https")
        || !uri
            .host()
            .is_some_and(|host| host.eq_ignore_ascii_case("api.github.com"))
        || uri.port_u16().is_some_and(|port| port != 443)
        || uri.path() != "/graphql"
        || uri.query().is_some()
    {
        return false;
    }
    let mut names = std::collections::HashSet::new();
    for (name, _) in request.headers() {
        if !names.insert(name.as_str())
            || !matches!(
                name.as_str(),
                "authorization"
                    | "content-type"
                    | "content-length"
                    | "transfer-encoding"
                    | "host"
                    | "user-agent"
                    | "accept"
                    | "accept-encoding"
                    | "connection"
                    | "x-github-next-global-id"
                    | "x-github-api-version"
                    | "time-zone"
                    | "cache-control"
            )
        {
            return false;
        }
    }
    if request.headers().get("host").is_some_and(|value| {
        !value.to_str().is_ok_and(|host| {
            host.eq_ignore_ascii_case("api.github.com")
                || host.eq_ignore_ascii_case("api.github.com:443")
        })
    }) {
        return false;
    }
    if request.headers().get("connection").is_some_and(|value| {
        !value
            .to_str()
            .is_ok_and(|s| s.eq_ignore_ascii_case("keep-alive") || s.eq_ignore_ascii_case("close"))
    }) {
        return false;
    }
    request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            let mut parts = value.split(';').map(str::trim);
            let media = parts.next().unwrap_or("");
            (media.eq_ignore_ascii_case("application/json")
                || media.eq_ignore_ascii_case("application/graphql"))
                && parts.all(|parameter| {
                    parameter.eq_ignore_ascii_case("charset=utf-8")
                        || parameter.eq_ignore_ascii_case("charset=\"utf-8\"")
                })
        })
}
const LOOKUP: &str = "query FriendzoneTarget($id: ID!) { node(id: $id) { __typename ... on Issue { id number title url repository { id nameWithOwner } } ... on PullRequest { id number title url repository { id nameWithOwner } } } }";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub entry: String,
    /// Token+route digest, never exported by host APIs. Token rotation makes
    /// old grants inactive until explicitly resolved/granted again.
    pub digest: String,
}

pub struct Credential {
    pub binding: Binding,
    pub header_value: String,
}
impl Credential {
    pub fn from_entry(
        settings: &crate::settings::Settings,
        entry: &crate::settings::EscrowEntry,
    ) -> Option<Self> {
        if !entry.hosts.iter().any(|h| h == "api.github.com")
            || entry.header != "authorization"
            || entry.prefix != "Bearer "
        {
            return None;
        }
        let real = settings.real_value(entry)?;
        let mut hash = Sha256::new();
        for value in [
            &entry.name,
            &entry.fake,
            &entry.header,
            &entry.prefix,
            &real,
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        let header_value = format!("Bearer {real}");
        if header_value
            .parse::<reqwest::header::HeaderValue>()
            .is_err()
        {
            return None;
        }
        Some(Self {
            binding: Binding {
                entry: entry.name.clone(),
                digest: format!("{:x}", hash.finalize()),
            },
            header_value,
        })
    }
    pub fn current(settings: &crate::settings::Settings, binding: &Binding) -> Option<Self> {
        let entry = settings
            .entries()
            .into_iter()
            .find(|e| e.name == binding.entry)?;
        let credential = Self::from_entry(settings, &entry)?;
        (credential.binding == *binding).then_some(credential)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub node_id: String,
    pub repository_id: String,
    pub repository: String,
    pub kind: String,
    pub number: u64,
    pub title: String,
    pub url: String,
}
impl Target {
    pub fn same_identity(&self, other: &Self) -> bool {
        self.node_id == other.node_id
            && self.repository_id == other.repository_id
            && self.repository == other.repository
            && self.kind == other.kind
            && self.number == other.number
            && self.url == other.url
    }
    pub fn validate(&self) -> Result<()> {
        if self.node_id.is_empty()
            || self.node_id.len() > 512
            || self.repository_id.is_empty()
            || self.repository_id.len() > 512
            || self.number == 0
            || self.title.len() > 4096
        {
            bail!("invalid GitHub target metadata");
        }
        let parts: Vec<_> = self.repository.split('/').collect();
        if parts.len() != 2
            || parts.iter().any(|part| {
                part.is_empty()
                    || *part == "."
                    || *part == ".."
                    || !part
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
            })
        {
            bail!("invalid GitHub repository identity");
        }
        let segment = match self.kind.as_str() {
            "Issue" => "issues",
            "PullRequest" => "pull",
            _ => bail!("target is not an issue or pull request"),
        };
        let expected = format!(
            "https://github.com/{}/{segment}/{}",
            self.repository, self.number
        );
        if self.url != expected {
            bail!("GitHub target URL does not match its repository and number");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: Uuid,
    pub target: Target,
    pub binding: Binding,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
impl Grant {
    pub fn validate(&self) -> Result<()> {
        self.target.validate()?;
        if self.binding.entry.is_empty()
            || self.binding.digest.len() != 64
            || !self.binding.digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("invalid comment permission credential binding");
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Client {
    client: reqwest::Client,
    endpoint: String,
    slots: std::sync::Arc<tokio::sync::Semaphore>,
}
impl Default for Client {
    fn default() -> Self {
        Self::new(ENDPOINT)
    }
}
impl Client {
    fn new(endpoint: &str) -> Self {
        Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(8))
                .user_agent("Friendzone target resolver")
                .build()
                .expect("GitHub client"),
            endpoint: endpoint.into(),
            slots: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }
    #[cfg(test)]
    pub(crate) fn for_test(endpoint: &str) -> Self {
        Self::new(endpoint)
    }
    pub async fn resolve(&self, id: &str, credential: &Credential) -> Result<Target> {
        if id.is_empty() || id.len() > 512 {
            bail!("invalid GitHub node ID");
        }
        let _permit = self
            .slots
            .try_acquire()
            .context("GitHub lookup busy; retry shortly")?;
        // Neither URL, headers nor query text is supplied by the guest/UI.
        // Errors intentionally omit upstream bodies and request headers.
        let mut response = self
            .client
            .post(&self.endpoint)
            .header("authorization", &credential.header_value)
            .json(&serde_json::json!({"query":LOOKUP,"variables":{"id":id}}))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("GitHub lookup could not connect or timed out"))?;
        if !response.status().is_success() {
            bail!(
                "GitHub target lookup returned HTTP {}; check token access and rate limits",
                response.status().as_u16()
            );
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("GitHub lookup response interrupted"))?
        {
            if bytes.len() + chunk.len() > 64 * 1024 {
                bail!("GitHub lookup response exceeds limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).context("invalid GitHub lookup response")?;
        if json
            .get("errors")
            .is_some_and(|v| v.as_array().is_none_or(|v| !v.is_empty()))
        {
            bail!("GitHub lookup returned GraphQL errors; target not verified");
        }
        let node = &json["data"]["node"];
        let string = |value: &serde_json::Value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("incomplete GitHub target metadata")
        };
        let target = Target {
            node_id: string(&node["id"])?,
            repository_id: string(&node["repository"]["id"])?,
            repository: string(&node["repository"]["nameWithOwner"])?,
            kind: string(&node["__typename"])?,
            number: node["number"]
                .as_u64()
                .context("invalid GitHub issue/PR number")?,
            title: string(&node["title"])?,
            url: string(&node["url"])?,
        };
        target.validate()?;
        Ok(target)
    }
}

#[derive(Clone)]
pub struct CommentContext {
    pub binding: Binding,
    pub subject_id: String,
    pub epoch: Uuid,
    pub revision: Uuid,
}
#[derive(Clone, Serialize)]
pub struct Resolved {
    pub target: Target,
    pub credential: String,
}

/// Only this exact transport shape may be reconstructed under a grant.
pub fn comment_credential(
    settings: &crate::settings::Settings,
    request: &hudsucker::hyper::Request<hudsucker::Body>,
) -> Option<Credential> {
    if request.method() != hudsucker::hyper::Method::POST || request.uri() != ENDPOINT {
        return None;
    }
    let mut names = std::collections::HashSet::new();
    for (name, _) in request.headers() {
        if !names.insert(name.as_str())
            || !matches!(
                name.as_str(),
                "authorization"
                    | "content-type"
                    | "content-length"
                    | "transfer-encoding"
                    | "host"
                    | "user-agent"
                    | "accept"
                    | "accept-encoding"
                    | "connection"
            )
        {
            return None;
        }
    }
    if request
        .headers()
        .get("host")
        .is_some_and(|host| host != "api.github.com" && host != "api.github.com:443")
    {
        return None;
    }
    let content_type = request.headers().get("content-type")?.to_str().ok()?;
    if !matches!(
        content_type.to_ascii_lowercase().as_str(),
        "application/json" | "application/json; charset=utf-8" | "application/graphql"
    ) {
        return None;
    }
    let presented = request.headers().get("authorization")?.to_str().ok()?;
    let entries: Vec<_> = settings
        .entries()
        .into_iter()
        .filter(|e| e.header == "authorization" && presented == format!("{}{}", e.prefix, e.fake))
        .collect();
    if entries.len() != 1 {
        return None;
    }
    Credential::from_entry(settings, &entries[0])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn query_transport_keeps_github_authority_and_envelope_unambiguous() {
        let request = |url: &str| {
            hudsucker::hyper::Request::builder()
                .method("POST")
                .uri(url)
                .header("content-type", "application/json; charset=\"utf-8\"")
                .body(hudsucker::Body::empty())
                .unwrap()
        };
        for url in [
            ENDPOINT,
            "https://api.github.com:443/graphql",
            "https://API.GITHUB.COM/graphql",
        ] {
            assert!(read_transport(&request(url)));
        }
        for url in [
            "http://api.github.com/graphql",
            "https://api.github.com:8443/graphql",
            "https://example.com/graphql",
            "https://api.github.com/graphql?operationName=Write",
            "https://api.github.com/graphql?",
            "https://api.github.com/other",
        ] {
            assert!(!read_transport(&request(url)), "{url}");
        }
        for (name, value) in [
            ("host", "evil.test"),
            ("x-http-method-override", "DELETE"),
            ("x-operation-name", "Write"),
            ("cookie", "auth=x"),
            ("content-type", "application/json; charset=utf-16"),
            ("connection", "content-type"),
            ("upgrade", "websocket"),
        ] {
            let mut req = request(ENDPOINT);
            req.headers_mut().insert(
                hudsucker::hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
            assert!(!read_transport(&req), "{name}");
        }
        let mut req = request(ENDPOINT);
        req.headers_mut()
            .insert("x-github-next-global-id", "1".parse().unwrap());
        assert!(read_transport(&req));
        req.headers_mut()
            .append("content-type", "application/graphql".parse().unwrap());
        assert!(!read_transport(&req));
    }

    #[test]
    fn automatic_transport_requires_one_exact_escrow_binding_and_rejects_semantic_headers() {
        let dir = std::env::temp_dir().join(format!("fz-comment-credentials-{}", Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let entry = settings
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
        settings.set_secret("github", "secret").unwrap();
        let request = |url: &str| {
            hudsucker::hyper::Request::builder()
                .method("POST")
                .uri(url)
                .header("authorization", "Bearer fake")
                .header("content-type", "application/json")
                .body(hudsucker::Body::empty())
                .unwrap()
        };
        let valid = comment_credential(&settings, &request(ENDPOINT)).unwrap();
        for url in [
            "http://api.github.com/graphql",
            "https://api.github.com:8443/graphql",
            "https://api.github.com/graphql?query=other",
            "https://api.github.com/repos/x",
        ] {
            assert!(comment_credential(&settings, &request(url)).is_none());
        }
        for (name, value) in [
            ("x-http-method-override", "DELETE"),
            ("cookie", "session=secret"),
            ("x-github-next-global-id", "1"),
            ("host", "evil.test"),
            ("authorization", "Bearer real-token"),
        ] {
            let mut req = request(ENDPOINT);
            req.headers_mut().insert(
                hudsucker::hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
            assert!(comment_credential(&settings, &req).is_none(), "{name}");
        }
        let mut req = request(ENDPOINT);
        req.headers_mut()
            .append("authorization", "Bearer fake".parse().unwrap());
        assert!(comment_credential(&settings, &req).is_none());
        settings.set_secret("github", "rotated").unwrap();
        assert!(Credential::current(&settings, &valid.binding).is_none());
        settings.set_secret("github", "secret").unwrap();
        assert!(Credential::current(&settings, &valid.binding).is_some());
        settings
            .update_entry(
                &entry.name,
                vec!["elsewhere.test".into()],
                "authorization".into(),
                "Bearer ".into(),
                None,
            )
            .unwrap();
        assert!(Credential::current(&settings, &valid.binding).is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
    pub fn target() -> Target {
        Target {
            node_id: "canonical".into(),
            repository_id: "repo-id".into(),
            repository: "cline/cline".into(),
            kind: "Issue".into(),
            number: 482,
            title: "A real issue <script>".into(),
            url: "https://github.com/cline/cline/issues/482".into(),
        }
    }
    pub fn response() -> serde_json::Value {
        let t = target();
        serde_json::json!({"data":{"node":{"__typename":t.kind,"id":t.node_id,"number":t.number,"title":t.title,"url":t.url,"repository":{"id":t.repository_id,"nameWithOwner":t.repository}}}})
    }
    pub fn assert_lookup(json: &serde_json::Value) {
        assert_eq!(json["query"], LOOKUP);
        assert!(json["variables"]["id"].is_string());
    }
    #[tokio::test]
    async fn lookup_uses_fixed_query_and_fails_on_redirect_errors_and_identity_mismatch() {
        use axum::{Json, Router, routing::post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener,Router::new().route("/graphql",post(|headers:axum::http::HeaderMap,Json(json):Json<serde_json::Value>|async move {
            assert_lookup(&json);assert_eq!(headers["authorization"],"Bearer secret");
            let id=json["variables"]["id"].as_str().unwrap();
            let body=match id {"errors"=>serde_json::json!({"errors":[{"message":"do not echo secret"}]}),"null"=>serde_json::json!({"data":{"node":null}}),"wrong-url"=>{let mut value=response();value["data"]["node"]["url"]="https://evil.test/".into();value},_=>response()};
            if id=="redirect" {(axum::http::StatusCode::FOUND,[("location","https://evil.test/")],Json(body))}else{(axum::http::StatusCode::OK,[("location","")],Json(body))}
        }))).await.unwrap()
        });
        let client = Client::for_test(&format!("http://{addr}/graphql"));
        let credential = Credential {
            binding: Binding {
                entry: "github".into(),
                digest: "0".repeat(64),
            },
            header_value: "Bearer secret".into(),
        };
        assert_eq!(
            client.resolve("legacy-alias", &credential).await.unwrap(),
            target()
        );
        for id in ["errors", "null", "wrong-url", "redirect"] {
            let error = client
                .resolve(id, &credential)
                .await
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret"));
        }
        task.abort();
    }
}
