//! Fixed GitHub target reads and credential-bound comment permissions.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const ENDPOINT: &str = "https://api.github.com/graphql";

/// Only a uniquely matched escrow fake supplies credentials for display reads.
pub fn display_credential(
    settings: &crate::settings::Settings,
    request: &hudsucker::hyper::Request<hudsucker::Body>,
) -> Option<Credential> {
    if !read_transport(request) {
        return None;
    }
    let presented = request.headers().get("authorization")?.to_str().ok()?;
    let entries: Vec<_> = settings
        .entries()
        .into_iter()
        .filter(|entry| {
            entry.header == "authorization"
                && (presented == format!("{}{}", entry.prefix, entry.fake)
                    || presented == entry.fake
                    || crate::settings::github_token_matches(entry, presented))
        })
        .collect();
    if entries.len() != 1 {
        return None;
    }
    Credential::from_entry(settings, &entries[0])
}

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
                    | "graphql-features"
            )
        {
            return false;
        }
    }
    // gh 2.100.0 includes this preview header in PR queries. Only the known
    // read-schema preview is accepted, not arbitrary future feature switches.
    if request
        .headers()
        .get("graphql-features")
        .is_some_and(|value| value != "merge_queue")
    {
        return false;
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
const DISPLAY_LOOKUP: &str = "query FriendzoneDisplayTarget($id: ID!) { node(id: $id) { __typename id ... on Repository { nameWithOwner url } ... on Issue { number title url repository { id nameWithOwner } } ... on PullRequest { ...PRContext } ... on PullRequestReviewThread { pullRequest { ...PRContext } } ... on PullRequestReview { pullRequest { ...PRContext } } ... on PullRequestReviewComment { pullRequest { ...PRContext } } } } fragment PRContext on PullRequest { id number title url repository { id nameWithOwner } baseRefName headRefName headRefOid headRepository { id nameWithOwner } headRef { name } }";
const DISPLAY_CACHE_TTL: Duration = Duration::from_secs(60);
const DISPLAY_CACHE_LIMIT: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisplayLookup {
    pub node_id: String,
    pub kind: String,
    pub repository_id: String,
    pub repository: String,
    pub number: Option<u64>,
    pub url: String,
    pub pull_request_id: Option<String>,
    pub branch: Option<BranchContext>,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub cached: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BranchContext {
    pub base: String,
    pub head: String,
    pub head_oid: String,
    pub head_repository: Option<String>,
    pub head_exists: bool,
}

struct DisplayCacheEntry {
    binding: Binding,
    requested_id: String,
    inserted: Instant,
    lookup: DisplayLookup,
}

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
        if !entry.hosts.iter().any(|h| crate::settings::host_matches(h, "api.github.com"))
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
        validate_repository(&self.repository)?;
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

fn validate_repository(repository: &str) -> Result<()> {
    let parts: Vec<_> = repository.split('/').collect();
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
    Ok(())
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
    display_cache: Arc<Mutex<VecDeque<DisplayCacheEntry>>>,
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
            display_cache: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
    #[cfg(test)]
    pub(crate) fn for_test(endpoint: &str) -> Self {
        Self::new(endpoint)
    }
    async fn lookup(
        &self,
        id: &str,
        credential: &Credential,
        query: &str,
    ) -> Result<serde_json::Value> {
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
            .json(&serde_json::json!({"query":query,"variables":{"id":id}}))
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
        let node = json["data"]["node"].clone();
        if !node.is_object() {
            bail!("GitHub target unavailable to this credential");
        }
        Ok(node)
    }
    /// Authorization lookups always contact GitHub; display metadata cannot grant access.
    pub async fn resolve(&self, id: &str, credential: &Credential) -> Result<Target> {
        let node = self.lookup(id, credential, LOOKUP).await?;
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

    /// Display snapshots change on the next lookup after expiry or credential rotation.
    /// Cache hits say when GitHub was consulted; they are never authorization evidence.
    pub async fn resolve_display(
        &self,
        id: &str,
        expected_type: &str,
        credential: &Credential,
    ) -> Result<DisplayLookup> {
        if let Some(lookup) = self.cached_display(id, expected_type, credential) {
            return Ok(lookup);
        }
        let node = self.lookup(id, credential, DISPLAY_LOOKUP).await?;
        let lookup = display_metadata(&node)?;
        check_display_type(&lookup.kind, expected_type)?;
        let mut cache = self.display_cache.lock().expect("GitHub display cache");
        cache.retain(|entry| {
            entry.inserted.elapsed() < DISPLAY_CACHE_TTL
                && !(entry.binding == credential.binding && entry.requested_id == id)
        });
        while cache.len() >= DISPLAY_CACHE_LIMIT {
            cache.pop_front();
        }
        cache.push_back(DisplayCacheEntry {
            binding: credential.binding.clone(),
            requested_id: id.into(),
            inserted: Instant::now(),
            lookup: lookup.clone(),
        });
        Ok(lookup)
    }

    pub fn cached_display(
        &self,
        id: &str,
        expected_type: &str,
        credential: &Credential,
    ) -> Option<DisplayLookup> {
        let mut cache = self.display_cache.lock().expect("GitHub display cache");
        cache.retain(|entry| entry.inserted.elapsed() < DISPLAY_CACHE_TTL);
        let mut lookup = cache
            .iter()
            .find(|entry| {
                entry.binding == credential.binding
                    && (entry.requested_id == id || entry.lookup.node_id == id)
            })
            .map(|entry| entry.lookup.clone())?;
        check_display_type(&lookup.kind, expected_type).ok()?;
        lookup.cached = true;
        Some(lookup)
    }
}

fn check_display_type(kind: &str, expected: &str) -> Result<()> {
    if kind == expected
        || expected == "Node (unknown type)"
        || expected == "Issue or PullRequest" && matches!(kind, "Issue" | "PullRequest")
    {
        Ok(())
    } else {
        bail!("GitHub node type does not match the mutation input")
    }
}

fn display_metadata(node: &serde_json::Value) -> Result<DisplayLookup> {
    let string = |value: &serde_json::Value| -> Result<String> {
        let text = value
            .as_str()
            .context("incomplete GitHub display metadata")?;
        if text.is_empty() || text.len() > 512 || text.chars().any(char::is_control) {
            bail!("invalid GitHub display metadata");
        }
        Ok(text.into())
    };
    let kind = string(&node["__typename"])?;
    let subject = match kind.as_str() {
        "PullRequestReviewThread" | "PullRequestReview" | "PullRequestReviewComment" => {
            &node["pullRequest"]
        }
        "PullRequest" | "Issue" | "Repository" => node,
        _ => bail!("GitHub node type is not supported for display"),
    };
    let repository = if kind == "Repository" {
        subject
    } else {
        &subject["repository"]
    };
    let mut lookup = DisplayLookup {
        node_id: string(&node["id"])?,
        kind: kind.clone(),
        repository_id: string(&repository["id"])?,
        repository: string(&repository["nameWithOwner"])?,
        number: None,
        url: string(&subject["url"])?,
        pull_request_id: None,
        branch: None,
        fetched_at: chrono::Utc::now(),
        cached: false,
    };
    if kind == "Repository" {
        validate_repository(&lookup.repository)?;
        if lookup.url != format!("https://github.com/{}", lookup.repository) {
            bail!("GitHub repository URL does not match its identity");
        }
    } else {
        let is_pr = kind != "Issue";
        let target = Target {
            node_id: string(&subject["id"])?,
            repository_id: lookup.repository_id.clone(),
            repository: lookup.repository.clone(),
            kind: if is_pr { "PullRequest" } else { "Issue" }.into(),
            number: subject["number"]
                .as_u64()
                .context("invalid GitHub issue/PR number")?,
            title: subject["title"]
                .as_str()
                .context("missing GitHub title")?
                .into(),
            url: lookup.url.clone(),
        };
        target.validate()?;
        lookup.number = Some(target.number);
        if is_pr {
            lookup.pull_request_id = Some(target.node_id);
            let head_repository = if subject["headRepository"].is_null() {
                None
            } else {
                let repository = string(&subject["headRepository"]["nameWithOwner"])?;
                validate_repository(&repository)?;
                Some(repository)
            };
            lookup.branch = Some(BranchContext {
                base: string(&subject["baseRefName"])?,
                head: string(&subject["headRefName"])?,
                head_oid: string(&subject["headRefOid"])?,
                head_repository,
                head_exists: !subject["headRef"].is_null(),
            });
        }
    }
    Ok(lookup)
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
            ("graphql-features", "unrecognized"),
            ("graphql-features", "merge_queue,unrecognized"),
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
        let mut gh = request(ENDPOINT);
        for (name, value) in [
            ("graphql-features", "merge_queue"),
            ("time-zone", "America/New_York"),
            ("x-github-api-version", "2022-11-28"),
            ("authorization", "token fake-github"),
            ("user-agent", "GitHub CLI 2.100.0"),
        ] {
            gh.headers_mut().insert(
                hudsucker::hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        assert!(read_transport(&gh));
        gh.headers_mut()
            .append("graphql-features", "merge_queue".parse().unwrap());
        assert!(
            !read_transport(&gh),
            "duplicate preview headers remain ambiguous"
        );
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
        for value in ["Bearer fake", "token fake", "ToKeN fake", "fake"] {
            let mut req = request(ENDPOINT);
            req.headers_mut()
                .insert("authorization", value.parse().unwrap());
            assert_eq!(
                display_credential(&settings, &req).unwrap().binding,
                valid.binding
            );
        }
        for value in [
            "Bearer real-token",
            "token fake-extra",
            "token  fake",
            "Digest fake",
        ] {
            let mut req = request(ENDPOINT);
            req.headers_mut()
                .insert("authorization", value.parse().unwrap());
            assert!(display_credential(&settings, &req).is_none());
        }
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
    async fn display_lookups_cache_by_credential_expire_bound_size_and_never_authorize() {
        use axum::{Json, Router, routing::post};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/graphql", post(move |Json(request): Json<serde_json::Value>| {
                let hits = observed.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let id = request["variables"]["id"].as_str().unwrap();
                    let mut response = response();
                    if request["query"] == DISPLAY_LOOKUP {
                        let pr = serde_json::json!({"id":"canonical-pr","number":482,"title":"PR","url":"https://github.com/cline/cline/pull/482","repository":{"id":"repo-id","nameWithOwner":"cline/cline"},"baseRefName":"main","headRefName":"feature","headRefOid":"a".repeat(40),"headRepository":{"id":"fork-id","nameWithOwner":"contributor/cline"},"headRef":null});
                        let node = match id {
                            "thread" => serde_json::json!({"id":"canonical-thread","__typename":"PullRequestReviewThread","pullRequest":pr}),
                            "review" => serde_json::json!({"id":"canonical-review","__typename":"PullRequestReview","pullRequest":pr}),
                            "comment" => serde_json::json!({"id":"canonical-comment","__typename":"PullRequestReviewComment","pullRequest":pr}),
                            "repository" => serde_json::json!({"id":"repo-id","__typename":"Repository","nameWithOwner":"cline/cline","url":"https://github.com/cline/cline"}),
                            "error" => { return Json(serde_json::json!({"errors":[{"message":"private upstream error"}]})); },
                            "null" => serde_json::Value::Null,
                            _ => response["data"]["node"].clone(),
                        };
                        response["data"]["node"] = node;
                    } else { assert_lookup(&request); }
                    Json(response)
                }
            }))).await.unwrap();
        });
        let client = Client::for_test(&format!("http://{addr}/graphql"));
        let credential = Credential {
            binding: Binding {
                entry: "github".into(),
                digest: "a".repeat(64),
            },
            header_value: "Bearer secret".into(),
        };
        let first = client
            .resolve_display("legacy", "Issue", &credential)
            .await
            .unwrap();
        assert!(!first.cached);
        let cached = client
            .resolve_display("canonical", "Issue", &credential)
            .await
            .unwrap();
        assert!(cached.cached);
        assert_eq!(cached.fetched_at, first.fetched_at);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(
            client
                .resolve_display("legacy", "PullRequest", &credential)
                .await
                .is_err()
        );
        client.resolve("legacy", &credential).await.unwrap();
        client.resolve("legacy", &credential).await.unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            4,
            "display type mismatch and both authorization lookups contact GitHub"
        );
        let rotated = Credential {
            binding: Binding {
                entry: "github".into(),
                digest: "b".repeat(64),
            },
            header_value: "Bearer rotated".into(),
        };
        assert!(
            !client
                .resolve_display("legacy", "Issue", &rotated)
                .await
                .unwrap()
                .cached
        );
        for entry in client.display_cache.lock().unwrap().iter_mut() {
            entry.inserted = Instant::now() - DISPLAY_CACHE_TTL;
        }
        assert!(
            client
                .cached_display("legacy", "Issue", &credential)
                .is_none()
        );
        for (id, kind) in [
            ("thread", "PullRequestReviewThread"),
            ("review", "PullRequestReview"),
            ("comment", "PullRequestReviewComment"),
        ] {
            let lookup = client.resolve_display(id, kind, &credential).await.unwrap();
            assert_eq!(lookup.repository, "cline/cline");
            assert_eq!(lookup.number, Some(482));
            assert_eq!(lookup.pull_request_id.as_deref(), Some("canonical-pr"));
            let branch = lookup.branch.unwrap();
            assert_eq!(branch.head_repository.as_deref(), Some("contributor/cline"));
            assert!(!branch.head_exists);
        }
        assert_eq!(
            client
                .resolve_display("repository", "Repository", &credential)
                .await
                .unwrap()
                .number,
            None
        );
        for id in ["error", "null"] {
            let before = hits.load(Ordering::SeqCst);
            for _ in 0..2 {
                assert!(
                    client
                        .resolve_display(id, "Issue", &credential)
                        .await
                        .is_err()
                );
            }
            assert_eq!(
                hits.load(Ordering::SeqCst),
                before + 2,
                "failures are not cached"
            );
        }
        for index in 0..DISPLAY_CACHE_LIMIT + 1 {
            client
                .resolve_display(&format!("issue-{index}"), "Issue", &credential)
                .await
                .unwrap();
        }
        assert_eq!(
            client.display_cache.lock().unwrap().len(),
            DISPLAY_CACHE_LIMIT
        );
        assert!(
            client
                .cached_display("issue-0", "Issue", &credential)
                .is_none()
        );
        server.abort();
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
