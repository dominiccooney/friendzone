//! One-shot review of immutable, inspectable HTTP requests. Only the waiting
//! proxy future owns the request bytes; this queue never executes/replays one.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use hudsucker::{Body, hyper::Request};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{oneshot, watch};
use uuid::Uuid;

pub const MAX_BODY: usize = 64 * 1024;
pub const MAX_HEADERS: usize = 16 * 1024;
pub const MAX_PENDING: usize = 32;
pub const MAX_PER_GUEST: usize = 8;
pub const WAIT_LIMIT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub id: Uuid,
    pub container: String,
    pub method: String,
    pub url: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub fingerprint: String,
    pub body_bytes: usize,
    pub reason: String,
}

#[derive(Clone, Serialize)]
pub struct Detail {
    #[serde(flatten)]
    pub summary: Summary,
    /// Credential-bearing headers are intentionally not disclosed.
    pub headers: Vec<(String, String)>,
    /// Literal UTF-8, not rendered HTML/Markdown or an AI-generated summary.
    pub body: String,
    /// Broker-parsed view of the same body, not an alternate authorization or
    /// request representation. Kept out of SSE and notifications with bodies.
    pub graphql: Option<crate::graphql::Review>,
}

impl Detail {
    pub fn from_request(container: &str, request: &Request<Body>, bytes: &[u8]) -> Result<Self> {
        if request.uri().to_string().len() > 8192 {
            bail!("request URL exceeds the review limit");
        }
        if bytes.len() > MAX_BODY {
            bail!("request body exceeds the 64 KiB review limit");
        }
        if request.headers().contains_key("content-encoding") {
            bail!("compressed/encoded writes cannot be safely reviewed in this inbox");
        }
        let body = std::str::from_utf8(bytes).map_err(|_| {
            anyhow::anyhow!("binary writes cannot be reviewed; git push remains blocked")
        })?;
        if body
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            bail!("request contains non-text control bytes and cannot be reviewed");
        }
        if !bytes.is_empty() {
            let content_type = request
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if !(content_type == "application/json"
                || content_type == "application/graphql"
                || content_type.starts_with("text/"))
            {
                bail!(
                    "only JSON/text writes are reviewable; binary, multipart and form writes remain blocked"
                );
            }
        }
        let mut hash = Sha256::new();
        // Delimit length-prefixed fields so the digest commits to the exact
        // method/URL/header values/body, including hidden credential values.
        let mut field = |value: &[u8]| {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        };
        field(request.method().as_str().as_bytes());
        field(request.uri().to_string().as_bytes());
        let mut headers = Vec::new();
        let mut header_bytes = 0;
        for (name, value) in request.headers() {
            header_bytes += name.as_str().len() + value.as_bytes().len();
            if header_bytes > MAX_HEADERS {
                bail!("request headers exceed the review limit");
            }
            field(name.as_str().as_bytes());
            field(value.as_bytes());
            let sensitive = name == "authorization"
                || name == "proxy-authorization"
                || name == "cookie"
                || name.as_str().contains("token")
                || name.as_str().contains("key")
                || name.as_str().contains("secret");
            headers.push((
                name.to_string(),
                if sensitive {
                    "[redacted]".into()
                } else {
                    value
                        .to_str()
                        .map_err(|_| anyhow::anyhow!("non-text header cannot be reviewed"))?
                        .to_owned()
                },
            ));
        }
        field(bytes);
        let created_at = Utc::now();
        let is_graphql = request
            .uri()
            .host()
            .is_some_and(|host| host.eq_ignore_ascii_case("api.github.com"))
            && request.uri().path() == "/graphql";
        let graphql = is_graphql.then(|| {
            if request.uri().query().is_some() {
                crate::graphql::Review::Unavailable { message: "URL query parameters may change GraphQL operation selection; structured review is unavailable. Inspect the complete URL and raw body.".into() }
            } else {
                crate::graphql::review(body, request.headers().get("content-type").and_then(|v|v.to_str().ok()).unwrap_or(""))
            }
        });
        let reason = if is_graphql {
            "GitHub GraphQL: inspect the selected operation, actual fields, arguments and targets. Parsed views are advisory; all GraphQL POSTs still require one-shot approval."
        } else {
            "GitHub operation requires one-shot approval. Review the full destination and payload; this does not grant future requests."
        };
        Ok(Self {
            summary: Summary {
                id: Uuid::new_v4(),
                container: container.into(),
                method: request.method().to_string(),
                url: request.uri().to_string(),
                created_at,
                expires_at: created_at + chrono::Duration::seconds(WAIT_LIMIT.as_secs() as i64),
                fingerprint: format!("{:x}", hash.finalize()),
                body_bytes: bytes.len(),
                reason: reason.into(),
            },
            headers,
            body: body.into(),
            graphql,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Deny,
}

struct Entry {
    detail: Detail,
    sender: oneshot::Sender<Decision>,
    deadline: tokio::time::Instant,
}
struct Inner {
    entries: Mutex<HashMap<Uuid, Entry>>,
    changes: watch::Sender<u64>,
    capacity: usize,
    per_guest: usize,
}
#[derive(Clone)]
pub struct Queue(Arc<Inner>);

impl Queue {
    pub fn new(changes: watch::Sender<u64>) -> Self {
        Self::with_limits(changes, MAX_PENDING, MAX_PER_GUEST)
    }
    fn with_limits(changes: watch::Sender<u64>, capacity: usize, per_guest: usize) -> Self {
        Self(Arc::new(Inner {
            entries: Mutex::new(HashMap::new()),
            changes,
            capacity,
            per_guest,
        }))
    }
    fn notify(&self) {
        self.0
            .changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }
    pub fn enqueue(&self, detail: Detail) -> Result<Ticket> {
        let mut entries = self.0.entries.lock().expect("review queue");
        if entries.contains_key(&detail.summary.id) {
            bail!("request is already waiting; cannot replace its snapshot");
        }
        if entries.len() >= self.0.capacity
            || entries
                .values()
                .filter(|entry| entry.detail.summary.container == detail.summary.container)
                .count()
                >= self.0.per_guest
        {
            bail!(
                "pending review queue is full; deny or resolve existing requests before retrying"
            );
        }
        let (sender, receiver) = oneshot::channel();
        let id = detail.summary.id;
        let deadline = tokio::time::Instant::now() + WAIT_LIMIT;
        entries.insert(
            id,
            Entry {
                detail,
                sender,
                deadline,
            },
        );
        drop(entries);
        self.notify();
        Ok(Ticket {
            queue: self.clone(),
            id,
            receiver,
            deadline,
        })
    }
    pub fn summaries(&self) -> Vec<Summary> {
        let mut summaries: Vec<_> = self
            .0
            .entries
            .lock()
            .expect("review queue")
            .values()
            .map(|entry| entry.detail.summary.clone())
            .collect();
        summaries.sort_by_key(|summary| summary.created_at);
        summaries
    }
    pub fn detail(&self, id: Uuid) -> Option<Detail> {
        self.0
            .entries
            .lock()
            .expect("review queue")
            .get(&id)
            .map(|entry| entry.detail.clone())
    }
    pub fn decide(&self, id: Uuid, fingerprint: &str, decision: Decision) -> Result<()> {
        let mut entries = self.0.entries.lock().expect("review queue");
        let entry = entries.get(&id).ok_or_else(|| {
            anyhow::anyhow!("request is no longer waiting (decided, cancelled or expired)")
        })?;
        if entry.detail.summary.fingerprint != fingerprint {
            bail!("request fingerprint mismatch; reload the review");
        }
        if entry.deadline <= tokio::time::Instant::now() || entry.sender.is_closed() {
            entries.remove(&id);
            drop(entries);
            self.notify();
            bail!("request expired or the waiting proxy request was cancelled");
        }
        let entry = entries.remove(&id).expect("checked entry");
        drop(entries);
        self.notify();
        entry
            .sender
            .send(decision)
            .map_err(|_| anyhow::anyhow!("waiting proxy request was cancelled"))
    }
    pub fn cancel_container(&self, container: &str) {
        let mut entries = self.0.entries.lock().expect("review queue");
        entries.retain(|_, entry| entry.detail.summary.container != container);
        drop(entries);
        self.notify();
    }
    fn remove(&self, id: Uuid) {
        if self
            .0
            .entries
            .lock()
            .expect("review queue")
            .remove(&id)
            .is_some()
        {
            self.notify();
        }
    }
}

pub struct Ticket {
    queue: Queue,
    id: Uuid,
    receiver: oneshot::Receiver<Decision>,
    deadline: tokio::time::Instant,
}
impl Ticket {
    pub async fn wait(mut self) -> Result<Decision> {
        tokio::time::timeout_at(self.deadline, &mut self.receiver)
            .await
            .map_err(|_| {
                anyhow::anyhow!("review expired after 120 seconds; request was not forwarded")
            })?
            .map_err(|_| {
                anyhow::anyhow!(
                    "review cancelled by container policy change or request cancellation"
                )
            })
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        self.queue.remove(self.id);
    }
}

/// Reserve before buffering so concurrent incomplete uploads cannot retain
/// an unbounded number of request bodies. Permit is held through the wait.
pub fn buffer_slots() -> &'static Arc<tokio::sync::Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_PENDING)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphql_analysis_is_advisory_and_never_changes_raw_snapshot_or_fingerprint() {
        let request = |uri: &str| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::empty())
                .unwrap()
        };
        let body=br#"{"query":"query($n:Int=42){repository(owner:\"cline\",name:\"cline\"){pullRequest(number:$n){id}}}"}"#;
        let detail =
            Detail::from_request("guest", &request("https://api.github.com/graphql"), body)
                .unwrap();
        let crate::graphql::Review::Parsed { analysis } = detail.graphql.as_ref().unwrap() else {
            panic!("parsed query")
        };
        assert_eq!(analysis.operation_type, "query");
        assert_eq!(detail.body.as_bytes(), body);
        assert!(
            !serde_json::to_string(&detail.summary)
                .unwrap()
                .contains("pullRequest"),
            "parsed bodies must not leak into SSE/notifications"
        );
        let repeated =
            Detail::from_request("guest", &request("https://api.github.com/graphql"), body)
                .unwrap();
        assert_eq!(detail.summary.fingerprint, repeated.summary.fingerprint);
        let formatted = serde_json::json!({"query":analysis.formatted_document}).to_string();
        let rewritten = Detail::from_request(
            "guest",
            &request("https://api.github.com/graphql"),
            formatted.as_bytes(),
        )
        .unwrap();
        assert_ne!(
            detail.summary.fingerprint, rewritten.summary.fingerprint,
            "formatting is not the authorization identity"
        );
        let ambiguous = Detail::from_request(
            "guest",
            &request("https://api.github.com/graphql?operationName=Other"),
            body,
        )
        .unwrap();
        assert!(matches!(
            ambiguous.graphql,
            Some(crate::graphql::Review::Unavailable { .. })
        ));
        let invalid = Detail::from_request(
            "guest",
            &request("https://api.github.com/graphql"),
            br#"{"query":"mutation {"}"#,
        )
        .unwrap();
        assert!(matches!(
            invalid.graphql,
            Some(crate::graphql::Review::Unavailable { .. })
        ));
        assert!(
            Detail::from_request(
                "guest",
                &request("https://api.github.com/repos/x/y/issues"),
                body
            )
            .unwrap()
            .graphql
            .is_none()
        );
    }
    fn detail(guest: &str) -> Detail {
        Detail::from_request(
            guest,
            &Request::builder()
                .method("POST")
                .uri("https://api.github.com/graphql")
                .header("content-type", "application/json")
                .header("authorization", "Bearer guest-secret")
                .body(Body::empty())
                .unwrap(),
            br#"{"query":"mutation { addComment(input: {}) { clientMutationId } }"}"#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn decisions_bind_exact_snapshot_and_cannot_replay() {
        let queue = Queue::new(watch::Sender::new(0));
        let detail = detail("guest");
        let id = detail.summary.id;
        let serialized = serde_json::to_string(&detail).unwrap();
        assert!(!serialized.contains("guest-secret"));
        assert!(serialized.contains("[redacted]"));
        let ticket = queue.enqueue(detail.clone()).unwrap();
        assert!(queue.decide(id, "wrong", Decision::Approve).is_err());
        assert_eq!(queue.summaries().len(), 1);
        queue
            .decide(id, &detail.summary.fingerprint, Decision::Approve)
            .unwrap();
        assert_eq!(ticket.wait().await.unwrap(), Decision::Approve);
        assert!(
            queue
                .decide(id, &detail.summary.fingerprint, Decision::Approve)
                .is_err()
        );
        assert!(queue.detail(id).is_none());
        let next = detail.clone();
        let ticket = queue.enqueue(next).unwrap();
        queue
            .decide(id, &detail.summary.fingerprint, Decision::Deny)
            .unwrap();
        assert_eq!(ticket.wait().await.unwrap(), Decision::Deny);
    }

    #[tokio::test]
    async fn limits_cancellation_and_expiry_fail_closed() {
        let queue = Queue::with_limits(watch::Sender::new(0), 2, 1);
        let ticket = queue.enqueue(detail("one")).unwrap();
        assert!(queue.enqueue(detail("one")).is_err());
        let other = queue.enqueue(detail("two")).unwrap();
        assert!(queue.enqueue(detail("three")).is_err());
        drop(ticket);
        assert_eq!(queue.summaries().len(), 1);
        queue.cancel_container("two");
        assert!(other.wait().await.is_err());
        let mut ticket = queue.enqueue(detail("one")).unwrap();
        ticket.deadline = tokio::time::Instant::now();
        assert!(
            ticket
                .wait()
                .await
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
        assert!(queue.summaries().is_empty());
        let detail = detail("one");
        let ticket = queue.enqueue(detail.clone()).unwrap();
        queue
            .0
            .entries
            .lock()
            .unwrap()
            .get_mut(&detail.summary.id)
            .unwrap()
            .deadline = tokio::time::Instant::now();
        assert!(
            queue
                .decide(
                    detail.summary.id,
                    &detail.summary.fingerprint,
                    Decision::Approve
                )
                .is_err()
        );
        assert!(ticket.wait().await.is_err());
    }

    #[test]
    fn review_never_truncates_or_interprets_hostile_bytes() {
        let request = Request::builder()
            .method("POST")
            .uri("https://api.github.com/graphql")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();
        let bytes =
            br#"{"query":"<script>steal()</script>","variables":{"text":"mutation is just text"}}"#;
        let detail = Detail::from_request("guest", &request, bytes).unwrap();
        assert_eq!(detail.body.as_bytes(), bytes);
        assert_eq!(detail.summary.body_bytes, bytes.len());
        assert!(Detail::from_request("guest", &request, &vec![b'x'; MAX_BODY + 1]).is_err());
        assert!(Detail::from_request("guest", &request, &[0, 255]).is_err());
        let original = detail.summary.fingerprint;
        let mut changed = request;
        changed
            .headers_mut()
            .insert("content-encoding", "gzip".parse().unwrap());
        assert!(Detail::from_request("guest", &changed, bytes).is_err());
        changed.headers_mut().remove("content-encoding");
        changed
            .headers_mut()
            .insert("authorization", "secret".parse().unwrap());
        assert_ne!(
            Detail::from_request("guest", &changed, bytes)
                .unwrap()
                .summary
                .fingerprint,
            original
        );
    }
}
