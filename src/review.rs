//! One-shot review of immutable, inspectable HTTP requests. Only the waiting
//! proxy future owns the request bytes; this queue never executes/replays one.
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
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
pub const HISTORY_LIMIT: usize = 100;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Approved,
    Sending,
    ResponseReceived,
    GraphqlError,
    Denied,
    Expired,
    Cancelled,
    Blocked,
    UpstreamError,
    Unknown,
}

impl Status {
    fn active(self) -> bool {
        matches!(self, Self::Pending | Self::Approved | Self::Sending)
    }
}

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
    pub status: Status,
    pub updated_at: DateTime<Utc>,
    pub http_status: Option<u16>,
    pub outcome: Option<String>,
    /// Durable plugin job vs a waiting proxy connection.
    pub asynchronous: bool,
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
    /// Classified by the same parse used for the view, before display limits.
    #[serde(skip)]
    pub graphql_read: bool,
    pub comment_permission_supported: bool,
    pub resolved_target: Option<crate::github::Resolved>,
    pub resolution_id: Option<Uuid>,
    #[serde(skip)]
    pub comment_context: Option<crate::github::CommentContext>,
}

impl Detail {
    pub fn from_request(container: &str, request: &Request<Body>, bytes: &[u8]) -> Result<Self> {
        Self::from_request_with_limit(container, request, bytes, MAX_BODY)
    }

    pub fn from_request_with_limit(
        container: &str,
        request: &Request<Body>,
        bytes: &[u8],
        max_body: usize,
    ) -> Result<Self> {
        if request.uri().to_string().len() > 8192 {
            bail!("request URL exceeds the review limit");
        }
        if bytes.len() > max_body {
            bail!("request body exceeds the review limit ({max_body} bytes)");
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
        let mut graphql_read = false;
        let graphql = is_graphql.then(|| {
            if request.uri().query().is_some() {
                crate::graphql::Review::Unavailable { message: "URL query parameters may change GraphQL operation selection; structured review is unavailable. Inspect the complete URL and raw body.".into() }
            } else {
                let (read_only, view) = crate::graphql::inspect_with_limit(body, request.headers().get("content-type").and_then(|v|v.to_str().ok()).unwrap_or(""), max_body);
                graphql_read = read_only && crate::github::read_transport(request);
                view
            }
        });
        let reason = if is_graphql {
            "GitHub GraphQL operation requires approval."
        } else {
            "GitHub operation requires approval."
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
                status: Status::Pending,
                updated_at: created_at,
                http_status: None,
                outcome: None,
                asynchronous: false,
            },
            headers,
            body: body.into(),
            graphql,
            graphql_read,
            comment_permission_supported: false,
            resolved_target: None,
            resolution_id: None,
            comment_context: None,
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
#[derive(Default)]
struct QueueData {
    pending: HashMap<Uuid, Entry>,
    recent: VecDeque<Detail>,
}
impl QueueData {
    fn archive(
        &mut self,
        id: Uuid,
        status: Status,
        outcome: &str,
    ) -> Option<oneshot::Sender<Decision>> {
        let mut entry = self.pending.remove(&id)?;
        entry.detail.summary.status = status;
        entry.detail.summary.updated_at = Utc::now();
        entry.detail.summary.outcome = Some(outcome.into());
        // Retained snapshots are read-only: never a source of new grants.
        entry.detail.comment_context = None;
        entry.detail.comment_permission_supported = false;
        self.recent.push_back(entry.detail);
        while self.recent.len() > HISTORY_LIMIT {
            self.recent.pop_front();
        }
        Some(entry.sender)
    }
}
struct Inner {
    entries: Mutex<QueueData>,
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
            entries: Mutex::new(QueueData::default()),
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
        if entries.pending.contains_key(&detail.summary.id)
            || entries
                .recent
                .iter()
                .any(|item| item.summary.id == detail.summary.id)
        {
            bail!("request is already waiting; cannot replace its snapshot");
        }
        if entries.pending.len() >= self.0.capacity
            || entries
                .pending
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
        entries.pending.insert(
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
    #[cfg(test)]
    pub fn summaries(&self) -> Vec<Summary> {
        let mut summaries: Vec<_> = self
            .0
            .entries
            .lock()
            .expect("review queue")
            .pending
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
            .pending
            .get(&id)
            .filter(|entry| {
                entry.deadline > tokio::time::Instant::now() && !entry.sender.is_closed()
            })
            .map(|entry| entry.detail.clone())
    }
    /// UI reads may inspect retained snapshots; grant/resolve callers must
    /// continue using detail(), which only returns live pending requests.
    pub fn inspect(&self, id: Uuid) -> Option<Detail> {
        let entries = self.0.entries.lock().expect("review queue");
        entries
            .pending
            .get(&id)
            .map(|entry| entry.detail.clone())
            .or_else(|| {
                entries
                    .recent
                    .iter()
                    .find(|item| item.summary.id == id)
                    .cloned()
            })
    }
    #[cfg(test)]
    pub fn recent(&self) -> Vec<Summary> {
        self.0
            .entries
            .lock()
            .expect("review queue")
            .recent
            .iter()
            .rev()
            .map(|item| item.summary.clone())
            .collect()
    }
    pub fn view(&self) -> (Vec<Summary>, Vec<Summary>) {
        let entries = self.0.entries.lock().expect("review queue");
        let mut pending: Vec<_> = entries
            .pending
            .values()
            .map(|entry| entry.detail.summary.clone())
            .collect();
        pending.sort_by_key(|item| item.created_at);
        let recent = entries
            .recent
            .iter()
            .rev()
            .map(|item| item.summary.clone())
            .collect();
        (pending, recent)
    }
    pub fn tracks_response(&self, id: Uuid) -> bool {
        self.0
            .entries
            .lock()
            .expect("review queue")
            .recent
            .iter()
            .any(|item| item.summary.id == id && item.graphql.is_some())
    }
    pub fn response_detail(&self, id: Uuid, status: Status, outcome: &str) {
        let mut entries = self.0.entries.lock().expect("review queue");
        let Some(detail) = entries.recent.iter_mut().find(|item| item.summary.id == id) else {
            return;
        };
        if detail.summary.status != Status::ResponseReceived {
            return;
        }
        detail.summary.status = status;
        detail.summary.outcome = Some(outcome.into());
        detail.summary.updated_at = Utc::now();
        drop(entries);
        self.notify();
    }
    /// Decision removal and outcome publication share the queue lock. Later
    /// proxy observations refine only nonterminal outcomes; late callbacks or
    /// cleanup cannot turn Denied/Expired into Approved or erase a response.
    pub fn observe(&self, id: Uuid, status: Status, http_status: Option<u16>, outcome: &str) {
        let mut entries = self.0.entries.lock().expect("review queue");
        let Some(detail) = entries.recent.iter_mut().find(|item| item.summary.id == id) else {
            return;
        };
        if !detail.summary.status.active() {
            return;
        }
        detail.summary.status = status;
        detail.summary.updated_at = Utc::now();
        detail.summary.http_status = http_status;
        detail.summary.outcome = Some(outcome.into());
        drop(entries);
        self.notify();
    }
    fn cancel_pending(&self, id: Uuid, status: Status, outcome: &str) {
        let mut entries = self.0.entries.lock().expect("review queue");
        if entries.archive(id, status, outcome).is_none() {
            return;
        }
        drop(entries);
        self.notify();
    }
    pub fn decide(&self, id: Uuid, fingerprint: &str, decision: Decision) -> Result<()> {
        let mut entries = self.0.entries.lock().expect("review queue");
        let entry = entries.pending.get(&id).ok_or_else(|| {
            anyhow::anyhow!("request is no longer waiting (decided, cancelled or expired)")
        })?;
        if entry.detail.summary.fingerprint != fingerprint {
            bail!("request fingerprint mismatch; reload the review");
        }
        if entry.deadline <= tokio::time::Instant::now() || entry.sender.is_closed() {
            let status = if entry.deadline <= tokio::time::Instant::now() {
                Status::Expired
            } else {
                Status::Cancelled
            };
            entries.archive(
                id,
                status,
                "Not sent. Review expired or client stopped waiting.",
            );
            drop(entries);
            self.notify();
            bail!("request expired or the waiting proxy request was cancelled");
        }
        let (status, outcome) = match decision {
            Decision::Approve => (
                Status::Approved,
                "Approved once; checking current policy before sending.",
            ),
            Decision::Deny => (Status::Denied, "Denied by host. Not sent."),
        };
        let sender = entries.archive(id, status, outcome).expect("checked entry");
        let sent = sender.send(decision).is_ok();
        drop(entries);
        self.notify();
        if !sent {
            self.observe(
                id,
                Status::Cancelled,
                None,
                "Client stopped waiting. Not sent.",
            );
            bail!("waiting proxy request was cancelled");
        }
        Ok(())
    }
    pub fn set_resolved(
        &self,
        id: Uuid,
        fingerprint: &str,
        resolved: crate::github::Resolved,
        revision: Uuid,
    ) -> Result<Detail> {
        let mut entries = self.0.entries.lock().expect("review queue");
        let entry = entries
            .pending
            .get_mut(&id)
            .context("request no longer waiting")?;
        if entry.detail.summary.fingerprint != fingerprint
            || entry.deadline <= tokio::time::Instant::now()
            || entry.sender.is_closed()
        {
            bail!("request changed, expired or cancelled");
        }
        entry.detail.resolved_target = Some(resolved);
        entry
            .detail
            .comment_context
            .as_mut()
            .context("no comment context")?
            .revision = revision;
        entry.detail.resolution_id = Some(Uuid::new_v4());
        Ok(entry.detail.clone())
    }
    pub fn cancel_container(&self, container: &str) {
        let mut entries = self.0.entries.lock().expect("review queue");
        let ids: Vec<_> = entries
            .pending
            .iter()
            .filter(|(_, entry)| entry.detail.summary.container == container)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            entries.archive(
                id,
                Status::Cancelled,
                "Container permissions changed. Not sent.",
            );
        }
        drop(entries);
        self.notify();
    }
    fn remove(&self, id: Uuid) {
        self.cancel_pending(
            id,
            Status::Cancelled,
            "Waiting request was cancelled. Not sent.",
        );
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
                self.queue.cancel_pending(
                    self.id,
                    Status::Expired,
                    "No decision within 2 minutes. Not sent.",
                );
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
        assert_eq!(queue.inspect(id).unwrap().summary.status, Status::Approved);
        assert!(
            queue.enqueue(detail.clone()).is_err(),
            "cannot requeue a retained ID"
        );
        let mut next = detail.clone();
        next.summary.id = Uuid::new_v4();
        let id = next.summary.id;
        let ticket = queue.enqueue(next).unwrap();
        queue
            .decide(id, &detail.summary.fingerprint, Decision::Deny)
            .unwrap();
        assert_eq!(ticket.wait().await.unwrap(), Decision::Deny);
        assert_eq!(queue.inspect(id).unwrap().summary.status, Status::Denied);
        queue.observe(id, Status::Sending, None, "late approval");
        assert_eq!(queue.inspect(id).unwrap().summary.status, Status::Denied);
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
        let expired_id = ticket.id;
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
        assert_eq!(
            queue.inspect(expired_id).unwrap().summary.status,
            Status::Expired
        );
        let detail = detail("one");
        let ticket = queue.enqueue(detail.clone()).unwrap();
        queue
            .0
            .entries
            .lock()
            .unwrap()
            .pending
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

    #[tokio::test]
    async fn recent_history_is_bounded_read_only_and_separate_from_pending_capacity() {
        let queue = Queue::with_limits(watch::Sender::new(0), 1, 1);
        let mut ids = Vec::new();
        for _ in 0..HISTORY_LIMIT + 2 {
            let entry = detail("guest");
            ids.push(entry.summary.id);
            let ticket = queue.enqueue(entry.clone()).unwrap();
            queue
                .decide(entry.summary.id, &entry.summary.fingerprint, Decision::Deny)
                .unwrap();
            assert_eq!(ticket.wait().await.unwrap(), Decision::Deny);
        }
        assert!(queue.inspect(ids[0]).is_none());
        assert!(queue.inspect(ids[1]).is_none());
        assert_eq!(queue.recent().len(), HISTORY_LIMIT);
        let last = queue.inspect(*ids.last().unwrap()).unwrap();
        assert_eq!(last.body, detail("guest").body);
        assert!(!last.comment_permission_supported);
        assert!(last.comment_context.is_none());
        let json = serde_json::to_string(&queue.view()).unwrap();
        assert!(!json.contains("guest-secret"));
        assert!(!json.contains("addComment"), "history SSE carries no body");
        let ticket = queue.enqueue(detail("new")).unwrap();
        assert_eq!(queue.view().0.len(), 1);
        drop(ticket);
        assert_eq!(queue.recent()[0].status, Status::Cancelled);
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
