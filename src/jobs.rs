//! Durable, guest-owned GraphQL jobs. Submission/decision/execution are separate
//! transactions. Never retry Sending after restart: the remote effect is unknown.
use crate::{
    review::{Detail, Status, Summary},
    settings::Settings,
    state::AppState,
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

pub const MAX_PAYLOAD: usize = 10 * 1024 * 1024;
const MAX_RESULT: usize = 4 * 1024 * 1024;
const MAX_STORAGE: usize = 256 * 1024 * 1024;
const MAX_JOBS: usize = 100;
const REVIEW_HOURS: i64 = 24;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub request_key: String,
    pub session_id: String,
    pub query: String,
    #[serde(default)]
    pub variables: serde_json::Value,
    pub operation_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        dir: PathBuf,
        app: AppState,
        settings: Settings,
        peer: IpAddr,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("fz-jobs-{}", Uuid::new_v4()));
            let app = AppState::load(&dir).unwrap();
            let settings = Settings::load(&dir).unwrap();
            settings
                .add_entry(crate::settings::EscrowEntry {
                    name: "github".into(),
                    hosts: vec!["api.github.com".into()],
                    header: "authorization".into(),
                    prefix: "Bearer ".into(),
                    fake: "fake-github".into(),
                    real_env: None,
                    guest_env: None,
                })
                .unwrap();
            settings.set_secret("github", "host-secret").unwrap();
            app.add_container("guest").unwrap();
            Self {
                dir,
                app,
                settings,
                peer: "127.0.0.1".parse().unwrap(),
            }
        }
        fn submit(&self, key: &str, query: &str) -> serde_json::Value {
            self.app
                .jobs
                .submit(
                    &self.app,
                    &self.settings,
                    "guest",
                    self.peer,
                    Submission {
                        request_key: key.into(),
                        session_id: "session".into(),
                        query: query.into(),
                        variables: serde_json::Value::Null,
                        operation_name: None,
                    },
                )
                .unwrap()
        }
        fn id(value: &serde_json::Value) -> Uuid {
            value["id"].as_str().unwrap().parse().unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    async fn jobs_survive_disconnect_execute_once_and_keep_original_payload_and_result() {
        let f = Fixture::new();
        let large = "a".repeat(90000);
        let input=Submission{request_key:"publish".into(),session_id:"session".into(),query:"mutation($body:String!){addComment(input:{subjectId:\"id\",body:$body}){clientMutationId}}".into(),variables:serde_json::json!({"body":large}),operation_name:None};
        let accepted = f
            .app
            .jobs
            .submit(&f.app, &f.settings, "guest", f.peer, input.clone())
            .unwrap();
        let id = Fixture::id(&accepted);
        assert_eq!(accepted["status"], "pending");
        assert_eq!(
            f.app
                .jobs
                .submit(&f.app, &f.settings, "guest", f.peer, input.clone())
                .unwrap()["id"],
            accepted["id"]
        );
        let mut changed = input.clone();
        changed.query.push(' ');
        assert!(
            f.app
                .jobs
                .submit(&f.app, &f.settings, "guest", f.peer, changed)
                .is_err()
        );
        let detail = f.app.jobs.inspect(id).unwrap();
        assert!(detail.body.len() > 65536);
        assert_eq!(detail.summary.status, Status::Pending);
        assert!(
            !serde_json::to_string(&detail)
                .unwrap()
                .contains("host-secret")
        );
        assert!(
            f.app
                .jobs
                .decide(id, "wrong", crate::review::Decision::Approve)
                .is_err()
        );
        let received = Arc::new(Mutex::new(Vec::<String>::new()));
        let observed = received.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().route(
                    "/graphql",
                    axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
                        observed.lock().unwrap().push(body);
                        assert_eq!(headers["authorization"], "Bearer host-secret");
                        async { axum::Json(serde_json::json!({"data":{"id":"result"}})) }
                    }),
                ),
            )
            .await
            .unwrap()
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        assert!(received.lock().unwrap().is_empty());
        f.app
            .jobs
            .decide(
                id,
                &detail.summary.fingerprint,
                crate::review::Decision::Approve,
            )
            .unwrap();
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        assert_eq!(*received.lock().unwrap(), vec![detail.body]);
        let instance = f.app.async_identity("guest", f.peer).unwrap().0;
        let result = f.app.jobs.get("guest", instance, id, "session").unwrap();
        assert_eq!(result["status"], "response_received");
        assert!(result["result"].as_str().unwrap().contains("result"));
        assert!(
            f.app
                .jobs
                .decide(
                    id,
                    &detail.summary.fingerprint,
                    crate::review::Decision::Approve
                )
                .is_err()
        );
        assert!(f.app.jobs.get("other", instance, id, "session").is_err());
        assert!(
            f.app
                .jobs
                .get("guest", instance, id, "other-session")
                .is_err()
        );
        let restarted = AppState::load(&f.dir).unwrap();
        assert_eq!(
            restarted.async_identity("guest", f.peer).unwrap().0,
            instance
        );
        assert_eq!(
            restarted
                .jobs
                .get("guest", instance, id, "session")
                .unwrap()["status"],
            "response_received"
        );
        f.app.remove_container("guest").unwrap();
        f.app.add_container("guest").unwrap();
        assert!(
            f.app
                .jobs
                .get(
                    "guest",
                    f.app.async_identity("guest", f.peer).unwrap().0,
                    id,
                    "session"
                )
                .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn queries_auto_queue_and_policy_credentials_restart_and_storage_fail_closed() {
        let f = Fixture::new();
        let read = f.submit("read", "query { viewer { id } }");
        assert_eq!(read["status"], "approved");
        let id = Fixture::id(&read);
        let instance = f.app.async_identity("guest", f.peer).unwrap().0;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        f.settings.set_secret("github", "rotated").unwrap();
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, "http://127.0.0.1:1")
            .await
            .unwrap();
        assert_eq!(
            f.app.jobs.get("guest", instance, id, "session").unwrap()["status"],
            "blocked"
        );
        let killed = f.submit("killed", "mutation { x }");
        f.app.set_killed("guest".into(), true).unwrap();
        f.app.set_killed("guest".into(), false).unwrap();
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, "http://127.0.0.1:1")
            .await
            .unwrap();
        assert_eq!(
            f.app
                .jobs
                .get("guest", instance, Fixture::id(&killed), "session")
                .unwrap()["status"],
            "cancelled"
        );
        let waiting = f.submit("waiting", "mutation { x }");
        let sending = f.submit("sending", "query { viewer { id } }");
        f.app
            .jobs
            .transaction(|d| {
                d.jobs
                    .get_mut(&Fixture::id(&sending))
                    .unwrap()
                    .set(Status::Sending, "sending");
                Ok(())
            })
            .unwrap();
        let restarted = AppState::load(&f.dir).unwrap();
        assert_eq!(
            restarted
                .jobs
                .get("guest", instance, Fixture::id(&waiting), "session")
                .unwrap()["status"],
            "cancelled"
        );
        assert_eq!(
            restarted
                .jobs
                .get("guest", instance, Fixture::id(&sending), "session")
                .unwrap()["status"],
            "unknown"
        );
        let pending = f.submit("disk", "mutation { x }");
        let id = Fixture::id(&pending);
        let detail = f.app.jobs.inspect(id).unwrap();
        let file = f.dir.join("async-jobs.json");
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(
            f.app
                .jobs
                .decide(
                    id,
                    &detail.summary.fingerprint,
                    crate::review::Decision::Approve
                )
                .is_err()
        );
        assert_eq!(
            f.app.jobs.inspect(id).unwrap().summary.status,
            Status::Pending
        );
    }

    #[tokio::test]
    async fn cancellation_expiry_limits_and_upstream_errors_are_observable_without_replay() {
        let f = Fixture::new();
        let instance = f.app.async_identity("guest", f.peer).unwrap().0;
        let cancelled = f.submit("cancel", "query { viewer { id } }");
        let id = Fixture::id(&cancelled);
        f.app.jobs.cancel("guest", instance, id, "session").unwrap();
        assert_eq!(
            f.app.jobs.get("guest", instance, id, "session").unwrap()["status"],
            "cancelled"
        );
        let expired = f.submit("expire", "mutation { x }");
        let id = Fixture::id(&expired);
        f.app
            .jobs
            .transaction(|s| {
                s.jobs.get_mut(&id).unwrap().expires_at = Utc::now() - chrono::Duration::seconds(1);
                Ok(())
            })
            .unwrap();
        let detail = f.app.jobs.inspect(id).unwrap();
        assert!(
            f.app
                .jobs
                .decide(
                    id,
                    &detail.summary.fingerprint,
                    crate::review::Decision::Approve
                )
                .is_err()
        );
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, "http://127.0.0.1:1")
            .await
            .unwrap();
        assert_eq!(
            f.app.jobs.get("guest", instance, id, "session").unwrap()["status"],
            "expired"
        );
        assert!(
            f.app
                .jobs
                .submit(
                    &f.app,
                    &f.settings,
                    "guest",
                    f.peer,
                    Submission {
                        request_key: "huge".into(),
                        session_id: "session".into(),
                        query: "query($s:String){viewer{id}}".into(),
                        variables: serde_json::json!({"s":"x".repeat(MAX_PAYLOAD)}),
                        operation_name: None
                    }
                )
                .is_err()
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().route(
                    "/graphql",
                    axum::routing::post(|| async {
                        axum::Json(
                            serde_json::json!({"errors":[{"message":"not allowed"}],"data":null}),
                        )
                    }),
                ),
            )
            .await
            .unwrap()
        });
        let read = f.submit("errors", "query { viewer { id } }");
        let id = Fixture::id(&read);
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        let result = f.app.jobs.get("guest", instance, id, "session").unwrap();
        assert_eq!(result["status"], "graphql_error");
        assert_eq!(result["http_status"], 200);
        assert!(result["result"].as_str().unwrap().contains("not allowed"));
        assert!(f.app.jobs.cancel("guest", instance, id, "session").is_err());
        f.app.jobs.delete("guest", instance, id, "session").unwrap();
        assert!(f.app.jobs.get("guest", instance, id, "session").is_err());
        server.abort();
    }

    #[tokio::test]
    async fn http_499_is_terminal_error_with_result_and_survives_restart_without_retry() {
        let f = Fixture::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = count.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().route(
                    "/graphql",
                    axum::routing::post(move || {
                        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        async {
                            (
                                axum::http::StatusCode::from_u16(499).unwrap(),
                                "upstream closed request",
                            )
                        }
                    }),
                ),
            )
            .await
            .unwrap()
        });
        let accepted=f.submit("499","mutation PublishBackgroundCommandStreaming { createCommitOnBranch(input:{branch:{repositoryNameWithOwner:\"cline/cline\",branchName:\"feature\"}}){clientMutationId} }");
        let id = Fixture::id(&accepted);
        let detail = f.app.jobs.inspect(id).unwrap();
        f.app
            .jobs
            .decide(
                id,
                &detail.summary.fingerprint,
                crate::review::Decision::Approve,
            )
            .unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        let instance = f.app.async_identity("guest", f.peer).unwrap().0;
        let result = f.app.jobs.get("guest", instance, id, "session").unwrap();
        assert_eq!(result["status"], "upstream_error");
        assert_eq!(result["http_status"], 499);
        assert_eq!(result["terminal"], true);
        assert_eq!(result["result"], "upstream closed request");
        let restarted = AppState::load(&f.dir).unwrap();
        restarted
            .jobs
            .tick(&restarted, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        let facts = restarted.jobs.inspect(id).unwrap().summary.facts.unwrap();
        assert_eq!(facts.repositories, vec!["cline/cline"]);
        server.abort();
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Job {
    id: Uuid,
    container: String,
    instance: Uuid,
    epoch: Uuid,
    peer: IpAddr,
    submission: Submission,
    body: String,
    fingerprint: String,
    binding: crate::github::Binding,
    status: Status,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    http_status: Option<u16>,
    outcome: String,
    result: Option<String>,
    #[serde(default)]
    facts: Option<crate::graphql::Facts>,
}
impl Job {
    fn summary(&self) -> Summary {
        Summary {
            id: self.id,
            container: self.container.clone(),
            method: "POST".into(),
            url: crate::github::ENDPOINT.into(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            fingerprint: self.fingerprint.clone(),
            body_bytes: self.body.len(),
            reason: "Async GraphQL job · client may disconnect".into(),
            status: self.status,
            updated_at: self.updated_at,
            http_status: self.http_status,
            outcome: Some(self.outcome.clone()),
            asynchronous: true,
            facts: self.facts.clone(),
        }
    }
    fn terminal(&self) -> bool {
        !matches!(
            self.status,
            Status::Pending | Status::Approved | Status::Sending
        )
    }
    fn set(&mut self, status: Status, outcome: &str) {
        self.status = status;
        self.outcome = outcome.into();
        self.updated_at = Utc::now();
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u32,
    jobs: BTreeMap<Uuid, Job>,
}
struct Inner {
    data: Mutex<Saved>,
    path: Option<PathBuf>,
    changes: tokio::sync::watch::Sender<u64>,
}
#[derive(Clone)]
pub struct Jobs(Arc<Inner>);
impl Jobs {
    pub fn new(changes: tokio::sync::watch::Sender<u64>) -> Self {
        Self(Arc::new(Inner {
            data: Mutex::new(Saved {
                version: 1,
                ..Default::default()
            }),
            path: None,
            changes,
        }))
    }
    pub fn load(dir: &Path, changes: tokio::sync::watch::Sender<u64>) -> Result<Self> {
        let path = dir.join("async-jobs.json");
        if path.exists() && std::fs::metadata(&path)?.len() > MAX_STORAGE as u64 {
            bail!("async job store exceeds limit");
        }
        let mut saved: Saved = match std::fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() > MAX_STORAGE {
                    bail!("async job store exceeds limit");
                }
                serde_json::from_slice(&bytes).context("invalid async job store")?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Saved {
                version: 1,
                ..Default::default()
            },
            Err(e) => return Err(e.into()),
        };
        if saved.version != 1 || saved.jobs.len() > MAX_JOBS {
            bail!("unsupported async job store");
        }
        for job in saved.jobs.values_mut() {
            if job.facts.is_none() {
                job.facts =
                    crate::graphql::inspect_with_limit(&job.body, "application/json", MAX_PAYLOAD)
                        .1
                        .facts();
            }
            match job.status {
                Status::Sending=>job.set(Status::Unknown,"Broker restarted during execution. Not retried; inspect upstream state."),
                Status::Pending | Status::Approved=>job.set(Status::Cancelled,"Broker restarted before execution. Not sent; submit a new request if still needed."),
                _=>{}
            }
        }
        let jobs = Self(Arc::new(Inner {
            data: Mutex::new(saved),
            path: Some(path),
            changes,
        }));
        jobs.transaction(|_| Ok(()))?;
        Ok(jobs)
    }
    fn transaction<T>(&self, edit: impl FnOnce(&mut Saved) -> Result<T>) -> Result<T> {
        let mut current = self.0.data.lock().expect("jobs lock");
        let mut next = current.clone();
        let result = edit(&mut next)?;
        let bytes = serde_json::to_vec(&next)?;
        // Reserve worst-case JSON escaping for accepted results before any
        // remote effect; storage pressure must not prevent result recording.
        let reserved =
            next.jobs.values().filter(|j| !j.terminal()).count() * (MAX_RESULT * 6 + 4096);
        if bytes.len() + reserved > MAX_STORAGE {
            bail!("async job storage full; remove completed jobs");
        }
        if let Some(path) = &self.0.path {
            crate::storage::atomic_write(path, &bytes)?;
        }
        *current = next;
        drop(current);
        self.0.changes.send_modify(|v| *v = v.wrapping_add(1));
        Ok(result)
    }
    pub fn submit(
        &self,
        app: &AppState,
        settings: &Settings,
        container: &str,
        peer: IpAddr,
        input: Submission,
    ) -> Result<serde_json::Value> {
        if input.request_key.is_empty()
            || input.request_key.len() > 128
            || input.session_id.is_empty()
            || input.session_id.len() > 256
        {
            bail!("request_key and session_id required (128/256 byte limits)");
        }
        if input.query.is_empty() || !(input.variables.is_null() || input.variables.is_object()) {
            bail!("query required; variables must be object or null");
        }
        let body = serde_json::to_string(
            &serde_json::json!({"query":input.query,"variables":input.variables,"operationName":input.operation_name}),
        )?;
        if body.len() > MAX_PAYLOAD {
            bail!("GraphQL job exceeds 10 MiB");
        }
        let (instance, epoch) = app
            .async_identity(container, peer)
            .context("guest is not authorized")?;
        // Persist legacy guest incarnation before storing jobs owned by it.
        app.persist_guest_identity()?;
        if let Some(existing) = self
            .0
            .data
            .lock()
            .expect("jobs lock")
            .jobs
            .values()
            .find(|j| {
                j.container == container
                    && j.instance == instance
                    && j.submission.request_key == input.request_key
            })
            .cloned()
        {
            if existing.body != body || existing.submission.session_id != input.session_id {
                bail!("request_key already belongs to different content/session");
            }
            return Ok(Self::guest_value(&existing, false));
        }
        let entries: Vec<_> = settings
            .entries()
            .into_iter()
            .filter_map(|e| crate::github::Credential::from_entry(settings, &e))
            .collect();
        if entries.len() != 1 {
            bail!("configure exactly one GitHub Bearer escrow credential before submitting jobs");
        }
        let binding = entries[0].binding.clone();
        let request = hudsucker::hyper::Request::builder()
            .method("POST")
            .uri(crate::github::ENDPOINT)
            .header("content-type", "application/json")
            .body(hudsucker::Body::empty())?;
        let detail =
            Detail::from_request_with_limit(container, &request, body.as_bytes(), MAX_PAYLOAD)?;
        let now = Utc::now();
        let job = Job {
            id: detail.summary.id,
            container: container.into(),
            instance,
            epoch,
            peer,
            submission: input,
            body,
            fingerprint: detail.summary.fingerprint,
            binding,
            status: if detail.graphql_read {
                Status::Approved
            } else {
                Status::Pending
            },
            created_at: now,
            updated_at: now,
            expires_at: now + chrono::Duration::hours(REVIEW_HOURS),
            http_status: None,
            outcome: if detail.graphql_read {
                "Read-only query queued"
            } else {
                "Awaiting host approval"
            }
            .into(),
            result: None,
            facts: detail.summary.facts,
        };
        self.transaction(|store| {
            if let Some(existing) = store.jobs.values().find(|j| {
                j.container == container
                    && j.instance == instance
                    && j.submission.request_key == job.submission.request_key
            }) {
                if existing.body != job.body
                    || existing.submission.session_id != job.submission.session_id
                {
                    bail!("request_key conflict");
                }
                return Ok(Self::guest_value(existing, false));
            }
            if store.jobs.len() >= MAX_JOBS
                || store.jobs.values().filter(|j| !j.terminal()).count() >= 32
                || store
                    .jobs
                    .values()
                    .filter(|j| j.container == container && !j.terminal())
                    .count()
                    >= 8
            {
                bail!("async job capacity reached; finish/cancel jobs or remove old results");
            }
            let value = Self::guest_value(&job, false);
            store.jobs.insert(job.id, job);
            Ok(value)
        })
    }
    fn guest_value(job: &Job, result: bool) -> serde_json::Value {
        serde_json::json!({"id":job.id,"request_key":job.submission.request_key,"session_id":job.submission.session_id,"status":job.status,"updated_at":job.updated_at,"http_status":job.http_status,"outcome":job.outcome,"terminal":job.terminal(),"result":if result {job.result.as_deref()}else{None}})
    }
    pub fn list(&self, container: &str, instance: Uuid, session: &str) -> Vec<serde_json::Value> {
        self.0
            .data
            .lock()
            .expect("jobs lock")
            .jobs
            .values()
            .filter(|j| {
                j.container == container
                    && j.instance == instance
                    && j.submission.session_id == session
            })
            .map(|j| Self::guest_value(j, false))
            .collect()
    }
    pub fn get(
        &self,
        container: &str,
        instance: Uuid,
        id: Uuid,
        session: &str,
    ) -> Result<serde_json::Value> {
        let data = self.0.data.lock().expect("jobs lock");
        let job = data
            .jobs
            .get(&id)
            .filter(|j| {
                j.container == container
                    && j.instance == instance
                    && j.submission.session_id == session
            })
            .context("job not found")?;
        Ok(Self::guest_value(job, true))
    }
    pub fn cancel(&self, container: &str, instance: Uuid, id: Uuid, session: &str) -> Result<()> {
        self.transaction(|data| {
            let job = data
                .jobs
                .get_mut(&id)
                .filter(|j| {
                    j.container == container
                        && j.instance == instance
                        && j.submission.session_id == session
                })
                .context("job not found")?;
            if !matches!(job.status, Status::Pending | Status::Approved) {
                bail!("cannot cancel job after execution starts");
            }
            job.set(
                Status::Cancelled,
                "Cancelled by submitting guest. Not sent.",
            );
            Ok(())
        })
    }
    pub fn delete(&self, container: &str, instance: Uuid, id: Uuid, session: &str) -> Result<()> {
        self.transaction(|data| {
            let job = data
                .jobs
                .get(&id)
                .filter(|j| {
                    j.container == container
                        && j.instance == instance
                        && j.submission.session_id == session
                })
                .context("job not found")?;
            if !job.terminal() {
                bail!("cancel or finish job before removing it");
            }
            data.jobs.remove(&id);
            Ok(())
        })
    }
    pub fn summaries(&self) -> (Vec<Summary>, Vec<Summary>) {
        let data = self.0.data.lock().expect("jobs lock");
        data.jobs
            .values()
            .map(Job::summary)
            .partition(|s| s.status == Status::Pending)
    }
    pub fn inspect(&self, id: Uuid) -> Option<Detail> {
        let job = self
            .0
            .data
            .lock()
            .expect("jobs lock")
            .jobs
            .get(&id)?
            .clone();
        let request = hudsucker::hyper::Request::builder()
            .method("POST")
            .uri(crate::github::ENDPOINT)
            .header("content-type", "application/json")
            .body(hudsucker::Body::empty())
            .ok()?;
        let mut detail = Detail::from_request_with_limit(
            &job.container,
            &request,
            job.body.as_bytes(),
            MAX_PAYLOAD,
        )
        .ok()?;
        detail.summary = job.summary();
        Some(detail)
    }
    pub fn contains(&self, id: Uuid) -> bool {
        self.0
            .data
            .lock()
            .expect("jobs lock")
            .jobs
            .contains_key(&id)
    }
    pub fn decide(
        &self,
        id: Uuid,
        fingerprint: &str,
        decision: crate::review::Decision,
    ) -> Result<()> {
        self.transaction(|data| {
            let job = data.jobs.get_mut(&id).context("job not found")?;
            if job.status != Status::Pending
                || job.fingerprint != fingerprint
                || job.expires_at <= Utc::now()
            {
                bail!("job no longer pending or fingerprint changed");
            }
            match decision {
                crate::review::Decision::Approve => {
                    job.set(Status::Approved, "Approved; queued for execution")
                }
                crate::review::Decision::Deny => {
                    job.set(Status::Denied, "Denied by host. Not sent.")
                }
            };
            Ok(())
        })
    }
    pub async fn run(&self, app: AppState, settings: Settings) {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(90))
            .build()
            .expect("job client");
        loop {
            if let Err(error) = self
                .tick(&app, &settings, &client, crate::github::ENDPOINT)
                .await
            {
                tracing::error!(%error,"async job worker paused");
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    pub(crate) async fn tick(
        &self,
        app: &AppState,
        settings: &Settings,
        client: &reqwest::Client,
        endpoint: &str,
    ) -> Result<()> {
        let work: Vec<_> = self
            .0
            .data
            .lock()
            .expect("jobs lock")
            .jobs
            .values()
            .filter(|j| matches!(j.status, Status::Pending | Status::Approved))
            .cloned()
            .collect();
        for job in work {
            if job.expires_at <= Utc::now()
                || app.async_identity(&job.container, job.peer) != Some((job.instance, job.epoch))
            {
                self.transaction(|data| {
                    let Some(j) = data.jobs.get_mut(&job.id) else {
                        return Ok(());
                    };
                    if matches!(j.status, Status::Pending | Status::Approved) {
                        if j.expires_at <= Utc::now() {
                            j.set(Status::Expired, "Review expired after 24 hours. Not sent.");
                        } else {
                            j.set(Status::Cancelled, "Guest permissions changed. Not sent.");
                        }
                    }
                    Ok(())
                })?;
                continue;
            }
            if job.status != Status::Approved {
                continue;
            }
            let Some(credential) = crate::github::Credential::current(settings, &job.binding)
            else {
                self.transaction(|d| {
                    if let Some(j) = d.jobs.get_mut(&job.id)
                        && j.status == Status::Approved
                    {
                        j.set(
                            Status::Blocked,
                            "GitHub credential changed. Not sent; submit again.",
                        );
                    }
                    Ok(())
                })?;
                continue;
            };
            // Shared policy lock is the admission boundary, just like proxy
            // review admission. Persist Sending BEFORE the first upstream byte.
            let admitted =
                app.with_async_identity(&job.container, job.peer, job.instance, job.epoch, || {
                    self.transaction(|d| {
                        let Some(j) = d.jobs.get_mut(&job.id) else {
                            return Ok(false);
                        };
                        if j.status != Status::Approved || j.expires_at <= Utc::now() {
                            return Ok(false);
                        }
                        j.set(Status::Sending, "Executing on GitHub");
                        Ok(true)
                    })
                })?;
            if !admitted {
                continue;
            }
            let response = client
                .post(endpoint)
                .header("authorization", &credential.header_value)
                .header("content-type", "application/json")
                .header("user-agent", "Friendzone async GraphQL")
                .body(job.body.clone())
                .send()
                .await;
            let (status, http, outcome, result) = match response {
                Err(_) => (
                    Status::Unknown,
                    None,
                    "No reply after sending; not automatically retried".to_owned(),
                    None,
                ),
                Ok(mut response) => {
                    let http = response.status().as_u16();
                    let mut bytes = Vec::new();
                    let mut complete = true;
                    loop {
                        match response.chunk().await {
                            Ok(Some(chunk)) if bytes.len() + chunk.len() <= MAX_RESULT => {
                                bytes.extend_from_slice(&chunk)
                            }
                            Ok(None) => break,
                            _ => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if !complete {
                        (
                            Status::Unknown,
                            Some(http),
                            "Response incomplete or over 4 MiB; inspect upstream before retrying"
                                .into(),
                            None,
                        )
                    } else {
                        let json = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
                        let errors = json
                            .as_ref()
                            .and_then(|v| v.get("errors"))
                            .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()));
                        (
                            if http >= 400 {
                                Status::UpstreamError
                            } else if errors {
                                Status::GraphqlError
                            } else {
                                Status::ResponseReceived
                            },
                            Some(http),
                            if http >= 400 {
                                format!(
                                    "GitHub returned HTTP {http}; inspect the response before retrying"
                                )
                            } else if errors {
                                "GraphQL errors returned".into()
                            } else {
                                "Response received".into()
                            },
                            Some(String::from_utf8_lossy(&bytes).into_owned()),
                        )
                    }
                }
            };
            self.transaction(|d| {
                let j = d
                    .jobs
                    .get_mut(&job.id)
                    .context("job missing after execution")?;
                j.set(status, &outcome);
                j.http_status = http;
                j.result = result;
                Ok(())
            })?;
        }
        Ok(())
    }
}
