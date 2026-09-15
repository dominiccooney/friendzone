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
    time::Instant,
};
use uuid::Uuid;

pub const MAX_PAYLOAD: usize = 10 * 1024 * 1024;
const MAX_RESULT: usize = 4 * 1024 * 1024;
const MAX_STORAGE: usize = 256 * 1024 * 1024;
const MAX_JOBS: usize = 100;
const REVIEW_HOURS: i64 = 24;

/// Bounded metadata retained to distinguish approval/queue time, transport
/// failures, and responses from GitHub or an intervening edge. Only explicitly
/// allowlisted response headers are copied; request headers and bodies never are.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UpstreamDiagnostics {
    pub approved_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub headers_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub accepted_to_approval_ms: Option<u64>,
    pub approval_to_admission_ms: Option<u64>,
    pub accepted_to_admission_ms: Option<u64>,
    pub time_to_headers_ms: Option<u64>,
    pub total_ms: Option<u64>,
    pub remote_addr: Option<String>,
    pub http_version: Option<String>,
    pub response_headers: Vec<(String, String)>,
    pub response_bytes: Option<u64>,
    pub response_complete: Option<bool>,
    pub transport_error: Option<String>,
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn wall_elapsed_ms(start: DateTime<Utc>, end: DateTime<Utc>) -> u64 {
    end.signed_duration_since(start).num_milliseconds().max(0) as u64
}

fn transport_error_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection_failed"
    } else if error.is_body() {
        "body_transfer_failed"
    } else if error.is_request() {
        "request_failed"
    } else {
        "transport_failed"
    }
}

fn diagnostic_response_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    // These identify protocol/edge behavior or carry provider correlation and
    // rate-limit facts. Never broaden this to cookies, auth, or arbitrary X-*.
    const SAFE: &[&str] = &[
        "date",
        "server",
        "via",
        "content-type",
        "content-length",
        "x-github-request-id",
        "x-github-media-type",
        "x-github-api-version-selected",
        "x-request-id",
        "x-correlation-id",
        "x-trace-id",
        "traceparent",
        "x-fastly-request-id",
        "x-timer",
        "x-served-by",
        "x-cache",
        "x-cache-hits",
        "cf-ray",
        "x-amz-cf-id",
        "x-amz-request-id",
        "x-azure-ref",
        "x-envoy-upstream-service-time",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
        "x-ratelimit-used",
    ];
    let mut result = Vec::new();
    let mut total = 0usize;
    for name in SAFE {
        for value in headers.get_all(*name) {
            let Ok(value) = value.to_str() else {
                continue;
            };
            if value.len() > 1024 || value.chars().any(char::is_control) {
                continue;
            }
            let size = name.len() + value.len();
            if total + size > 8192 || result.len() >= 32 {
                return result;
            }
            total += size;
            result.push(((*name).to_owned(), value.to_owned()));
        }
    }
    result
}

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
        let retry = f
            .app
            .jobs
            .submit(&f.app, &f.settings, "guest", f.peer, input.clone())
            .unwrap();
        assert_ne!(retry["id"], accepted["id"]);
        assert_eq!(retry["request_key"], accepted["request_key"]);
        let instance = f.app.async_identity("guest", f.peer).unwrap().0;
        f.app
            .jobs
            .cancel("guest", instance, Fixture::id(&retry), "session")
            .unwrap();
        let mut changed = input.clone();
        changed.query.push(' ');
        let changed = f
            .app
            .jobs
            .submit(&f.app, &f.settings, "guest", f.peer, changed)
            .unwrap();
        f.app
            .jobs
            .cancel("guest", instance, Fixture::id(&changed), "session")
            .unwrap();
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
                                [
                                    ("x-github-request-id", "GITHUB-CORRELATION-123"),
                                    ("x-secret-internal", "must-not-be-retained"),
                                ],
                                "",
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
        assert_eq!(result["result"], "");
        assert_eq!(result["upstream"]["response_bytes"], 0);
        assert_eq!(result["upstream"]["response_complete"], true);
        assert!(result["upstream"]["started_at"].is_string());
        assert!(result["upstream"]["headers_at"].is_string());
        assert!(result["upstream"]["finished_at"].is_string());
        assert!(result["upstream"]["time_to_headers_ms"].is_number());
        assert!(result["upstream"]["total_ms"].is_number());
        assert!(result["upstream"]["remote_addr"].is_string());
        assert!(
            result["upstream"]["response_headers"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!([
                    "x-github-request-id",
                    "GITHUB-CORRELATION-123"
                ]))
        );
        assert!(!result.to_string().contains("must-not-be-retained"));
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

    #[tokio::test]
    async fn transport_failure_records_safe_diagnostics_without_replaying() {
        let f = Fixture::new();
        // Keep a listening socket open without accepting. The client can
        // connect, then deterministically times out waiting for HTTP headers.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let read = f.submit("connection", "query { viewer { id } }");
        let id = Fixture::id(&read);
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
        assert_eq!(result["status"], "unknown");
        assert!(result["http_status"].is_null());
        assert_eq!(result["upstream"]["transport_error"], "timeout");
        assert_eq!(result["upstream"]["response_bytes"], 0);
        assert_eq!(result["upstream"]["response_complete"], false);
        assert!(
            result["upstream"]["response_headers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        assert_eq!(
            f.app.jobs.get("guest", instance, id, "session").unwrap()["status"],
            "unknown"
        );
    }

    #[tokio::test]
    async fn publish_commit_then_create_pr_acceptance_never_replays_either_operation() {
        let f = Fixture::new();
        let received = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let observed = received.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().route(
                    "/graphql",
                    axum::routing::post(
                        move |headers: axum::http::HeaderMap,
                              axum::Json(body): axum::Json<serde_json::Value>| {
                            let observed = observed.clone();
                            async move {
                                assert_eq!(headers["authorization"], "Bearer host-secret");
                                observed.lock().unwrap().push(body.clone());
                                match body["operationName"].as_str() {
                                    Some("PublishCommit") => axum::Json(serde_json::json!({
                                        "data":{"createCommitOnBranch":{"commit":{"oid":"new-commit","url":"https://github.test/commit/new-commit"}}}
                                    })),
                                    Some("CreatePullRequest") => axum::Json(serde_json::json!({
                                        "data":{"createPullRequest":{"pullRequest":{"number":42,"url":"https://github.test/pull/42"}}}
                                    })),
                                    other => panic!("unexpected operation {other:?}"),
                                }
                            }
                        },
                    ),
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
        let submit =
            |request_key: &str, operation_name: &str, query: &str, variables: serde_json::Value| {
                f.app
                    .jobs
                    .submit(
                        &f.app,
                        &f.settings,
                        "guest",
                        f.peer,
                        Submission {
                            request_key: request_key.into(),
                            session_id: "session".into(),
                            query: query.into(),
                            variables,
                            operation_name: Some(operation_name.into()),
                        },
                    )
                    .unwrap()
            };
        let approve = |id: Uuid| {
            let detail = f.app.jobs.inspect(id).unwrap();
            f.app
                .jobs
                .decide(
                    id,
                    &detail.summary.fingerprint,
                    crate::review::Decision::Approve,
                )
                .unwrap();
        };
        let contents = "YWJj".repeat(30_000);
        let commit = submit(
            "publish-files",
            "PublishCommit",
            "mutation PublishCommit($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid url}}}",
            serde_json::json!({"input":{
                "branch":{"repositoryNameWithOwner":"cline/cline","branchName":"dpc/feature"},
                "expectedHeadOid":"old-commit",
                "message":{"headline":"Publish tested files"},
                "fileChanges":{"additions":[{"path":"src/large.ts","contents":contents}]}
            }}),
        );
        let commit_id = Fixture::id(&commit);
        let facts = f
            .app
            .jobs
            .inspect(commit_id)
            .unwrap()
            .summary
            .facts
            .unwrap();
        assert_eq!(facts.operation_name.as_deref(), Some("PublishCommit"));
        assert_eq!(facts.repositories, vec!["cline/cline"]);
        assert_eq!(facts.targets, vec!["branch dpc/feature"]);
        approve(commit_id);
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        let instance = f.app.async_identity("guest", f.peer).unwrap().0;
        let commit_result = f
            .app
            .jobs
            .get("guest", instance, commit_id, "session")
            .unwrap();
        assert_eq!(commit_result["status"], "response_received");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(commit_result["result"].as_str().unwrap())
                .unwrap()["data"]["createCommitOnBranch"]["commit"]["oid"],
            "new-commit"
        );

        let pull = submit(
            "open-pr",
            "CreatePullRequest",
            "mutation CreatePullRequest($input:CreatePullRequestInput!){createPullRequest(input:$input){pullRequest{number url}}}",
            serde_json::json!({"input":{
                "repositoryId":"repository-node-id","baseRefName":"main",
                "headRefName":"dpc/feature","title":"Tested PR","body":"Details"
            }}),
        );
        let pull_id = Fixture::id(&pull);
        assert_ne!(pull_id, commit_id);
        approve(pull_id);
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        let pull_result = f
            .app
            .jobs
            .get("guest", instance, pull_id, "session")
            .unwrap();
        assert_eq!(pull_result["status"], "response_received");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(pull_result["result"].as_str().unwrap())
                .unwrap()["data"]["createPullRequest"]["pullRequest"]["number"],
            42
        );
        f.app
            .jobs
            .tick(&f.app, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        let restarted = AppState::load(&f.dir).unwrap();
        restarted
            .jobs
            .tick(&restarted, &f.settings, &client, &endpoint)
            .await
            .unwrap();
        let requests = received.lock().unwrap();
        assert_eq!(requests.len(), 2, "completed writes must never replay");
        assert_eq!(
            requests[0]["variables"]["input"]["expectedHeadOid"],
            "old-commit"
        );
        assert_eq!(
            requests[1]["variables"]["input"]["headRefName"],
            "dpc/feature"
        );
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
    #[serde(default)]
    upstream: Option<UpstreamDiagnostics>,
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
            request_key: Some(self.submission.request_key.clone()),
            upstream: self.upstream.clone(),
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
            upstream: None,
        };
        self.transaction(|store| {
            // Every explicit POST is a distinct job. request_key is a human
            // correlation label, never an idempotency/deduplication key.
            // Workers execute by UUID and never submit/retry on their own.
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
        serde_json::json!({
            "id":job.id,
            "request_key":job.submission.request_key,
            "session_id":job.submission.session_id,
            "status":job.status,
            "created_at":job.created_at,
            "updated_at":job.updated_at,
            "http_status":job.http_status,
            "outcome":job.outcome,
            "terminal":job.terminal(),
            "upstream":job.upstream,
            "result":if result {job.result.as_deref()}else{None}
        })
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
                    let approved_at = Utc::now();
                    job.set(Status::Approved, "Approved; queued for execution");
                    job.upstream = Some(UpstreamDiagnostics {
                        approved_at: Some(approved_at),
                        accepted_to_approval_ms: Some(wall_elapsed_ms(job.created_at, approved_at)),
                        ..Default::default()
                    });
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
            let started_at = Utc::now();
            let mut sending_diagnostics = job.upstream.clone().unwrap_or_default();
            sending_diagnostics.started_at = Some(started_at);
            sending_diagnostics.accepted_to_admission_ms =
                Some(wall_elapsed_ms(job.created_at, started_at));
            sending_diagnostics.approval_to_admission_ms = sending_diagnostics
                .approved_at
                .map(|approved_at| wall_elapsed_ms(approved_at, started_at));
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
                        j.upstream = Some(sending_diagnostics.clone());
                        Ok(true)
                    })
                })?;
            if !admitted {
                continue;
            }
            let transfer_started = Instant::now();
            tracing::info!(
                request_id = %job.id,
                body_bytes = job.body.len(),
                accepted_to_approval_ms = sending_diagnostics.accepted_to_approval_ms,
                approval_to_admission_ms = sending_diagnostics.approval_to_admission_ms,
                "async GraphQL request sending"
            );
            let response = client
                .post(endpoint)
                .header("authorization", &credential.header_value)
                .header("content-type", "application/json")
                .header("user-agent", "Friendzone async GraphQL")
                .body(job.body.clone())
                .send()
                .await;
            let (status, http, outcome, result, diagnostics) = match response {
                Err(error) => {
                    let finished_at = Utc::now();
                    let error_kind = transport_error_kind(&error);
                    let mut diagnostics = sending_diagnostics.clone();
                    diagnostics.finished_at = Some(finished_at);
                    diagnostics.total_ms = Some(elapsed_ms(transfer_started));
                    diagnostics.response_bytes = Some(0);
                    diagnostics.response_complete = Some(false);
                    diagnostics.transport_error = Some(error_kind.into());
                    tracing::warn!(
                        request_id = %job.id,
                        transport_error = error_kind,
                        total_ms = diagnostics.total_ms.unwrap_or_default(),
                        "async GraphQL transport failed"
                    );
                    (
                        Status::Unknown,
                        None,
                        format!("No reply after sending ({error_kind}); not automatically retried"),
                        None,
                        diagnostics,
                    )
                }
                Ok(mut response) => {
                    let headers_at = Utc::now();
                    let http = response.status().as_u16();
                    let time_to_headers_ms = elapsed_ms(transfer_started);
                    let remote_addr = response.remote_addr().map(|address| address.to_string());
                    let http_version = format!("{:?}", response.version());
                    let response_headers = diagnostic_response_headers(response.headers());
                    tracing::info!(
                        request_id = %job.id,
                        http_status = http,
                        time_to_headers_ms,
                        remote_addr = remote_addr.as_deref().unwrap_or("unknown"),
                        github_request_id = response_headers
                            .iter()
                            .find(|(name, _)| name == "x-github-request-id")
                            .map(|(_, value)| value.as_str())
                            .unwrap_or("absent"),
                        server = response_headers
                            .iter()
                            .find(|(name, _)| name == "server")
                            .map(|(_, value)| value.as_str())
                            .unwrap_or("absent"),
                        via = response_headers
                            .iter()
                            .find(|(name, _)| name == "via")
                            .map(|(_, value)| value.as_str())
                            .unwrap_or("absent"),
                        "async GraphQL response headers received"
                    );
                    let mut bytes = Vec::new();
                    let mut observed_bytes = 0u64;
                    let mut complete = true;
                    let mut body_error = None;
                    loop {
                        match response.chunk().await {
                            Ok(Some(chunk)) if bytes.len() + chunk.len() <= MAX_RESULT => {
                                observed_bytes = observed_bytes.saturating_add(chunk.len() as u64);
                                bytes.extend_from_slice(&chunk)
                            }
                            Ok(None) => break,
                            Err(error) => {
                                complete = false;
                                body_error = Some(transport_error_kind(&error).to_owned());
                                break;
                            }
                            Ok(Some(chunk)) => {
                                observed_bytes = observed_bytes.saturating_add(chunk.len() as u64);
                                complete = false;
                                body_error = Some("response_too_large".into());
                                break;
                            }
                        }
                    }
                    let finished_at = Utc::now();
                    let total_ms = elapsed_ms(transfer_started);
                    let mut diagnostics = sending_diagnostics.clone();
                    diagnostics.headers_at = Some(headers_at);
                    diagnostics.finished_at = Some(finished_at);
                    diagnostics.time_to_headers_ms = Some(time_to_headers_ms);
                    diagnostics.total_ms = Some(total_ms);
                    diagnostics.remote_addr = remote_addr;
                    diagnostics.http_version = Some(http_version);
                    diagnostics.response_headers = response_headers;
                    diagnostics.response_bytes = Some(observed_bytes);
                    diagnostics.response_complete = Some(complete);
                    diagnostics.transport_error = body_error.clone();
                    tracing::info!(
                        request_id = %job.id,
                        http_status = http,
                        response_bytes = observed_bytes,
                        response_complete = complete,
                        total_ms,
                        body_error = body_error.as_deref().unwrap_or("none"),
                        "async GraphQL request completed"
                    );
                    if !complete {
                        (
                            Status::Unknown,
                            Some(http),
                            format!(
                                "Response incomplete ({}) or over 4 MiB; inspect upstream before retrying",
                                body_error.as_deref().unwrap_or("body transfer failed")
                            ),
                            None,
                            diagnostics,
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
                                    "Upstream endpoint returned HTTP {http}; inspect the response before retrying"
                                )
                            } else if errors {
                                "GraphQL errors returned".into()
                            } else {
                                "Response received".into()
                            },
                            Some(String::from_utf8_lossy(&bytes).into_owned()),
                            diagnostics,
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
                j.upstream = Some(diagnostics);
                Ok(())
            })?;
        }
        Ok(())
    }
}
