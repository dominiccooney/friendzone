use std::{net::SocketAddr, path::PathBuf, process::Output, time::Duration};

use axum::{Router, http::StatusCode, routing::get};
use tokio::{net::TcpListener, process::Command, task::JoinHandle};

struct TestServer {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl TestServer {
    async fn start(app: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { address, task }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn proxy_url(&self) -> String {
        format!("http://scratch-kali:x@{}", self.address)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fz-guest-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn denying_proxy() -> TestServer {
    TestServer::start(Router::new().fallback(|| async {
        (
            StatusCode::FORBIDDEN,
            "friendzone: container awaiting approval; approve it in the UI inbox",
        )
    }))
    .await
}

async fn run_fz(proxy: &TestServer, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fz"));
    command.args(args).kill_on_drop(true);
    // Model a sourced guest env, without mutating the test runner's
    // environment (other tests and Tokio threads run concurrently).
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(name, proxy.proxy_url());
    }
    command.env("NO_PROXY", "").env("no_proxy", "");
    for name in ["REQUEST_METHOD", "SUDO_USER", "SUDO_UID", "SUDO_GID"] {
        command.env_remove(name);
    }
    tokio::time::timeout(Duration::from_secs(20), command.output())
        .await
        .expect("fz command timed out")
        .expect("run fz command")
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

#[tokio::test]
async fn doctor_checks_broker_directly_with_proxy_env_set() {
    let broker = TestServer::start(Router::new().route("/health", get(|| async { "ok" }))).await;
    let proxy = denying_proxy().await;
    let output = run_fz(
        &proxy,
        &[
            "doctor",
            "--broker",
            &broker.url(),
            "--proxy",
            &proxy.proxy_url(),
        ],
    )
    .await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("[PASS] broker reachable"), "{text}");
    assert!(text.contains("TCP only"), "{text}");
    assert!(
        text.contains("container approval and proxy forwarding are not tested yet"),
        "{text}"
    );
}

#[tokio::test]
async fn doctor_still_reports_broker_http_errors() {
    let broker = TestServer::start(
        Router::new().route("/health", get(|| async { StatusCode::SERVICE_UNAVAILABLE })),
    )
    .await;
    let proxy = denying_proxy().await;
    let output = run_fz(
        &proxy,
        &[
            "doctor",
            "--broker",
            &broker.url(),
            "--proxy",
            &proxy.proxy_url(),
        ],
    )
    .await;
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("[FAIL] broker reachable"), "{text}");
    assert!(text.contains("503 Service Unavailable"), "{text}");
}

#[tokio::test]
async fn setup_fetches_all_bootstrap_endpoints_directly_with_proxy_env_set() {
    let broker = TestServer::start(
        Router::new()
            .route("/bootstrap/ca.pem", get(|| async { "TEST CERTIFICATE" }))
            .route(
                "/bootstrap/env",
                get(|| async { "export ANTHROPIC_API_KEY=fz-test-fake\n" }),
            )
            .route(
                "/bootstrap/info",
                get(|| async { axum::Json(serde_json::json!({"proxy_port": 8080})) }),
            )
            .route(
                "/bootstrap/hello",
                get(|| async { axum::Json(serde_json::json!({"approved": false})) }),
            ),
    )
    .await;
    let proxy = denying_proxy().await;
    let dir = TempDir::new();
    let cert_path = dir.0.join("friendzone-ca.pem");
    // No --install or Cline fake: setup only writes into this temp dir,
    // never the user's trust store or provider settings.
    let output = run_fz(
        &proxy,
        &[
            "setup",
            "--broker",
            &broker.url(),
            "--container",
            "scratch-kali",
            "--shell",
            "sh",
            "--output",
            cert_path.to_str().unwrap(),
        ],
    )
    .await;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("awaiting approval"), "{text}");
    assert_eq!(
        std::fs::read_to_string(cert_path).unwrap(),
        "TEST CERTIFICATE"
    );
    let env = std::fs::read_to_string(dir.0.join("friendzone-env.sh")).unwrap();
    assert!(env.contains("export HTTP_PROXY='http://scratch-kali:x@127.0.0.1:8080'"));
    assert!(env.contains("export FZ_HOST='127.0.0.1'"));
    assert!(env.contains("export ANTHROPIC_API_KEY='fz-test-fake'"));
}
