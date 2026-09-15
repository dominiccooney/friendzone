use std::{net::SocketAddr, process::Output, time::Duration};

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
        format!("http://{}", self.address)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn denying_proxy() -> TestServer {
    TestServer::start(Router::new().fallback(|| async {
        (
            StatusCode::FORBIDDEN,
            "friendzone: container awaiting approval; use Approve + pin IP in the UI inbox",
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
async fn obsolete_setup_command_is_not_a_second_installation_path() {
    let proxy = denying_proxy().await;
    let output = run_fz(&proxy, &["setup"]).await;
    assert!(!output.status.success());
    assert!(output_text(&output).contains("unrecognized subcommand"));
}
