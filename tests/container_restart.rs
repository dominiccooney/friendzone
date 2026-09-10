//! Exercise durable approvals through the binary and real management/proxy
//! listeners. Uses isolated ports and data, never the running user's broker.
use std::{path::PathBuf, process::Stdio, time::Duration};

use serde_json::{Value, json};

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fz-restart-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Broker {
    child: tokio::process::Child,
    ui: String,
    bootstrap: String,
    proxy: String,
    client: reqwest::Client,
}
impl Broker {
    async fn start(dir: &TempDir) -> Self {
        let mut listeners = Vec::new();
        for _ in 0..3 {
            listeners.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        }
        let addresses: Vec<_> = listeners
            .iter()
            .map(|l| l.local_addr().unwrap().to_string())
            .collect();
        drop(listeners);
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_fz"));
        command
            .args([
                "broker",
                "--proxy-addr",
                &addresses[0],
                "--ui-addr",
                &addresses[1],
                "--bootstrap-addr",
                &addresses[2],
                "--data-dir",
            ])
            .arg(&dir.0)
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for name in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            command.env_remove(name);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let mut broker = Self {
            child: command.spawn().unwrap(),
            client,
            proxy: format!("http://{}", addresses[0]),
            ui: format!("http://{}", addresses[1]),
            bootstrap: format!("http://{}", addresses[2]),
        };
        for _ in 0..100 {
            assert!(
                broker.child.try_wait().unwrap().is_none(),
                "temporary broker exited during startup"
            );
            if broker
                .client
                .get(format!("{}/health", broker.ui))
                .send()
                .await
                .is_ok()
                && broker
                    .client
                    .get(format!("{}/health", broker.bootstrap))
                    .send()
                    .await
                    .is_ok()
            {
                return broker;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("temporary broker did not become ready");
    }
    async fn stop(mut self) {
        self.child.kill().await.unwrap();
        self.child.wait().await.unwrap();
    }
    async fn post(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}{path}", self.ui))
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    async fn snapshot(&self) -> Value {
        self.client
            .get(format!("{}/api/state", self.ui))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    async fn announce(&self, name: &str) {
        self.client
            .get(format!("{}/bootstrap/hello", self.bootstrap))
            .query(&[("container", name)])
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
    async fn proxy_request(&self, name: &str) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .proxy(
                reqwest::Proxy::all(&self.proxy)
                    .unwrap()
                    .basic_auth(name, "x"),
            )
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        // Allowed request reaches only this fixture's bootstrap health endpoint.
        client
            .get(format!("{}/health", self.bootstrap))
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn proxy_blocks_guest_loopback_but_allows_configured_bootstrap() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn send(proxy: &str, request: &str) -> String {
        let mut socket = tokio::net::TcpStream::connect(proxy.strip_prefix("http://").unwrap())
            .await
            .unwrap();
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8(bytes).unwrap()
    }

    let dir = TempDir::new();
    let broker = Broker::start(&dir).await;
    assert!(
        broker
            .post("/api/containers", json!({"name":"guest"}))
            .await
            .status()
            .is_success()
    );
    // Keep a real TCP listener alive: a 403 is insufficient evidence if a
    // connection still reached it, or if no service was listening anyway.
    let hub = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub_port = hub.local_addr().unwrap().port();
    for host in [
        "127.0.0.1",
        "127.1",
        "2130706433",
        "localhost",
        "[::ffff:127.0.0.1]",
    ] {
        for method in ["GET", "POST", "CONNECT"] {
            let target = if method == "CONNECT" {
                format!("{host}:{hub_port}")
            } else {
                format!("http://{host}:{hub_port}/health")
            };
            let response = send(&broker.proxy, &format!("{method} {target} HTTP/1.1\r\nHost: {host}:{hub_port}\r\nProxy-Authorization: Basic Z3Vlc3Q6eA==\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")).await;
            assert!(
                response.starts_with("HTTP/1.1 403"),
                "{method} {target}: {response}"
            );
            assert!(response.contains("host loopback"));
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), hub.accept())
            .await
            .is_err(),
        "proxy connected to the blocked hub listener"
    );

    // Exercises actual CLI -> proxy_server -> EventHandler wiring with a
    // nondefault bootstrap port, rather than just configuring a test handler.
    let response = broker.proxy_request("guest").await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "ok");

    let authority = broker.bootstrap.strip_prefix("http://").unwrap();
    let mut tunnel = tokio::net::TcpStream::connect(broker.proxy.strip_prefix("http://").unwrap())
        .await
        .unwrap();
    tunnel.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic Z3Vlc3Q6eA==\r\n\r\n").as_bytes()).await.unwrap();
    let mut handshake = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !handshake.ends_with(b"\r\n\r\n") {
            handshake.push(tunnel.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(handshake.starts_with(b"HTTP/1.1 200"));
    tunnel
        .write_all(
            format!("GET /health HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("ok"), "{response}");
    // Bootstrap is guest-safe, not a management bypass.
    let response = send(&broker.proxy, &format!("GET {}/api/state HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic Z3Vlc3Q6eA==\r\nConnection: close\r\n\r\n", broker.bootstrap)).await;
    assert!(response.starts_with("HTTP/1.1 404"));
    let view = broker.snapshot().await;
    assert!(view["pending_requests"].as_array().unwrap().is_empty());
    let blocked: Vec<_> = view["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["verdict"] == "blocked")
        .collect();
    assert_eq!(blocked.len(), 15);
    assert!(
        blocked
            .iter()
            .all(|r| r["status"] == 403 && r["detail"].as_str().unwrap().contains("host loopback"))
    );
    broker.stop().await;
}

#[tokio::test]
async fn approvals_pins_kills_removals_and_http_save_errors_survive_restart() {
    let dir = TempDir::new();
    let broker = Broker::start(&dir).await;
    broker.announce("pinned").await;
    assert!(
        broker
            .post(
                "/api/containers/pinned/approve",
                json!({"pin_to_last_ip":true})
            )
            .await
            .status()
            .is_success()
    );
    assert!(
        broker
            .post("/api/containers", json!({"name":"killed"}))
            .await
            .status()
            .is_success()
    );
    assert!(
        broker
            .post("/api/containers/killed/kill", json!({"killed":true}))
            .await
            .status()
            .is_success()
    );
    broker.announce("wrong-ip").await;
    assert!(
        broker
            .post(
                "/api/containers/wrong-ip/approve",
                json!({"pin_to_last_ip":true})
            )
            .await
            .status()
            .is_success()
    );
    assert!(
        broker
            .post("/api/containers/wrong-ip/pin", json!({"ip":"192.0.2.123"}))
            .await
            .status()
            .is_success()
    );
    broker.announce("pending").await;
    assert!(broker.proxy_request("pinned").await.status().is_success());
    broker.stop().await; // kill rather than graceful shutdown: each mutation must already be durable

    let broker = Broker::start(&dir).await;
    let view = broker.snapshot().await;
    let containers = view["containers"].as_array().unwrap();
    assert_eq!(containers.len(), 3);
    assert!(containers.iter().all(|c| c["last_activity"].is_null()));
    let pinned = containers.iter().find(|c| c["id"] == "pinned").unwrap();
    assert_eq!(pinned["state"], "approved");
    assert_eq!(pinned["pinned_ip"], "127.0.0.1");
    assert!(broker.proxy_request("pinned").await.status().is_success());
    let denied = broker.proxy_request("wrong-ip").await;
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(denied.text().await.unwrap().contains("different address"));
    assert_eq!(
        broker.proxy_request("killed").await.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        broker.proxy_request("pending").await.status(),
        reqwest::StatusCode::FORBIDDEN
    );

    // Make persistence fail. API must return failure and not resume/approve.
    let policy_path = dir.0.join("containers.json");
    let policy = std::fs::read(&policy_path).unwrap();
    std::fs::remove_file(&policy_path).unwrap();
    std::fs::create_dir(&policy_path).unwrap();
    let failed = broker
        .post("/api/containers/killed/kill", json!({"killed":false}))
        .await;
    assert_eq!(failed.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(failed.text().await.unwrap().contains("not applied"));
    assert_eq!(
        broker
            .post(
                "/api/containers/pending/approve",
                json!({"pin_to_last_ip":false})
            )
            .await
            .status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        broker.proxy_request("killed").await.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        broker.proxy_request("pending").await.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    std::fs::remove_dir(&policy_path).unwrap();
    std::fs::write(&policy_path, policy).unwrap();

    assert!(
        broker
            .post("/api/containers/killed/kill", json!({"killed":false}))
            .await
            .status()
            .is_success()
    );
    assert!(
        broker
            .client
            .delete(format!("{}/api/containers/pinned", broker.ui))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    broker.stop().await;
    let broker = Broker::start(&dir).await;
    assert!(broker.proxy_request("killed").await.status().is_success());
    assert_eq!(
        broker.proxy_request("pinned").await.status(),
        reqwest::StatusCode::FORBIDDEN,
        "removed approval must not return after restart"
    );
    broker.stop().await;
}
