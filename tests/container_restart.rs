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
async fn live_pac_tracks_credential_hosts_not_secret_availability() {
    let dir = TempDir::new();
    let broker = Broker::start(&dir).await;
    let url = format!("{}/bootstrap/proxy.pac", broker.bootstrap);
    let execute = |source: &str, cases: Value| {
        let script = dir.0.join("generated.pac");
        let expected = dir.0.join("expected.json");
        std::fs::write(&script, source).unwrap();
        std::fs::write(&expected, cases.to_string()).unwrap();
        let output = std::process::Command::new("node")
            .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/check_pac.cjs"))
            .arg(&script).arg(&expected).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    };
    // PAC is available for setup before a guest is approved or pinned.
    let response = broker.client.get(&url).send().await.unwrap();
    assert_eq!(response.headers()["content-type"], "application/x-ns-proxy-autoconfig");
    assert_eq!(response.headers()["cache-control"], "no-store");
    execute(&response.text().await.unwrap(), json!([["api.example.com", "DIRECT"], ["example.com", "DIRECT"]]));
    let proxy = format!("PROXY {}", broker.proxy.strip_prefix("http://").unwrap());
    let response = broker.post("/api/escrow", json!({"name":"test", "hosts":["API.Example.COM.","api.example.com","storage.googleapis.com","metadata","metadata.google.internal","169.254.169.254","[fd20:ce::254]","localhost","127.1"], "header":"authorization", "prefix":"Bearer ", "guest_env":"TEST_API_KEY"})).await;
    assert!(response.status().is_success());
    let entry: Value = response.json().await.unwrap();
    let response = broker.client.get(&url).send().await.unwrap();
    execute(&response.text().await.unwrap(), json!([
        ["api.example.com",proxy], ["API.EXAMPLE.COM.",proxy], ["storage.googleapis.com",proxy],
        ["api.example.com.evil.test","DIRECT"], ["example.com","DIRECT"], ["metadata","DIRECT"],
        ["metadata.google.internal","DIRECT"], ["169.254.169.254","DIRECT"], ["[fd20:ce::254]","DIRECT"],
        ["localhost","DIRECT"], ["127.0.0.1","DIRECT"], ["35.190.247.13","DIRECT"]
    ]));
    assert!(entry["fake"].as_str().unwrap().starts_with("fz-"));
    let response = broker.client.put(format!("{}/api/escrow/test", broker.ui))
        .json(&json!({"hosts":["new.example.com"],"header":"authorization","prefix":"Bearer ","guest_env":"TEST_API_KEY"})).send().await.unwrap();
    assert!(response.status().is_success());
    let source = broker.client.get(&url).send().await.unwrap().text().await.unwrap();
    execute(&source, json!([["api.example.com","DIRECT"],["new.example.com",proxy],["storage.googleapis.com","DIRECT"]]));
    assert!(broker.client.delete(format!("{}/api/escrow/test",broker.ui)).send().await.unwrap().status().is_success());
    let source = broker.client.get(&url).send().await.unwrap().text().await.unwrap();
    execute(&source, json!([["new.example.com","DIRECT"]]));
    broker.stop().await;
}

#[tokio::test]
async fn proxy_rejects_gce_infrastructure_over_http_and_connect() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = TempDir::new();
    let broker = Broker::start(&dir).await;
    assert!(
        broker
            .post("/api/containers", json!({"name":"guest"}))
            .await
            .status()
            .is_success()
    );
    let proxy_port = reqwest::Url::parse(&broker.proxy).unwrap().port().unwrap();
    for host in ["127.0.0.1", "localhost", "broker-alias.test"] {
        for method in ["GET", "CONNECT"] {
            let target = if method == "CONNECT" { format!("{host}:{proxy_port}") } else { format!("http://{host}:{proxy_port}/") };
            let mut socket = tokio::net::TcpStream::connect(broker.proxy.strip_prefix("http://").unwrap()).await.unwrap();
            socket.write_all(format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: Basic Z3Vlc3Q6eA==\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut bytes = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut bytes)).await.unwrap().unwrap();
            let response = String::from_utf8(bytes).unwrap();
            assert!(response.starts_with("HTTP/1.1 403") && response.contains("proxy listener"), "{response}");
        }
    }
    let port = reqwest::Url::parse(&broker.bootstrap)
        .unwrap()
        .port()
        .unwrap();
    let hosts = [
        "metadata",
        "METADATA.GOOGLE.INTERNAL.",
        "169.254.169.254",
        "169.254.0.1",
        "169.254.255.254",
        "2852039166",
        "0xa9fea9fe",
        "0251.0376.0251.0376",
        "[::ffff:169.254.169.254]",
        "[::169.254.169.254]",
        "[fd20:ce::254]",
        "[fe80::1]",
        "[febf:ffff::1]",
    ];
    for host in hosts {
        for method in ["GET", "POST", "CONNECT"] {
            // Even the actual bootstrap port must not grant an exception.
            let target = if method == "CONNECT" {
                format!("{host}:{port}")
            } else {
                format!("http://{host}:{port}/computeMetadata/v1/")
            };
            let mut socket =
                tokio::net::TcpStream::connect(broker.proxy.strip_prefix("http://").unwrap())
                    .await
                    .unwrap();
            socket.write_all(format!("{method} {target} HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic Z3Vlc3Q6eA==\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            let mut bytes = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            let response = String::from_utf8(bytes).unwrap();
            assert!(
                response.starts_with("HTTP/1.1 403"),
                "{method} {target}: {response}"
            );
            assert!(
                response.contains("instance-local infrastructure"),
                "{response}"
            );
        }
    }
    let view = broker.snapshot().await;
    assert!(view["pending_requests"].as_array().unwrap().is_empty());
    let requests = view["requests"].as_array().unwrap();
    assert_eq!(requests.len(), hosts.len() * 3 + 6);
    assert!(
        requests
            .iter()
            .all(|r| r["verdict"] == "blocked" && r["status"] == 403)
    );
    broker.stop().await;
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
    // This single-process fixture has one loopback source address. Announce all
    // pending labels before one of them claims it; production guests require
    // distinct spoof-protected source addresses.
    broker.announce("wrong-ip").await;
    broker.announce("pending").await;
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
    assert!(
        broker
            .post(
                "/api/containers/wrong-ip/approve",
                json!({"pin_to_last_ip":false})
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
    assert!(
        denied
            .text()
            .await
            .unwrap()
            .contains("does not own source address")
    );
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
