//! All upstream traffic goes to a local fixture through a test-only connector.
//! Git runs with a temporary home and empty config; never host helpers/tokens.
use super::*;
use axum::{
    Router,
    body::Bytes,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use hudsucker::{Proxy, certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
use sha2::Digest;
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn advertisement(service: &str) -> String {
    let packet = |line: String| format!("{:04x}{line}", line.len() + 4);
    format!(
        "{}0000{}0000",
        packet(format!("# service={service}\n")),
        packet(format!(
            "{} refs/heads/main\0report-status\n",
            "1".repeat(40)
        ))
    )
}

#[tokio::test]
async fn real_git_basic_retry_and_receive_discovery_use_escrow_without_enabling_push() {
    let dir = TempDir(std::env::temp_dir().join(format!("fz-git-basic-{}", uuid::Uuid::new_v4())));
    let files = crate::ca::AuthorityFiles::load_or_create(&dir.0).unwrap();
    let ca = dir.0.join("guest-ca.pem");
    std::fs::write(&ca, &files.cert_pem).unwrap();
    let config = dir.0.join("empty-gitconfig");
    std::fs::write(
        &config,
        "[credential]\n\thelper = !f() { if test \"$1\" = get; then printf \"%s\\n\" \"username=stale\" \"password=stale\"; fi; }; f\n",
    )
    .unwrap();
    let helper_config = dir.0.join("friendzone.gitconfig");
    std::fs::write(&helper_config, crate::bootstrap::GITHUB_GIT_CONFIG).unwrap();
    let settings = crate::settings::Settings::load(&dir.0).unwrap();
    settings
        .add_entry(crate::settings::EscrowEntry {
            name: "github".into(),
            hosts: vec!["github.com".into()],
            header: "authorization".into(),
            prefix: "Bearer ".into(),
            fake: "fake-github-token".into(),
            real_env: None,
            guest_env: None,
        })
        .unwrap();
    settings.set_secret("github", "fixture-real-token").unwrap();
    let state = AppState::default();
    state.add_container("guest").unwrap();
    state
        .set_pinned_ip("guest", Some("127.0.0.1".parse().unwrap()))
        .unwrap();
    let seen = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let received = seen.clone();
    let lfs_seen = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let lfs_received = lfs_seen.clone();
    let lfs_object = b"Friendzone Git LFS fixture\n".to_vec();
    let lfs_oid = format!("{:x}", sha2::Sha256::digest(&lfs_object));
    let lfs_oid_response = lfs_oid.clone();
    let lfs_object_response = lfs_object.clone();
    let lfs_object_download = lfs_object.clone();
    let cargo_hits = Arc::new(AtomicUsize::new(0));
    let cargo_received = cargo_hits.clone();
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let _upstream =
        Task(tokio::spawn(async move {
            axum::serve(
            upstream,
            Router::new()
                .route(
                    "/cline/cline.git/info/refs",
                    get(
                        move |headers: HeaderMap,
                              axum::extract::Query(query): axum::extract::Query<
                            std::collections::HashMap<String, String>,
                        >| {
                            let received = received.clone();
                            async move {
                                assert!(!headers.contains_key("proxy-authorization"));
                                let auth = headers
                                    .get("authorization")
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_owned);
                                let expected = format!(
                                    "Basic {}",
                                    STANDARD.encode(b"x-access-token:fixture-real-token")
                                );
                                let valid = auth.as_deref() == Some(&expected);
                                received.lock().unwrap().push(auth);
                                if !valid {
                                    return (
                                        StatusCode::UNAUTHORIZED,
                                        [("www-authenticate", "Basic realm=\"GitHub\"")],
                                        "Authentication required",
                                    )
                                        .into_response();
                                }
                                let service = query.get("service").unwrap();
                                assert!(matches!(
                                    service.as_str(),
                                    "git-upload-pack" | "git-receive-pack"
                                ));
                                (
                                    [(
                                        "content-type",
                                        format!("application/x-{service}-advertisement"),
                                    )],
                                    advertisement(service),
                                )
                                    .into_response()
                            }
                        },
                    ),
                )
                .route(
                    "/cline/cline.git/info/lfs/objects/batch",
                    post(move |headers: HeaderMap, body: Bytes| {
                        let lfs_received = lfs_received.clone();
                        let oid = lfs_oid_response.clone();
                        async move {
                            assert!(headers["content-type"]
                                .to_str()
                                .unwrap()
                                .to_ascii_lowercase()
                                .starts_with("application/vnd.git-lfs+json"));
                            assert!(!headers.contains_key("proxy-authorization"));
                            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                            assert_eq!(request["operation"], "download");
                            assert_eq!(request["objects"][0]["oid"], oid);
                            let auth = headers
                                .get("authorization")
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_owned);
                            let expected = format!(
                                "Basic {}",
                                STANDARD.encode(b"x-access-token:fixture-real-token")
                            );
                            lfs_received.lock().unwrap().push(auth.clone());
                            if auth.as_deref() != Some(&expected) {
                                return (
                                    StatusCode::UNAUTHORIZED,
                                    [("lfs-authenticate", "Basic realm=\"Git LFS\"")],
                                    axum::Json(serde_json::json!({"message":"Credentials needed"})),
                                )
                                    .into_response();
                            }
                            axum::Json(serde_json::json!({
                                "transfer":"basic",
                                "objects":[{
                                    "oid":oid,
                                    "size":lfs_object_response.len(),
                                    "authenticated":true,
                                    "actions":{"download":{"href":"https://github.com/lfs-object"}}
                                }],
                                "hash_algo":"sha256"
                            }))
                            .into_response()
                        }
                    }),
                )
                .route(
                    "/lfs-object",
                    get(move || {
                        let object = lfs_object_download.clone();
                        async move { object }
                    }),
                )
                .route(
                    "/config.json",
                    get(|| async {
                        axum::Json(serde_json::json!({
                            "dl":"https://static.crates.io/crates",
                            "api":"https://crates.io"
                        }))
                    }),
                )
                .route(
                    "/api/v1/crates",
                    get(move |headers: HeaderMap| {
                        let cargo_received = cargo_received.clone();
                        async move {
                            assert!(!headers.contains_key("proxy-authorization"));
                            cargo_received.fetch_add(1, Ordering::SeqCst);
                            axum::Json(serde_json::json!({
                                "crates":[{
                                    "id":"friendzone-cargo-ca-fixture",
                                    "name":"friendzone-cargo-ca-fixture",
                                    "updated_at":"2026-01-01T00:00:00Z",
                                    "versions":null,"keywords":null,"categories":null,"badges":[],
                                    "created_at":"2026-01-01T00:00:00Z",
                                    "downloads":1,"recent_downloads":1,"default_version":"1.2.3",
                                    "num_versions":1,"yanked":false,"max_version":"1.2.3",
                                    "newest_version":"1.2.3","max_stable_version":"1.2.3",
                                    "description":"local Cargo CA fixture","homepage":null,
                                    "documentation":null,"repository":null,"links":{},
                                    "exact_match":true,"trustpub_only":false
                                }],
                                "meta":{"total":1,"next_page":null,"prev_page":null}
                            }))
                        }
                    }),
                ),
        )
        .await
        .unwrap();
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connector = tower::service_fn(move |uri: hudsucker::hyper::Uri| {
        Box::pin(async move {
            if !matches!(
                uri.host(),
                Some("github.com") | Some("crates.io") | Some("index.crates.io")
            ) {
                return Err(std::io::Error::other(
                    "fixture connector refuses unexpected destinations",
                ));
            }
            tokio::net::TcpStream::connect(upstream_address)
                .await
                .map(hudsucker::hyper_util::rt::TokioIo::new)
        })
    });
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(RcgenAuthority::new(
            files.issuer().unwrap(),
            10,
            aws_lc_rs::default_provider(),
        ))
        .with_http_connector(connector)
        .with_http_handler(EventHandler::new(
            state.clone(),
            settings.clone(),
            8081,
            8082,
        ))
        .build()
        .unwrap();
    let _proxy = Task(tokio::spawn(async move {
        proxy.start().await.unwrap();
    }));
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(files.cert_pem.as_bytes()).unwrap())
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!("http://{address}")).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let discovery = "https://github.com/cline/cline.git/info/refs?service=git-receive-pack";
    let response = client.get(discovery).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["www-authenticate"],
        "Basic realm=\"GitHub\""
    );
    assert!(matches!(state.view().requests[0].verdict, Verdict::Allowed));
    assert_eq!(state.view().requests[0].status, Some(401));
    assert_eq!(seen.lock().unwrap().as_slice(), &[None]);
    let response = client
        .get(discovery)
        .basic_auth("x-access-token", Some("fake-github-token"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().await.unwrap(),
        advertisement("git-receive-pack")
    );
    assert_eq!(state.view().requests[0].status, Some(200));

    // A real Git process retries the server challenge using the same managed
    // include installed in guests. Only dummy credentials exist, and the
    // connector cannot go online.
    let mut git = tokio::process::Command::new("git");
    git.env_clear();
    // Exercise the installed Windows backend and the guest setup fix: Schannel
    // keeps verification enabled but is explicitly allowed to honor the PEM.
    if cfg!(windows) {
        git.args(["-c", "http.sslBackend=schannel"])
            .env("GIT_CONFIG_COUNT", "2")
            .env("GIT_CONFIG_KEY_0", "http.schannelUseSSLCAInfo")
            .env("GIT_CONFIG_VALUE_0", "true")
            .env("GIT_CONFIG_KEY_1", "include.path")
            .env("GIT_CONFIG_VALUE_1", &helper_config);
    } else {
        git.env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "include.path")
            .env("GIT_CONFIG_VALUE_0", &helper_config);
    }
    for key in [
        "PATH",
        "SystemRoot",
        "WINDIR",
        "SystemDrive",
        "COMSPEC",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(key) {
            git.env(key, value);
        }
    }
    git.current_dir(&dir.0)
        .env("HOME", &dir.0)
        .env("USERPROFILE", &dir.0)
        .env("XDG_CONFIG_HOME", &dir.0)
        .env("APPDATA", &dir.0)
        .env("LOCALAPPDATA", &dir.0)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSL_CAINFO", &ca)
        .env("GITHUB_TOKEN", "fake-github-token")
        .kill_on_drop(true)
        .args([
            "-c",
            "http.sslVerify=true",
            "-c",
            "protocol.version=0",
            "-c",
            "http.followRedirects=false",
            "-c",
            &format!("http.proxy=http://{address}"),
            "ls-remote",
            "https://github.com/cline/cline.git",
        ]);
    let before = seen.lock().unwrap().len();
    let output = tokio::time::timeout(Duration::from_secs(15), git.output())
        .await
        .unwrap()
        .expect("Git must be installed for Basic auth interoperability test");
    assert!(
        output.status.success(),
        "git ls-remote failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("refs/heads/main"));
    let observed = seen.lock().unwrap()[before..].to_vec();
    assert!(
        observed.contains(&None),
        "Git must first receive an origin challenge"
    );
    assert!(
        observed.iter().any(Option::is_some),
        "Git must retry with Basic credentials"
    );
    let expected = format!(
        "Basic {}",
        STANDARD.encode(b"x-access-token:fixture-real-token")
    );
    assert!(observed.iter().flatten().all(|value| value == &expected));

    // Git LFS is a separate process, but inherits the managed include through
    // GIT_CONFIG_* environment entries. The first empty helper clears inherited
    // helpers for GitHub; after the fixture's LFS-Authenticate 401, the second
    // returns only the fake token and Friendzone substitutes it.
    let repo = dir.0.join("lfs-repository");
    std::fs::create_dir_all(&repo).unwrap();
    for args in [
        vec!["init", "--quiet"],
        vec!["config", "user.name", "Fixture"],
        vec!["config", "user.email", "fixture@example.invalid"],
        vec![
            "remote",
            "add",
            "origin",
            "https://github.com/cline/cline.git",
        ],
    ] {
        assert!(
            std::process::Command::new("git")
                .current_dir(&repo)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    std::fs::write(
        repo.join("asset.bin"),
        format!(
            "version https://git-lfs.github.com/spec/v1\noid sha256:{lfs_oid}\nsize {}\n",
            lfs_object.len()
        ),
    )
    .unwrap();
    std::fs::write(
        repo.join(".gitattributes"),
        "asset.bin filter=lfs diff=lfs merge=lfs -text\n",
    )
    .unwrap();
    assert!(
        std::process::Command::new("git")
            .current_dir(&repo)
            .args(["add", ".gitattributes", "asset.bin"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("git")
            .current_dir(&repo)
            .args(["commit", "--quiet", "-m", "LFS pointer"])
            .status()
            .unwrap()
            .success()
    );
    let mut lfs = tokio::process::Command::new("git");
    lfs.current_dir(&repo)
        .env("GITHUB_TOKEN", "fake-github-token")
        .env("HTTPS_PROXY", format!("http://{address}"))
        .env("HTTP_PROXY", format!("http://{address}"))
        .env("NO_PROXY", "")
        .env("GIT_SSL_CAINFO", &ca)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("GIT_TERMINAL_PROMPT", "0")
        .kill_on_drop(true)
        .args(["lfs", "fetch", "origin", "HEAD"]);
    if cfg!(windows) {
        lfs.env("GIT_CONFIG_COUNT", "2")
            .env("GIT_CONFIG_KEY_0", "http.schannelUseSSLCAInfo")
            .env("GIT_CONFIG_VALUE_0", "true")
            .env("GIT_CONFIG_KEY_1", "include.path")
            .env("GIT_CONFIG_VALUE_1", &helper_config);
    } else {
        lfs.env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "include.path")
            .env("GIT_CONFIG_VALUE_0", &helper_config);
    }
    let output = tokio::time::timeout(Duration::from_secs(20), lfs.output())
        .await
        .unwrap()
        .expect("Git LFS must be installed for interoperability test");
    assert!(
        output.status.success(),
        "git lfs fetch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let downloaded = repo
        .join(".git/lfs/objects")
        .join(&lfs_oid[..2])
        .join(&lfs_oid[2..4])
        .join(&lfs_oid);
    assert_eq!(std::fs::read(downloaded).unwrap(), lfs_object);
    let lfs_auth = lfs_seen.lock().unwrap().clone();
    assert!(
        lfs_auth.contains(&None),
        "Git LFS must first receive a challenge"
    );
    assert!(lfs_auth.iter().any(Option::is_some));
    assert!(lfs_auth.iter().flatten().all(|value| value == &expected));

    let lfs_calls = lfs_auth.len();
    let blocked = client
        .post("https://github.com/cline/cline.git/info/lfs/objects/batch")
        .basic_auth("x-access-token", Some("fake-github-token"))
        .header("accept", "application/vnd.git-lfs+json")
        .header("content-type", "application/vnd.git-lfs+json")
        .body(format!(
            r#"{{"operation":"upload","transfers":["basic"],"objects":[{{"oid":"{lfs_oid}","size":{}}}]}}"#,
            lfs_object.len()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    assert!(blocked.text().await.unwrap().contains("Git LFS uploads"));
    assert_eq!(
        lfs_seen.lock().unwrap().len(),
        lfs_calls,
        "upload reached upstream"
    );
    assert!(state.reviews.summaries().is_empty());

    // Cargo's vendored libcurl uses Schannel on Windows. Its native CA setting
    // must verify the same generated interception certificate. CARGO_HOME and
    // the connector are isolated, so this cannot read user config or go online.
    let cargo_executable = std::process::Command::new("rustup")
        .args(["which", "cargo"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|path| PathBuf::from(path.trim()))
        .unwrap_or_else(|| PathBuf::from("cargo"));
    let mut cargo = tokio::process::Command::new(cargo_executable);
    cargo.env_clear();
    for key in [
        "PATH",
        "SystemRoot",
        "WINDIR",
        "SystemDrive",
        "COMSPEC",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(key) {
            cargo.env(key, value);
        }
    }
    cargo
        .current_dir(&dir.0)
        .env("HOME", &dir.0)
        .env("USERPROFILE", &dir.0)
        .env("CARGO_HOME", dir.0.join("cargo-home"))
        .env("HTTP_PROXY", format!("http://{address}"))
        .env("HTTPS_PROXY", format!("http://{address}"))
        .env("NO_PROXY", "")
        .env("CARGO_HTTP_CAINFO", &ca)
        .env("CARGO_HTTP_CHECK_REVOKE", "false")
        .env("CARGO_HTTP_TIMEOUT", "10")
        .kill_on_drop(true)
        .args(["search", "friendzone-cargo-ca-fixture", "--limit", "1"]);
    let output = tokio::time::timeout(Duration::from_secs(15), cargo.output())
        .await
        .unwrap()
        .expect("Cargo must be installed for CA interoperability test");
    assert!(
        output.status.success(),
        "cargo search failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("friendzone-cargo-ca-fixture"));
    assert_eq!(cargo_hits.load(Ordering::SeqCst), 1);

    let before = seen.lock().unwrap().len();
    let blocked = client
        .post("https://github.com/cline/cline.git/git-receive-pack")
        .basic_auth("octocat", Some("fake-github-token"))
        .body("unreviewed pack")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    assert!(state.reviews.summaries().is_empty());
    assert_eq!(
        seen.lock().unwrap().len(),
        before,
        "write was not forwarded"
    );
    let blocked = client
        .get("https://wrong.example/info/refs?service=git-receive-pack")
        .basic_auth("octocat", Some("fake-github-token"))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    assert!(blocked.text().await.unwrap().contains("non-pinned host"));
    settings.remove_secret("github").unwrap();
    assert_eq!(
        client
            .get(discovery)
            .basic_auth("octocat", Some("fake-github-token"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        before,
        "missing secret was not forwarded"
    );
    let audit = serde_json::to_string(&state.view()).unwrap();
    assert!(!audit.contains("fixture-real-token"));
    assert!(!audit.contains(&STANDARD.encode(b"x-access-token:fixture-real-token")));
}
