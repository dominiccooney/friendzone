use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};

pub async fn run(
    broker: &str,
    output: Option<PathBuf>,
    install: bool,
    container: Option<String>,
) -> Result<()> {
    let client = crate::guest_http::broker_client()?;
    let url = format!("{}/bootstrap/ca.pem", broker.trim_end_matches('/'));
    let cert = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .context("broker rejected certificate request")?
        .bytes()
        .await?;
    let target = TargetUser::resolve();
    let path = output.unwrap_or_else(|| target.config_dir().join("friendzone-ca.pem"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        target.adopt(parent);
    }
    fs::write(&path, &cert).with_context(|| format!("write {}", path.display()))?;
    target.adopt(&path);
    println!("Saved Friendzone CA to {}", path.display());
    let container = container.unwrap_or_else(guest_hostname);
    fetch_guest_env(&client, broker, &path, &container, &target).await?;
    if install {
        install_ca(&path)?;
    } else {
        println!("Install it in the guest trust store, or rerun with --install.");
    }
    print_runtime_instructions(&path);
    Ok(())
}

/// Who setup is really for. `sudo ./fz setup` runs as root, but the
/// agent runs as the invoking user: files must land in that user's
/// home and be owned by them, not vanish into /root (mode 0700).
struct TargetUser {
    /// Set when running under sudo for a non-root user.
    sudo_home: Option<PathBuf>,
    /// uid/gid to hand written files back to.
    owner: Option<(u32, u32)>,
}

impl TargetUser {
    fn resolve() -> Self {
        #[cfg(unix)]
        if let Ok(user) = std::env::var("SUDO_USER")
            && user != "root"
        {
            let home = PathBuf::from("/home").join(&user);
            if home.is_dir() {
                let uid = std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok());
                let gid = std::env::var("SUDO_GID").ok().and_then(|v| v.parse().ok());
                return Self {
                    sudo_home: Some(home),
                    owner: uid.zip(gid),
                };
            }
        }
        Self {
            sudo_home: None,
            owner: None,
        }
    }

    fn home(&self) -> PathBuf {
        self.sudo_home
            .clone()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."))
    }

    fn config_dir(&self) -> PathBuf {
        match &self.sudo_home {
            Some(home) => home.join(".config").join("friendzone"),
            None => dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("friendzone"),
        }
    }

    /// Hands a written path back to the invoking user and makes it
    /// world-readable (0755 dirs / 0644 files): everything setup writes
    /// is non-secret (public CA, worthless fakes, provider config).
    fn adopt(&self, path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some((uid, gid)) = self.owner {
                let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid));
            }
            if let Ok(metadata) = fs::metadata(path) {
                let mode = if metadata.is_dir() { 0o755 } else { 0o644 };
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
            }
        }
        #[cfg(not(unix))]
        let _ = path;
    }
}

fn guest_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_owned())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "guest".to_owned())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn guest_environment(
    broker: &str,
    port: u16,
    container: &str,
    cert: &Path,
    fakes: &str,
) -> Result<String> {
    let broker = reqwest::Url::parse(broker).context("parse broker URL")?;
    let host = broker.host_str().context("broker URL has no host")?;
    let host = host.trim_matches(['[', ']']);
    let mut proxy = broker.clone();
    proxy
        .set_scheme("http")
        .map_err(|_| anyhow::anyhow!("invalid proxy scheme"))?;
    proxy
        .set_port(Some(port))
        .map_err(|_| anyhow::anyhow!("invalid proxy port"))?;
    proxy
        .set_username(container)
        .map_err(|_| anyhow::anyhow!("invalid container name"))?;
    proxy
        .set_password(Some("x"))
        .map_err(|_| anyhow::anyhow!("invalid proxy credentials"))?;
    proxy.set_path("");
    proxy.set_query(None);
    proxy.set_fragment(None);
    let proxy = shell_quote(proxy.as_str().trim_end_matches('/'));
    let host = shell_quote(host);
    let cert = shell_quote(&cert.to_string_lossy());
    Ok(format!(
        "# Friendzone guest environment; source this in the agent's shell.\n\
         export FZ_HOST={host}\n\
         export FZ_BROKER={}\n\
         export HTTP_PROXY={proxy}\n\
         export HTTPS_PROXY={proxy}\n\
         export http_proxy={proxy}\n\
         export https_proxy={proxy}\n\
         # Guest loopback (including the Cline hub) must stay in the guest.\n\
         # Merge both cases literally: no globbing, duplicate entries or lost exclusions.\n\
         _fz_no_proxy_rest=\"$FZ_HOST,localhost,127.0.0.1,::1,[::1],${{NO_PROXY:-}},${{no_proxy:-}},\"\n\
         _fz_no_proxy_list=\n\
         while [ -n \"$_fz_no_proxy_rest\" ]; do\n\
           _fz_no_proxy_item=${{_fz_no_proxy_rest%%,*}}\n\
           _fz_no_proxy_rest=${{_fz_no_proxy_rest#*,}}\n\
           _fz_no_proxy_item=${{_fz_no_proxy_item#\"${{_fz_no_proxy_item%%[![:space:]]*}}\"}}\n\
           _fz_no_proxy_item=${{_fz_no_proxy_item%\"${{_fz_no_proxy_item##*[![:space:]]}}\"}}\n\
           [ -n \"$_fz_no_proxy_item\" ] || continue\n\
           case ,$_fz_no_proxy_list, in\n\
             *,\"$_fz_no_proxy_item\",*) ;;\n\
             *) _fz_no_proxy_list=\"${{_fz_no_proxy_list:+$_fz_no_proxy_list,}}$_fz_no_proxy_item\" ;;\n\
           esac\n\
         done\n\
         export NO_PROXY=\"$_fz_no_proxy_list\"\n\
         export no_proxy=\"$NO_PROXY\"\n\
         unset _fz_no_proxy_rest _fz_no_proxy_list _fz_no_proxy_item\n\
         export NODE_EXTRA_CA_CERTS={cert}\n\
         export REQUESTS_CA_BUNDLE={cert}\n\
         export SSL_CERT_FILE={cert}\n\
         export GIT_SSL_CAINFO={cert}\n\
         export GIT_PROXY_SSL_CAINFO={cert}\n\
         {fakes}",
        shell_quote(broker.as_str().trim_end_matches('/')),
    ))
}

/// Pulls the fake credentials and proxy facts from the broker and
/// writes one complete, sourceable env file: proxy vars (with this
/// container's identity), CA bundles for common runtimes, and the fake
/// keys. Fakes only; reals never leave the host.
async fn fetch_guest_env(
    client: &reqwest::Client,
    broker: &str,
    cert_path: &Path,
    container: &str,
    target: &TargetUser,
) -> Result<()> {
    let base = broker.trim_end_matches('/');
    let url = format!("{base}/bootstrap/env");
    let fakes = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .context("broker rejected env request")?
        .text()
        .await?;
    let info: serde_json::Value = client
        .get(format!("{base}/bootstrap/info"))
        .send()
        .await
        .context("fetch broker info")?
        .json()
        .await
        .context("parse broker info")?;
    let proxy_port = info
        .get("proxy_port")
        .and_then(serde_json::Value::as_u64)
        .context("no proxy_port in broker info")?;
    let proxy_port = u16::try_from(proxy_port).context("invalid proxy_port")?;
    let env = guest_environment(base, proxy_port, container, cert_path, &fakes)?;
    let env_path = cert_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("friendzone-env.sh");
    fs::write(&env_path, &env).with_context(|| format!("write {}", env_path.display()))?;
    target.adopt(&env_path);
    // Announce this guest so a join request appears in the UI now.
    let approved = client
        .get(format!(
            "{base}/bootstrap/hello?container={}",
            urlencoding_min(container)
        ))
        .send()
        .await
        .ok();
    let approved = match approved {
        Some(response) => response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("approved").and_then(serde_json::Value::as_bool)),
        None => None,
    };
    println!("Container identity:   {container} (override with --container)");
    match approved {
        Some(true) => println!("Broker approval:      approved — traffic will flow"),
        Some(false) => println!(
            "Broker approval:      awaiting approval — open the friendzone UI inbox and approve '{container}'"
        ),
        None => println!("Broker approval:      could not check (broker unreachable?)"),
    }
    println!("Wrote guest env to    {}", env_path.display());
    println!();
    println!("Copy-paste to activate now, and add to the agent's shell profile:");
    println!();
    println!("  . {}", env_path.display());
    println!();
    if let Some(fake_key) = env_export_value(&env, "CLINE_API_KEY") {
        // The agent runs as the invoking user; its Cline reads that
        // user's ~/.cline, not root's.
        let home = target.home();
        match write_cline_provider_settings(&home, &fake_key) {
            Ok(path) => {
                // Hand the whole created chain back: ~/.cline down to
                // the settings file.
                let mut current = path.as_path();
                loop {
                    target.adopt(current);
                    match current.parent() {
                        Some(parent) if parent.starts_with(&home) && parent != home => {
                            current = parent
                        }
                        _ => break,
                    }
                }
                // Merging can preserve credentials for other providers;
                // unlike the CA/env, providers.json is not public data.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                }
                println!(
                    "Configured Cline inference (fake key) in {}",
                    path.display()
                );
            }
            Err(error) => println!("Could not configure Cline settings: {error:#}"),
        }
    }
    Ok(())
}

/// Percent-encodes the few characters plausible in a container name.
fn urlencoding_min(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('#', "%23")
        .replace('?', "%3F")
}

/// Extracts `export NAME=value` from the fetched env file.
fn env_export_value(env: &str, name: &str) -> Option<String> {
    env.lines().find_map(|line| {
        line.strip_prefix("export ")?
            .trim()
            .strip_prefix(name)?
            .strip_prefix('=')
            .map(str::to_owned)
    })
}

/// Cline v1 store contract: cline/cline b18de090, core/src/types/provider-settings.ts.
/// Invalid metadata causes Cline to discard the entire store. Use static
/// apiKey auth: OAuth refresh belongs to the broker, never to the guest.
/// Run setup while the guest's Cline is stopped to avoid competing writers.
fn write_cline_provider_settings(home: &Path, fake_key: &str) -> Result<PathBuf> {
    let settings_dir = home.join(".cline").join("data").join("settings");
    fs::create_dir_all(&settings_dir)
        .with_context(|| format!("create {}", settings_dir.display()))?;
    let path = settings_dir.join("providers.json");
    let mut root: serde_json::Value = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path)?)
            .with_context(|| format!("parse {}", path.display()))?
    } else {
        serde_json::json!({ "version": 1, "modes": {}, "providers": {} })
    };
    let object = root
        .as_object_mut()
        .context("providers.json is not an object")?;
    if object
        .get("version")
        .is_some_and(|v| v != &serde_json::json!(1))
    {
        anyhow::bail!("unsupported Cline providers.json version; leaving it unchanged");
    }
    object.insert("version".into(), serde_json::json!(1));
    object
        .entry("modes")
        .or_insert_with(|| serde_json::json!({}));
    let providers = root
        .as_object_mut()
        .context("providers.json is not an object")?
        .entry("providers")
        .or_insert_with(|| serde_json::json!({}));
    let providers = providers
        .as_object_mut()
        .context("providers key is not an object")?;
    match providers.get_mut("cline") {
        Some(existing) => {
            // Update only the key; keep the user's model choice etc.
            existing
                .pointer_mut("/settings")
                .and_then(|s| s.as_object_mut())
                .context("cline provider settings is not an object")?
                .insert("apiKey".into(), serde_json::json!(fake_key));
            let settings = existing["settings"].as_object_mut().expect("checked above");
            // A stale OAuth access token takes precedence over apiKey.
            // Explicit guest setup switches this provider to broker auth.
            settings.remove("auth");
            existing["tokenSource"] = serde_json::json!("manual");
            existing["updatedAt"] = serde_json::json!(
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            );
        }
        None => {
            providers.insert(
                "cline".into(),
                serde_json::json!({
                    "settings": { "provider": "cline", "apiKey": fake_key },
                    "updatedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "tokenSource": "manual",
                }),
            );
        }
    }
    let root_object = root.as_object_mut().expect("checked above");
    root_object
        .entry("lastUsedProvider")
        .or_insert_with(|| serde_json::json!("cline"));
    crate::storage::atomic_write(&path, serde_json::to_string_pretty(&root)?.as_bytes())?;
    Ok(path)
}

fn install_ca(path: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    let status = Command::new("certutil")
        .args(["-addstore", "-f", "Root"])
        .arg(path)
        .status()
        .context("run certutil")?;
    #[cfg(target_os = "macos")]
    let status = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
        ])
        .arg(path)
        .status()
        .context("run security")?;
    #[cfg(target_os = "linux")]
    let status = {
        let target = Path::new("/usr/local/share/ca-certificates/friendzone.crt");
        fs::copy(path, target).context("copy CA to system trust directory")?;
        Command::new("update-ca-certificates")
            .status()
            .context("run update-ca-certificates")?
    };
    if !status.success() {
        anyhow::bail!("system trust command failed with {status}");
    }
    println!("Installed Friendzone CA in the system trust store.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_guest_env_preserves_exclusions_and_is_idempotent() {
        #[cfg(windows)]
        let shell = "C:/Program Files/Git/bin/bash.exe";
        #[cfg(not(windows))]
        let shell = "/bin/sh";
        if !Path::new(shell).exists() {
            eprintln!("shell integration unavailable: {shell}");
            return;
        }
        let env = guest_environment(
            "http://172.31.208.1:8082",
            8080,
            "scratch-kali",
            Path::new("/tmp/a b'c.pem"),
            "",
        )
        .unwrap();
        for (initial, additional) in [
            ("unset NO_PROXY; export no_proxy=localhost", ""),
            ("export NO_PROXY=localhost; unset no_proxy", ""),
            ("unset NO_PROXY no_proxy", ""),
            (
                "export NO_PROXY=upper.test; export no_proxy=lower.test",
                ",upper.test,lower.test",
            ),
            (
                "export NO_PROXY=' upper.test ,127.0.0.1,,[::1]'; export no_proxy='*.internal,upper.test'",
                ",upper.test,*.internal",
            ),
        ] {
            let script = format!(
                "set -eu\n{initial}\n{env}\nfirst=$NO_PROXY\n{env}\n[ \"$first\" = \"$NO_PROXY\" ]\nprintf '%s\\n' \"$FZ_HOST\" \"$NO_PROXY\" \"$no_proxy\" \"$GIT_SSL_CAINFO\" \"$HTTPS_PROXY\"\n"
            );
            let output = Command::new(shell).args(["-c", &script]).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            let lines: Vec<_> = text.lines().collect();
            assert_eq!(lines[0], "172.31.208.1");
            assert_eq!(
                lines[1],
                format!("172.31.208.1,localhost,127.0.0.1,::1,[::1]{additional}")
            );
            assert_eq!(lines[1], lines[2]);
            assert_eq!(lines[3], "/tmp/a b'c.pem");
            assert_eq!(lines[4], "http://scratch-kali:x@172.31.208.1:8080");
        }
    }

    #[tokio::test]
    async fn loopback_health_stays_local_but_nonlocal_requests_still_use_proxy() {
        use axum::{Router, routing::get};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        #[cfg(windows)]
        let (shell, curl) = (
            "C:/Program Files/Git/bin/bash.exe",
            "C:/Windows/System32/curl.exe",
        );
        #[cfg(not(windows))]
        let (shell, curl) = ("/bin/sh", "curl");
        if !Path::new(shell).exists() {
            eprintln!("shell integration unavailable: {shell}");
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub_port = listener.local_addr().unwrap().port();
        let hub = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/health", get(|| async { "guest-hub" })),
            )
            .await
            .unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let proxy = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(move || {
                    observed.fetch_add(1, Ordering::SeqCst);
                    async { (axum::http::StatusCode::FORBIDDEN, "proxy-denial") }
                }),
            )
            .await
            .unwrap();
        });
        // Use a non-loopback broker identity so the host exemption cannot
        // accidentally make this regression test pass without loopback entries.
        let env = guest_environment(
            "http://192.0.2.1:8082",
            8080,
            "guest",
            Path::new("/unused/public-ca.pem"),
            "",
        )
        .unwrap();
        let mut urls = vec![
            format!("http://127.0.0.1:{hub_port}/health"),
            format!("http://localhost:{hub_port}/health"),
        ];
        let ipv6_hub = if let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await {
            urls.push(format!(
                "http://[::1]:{}/health",
                listener.local_addr().unwrap().port()
            ));
            Some(tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().route("/health", get(|| async { "guest-hub" })),
                )
                .await
                .unwrap();
            }))
        } else {
            eprintln!("IPv6 loopback is unavailable; IPv4/localhost checks still run");
            None
        };
        let mut script = format!(
            "set -eu\nunset NO_PROXY no_proxy\n{env}\nexport HTTP_PROXY={} http_proxy={} HTTPS_PROXY={} https_proxy={}\n",
            shell_quote(&proxy_url),
            shell_quote(&proxy_url),
            shell_quote(&proxy_url),
            shell_quote(&proxy_url),
        );
        for url in &urls {
            script.push_str(&format!("[ \"$({} --silent --show-error --fail --connect-timeout 2 --max-time 5 {})\" = guest-hub ]\n", shell_quote(curl), shell_quote(url)));
        }
        // Nonlocal DNS never needs to resolve: the mock proxy receives it.
        script.push_str(&format!("[ \"$({} --silent --show-error --connect-timeout 2 --max-time 5 http://not-local.invalid/health)\" = proxy-denial ]\n", shell_quote(curl)));
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            tokio::process::Command::new(shell)
                .args(["-c", &script])
                .kill_on_drop(true)
                .output(),
        )
        .await;
        hub.abort();
        proxy.abort();
        if let Some(hub) = ipv6_hub {
            hub.abort();
        }
        let output = output.expect("loopback probe timed out").unwrap();
        assert!(
            output.status.success(),
            "local requests must bypass the proxy: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "only the nonlocal request should reach the proxy"
        );
    }

    #[test]
    fn guest_env_quotes_values_and_supports_ipv6() {
        let env = guest_environment(
            "http://[::1]:8082/",
            8080,
            "guest",
            Path::new("/tmp/a b'c.pem"),
            "",
        )
        .unwrap();
        assert!(env.contains("export FZ_HOST='::1'"));
        assert!(env.contains("export HTTPS_PROXY='http://guest:x@[::1]:8080'"));
        assert!(env.contains("export GIT_SSL_CAINFO='/tmp/a b'\"'\"'c.pem'"));
        assert!(env.contains("export no_proxy=\"$NO_PROXY\""));
    }

    #[test]
    fn env_export_parsing() {
        let env = "# comment\nexport CLINE_API_KEY=fz-cline-abc\nexport OTHER=x\n";
        assert_eq!(
            env_export_value(env, "CLINE_API_KEY").as_deref(),
            Some("fz-cline-abc")
        );
        assert_eq!(env_export_value(env, "MISSING"), None);
        // Names sharing a prefix must not match.
        assert_eq!(env_export_value(env, "CLINE"), None);
    }

    #[test]
    fn cline_settings_write_merge_and_update() {
        let home = std::env::temp_dir().join(format!("fz-setup-{}", uuid::Uuid::new_v4()));
        // Fresh write.
        let path = write_cline_provider_settings(&home, "fake-1").unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root["providers"]["cline"]["settings"]["provider"], "cline");
        assert_eq!(root["providers"]["cline"]["settings"]["apiKey"], "fake-1");
        assert_eq!(root["lastUsedProvider"], "cline");
        assert_eq!(root["version"], 1);
        assert_eq!(root["modes"], serde_json::json!({}));
        assert_eq!(root["providers"]["cline"]["tokenSource"], "manual");
        assert!(
            root["providers"]["cline"]["updatedAt"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );

        // Simulate user edits: another provider, a model choice, and a
        // different lastUsedProvider — all must survive a re-run.
        let mut root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        root["providers"]["anthropic"] = serde_json::json!({"settings": {"provider": "anthropic"}});
        root["providers"]["cline"]["settings"]["model"] =
            serde_json::json!("x-ai/grok-code-fast-1");
        root["lastUsedProvider"] = serde_json::json!("anthropic");
        root["providers"]["cline"]["settings"]["auth"] =
            serde_json::json!({"accessToken": "stale", "refreshToken": "stale"});
        fs::write(&path, serde_json::to_string_pretty(&root).unwrap()).unwrap();

        write_cline_provider_settings(&home, "fake-2").unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root["providers"]["cline"]["settings"]["apiKey"], "fake-2");
        assert!(root["providers"]["cline"]["settings"].get("auth").is_none());
        assert_eq!(
            root["providers"]["cline"]["settings"]["model"], "x-ai/grok-code-fast-1",
            "user's model choice survives"
        );
        assert_eq!(
            root["providers"]["anthropic"]["settings"]["provider"],
            "anthropic"
        );
        assert_eq!(root["lastUsedProvider"], "anthropic", "user's choice kept");
        fs::remove_dir_all(home).unwrap();
    }
}

fn print_runtime_instructions(path: &Path) {
    println!(
        "The env file above already sets the proxy and CA variables ({}).",
        path.display()
    );
}
