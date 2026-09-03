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
    let url = format!("{}/bootstrap/ca.pem", broker.trim_end_matches('/'));
    let cert = reqwest::get(&url)
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
    fetch_guest_env(broker, &path, &container, &target).await?;
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

/// Broker host as the guest reaches it: the authority of --broker.
fn broker_host(broker: &str) -> String {
    let rest = broker
        .strip_prefix("http://")
        .or_else(|| broker.strip_prefix("https://"))
        .unwrap_or(broker);
    let authority = rest.split('/').next().unwrap_or(rest);
    authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
        .to_owned()
}

/// Pulls the fake credentials and proxy facts from the broker and
/// writes one complete, sourceable env file: proxy vars (with this
/// container's identity), CA bundles for common runtimes, and the fake
/// keys. Fakes only; reals never leave the host.
async fn fetch_guest_env(
    broker: &str,
    cert_path: &Path,
    container: &str,
    target: &TargetUser,
) -> Result<()> {
    let base = broker.trim_end_matches('/');
    let url = format!("{base}/bootstrap/env");
    let fakes = reqwest::get(&url)
        .await
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .context("broker rejected env request")?
        .text()
        .await?;
    let info: serde_json::Value = reqwest::get(format!("{base}/bootstrap/info"))
        .await
        .context("fetch broker info")?
        .json()
        .await
        .context("parse broker info")?;
    let proxy_port = info
        .get("proxy_port")
        .and_then(serde_json::Value::as_u64)
        .context("no proxy_port in broker info")?;
    let proxy_url = format!("http://{container}:x@{}:{proxy_port}", broker_host(base));
    let env = format!(
        "# Friendzone guest environment; source this in the agent's shell.\n\
         export HTTP_PROXY={proxy_url}\n\
         export HTTPS_PROXY={proxy_url}\n\
         export http_proxy={proxy_url}\n\
         export https_proxy={proxy_url}\n\
         export NODE_EXTRA_CA_CERTS={cert}\n\
         export REQUESTS_CA_BUNDLE={cert}\n\
         export SSL_CERT_FILE={cert}\n\
         export GIT_PROXY_SSL_CAINFO={cert}\n\
         {fakes}",
        cert = cert_path.display(),
    );
    let env_path = cert_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("friendzone-env.sh");
    fs::write(&env_path, &env).with_context(|| format!("write {}", env_path.display()))?;
    target.adopt(&env_path);
    // Announce this guest so a join request appears in the UI now.
    let approved = reqwest::get(format!(
        "{base}/bootstrap/hello?container={}",
        urlencoding_min(container)
    ))
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
                println!("Configured Cline inference (fake key) in {}", path.display());
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

/// Writes the Cline provider settings the CLI/IDE/SDK all read
/// (`~/.cline/data/settings/providers.json`; shape from cline/cline
/// sdk/packages/core/src/services/llms/provider-settings.ts and
/// .../storage/provider-settings-manager.ts): registers the `cline`
/// provider with the fake key so inference works through the broker
/// with no `cline auth`. Merge-safe: existing providers are kept, an
/// existing `cline` entry is only updated in its `apiKey`, and
/// `lastUsedProvider` is set only when absent.
fn write_cline_provider_settings(home: &Path, fake_key: &str) -> Result<PathBuf> {
    let settings_dir = home.join(".cline").join("data").join("settings");
    fs::create_dir_all(&settings_dir)
        .with_context(|| format!("create {}", settings_dir.display()))?;
    let path = settings_dir.join("providers.json");
    let mut root: serde_json::Value = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path)?)
            .with_context(|| format!("parse {}", path.display()))?
    } else {
        serde_json::json!({ "providers": {} })
    };
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
        }
        None => {
            providers.insert(
                "cline".into(),
                serde_json::json!({
                    "settings": { "provider": "cline", "apiKey": fake_key },
                    "updatedAt": chrono::Utc::now().to_rfc3339(),
                    "tokenSource": "friendzone",
                }),
            );
        }
    }
    let root_object = root.as_object_mut().expect("checked above");
    root_object
        .entry("lastUsedProvider")
        .or_insert_with(|| serde_json::json!("cline"));
    fs::write(&path, serde_json::to_string_pretty(&root)?)
        .with_context(|| format!("write {}", path.display()))?;
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
    fn broker_host_extraction() {
        assert_eq!(broker_host("http://172.31.208.1:8082"), "172.31.208.1");
        assert_eq!(broker_host("http://172.31.208.1:8082/"), "172.31.208.1");
        assert_eq!(broker_host("http://broker.local"), "broker.local");
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

        // Simulate user edits: another provider, a model choice, and a
        // different lastUsedProvider — all must survive a re-run.
        let mut root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        root["providers"]["anthropic"] = serde_json::json!({"settings": {"provider": "anthropic"}});
        root["providers"]["cline"]["settings"]["model"] = serde_json::json!("x-ai/grok-code-fast-1");
        root["lastUsedProvider"] = serde_json::json!("anthropic");
        fs::write(&path, serde_json::to_string_pretty(&root).unwrap()).unwrap();

        write_cline_provider_settings(&home, "fake-2").unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root["providers"]["cline"]["settings"]["apiKey"], "fake-2");
        assert_eq!(
            root["providers"]["cline"]["settings"]["model"],
            "x-ai/grok-code-fast-1",
            "user's model choice survives"
        );
        assert_eq!(root["providers"]["anthropic"]["settings"]["provider"], "anthropic");
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
