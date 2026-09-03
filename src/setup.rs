use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};

pub async fn run(broker: &str, output: Option<PathBuf>, install: bool) -> Result<()> {
    let url = format!("{}/bootstrap/ca.pem", broker.trim_end_matches('/'));
    let cert = reqwest::get(&url)
        .await
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .context("broker rejected certificate request")?
        .bytes()
        .await?;
    let path = output.unwrap_or_else(default_cert_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, &cert).with_context(|| format!("write {}", path.display()))?;
    println!("Saved Friendzone CA to {}", path.display());
    fetch_guest_env(broker, &path).await?;
    if install {
        install_ca(&path)?;
    } else {
        println!("Install it in the guest trust store, or rerun with --install.");
    }
    print_runtime_instructions(&path);
    Ok(())
}

/// Pulls the fake credentials the broker escrows and saves them next to
/// the CA as a sourceable env file. Fakes only; reals never leave the
/// host.
async fn fetch_guest_env(broker: &str, cert_path: &Path) -> Result<()> {
    let url = format!("{}/bootstrap/env", broker.trim_end_matches('/'));
    let env = reqwest::get(&url)
        .await
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .context("broker rejected env request")?
        .text()
        .await?;
    let env_path = cert_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("friendzone-env.sh");
    fs::write(&env_path, &env).with_context(|| format!("write {}", env_path.display()))?;
    println!("Saved fake credentials to {}", env_path.display());
    println!("Source them in the agent's shell: . {}", env_path.display());
    if let Some(fake_key) = env_export_value(&env, "CLINE_API_KEY") {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        match write_cline_provider_settings(&home, &fake_key) {
            Ok(path) => println!("Configured Cline inference (fake key) in {}", path.display()),
            Err(error) => println!("Could not configure Cline settings: {error:#}"),
        }
    }
    Ok(())
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

fn default_cert_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("friendzone")
        .join("friendzone-ca.pem")
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
    println!("For Node:   export NODE_EXTRA_CA_CERTS={}", path.display());
    println!("For Python: export REQUESTS_CA_BUNDLE={}", path.display());
    println!("Set HTTPS_PROXY and HTTP_PROXY to the broker proxy URL.");
}
