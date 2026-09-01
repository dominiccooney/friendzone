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
    if install {
        install_ca(&path)?;
    } else {
        println!("Install it in the guest trust store, or rerun with --install.");
    }
    print_runtime_instructions(&path);
    Ok(())
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

fn print_runtime_instructions(path: &Path) {
    println!("For Node:   export NODE_EXTRA_CA_CERTS={}", path.display());
    println!("For Python: export REQUESTS_CA_BUNDLE={}", path.display());
    println!("Set HTTPS_PROXY and HTTP_PROXY to the broker proxy URL.");
}
