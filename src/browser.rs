//! Open host URLs without interpreting any part of the URL as shell code.
use anyhow::{Context, Result};

#[cfg(windows)]
const OPEN_URL_SCRIPT: &str =
    "$ErrorActionPreference = 'Stop'; Start-Process -FilePath $env:FRIENDZONE_BROWSER_URL";

#[cfg(windows)]
fn windows_command(url: &str) -> std::process::Command {
    let mut command = std::process::Command::new("powershell.exe");
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        OPEN_URL_SCRIPT,
    ]);
    // Command::arg is not cmd.exe escaping. In particular, `cmd /C start`
    // splits OAuth queries at '&'. Pass the URL through the environment,
    // then use a fixed script that passes the value as one data argument.
    command.env("FRIENDZONE_BROWSER_URL", url);
    command
}

pub async fn open(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).context("invalid browser URL")?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        anyhow::bail!("browser URL must be HTTP(S)");
    }
    #[cfg(windows)]
    let command = windows_command(url);
    #[cfg(target_os = "macos")]
    let command = {
        let mut command = std::process::Command::new("open");
        command.arg(url);
        command
    };
    #[cfg(all(not(windows), not(target_os = "macos")))]
    let command = {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(url);
        command
    };
    let mut command = tokio::process::Command::from(command);
    command
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), command.status())
        .await
        .context("browser launcher timed out")?
        .context("start host browser")?;
    if !status.success() {
        anyhow::bail!("browser launcher failed; use the full authorization link in the UI");
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn windows_launcher_passes_oauth_url_as_one_literal_argument() {
        let url = "https://mcp.linear.app/authorize?response_type=code&client_id=test&redirect_uri=http%3A%2F%2F127.0.0.1%3A8081%2Foauth%2Fcallback&state=abc&scope=read%20write&test=$env:PATH%25!^'\"";
        let command = windows_command(url);
        assert_eq!(command.get_program(), "powershell.exe");
        assert_eq!(command.get_args().last().unwrap(), OPEN_URL_SCRIPT);
        assert!(!OPEN_URL_SCRIPT.contains(url));
        // Execute the exact launch script but shadow Start-Process to
        // inspect its argument. Never opens a real browser or OAuth login.
        let script = format!(
            "function Start-Process {{ param([string]$FilePath) [Console]::Write($FilePath) }}; {OPEN_URL_SCRIPT}"
        );
        let mut probe = std::process::Command::new(command.get_program());
        for (key, value) in command.get_envs() {
            if let Some(value) = value {
                probe.env(key, value);
            }
        }
        let output = probe
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "launcher probe failed");
        assert_eq!(String::from_utf8(output.stdout).unwrap(), url);
    }
}
