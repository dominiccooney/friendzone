//! Public guest scripts contain only an explicit broker address and guest name.
//! Render-time input is quoted as data, never interpolated as executable code.
use crate::setup::{Shell, powershell_quote, shell_quote};
use anyhow::{Context, Result, bail};

pub fn broker_origin(raw: &str) -> Result<String> {
    let url = reqwest::Url::parse(raw).context("invalid broker URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || raw.chars().any(char::is_control)
    {
        bail!("broker must be an HTTP(S) origin with no credentials, path, query or fragment");
    }
    if url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_unspecified())
    {
        bail!("wildcard bind address is not a guest-reachable broker");
    }
    Ok(url.as_str().trim_end_matches('/').into())
}

pub fn script(shell: Shell, broker: &str, container: &str) -> Result<String> {
    let broker = broker_origin(broker)?;
    if container.len() > 128 || container.chars().any(|c| c.is_control() || c == ':') {
        bail!("guest name must be at most 128 bytes without control characters or colon");
    }
    Ok(match shell {
        Shell::Sh => format!(
            "#!/bin/sh\n# GUEST ONLY: persists proxy/CA environment and shell profile hooks.\nbroker={}\ncontainer={}\n{}",
            shell_quote(&broker),
            shell_quote(container),
            // A Windows-host checkout may use CRLF; guest sh must receive LF.
            include_str!("bootstrap/setup.sh").replace("\r\n", "\n")
        ),
        Shell::Powershell => format!(
            "\u{feff}# GUEST ONLY: persists proxy/CA user environment; never run on the broker host.\n$broker={}\n$container={}\n{}",
            powershell_quote(&broker),
            powershell_quote(container),
            include_str!("bootstrap/setup.ps1")
        ),
    })
}

pub fn commands(broker: &str, container: &str) -> Result<serde_json::Value> {
    let broker = broker_origin(broker)?;
    let make_url = |shell: &str| -> Result<String> {
        let mut url = reqwest::Url::parse(&format!("{broker}/bootstrap/setup"))?;
        url.query_pairs_mut()
            .append_pair("shell", shell)
            .append_pair("broker", &broker)
            .append_pair("container", container);
        Ok(url.into())
    };
    // Validate the same contract before displaying an executable command.
    script(Shell::Sh, &broker, container)?;
    let sh_url = make_url("sh")?;
    let ps_url = make_url("powershell")?;
    let sh = format!(
        "(set -eu; umask 077; f=$(mktemp); trap 'rm -f \"$f\"' EXIT HUP INT TERM; code=$(curl --noproxy '*' --silent --show-error --connect-timeout 5 --max-time 30 -o \"$f\" -w '%{{http_code}}' {}); [ \"$code\" = 200 ] || {{ cat \"$f\" >&2; exit 1; }}; sh \"$f\")",
        shell_quote(&sh_url)
    );
    let ps = format!(
        "& {{ $ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Net.Http; $h=New-Object Net.Http.HttpClientHandler; $h.UseProxy=$false; $h.AllowAutoRedirect=$false; $c=New-Object Net.Http.HttpClient($h); $c.Timeout=[TimeSpan]::FromSeconds(30); $p=Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N')+'.ps1'); try {{ $r=$c.GetAsync({}).GetAwaiter().GetResult(); if ([int]$r.StatusCode -ne 200) {{ throw $r.Content.ReadAsStringAsync().GetAwaiter().GetResult() }}; [IO.File]::WriteAllBytes($p,$r.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()); & $p }} finally {{ $c.Dispose(); $h.Dispose(); if (Test-Path -LiteralPath $p) {{ Remove-Item -LiteralPath $p }} }} }}",
        powershell_quote(&ps_url)
    );
    Ok(
        serde_json::json!({"broker":broker,"sh_url":sh_url,"powershell_url":ps_url,"sh":sh,"powershell":ps}),
    )
}

pub fn target_filename(target: &str) -> Result<String> {
    match target {
        "linux-x86_64" | "linux-aarch64" | "windows-x86_64" | "windows-aarch64" => {
            Ok(format!("fz-{target}"))
        }
        _ => {
            bail!("supported targets: linux-x86_64, linux-aarch64, windows-x86_64, windows-aarch64")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_parameters_are_data_and_unknown_shells_targets_fail() {
        assert!(Shell::parse("/bin/zsh").unwrap() == Shell::Sh);
        assert!(Shell::parse("cmd.exe").is_err());
        for broker in [
            "http://u:p@host:8082",
            "http://host/path",
            "http://0.0.0.0:8082",
            "file:///tmp/x",
            "http://host/?bad=1",
        ] {
            assert!(broker_origin(broker).is_err(), "{broker}");
        }
        assert!(target_filename("../../secrets.json").is_err());
        let name = "guest'$(touch nope);\"";
        let sh = script(Shell::Sh, "http://[::1]:9082", name).unwrap();
        assert!(sh.contains(&format!("container={}\n", shell_quote(name))));
        let ps = script(Shell::Powershell, "http://host:9082", name).unwrap();
        assert!(ps.contains(&format!("$container={}\n", powershell_quote(name))));
        let cmds = commands("http://host:9082", name).unwrap();
        let url = reqwest::Url::parse(cmds["sh_url"].as_str().unwrap()).unwrap();
        assert_eq!(
            url.query_pairs().find(|(k, _)| k == "container").unwrap().1,
            name
        );
        assert!(cmds["sh"].as_str().unwrap().contains("--noproxy '*'"));
    }

    #[tokio::test]
    async fn shell_script_failure_never_changes_profiles_or_executes_error_body() {
        // Git bash supplies POSIX tools on Windows. Fake uname only selects
        // the Linux branch; the fixture returns a 404, never a real binary.
        #[cfg(windows)]
        let bash = "C:/Program Files/Git/bin/bash.exe";
        #[cfg(not(windows))]
        let bash = "/bin/bash";
        let home = std::env::temp_dir().join(format!("fz-script-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        let marker = home.join(".profile");
        std::fs::write(&marker, "untouched\n").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let broker = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new().fallback(|| async {
                    (
                        axum::http::StatusCode::NOT_FOUND,
                        "missing exact guest build",
                    )
                }),
            )
            .await
            .unwrap();
        });
        let path = home.join("setup.sh");
        std::fs::write(&path, script(Shell::Sh, &broker, "guest").unwrap()).unwrap();
        let command = format!(
            "uname() {{ case \"$1\" in -s) printf Linux;; -m) printf x86_64;; esac; }}; export -f uname; bash --noprofile --norc {}",
            shell_quote(&path.to_string_lossy())
        );
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::process::Command::new(bash)
                .args(["--noprofile", "--norc", "-c", &command])
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", home.join("config"))
                .env("HTTP_PROXY", "http://127.0.0.1:1")
                .env("http_proxy", "http://127.0.0.1:1")
                .env_remove("SUDO_USER")
                .env_remove("BASH_ENV")
                .env_remove("ENV")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        server.abort();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("missing exact guest build"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "untouched\n");
        assert!(!home.join(".bashrc").exists());
        assert!(!home.join(".zshenv").exists());
        std::fs::remove_dir_all(home).unwrap();
    }
}
