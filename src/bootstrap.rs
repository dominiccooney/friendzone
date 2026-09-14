//! Self-contained guest scripts; no guest Rust binary or compiler required.
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};

pub enum Shell {
    Sh,
    Powershell,
}
impl Shell {
    pub fn parse(value: &str) -> Result<Self> {
        match value
            .rsplit('/')
            .next()
            .unwrap_or(value)
            .to_ascii_lowercase()
            .as_str()
        {
            "sh" | "bash" | "zsh" => Ok(Self::Sh),
            "powershell" | "pwsh" => Ok(Self::Powershell),
            _ => bail!("Choose sh (Linux) or powershell (Windows)"),
        }
    }
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

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
        bail!("broker must be an HTTP(S) origin without credentials, path, query or fragment");
    }
    if url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_unspecified())
    {
        bail!("Enter a guest-reachable host, not a wildcard bind address");
    }
    Ok(url.as_str().trim_end_matches('/').into())
}
fn validate_container(container: &str) -> Result<()> {
    if container.len() > 128 || container.chars().any(|c| c.is_control() || c == ':') {
        bail!("guest name must be at most 128 bytes without controls or colon");
    }
    Ok(())
}

pub fn script(
    shell: Shell,
    broker: &str,
    container: &str,
    ca: &str,
    proxy_port: u16,
    settings: &crate::settings::Settings,
) -> Result<String> {
    let broker = broker_origin(broker)?;
    validate_container(container)?;
    let mut fakes = std::collections::BTreeMap::new();
    for entry in settings.entries() {
        if let Some(name) = entry.guest_env {
            if name.is_empty()
                || !name.bytes().enumerate().all(|(i, c)| {
                    c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                })
                || [
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "NO_PROXY",
                    "ALL_PROXY",
                    "FZ_HOST",
                    "FZ_BROKER",
                    "BASH_ENV",
                    "ENV",
                    "NODE_EXTRA_CA_CERTS",
                    "REQUESTS_CA_BUNDLE",
                    "SSL_CERT_FILE",
                    "GIT_SSL_CAINFO",
                    "GIT_PROXY_SSL_CAINFO",
                ]
                .iter()
                .any(|key| name.eq_ignore_ascii_case(key))
                || fakes
                    .keys()
                    .any(|key: &String| key.eq_ignore_ascii_case(&name))
            {
                bail!("invalid/conflicting guest environment variable {name}");
            }
            fakes.insert(name, entry.fake);
        }
    }
    let payload = serde_json::json!({"broker":broker,"container":container,"ca":ca,"proxy_port":proxy_port,"fakes":fakes,
        "plugin":STANDARD.encode(include_bytes!("plugin/friendzone.js")),
        "persistence":STANDARD.encode(include_bytes!("bootstrap/persist-environment.ps1"))});
    let encoded = STANDARD.encode(serde_json::to_vec(&payload)?);
    Ok(match shell {
        Shell::Sh => format!(
            "#!/bin/sh\n# Configure this Linux guest; Python 3 standard library only.\nset -eu\ncommand -v python3 >/dev/null 2>&1 || {{ echo 'Python 3 is required in the guest.' >&2; exit 1; }}\npython3 - {} <<'FRIENDZONE_PYTHON'\n{}\nif __name__ == '__main__':\n    import sys\n    main(sys.argv[1])\nFRIENDZONE_PYTHON\n",
            quote(&encoded),
            include_str!("bootstrap/configure.py").replace("\r\n", "\n")
        ),
        Shell::Powershell => format!(
            "\u{feff}# Configure this Windows guest; dot-sourcing only defines testable functions.\n$ErrorActionPreference='Stop'\n{}\n{}\nif ($MyInvocation.InvocationName -ne '.') {{\n    $data=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String({})) | ConvertFrom-Json\n    Start-FzGuestSetup $data\n}}\n",
            // Do not execute the persistence helper's command-line entry point.
            include_str!("bootstrap/persist-environment.ps1")
                .split("if ($MyInvocation.InvocationName -ne '.')")
                .next()
                .unwrap()
                .lines()
                .skip(1)
                .collect::<Vec<_>>()
                .join("\n"),
            include_str!("bootstrap/setup.ps1"),
            ps_quote(&encoded)
        ),
    })
}

pub fn commands(broker: &str, container: &str) -> Result<serde_json::Value> {
    let broker = broker_origin(broker)?;
    validate_container(container)?;
    let make = |shell| -> Result<String> {
        let mut url = reqwest::Url::parse(&format!("{broker}/bootstrap/setup"))?;
        url.query_pairs_mut()
            .append_pair("shell", shell)
            .append_pair("container", container);
        Ok(url.into())
    };
    let sh_url = make("sh")?;
    let ps_url = make("powershell")?;
    Ok(
        serde_json::json!({"broker":broker,"sh_url":sh_url,"powershell_url":ps_url,
        "sh":format!("curl --noproxy '*' -fsS {} -o friendzone-setup.sh",quote(&sh_url)),
        "powershell":format!("curl.exe --noproxy \"*\" -fsS {} -o friendzone-setup.ps1",ps_quote(&ps_url)),
        "sh_run":"sh ./friendzone-setup.sh","powershell_run":"& .\\friendzone-setup.ps1"}),
    )
}

/// Legacy binary download endpoint remains for doctor/older clients, not setup.
pub fn target_filename(target: &str) -> Result<String> {
    match target {
        "linux-x86_64" | "linux-aarch64" | "windows-x86_64" | "windows-aarch64" => {
            Ok(format!("fz-{target}"))
        }
        _ => bail!("unsupported binary target"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scripts_are_binary_free_and_payload_never_interpolates_guest_code() {
        let dir = std::env::temp_dir().join(format!("fz-bootstrap-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        for shell in [Shell::Sh, Shell::Powershell] {
            let powershell = matches!(shell, Shell::Powershell);
            let text = script(
                shell,
                "http://[::1]:9082",
                "guest'$(bad)",
                "CERTIFICATE",
                9080,
                &settings,
            )
            .unwrap();
            assert!(!text.contains("bootstrap/fz"));
            assert!(!text.contains("fz setup"));
            assert!(!text.contains("guest'$(bad)"));
            // Both installers carry exactly the shipped module, not a stale
            // wrapper or a separately maintained plugin implementation.
            let encoded = if powershell {
                text.split("$data=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('")
                    .nth(1)
                    .unwrap()
                    .split('\'')
                    .next()
                    .unwrap()
            } else {
                text.lines()
                    .find_map(|line| {
                        line.strip_prefix("python3 - '")
                            .and_then(|line| line.split('\'').next())
                    })
                    .unwrap()
            };
            let payload: serde_json::Value =
                serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
            let plugin = STANDARD
                .decode(payload["plugin"].as_str().unwrap())
                .unwrap();
            assert_eq!(plugin, include_bytes!("plugin/friendzone.js"));
            if !powershell && let Some(dir) = std::env::var_os("FZ_PLUGIN_TEST_ARTIFACT_DIR") {
                let dir = std::path::PathBuf::from(dir);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("linux-script.js"), plugin).unwrap();
            }
        }
        let cmds = commands("http://host:9082", "guest").unwrap();
        assert!(cmds["sh"].as_str().unwrap().starts_with("curl "));
        assert!(
            cmds["powershell"]
                .as_str()
                .unwrap()
                .starts_with("curl.exe ")
        );
        assert!(!cmds["sh"].as_str().unwrap().contains(";"));
        for raw in [
            "file:///tmp",
            "http://user:pass@host",
            "http://host/path",
            "http://0.0.0.0:8082",
        ] {
            assert!(broker_origin(raw).is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn powershell_script_configures_temp_guest_with_mock_user_environment() {
        let dir = std::env::temp_dir().join(format!("fz-cleanup-ps-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let script_path = dir.join("guest.ps1");
        std::fs::write(
            &script_path,
            script(
                Shell::Powershell,
                "http://192.0.2.1:9082",
                "guest'$(bad)",
                "CERTIFICATE",
                9080,
                &settings,
            )
            .unwrap(),
        )
        .unwrap();
        let command = dir.join("command.ps1");
        std::fs::write(
            &command,
            commands("http://host:9082", "guest").unwrap()["powershell"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut runtimes = vec![(
            "powershell51",
            std::path::PathBuf::from("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
        )];
        // Optional extra runtime, supplied explicitly by validation, never
        // installed/downloaded or discovered through an untrusted guest PATH.
        if let Some(path) = std::env::var_os("FZ_TEST_PWSH") {
            runtimes.push(("powershell7", path.into()));
        }
        for (runtime, executable) in runtimes {
            let home = dir.join(runtime);
            std::fs::create_dir_all(&home).unwrap();
            let inline = format!(
                "& ([scriptblock]::Create([IO.File]::ReadAllText({}))) -Implementation {} -TemporaryDirectory {} -BootstrapScript {} -BootstrapCommand {}",
                ps_quote(
                    &root
                        .join("tests/fixtures/test_user_environment.ps1")
                        .to_string_lossy()
                ),
                ps_quote(
                    &root
                        .join("src/bootstrap/persist-environment.ps1")
                        .to_string_lossy()
                ),
                ps_quote(&home.to_string_lossy()),
                ps_quote(&script_path.to_string_lossy()),
                ps_quote(&command.to_string_lossy())
            );
            let output = std::process::Command::new(executable)
                .args(["-NoProfile", "-NonInteractive", "-Command", &inline])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{runtime}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if let Some(artifacts) = std::env::var_os("FZ_PLUGIN_TEST_ARTIFACT_DIR") {
                let artifacts = std::path::PathBuf::from(artifacts);
                std::fs::create_dir_all(&artifacts).unwrap();
                // Use the bytes actually written by Invoke-FzConfigure, not source.
                std::fs::copy(
                    home.join("Guest space ' ü/.cline/plugins/friendzone.js"),
                    artifacts.join(format!("windows-{runtime}.js")),
                )
                .unwrap();
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
