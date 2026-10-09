//! Self-contained guest scripts; no guest Rust binary or compiler required.
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};

pub(crate) const GITHUB_GIT_CONFIG: &str = r#"# Friendzone managed Git configuration v1
[credential "https://github.com"]
	helper =
	helper = "!fz_github_credential() { test \"$1\" = get || exit 0; protocol=; host=; while IFS= read -r line; do case \"$line\" in protocol=*) protocol=${line#protocol=} ;; host=*) host=${line#host=} ;; esac; done; test \"$protocol\" = https && test \"$host\" = github.com && test -n \"$GITHUB_TOKEN\" || exit 0; printf \"%s\\n\" \"username=x-access-token\" \"password=$GITHUB_TOKEN\"; }; fz_github_credential"
"#;
const EMPTY_GIT_CONFIG: &str = "# Friendzone managed Git configuration v1\n";

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
    let mut git_github_auth = false;
    // Cline credentials are OAuth-only. The guest fake is delivered only while
    // the broker holds a session, so a disconnected entry writes no facade.
    let mut cline_oauth = false;
    // Routing, fake environment and Git configuration travel as one snapshot.
    let entries = settings.entries();
    let origin = reqwest::Url::parse(&broker)?;
    let proxy_hosts = crate::routing::credential_hosts(&entries, origin.host_str().unwrap());
    let proxy = crate::routing::proxy_origin(&broker, proxy_port);
    for entry in entries {
        git_github_auth |= entry.guest_env.as_deref() == Some("GITHUB_TOKEN")
            && entry.header.eq_ignore_ascii_case("authorization")
            && entry
                .hosts
                .iter()
                .any(|host| crate::settings::host_matches(host, "github.com"));
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
                    "FZ_PROXY",
                    "FZ_PAC_URL",
                    "FZ_PROXY_HOSTS",
                    "BASH_ENV",
                    "ENV",
                    "NODE_EXTRA_CA_CERTS",
                    "REQUESTS_CA_BUNDLE",
                    "SSL_CERT_FILE",
                    "GIT_SSL_CAINFO",
                    "GIT_PROXY_SSL_CAINFO",
                    "CARGO_HTTP_CAINFO",
                    "CARGO_HTTP_CHECK_REVOKE",
                    "CARGO_HTTP_PROXY",
                    "GIT_CONFIG_COUNT",
                    "CLINE_PLUGIN_IDLE_TIMEOUT_MS",
                ]
                .iter()
                .any(|key| name.eq_ignore_ascii_case(key))
                || ["GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"]
                    .iter()
                    .any(|prefix| {
                        let suffix = name.get(prefix.len()..);
                        name.get(..prefix.len())
                            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
                            && suffix.is_some_and(|suffix| {
                                !suffix.is_empty()
                                    && suffix.bytes().all(|byte| byte.is_ascii_digit())
                            })
                    })
                || fakes
                    .keys()
                    .any(|key: &String| key.eq_ignore_ascii_case(&name))
            {
                bail!("invalid/conflicting guest environment variable {name}");
            }
            if name == "CLINE_API_KEY" {
                if crate::oauth::ClineSession::load(settings, &entry.name).is_none() {
                    continue;
                }
                cline_oauth = true;
            }
            fakes.insert(name, entry.fake);
        }
    }
    let git_config = format!("{}{}", if git_github_auth {GITHUB_GIT_CONFIG} else {EMPTY_GIT_CONFIG}, crate::routing::git_proxy_config(&proxy_hosts, &proxy));
    let payload = serde_json::json!({"broker":broker,"container":container,"ca":ca,"proxy_port":proxy_port,"fakes":fakes,"cline_oauth":cline_oauth,
        "git_credential_config":git_config,
        "proxy_hosts":proxy_hosts,
        "infrastructure_no_proxy":crate::infrastructure::no_proxy(),
        "plugin":STANDARD.encode(include_bytes!("plugin/friendzone.js")),
        "persistence":STANDARD.encode(powershell_persistence())});
    let encoded = STANDARD.encode(serde_json::to_vec(&payload)?);
    Ok(match shell {
        Shell::Sh => format!(
            "#!/bin/sh\n# Configure this Linux guest; Python 3 standard library only.\nset -eu\ncommand -v python3 >/dev/null 2>&1 || {{ echo 'Python 3 is required in the guest.' >&2; exit 1; }}\npython3 - {} <<'FRIENDZONE_PYTHON'\n{}\nif __name__ == '__main__':\n    import sys\n    main(sys.argv[1])\nFRIENDZONE_PYTHON\n",
            quote(&encoded),
            include_str!("bootstrap/configure.py").replace("\r\n", "\n")
        ),
        Shell::Powershell => crlf(&format!(
            "\u{feff}param([switch]$SkipPowerShellProfile)\n# Configure this Windows guest; dot-sourcing only defines testable functions.\n$ErrorActionPreference='Stop'\n{}\n{}\nif ($MyInvocation.InvocationName -ne '.') {{\n    $data=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String({})) | ConvertFrom-Json\n    Start-FzGuestSetup $data ([bool]$SkipPowerShellProfile)\n}}\n",
            // Do not execute the persistence helper's command-line entry point.
            powershell_persistence()
                .split("if ($MyInvocation.InvocationName -ne '.')")
                .next()
                .unwrap()
                .lines()
                .skip(1)
                .collect::<Vec<_>>()
                .join("\n"),
            include_str!("bootstrap/setup.ps1"),
            ps_quote(&encoded)
        )),
    })
}

/// PowerShell artifacts use CRLF even when source files were saved with LF.
fn crlf(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\n', "\r\n")
}

fn powershell_persistence() -> String {
    let source = include_str!("bootstrap/persist-environment.ps1");
    let (parameters, implementation) = source.split_once('\n').unwrap();
    crlf(&format!(
        "{}\n{}\n{}\n{}",
        parameters.trim_end_matches('\r'),
        include_str!("bootstrap/certificate.ps1"),
        include_str!("bootstrap/powershell-profile.ps1"),
        implementation
    ))
}

pub fn machine_certificate_script(ca: &str) -> String {
    crlf(&format!(
        "\u{feff}# Certificate-only machine provisioning; no user configuration.\n$ErrorActionPreference='Stop'\n{}\n{}\nif ($MyInvocation.InvocationName -ne '.') {{\n    $pem=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String({}))\n    Install-FzMachineCertificate $pem\n}}\n",
        include_str!("bootstrap/certificate.ps1"),
        include_str!("bootstrap/machine-certificate.ps1"),
        ps_quote(&STANDARD.encode(ca.as_bytes()))
    ))
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
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "github".into(),
                hosts: vec!["api.github.com".into(), "github.com".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fz-test-github-token".into(),
                real_env: None,
                guest_env: Some("GITHUB_TOKEN".into()),
            })
            .unwrap();
        // A Cline entry without a broker-owned session delivers no guest fake
        // at all: there is no static-key mode for it to fall back to.
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "cline".into(),
                hosts: vec!["api.cline.bot".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fz-disconnected-cline".into(),
                real_env: None,
                guest_env: Some("CLINE_API_KEY".into()),
            })
            .unwrap();
        settings.set_secret("cline", "stale-static-key").unwrap();
        let authority = crate::ca::AuthorityFiles::load_or_create(&dir.join("script-ca")).unwrap();
        for shell in [Shell::Sh, Shell::Powershell] {
            let powershell = matches!(shell, Shell::Powershell);
            let text = script(
                shell,
                "http://[::1]:9082",
                "guest'$(bad)",
                &authority.cert_pem,
                9080,
                &settings,
            )
            .unwrap();
            if powershell {
                assert!(text.contains("\r\n"));
                assert!(!text.replace("\r\n", "").contains(['\r', '\n']));
            }
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
            let persistence = STANDARD
                .decode(payload["persistence"].as_str().unwrap())
                .unwrap();
            let persistence = std::str::from_utf8(&persistence).unwrap();
            assert!(persistence.contains("\r\n"));
            assert!(!persistence.replace("\r\n", "").contains(['\r', '\n']));
            let plugin = STANDARD
                .decode(payload["plugin"].as_str().unwrap())
                .unwrap();
            assert_eq!(plugin, include_bytes!("plugin/friendzone.js"));
            assert_eq!(payload["ca"], authority.cert_pem);
            assert_eq!(payload["cline_oauth"], false);
            assert!(payload["fakes"].get("CLINE_API_KEY").is_none(), "{}", payload["fakes"]);
            assert!(!text.contains("fz-disconnected-cline"));
            assert!(!text.contains("stale-static-key"));
            assert!(payload["git_credential_config"].as_str().unwrap().starts_with(GITHUB_GIT_CONFIG));
            assert_eq!(payload["proxy_hosts"], serde_json::json!(["api.cline.bot", "api.github.com", "github.com"]));
            assert!(payload["git_credential_config"].as_str().unwrap().contains("[http \"https://github.com\"]"));
            if !powershell {
                assert!(text.contains("/usr/local/share/ca-certificates/friendzone-local-ca.crt"));
                assert!(text.contains("update-ca-certificates"));
                assert!(text.contains("install_linux_ca(config / \"friendzone-ca.pem\", config)"));
            }
            if !powershell && let Some(dir) = std::env::var_os("FZ_PLUGIN_TEST_ARTIFACT_DIR") {
                let dir = std::path::PathBuf::from(dir);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("linux-script.js"), plugin).unwrap();
            }
        }
        settings.remove_entry("github").unwrap();
        let text = script(
            Shell::Sh,
            "http://[::1]:9082",
            "guest",
            &authority.cert_pem,
            9080,
            &settings,
        )
        .unwrap();
        let encoded = text
            .lines()
            .find_map(|line| {
                line.strip_prefix("python3 - '")
                    .and_then(|line| line.split('\'').next())
            })
            .unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
        assert!(payload["git_credential_config"].as_str().unwrap().starts_with(EMPTY_GIT_CONFIG));
        assert_eq!(payload["proxy_hosts"], serde_json::json!(["api.cline.bot"]));
        assert_eq!(payload["infrastructure_no_proxy"], serde_json::json!(crate::infrastructure::no_proxy()));
        assert!(payload["fakes"].get("GITHUB_TOKEN").is_none());
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

    #[test]
    fn cargo_proxy_environment_is_reserved_for_compatibility_activation() {
        let dir = std::env::temp_dir().join(format!("fz-bootstrap-proxy-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        for name in ["CARGO_HTTP_PROXY", "cargo_http_proxy"] {
            settings
                .add_entry(crate::settings::EscrowEntry {
                    name: name.into(),
                    hosts: vec!["api.example.com".into()],
                    header: "authorization".into(),
                    prefix: "Bearer ".into(),
                    fake: "fake".into(),
                    real_env: None,
                    guest_env: Some(name.into()),
                })
                .unwrap();
            for shell in [Shell::Sh, Shell::Powershell] {
                assert!(
                    script(shell, "http://192.0.2.1:9082", "guest", "", 9080, &settings).is_err()
                );
            }
            settings.remove_entry(name).unwrap();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn broker_owned_cline_session_generates_only_public_oauth_facade_metadata() {
        let dir = std::env::temp_dir().join(format!("fz-bootstrap-oauth-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let entry = settings
            .add_entry(crate::settings::EscrowEntry {
                name: "cline".into(),
                hosts: vec!["api.cline.bot".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fz-public-placeholder".into(),
                real_env: None,
                guest_env: Some("CLINE_API_KEY".into()),
            })
            .unwrap();
        settings
            .set_secret(&entry.name, "host-access-secret")
            .unwrap();
        settings
            .set_secret(
                &crate::oauth::ClineSession::secret_name(&entry.name),
                &serde_json::json!({
                    "refresh_token":"host-refresh-secret",
                    "expires_at":4_000_000_000_i64,
                    "api_base_url":"https://api.cline.bot"
                })
                .to_string(),
            )
            .unwrap();
        let authority = crate::ca::AuthorityFiles::load_or_create(&dir.join("ca")).unwrap();
        let text = script(
            Shell::Sh,
            "http://192.0.2.1:9082",
            "guest",
            &authority.cert_pem,
            9080,
            &settings,
        )
        .unwrap();
        let encoded = text
            .lines()
            .find_map(|line| {
                line.strip_prefix("python3 - '")
                    .and_then(|line| line.split('\'').next())
            })
            .unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
        assert_eq!(payload["cline_oauth"], true);
        assert_eq!(payload["fakes"]["CLINE_API_KEY"], "fz-public-placeholder");
        let serialized = payload.to_string();
        assert!(!serialized.contains("host-access-secret"));
        assert!(!serialized.contains("host-refresh-secret"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn powershell_script_configures_temp_guest_with_mock_user_environment() {
        let dir = std::env::temp_dir().join(format!("fz-cleanup-ps-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "github".into(),
                hosts: vec!["api.github.com".into(), "github.com".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fz-test-github-token".into(),
                real_env: None,
                guest_env: Some("GITHUB_TOKEN".into()),
            })
            .unwrap();
        let cline = settings
            .add_entry(crate::settings::EscrowEntry {
                name: "cline".into(),
                hosts: vec!["api.cline.bot".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fake'$(not-a-command)".into(),
                real_env: None,
                guest_env: Some("CLINE_API_KEY".into()),
            })
            .unwrap();
        settings
            .set_secret(&cline.name, "host-access-secret")
            .unwrap();
        settings.set_secret(&crate::oauth::ClineSession::secret_name(&cline.name), &serde_json::json!({"refresh_token":"host-refresh-secret", "expires_at":4_000_000_000_i64, "api_base_url":"https://api.cline.bot"}).to_string()).unwrap();
        let authority = crate::ca::AuthorityFiles::load_or_create(&dir.join("test-ca")).unwrap();
        let rotated = crate::ca::AuthorityFiles::load_or_create(&dir.join("rotated-ca")).unwrap();
        let rotated_path = dir.join("rotated-ca.pem");
        std::fs::write(&rotated_path, &rotated.cert_pem).unwrap();
        let script_path = dir.join("guest.ps1");
        std::fs::write(
            &script_path,
            script(
                Shell::Powershell,
                "http://192.0.2.1:9082",
                "guest'$(bad)",
                &authority.cert_pem,
                9080,
                &settings,
            )
            .unwrap(),
        )
        .unwrap();
        let command = dir.join("command.ps1");
        let machine_script = dir.join("machine-ca.ps1");
        std::fs::write(
            &machine_script,
            machine_certificate_script(&authority.cert_pem),
        )
        .unwrap();
        let persistence = dir.join("persist-environment.ps1");
        std::fs::write(&persistence, powershell_persistence()).unwrap();
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
                "& ([scriptblock]::Create([IO.File]::ReadAllText({}))) -Implementation {} -TemporaryDirectory {} -BootstrapScript {} -BootstrapCommand {} -RotationCertificate {}",
                ps_quote(
                    &root
                        .join("tests/fixtures/test_user_environment.ps1")
                        .to_string_lossy()
                ),
                ps_quote(&persistence.to_string_lossy()),
                ps_quote(&home.to_string_lossy()),
                ps_quote(&script_path.to_string_lossy()),
                ps_quote(&command.to_string_lossy()),
                ps_quote(&rotated_path.to_string_lossy())
            );
            let output = std::process::Command::new(&executable)
                .args(["-NoProfile", "-NonInteractive", "-Command", &inline])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{runtime}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let inline = format!(
                "& ([scriptblock]::Create([IO.File]::ReadAllText({}))) -BootstrapScript {} -MachineCertificateScript {} -TemporaryDirectory {}",
                ps_quote(
                    &root
                        .join("tests/fixtures/test_windows_bootstrap.ps1")
                        .to_string_lossy()
                ),
                ps_quote(&script_path.to_string_lossy()),
                ps_quote(&machine_script.to_string_lossy()),
                ps_quote(&home.join("machine-and-profile").to_string_lossy()),
            );
            std::fs::create_dir_all(home.join("machine-and-profile")).unwrap();
            let output = std::process::Command::new(&executable)
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
