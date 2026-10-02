//! Client routing is a snapshot of escrow destinations, not secret availability.
use crate::settings::EscrowEntry;

pub(crate) fn normalize_host(host: &str) -> Option<String> {
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/\\@?#\"'".contains(c))
    {
        return None;
    }
    let url = reqwest::Url::parse(&format!("http://{host}/")).ok()?;
    if url.port().is_some()
        || url.path() != "/"
        || (!host.starts_with('[') && host.contains(':'))
        || (host.starts_with('[') && !host.ends_with(']'))
    {
        return None;
    }
    Some(url.host_str()?.trim_end_matches('.').to_owned())
}

pub(crate) fn loopback_host(host: &str) -> bool {
    let Some(host) = normalize_host(host) else {
        return false;
    };
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.to_ipv4().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

pub(crate) fn credential_hosts(entries: &[EscrowEntry], broker_host: &str) -> Vec<String> {
    let broker_host = normalize_host(broker_host);
    let mut hosts: Vec<_> = entries
        .iter()
        .flat_map(|entry| &entry.hosts)
        .filter_map(|host| normalize_host(host))
        .filter(|host| {
            !loopback_host(host)
                && !crate::infrastructure::is_infrastructure_host(host)
                && Some(host) != broker_host.as_ref()
        })
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

pub(crate) fn proxy_origin(broker: &str, port: u16) -> String {
    let mut url = reqwest::Url::parse(broker).expect("validated broker origin");
    url.set_scheme("http").expect("HTTP proxy scheme");
    url.set_port(Some(port)).expect("HTTP proxy port");
    url.as_str().trim_end_matches('/').to_owned()
}

pub(crate) fn pac(entries: &[EscrowEntry], broker: &str, port: u16) -> String {
    let origin = reqwest::Url::parse(broker).expect("validated broker origin");
    let hosts = credential_hosts(entries, origin.host_str().unwrap());
    let proxy = proxy_origin(broker, port);
    let authority = proxy.strip_prefix("http://").unwrap();
    // No DNS lookups or HTTPS paths are required. A single PROXY result never
    // requests direct fallback if escrow is disconnected or the broker is down.
    format!(
        "// Friendzone selective routing; refreshed when the client fetches this PAC.\nfunction FindProxyForURL(url, host) {{\n  if (!/^https?:/i.test(url)) return 'DIRECT';\n  host = host.toLowerCase().replace(/\\.$/, '');\n  var hosts = {};\n  for (var i = 0; i < hosts.length; i++) {{\n    if (host === hosts[i]) return {};\n  }}\n  return 'DIRECT';\n}}\n",
        serde_json::to_string(&hosts).unwrap(),
        serde_json::to_string(&format!("PROXY {authority}")).unwrap()
    )
}

pub(crate) fn git_proxy_config(hosts: &[String], proxy: &str) -> String {
    hosts
        .iter()
        .map(|host| {
            format!(
                "[http \"https://{host}\"]\n\tproxy = {}\n",
                serde_json::to_string(proxy).unwrap()
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_normalization_does_not_accept_origins_ports_or_code() {
        assert_eq!(
            normalize_host("API.Example.COM."),
            Some("api.example.com".into())
        );
        for host in [
            "",
            "https://api.example.com",
            "api.example.com:80",
            "api.example.com:8443",
            "[::1]:80",
            "user@api.example.com",
            "api.example.com/path",
            "bad\n.example",
            "x\";throw 1",
        ] {
            assert_eq!(normalize_host(host), None, "{host}");
        }
    }

    #[test]
    fn pac_and_substitution_share_canonical_host_pins() {
        let dir = std::env::temp_dir().join(format!("fz-routing-{}", uuid::Uuid::new_v4()));
        let settings = crate::settings::Settings::load(&dir).unwrap();
        settings
            .add_entry(EscrowEntry {
                name: "test".into(),
                hosts: vec!["API.Example.COM.".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fake".into(),
                real_env: None,
                guest_env: None,
            })
            .unwrap();
        assert_eq!(
            credential_hosts(&settings.entries(), "broker.test"),
            vec!["api.example.com"]
        );
        assert!(matches!(
            settings.substitute("api.example.com", "/", |_| Some("Bearer fake".into())),
            crate::settings::Substitution::Block(_)
        ));
        settings.set_secret("test", "real").unwrap();
        assert!(
            matches!(settings.substitute("api.example.com", "/", |_| Some("Bearer fake".into())), crate::settings::Substitution::Replace { value, .. } if value == "Bearer real")
        );
        let git_config = dir.join("routing.gitconfig");
        std::fs::write(
            &git_config,
            git_proxy_config(
                &credential_hosts(&settings.entries(), "broker.test"),
                "http://broker.test:8080",
            ),
        )
        .unwrap();
        let output = std::process::Command::new("git")
            .args(["config", "--file"])
            .arg(&git_config)
            .args([
                "--get-urlmatch",
                "http.proxy",
                "https://api.example.com/path",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            "http://broker.test:8080"
        );
        let output = std::process::Command::new("git")
            .args(["config", "--file"])
            .arg(&git_config)
            .args([
                "--get-urlmatch",
                "http.proxy",
                "https://other.example.com/path",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
