//! Instance-local destinations must not be interpreted from the broker's network.
//!
//! GCE endpoints and the short `metadata` alias:
//! https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshoot-metadata-server
//! Link-local ranges: RFC 3927 (IPv4), RFC 4291 section 2.5.6 (IPv6).
use std::{net::IpAddr, sync::OnceLock};

#[derive(serde::Deserialize)]
struct Infrastructure {
    hosts: Vec<String>,
    addresses: Vec<IpAddr>,
    ranges: Vec<String>,
}

fn infrastructure() -> &'static Infrastructure {
    // The compiled policy changes only on broker restart. Both setup platforms
    // receive this same snapshot; existing guest processes need reactivation.
    static POLICY: OnceLock<Infrastructure> = OnceLock::new();
    POLICY.get_or_init(|| {
        serde_json::from_str(include_str!("infrastructure.json"))
            .expect("valid compiled infrastructure policy")
    })
}

pub(crate) fn no_proxy() -> Vec<String> {
    let policy = infrastructure();
    let mut entries = policy.hosts.clone();
    for ip in &policy.addresses {
        entries.push(ip.to_string());
        if ip.is_ipv6() {
            entries.push(format!("[{ip}]"));
        }
    }
    entries.extend(policy.ranges.clone());
    entries
}

pub(crate) fn is_infrastructure_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let policy = infrastructure();
    if policy.hosts.contains(&host) {
        return true;
    }
    // IPv6 URI literals may include a scope identifier. It changes the local
    // interface, not whether the address is instance-local.
    let bare = host.trim_matches(['[', ']']);
    let bare = bare.split('%').next().unwrap_or(bare);
    let ip = bare.parse::<IpAddr>().ok().or_else(|| {
        // URL's numeric IPv4 parser handles decimal, hex, octal and short forms.
        reqwest::Url::parse(&format!("http://{host}/"))
            .ok()?
            .host_str()?
            .trim_matches(['[', ']'])
            .parse()
            .ok()
    });
    let Some(mut ip) = ip else { return false };
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4()
    {
        ip = IpAddr::V4(v4);
    }
    policy.addresses.contains(&ip) || policy.ranges.iter().any(|range| contains(range, ip))
}

fn contains(range: &str, ip: IpAddr) -> bool {
    let (network, prefix) = range.split_once('/').expect("compiled CIDR");
    let network: IpAddr = network.parse().expect("compiled network address");
    let prefix: u32 = prefix.parse().expect("compiled network prefix");
    match (network, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) => {
            let mask = u32::MAX << (32 - prefix);
            u32::from(network) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) => {
            let mask = u128::MAX << (128 - prefix);
            u128::from(network) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infrastructure_targets_aliases_and_range_boundaries() {
        for host in [
            "metadata",
            "METADATA.",
            "metadata.google.internal",
            "METADATA.GOOGLE.INTERNAL.",
            "169.254.169.254",
            "169.254.0.0",
            "169.254.255.255",
            "2852039166",
            "0xa9fea9fe",
            "0251.0376.0251.0376",
            "169.254.43518",
            "169.254.169.254.",
            "[::ffff:169.254.169.254]",
            "[::169.254.169.254]",
            "[fd20:ce::254]",
            "[fd20:ce:0:0:0:0:0:254]",
            "[fe80::]",
            "[febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]",
            "[fe80::1%25eth0]",
        ] {
            assert!(is_infrastructure_host(host), "{host}");
        }
        for host in [
            "metadata.google.internal.evil.test",
            "other.google.internal",
            "example.com",
            "169.253.255.255",
            "169.255.0.0",
            "10.0.0.1",
            "127.0.0.1",
            "[fd20:ce::253]",
            "[fd20:ce::255]",
            "[fe7f:ffff::1]",
            "[fec0::]",
            "[2001:db8::1]",
            "[::ffff:10.0.0.1]",
        ] {
            assert!(!is_infrastructure_host(host), "{host}");
        }
    }

    #[test]
    fn all_setup_defaults_are_denied_destinations() {
        for entry in no_proxy() {
            let host = entry.split('/').next().unwrap();
            assert!(is_infrastructure_host(host), "{entry}");
        }
    }
}
