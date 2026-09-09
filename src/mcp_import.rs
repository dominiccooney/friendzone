//! Read-only Cline MCP adapter. Contract: cline/cline b18de090,
//! core/src/extensions/mcp/config-loader.ts (nested and legacy entries).
//! Cline owns OAuth refresh. We never execute commands or write its file.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClineSource {
    pub path: String,
    pub server: String,
}

#[derive(Serialize)]
pub struct Candidate {
    pub server: String,
    pub url: Option<String>,
    pub supported: bool,
    pub reason: String,
}

/// Cline b18de090 shared/src/storage/paths.ts: use the broker process's
/// environment/home, not the browser's OS or a guest path. Resolving a
/// suggestion does not read the file, and it need not exist yet.
pub fn default_settings_path() -> Option<PathBuf> {
    settings_path_from_env(|name| std::env::var(name).ok(), dirs::home_dir())
        .and_then(|path| std::path::absolute(path).ok())
}

fn settings_path_from_env(
    env: impl Fn(&str) -> Option<String>,
    os_home: Option<PathBuf>,
) -> Option<PathBuf> {
    let value = |name| {
        env(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    if let Some(path) = value("CLINE_MCP_SETTINGS_PATH") {
        return Some(path.into());
    }
    let data_dir = if let Some(dir) = value("CLINE_DATA_DIR") {
        PathBuf::from(dir)
    } else {
        let cline_dir = if let Some(dir) = value("CLINE_DIR") {
            PathBuf::from(dir)
        } else {
            let home = value("HOME")
                .filter(|v| v != "~")
                .or_else(|| value("USERPROFILE"))
                .or_else(|| {
                    value("HOMEDRIVE")
                        .zip(value("HOMEPATH"))
                        .map(|(drive, path)| format!("{drive}{path}"))
                })
                .map(PathBuf::from)
                .or(os_home)?;
            home.join(".cline")
        };
        cline_dir.join("data")
    };
    Some(data_dir.join("settings").join("cline_mcp_settings.json"))
}

fn read_servers(path: &str) -> Result<serde_json::Map<String, Value>> {
    if !Path::new(path).is_absolute() {
        bail!("Cline settings path must be absolute on the broker host (not a guest path)");
    }
    let text = std::fs::read_to_string(path).context("read host Cline MCP settings")?;
    let root: Value = serde_json::from_str(&text).context("parse Cline MCP settings")?;
    root.get("mcpServers")
        .and_then(Value::as_object)
        .cloned()
        .context("expected an mcpServers object")
}

fn transport(entry: &Value) -> Result<&Value> {
    if !entry.is_object() {
        bail!("server entry must be an object");
    }
    let transport = entry.get("transport").unwrap_or(entry);
    if !transport.is_object() {
        bail!("transport must be an object");
    }
    let kind = if entry.get("transport").is_some() {
        transport
            .get("type")
            .and_then(Value::as_str)
            .context("nested transport requires type")?
    } else {
        entry
            .get("type")
            .or_else(|| entry.get("transportType"))
            .and_then(Value::as_str)
            .unwrap_or(if entry.get("command").is_some() {
                "stdio"
            } else {
                "sse"
            })
    };
    if kind != "streamableHttp"
        && !(entry.get("type").is_none() && entry.get("transport").is_none() && kind == "http")
    {
        bail!("{kind} transport is not supported; no host commands are executed");
    }
    if entry
        .get("disabled")
        .is_some_and(|v| v != &Value::Bool(false))
    {
        bail!("server is disabled or has an invalid disabled flag in Cline");
    }
    Ok(transport)
}

fn endpoint(entry: &Value) -> Result<String> {
    let raw = transport(entry)?
        .get("url")
        .and_then(Value::as_str)
        .context("missing server URL")?;
    let url = reqwest::Url::parse(raw).context("invalid server URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("expected HTTP(S) URL without embedded credentials or fragment");
    }
    Ok(raw.to_owned())
}

pub fn preview(path: &str) -> Result<Vec<Candidate>> {
    let servers = read_servers(path)?;
    let mut candidates: Vec<_> = servers
        .into_iter()
        .map(|(server, entry)| match endpoint(&entry) {
            Ok(url) => Candidate {
                server,
                url: Some(url),
                supported: true,
                reason:
                    "Read-only Cline link; select tools and guests, then validate before applying"
                        .into(),
            },
            Err(error) => Candidate {
                server,
                url: None,
                supported: false,
                reason: error.to_string(),
            },
        })
        .collect();
    candidates.sort_by(|a, b| a.server.cmp(&b.server));
    Ok(candidates)
}

/// Read a complete current Cline snapshot per upstream request. Never
/// follow a moved endpoint with old credentials: re-import explicitly.
pub fn headers(source: &ClineSource, expected_url: &str) -> Result<BTreeMap<String, String>> {
    let servers = read_servers(&source.path)?;
    let entry = servers
        .get(&source.server)
        .context("linked Cline server was removed")?;
    if endpoint(entry)? != expected_url {
        bail!("linked Cline URL changed; review and re-import it");
    }
    let mut headers: BTreeMap<String, String> = match transport(entry)?.get("headers") {
        Some(value) => {
            serde_json::from_value(value.clone()).context("Cline headers must be a string map")?
        }
        None => BTreeMap::new(),
    };
    if entry
        .pointer("/oauth/authorizationRequired")
        .and_then(Value::as_bool)
        == Some(true)
    {
        bail!("linked server requires authorization; reconnect it in Cline on the host");
    }
    if let Some(token) = entry
        .pointer("/oauth/tokens/access_token")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    {
        headers.retain(|name, _| !name.eq_ignore_ascii_case("authorization"));
        headers.insert("Authorization".into(), format!("Bearer {token}"));
    }
    for (name, value) in &headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .context("invalid Cline header name")?;
        if matches!(
            name.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "proxy-authorization"
                | "mcp-session-id"
                | "mcp-protocol-version"
        ) {
            bail!(
                "Cline header {} cannot override broker transport state",
                name
            );
        }
        reqwest::header::HeaderValue::from_str(value).context("invalid Cline header value")?;
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_path_honors_cline_override_precedence() {
        let mut env = BTreeMap::from([
            ("CLINE_MCP_SETTINGS_PATH", " explicit.json "),
            ("CLINE_DATA_DIR", " data-override "),
            ("CLINE_DIR", " cline-override "),
            ("HOME", "host-home"),
        ]);
        let resolve = |env: &BTreeMap<&str, &str>| {
            settings_path_from_env(|name| env.get(name).map(|v| (*v).into()), None).unwrap()
        };
        assert_eq!(resolve(&env), PathBuf::from("explicit.json"));
        env.insert("CLINE_MCP_SETTINGS_PATH", " \t ");
        assert_eq!(
            resolve(&env),
            Path::new("data-override").join("settings/cline_mcp_settings.json")
        );
        env.remove("CLINE_DATA_DIR");
        assert_eq!(
            resolve(&env),
            Path::new("cline-override").join("data/settings/cline_mcp_settings.json")
        );
        env.remove("CLINE_DIR");
        assert_eq!(
            resolve(&env),
            Path::new("host-home").join(".cline/data/settings/cline_mcp_settings.json")
        );
    }

    #[test]
    fn default_path_uses_cline_home_fallbacks() {
        let resolve = |entries: &[(&str, &str)], fallback: Option<PathBuf>| {
            settings_path_from_env(
                |name| {
                    entries
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| (*value).into())
                },
                fallback,
            )
        };
        let suffix = ".cline/data/settings/cline_mcp_settings.json";
        assert_eq!(
            resolve(&[("HOME", "~"), ("USERPROFILE", " profile ")], None),
            Some(Path::new("profile").join(suffix))
        );
        assert_eq!(
            resolve(&[("HOMEDRIVE", "C:"), ("HOMEPATH", "\\Users\\guest")], None),
            Some(Path::new("C:\\Users\\guest").join(suffix))
        );
        assert_eq!(
            resolve(&[], Some("os-home".into())),
            Some(Path::new("os-home").join(suffix))
        );
        assert_eq!(resolve(&[], None), None);
    }

    #[test]
    fn cline_contract_handles_nested_legacy_and_unsupported_shapes() {
        let dir = std::env::temp_dir().join(format!("fz-import-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cline_mcp_settings.json");
        let root = json!({"mcpServers":{
            "nested":{"transport":{"type":"streamableHttp","url":"https://example.test/mcp","headers":{"x-api-key":"host-secret"}}},
            "legacy":{"transportType":"http","url":"https://example.test/mcp"},
            "stdio":{"command":"do-not-run","args":[],"env":{"KEY":"secret"}},
            "sse-default":{"url":"https://example.test/sse"},
            "disabled":{"transport":{"type":"streamableHttp","url":"https://example.test/mcp"},"disabled":true},
            "null":null,
            "array":[]
        }});
        std::fs::write(&path, serde_json::to_vec(&root).unwrap()).unwrap();
        let candidates = preview(path.to_str().unwrap()).unwrap();
        assert_eq!(candidates.iter().filter(|c| c.supported).count(), 2);
        assert!(
            !serde_json::to_string(&candidates)
                .unwrap()
                .contains("host-secret")
        );
        let source = ClineSource {
            path: path.to_str().unwrap().into(),
            server: "nested".into(),
        };
        assert_eq!(
            headers(&source, "https://example.test/mcp").unwrap()["x-api-key"],
            "host-secret"
        );
        assert!(headers(&source, "https://changed.test/mcp").is_err());
        assert!(preview("relative.json").is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(&path).unwrap()).unwrap(),
            root,
            "import never mutates Cline"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
