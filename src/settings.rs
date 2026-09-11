//! Escrow settings: generic (hosts, header) -> (fake key, real key)
//! entries. Substitution replaces only an exact fake match; a fake seen
//! toward any non-pinned host is a leak and blocks the request.
//! Real values come from the secrets file (written by the UI or OAuth
//! flow) or a named env var; fakes are worthless and live in plain JSON.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowEntry {
    pub name: String,
    /// Hosts the real value may be sent to (exact match).
    pub hosts: Vec<String>,
    /// Header carrying the credential, e.g. "authorization", "x-api-key".
    pub header: String,
    /// Header value prefix, e.g. "Bearer " (empty for x-api-key).
    #[serde(default)]
    pub prefix: String,
    /// The fake value the container holds.
    pub fake: String,
    /// Optional env var fallback for the real value.
    #[serde(default)]
    pub real_env: Option<String>,
    /// Env var name the guest should export the fake under.
    #[serde(default)]
    pub guest_env: Option<String>,
}

struct Inner {
    data_dir: PathBuf,
    entries: RwLock<Vec<EscrowEntry>>,
    /// name -> real value. Written by the UI and the OAuth flow.
    secrets: RwLock<HashMap<String, String>>,
}

#[derive(Clone)]
pub struct Settings(Arc<Inner>);

pub fn generate_fake(name: &str) -> String {
    format!("fz-{name}-{}", Uuid::new_v4().simple())
}

impl Settings {
    pub fn load(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir)?;
        let entries = read_json(&data_dir.join("escrow.json"))?.unwrap_or_default();
        let secrets = read_json(&data_dir.join("secrets.json"))?.unwrap_or_default();
        Ok(Self(Arc::new(Inner {
            data_dir: data_dir.to_owned(),
            entries: RwLock::new(entries),
            secrets: RwLock::new(secrets),
        })))
    }

    pub fn entries(&self) -> Vec<EscrowEntry> {
        self.0.entries.read().expect("settings lock").clone()
    }

    pub fn data_dir(&self) -> &Path {
        &self.0.data_dir
    }

    pub fn add_entry(&self, mut entry: EscrowEntry) -> Result<EscrowEntry> {
        if entry.fake.is_empty() {
            entry.fake = generate_fake(&entry.name);
        }
        let mut entries = self.0.entries.write().expect("settings lock");
        if entries.iter().any(|e| e.name == entry.name) {
            anyhow::bail!("escrow entry '{}' already exists", entry.name);
        }
        entries.push(entry.clone());
        write_json(&self.0.data_dir.join("escrow.json"), &*entries)?;
        Ok(entry)
    }

    /// Edits an entry's routing fields. The fake is deliberately
    /// preserved: guests keep their env files working across an edit.
    pub fn update_entry(
        &self,
        name: &str,
        hosts: Vec<String>,
        header: String,
        prefix: String,
        guest_env: Option<String>,
    ) -> Result<EscrowEntry> {
        let mut entries = self.0.entries.write().expect("settings lock");
        let entry = entries
            .iter_mut()
            .find(|entry| entry.name == name)
            .with_context(|| format!("no escrow entry '{name}'"))?;
        entry.hosts = hosts;
        entry.header = header;
        entry.prefix = prefix;
        entry.guest_env = guest_env;
        let updated = entry.clone();
        write_json(&self.0.data_dir.join("escrow.json"), &*entries)?;
        Ok(updated)
    }

    /// Deletes an escrow entry and its stored real value together, so
    /// no orphaned secret outlives its entry.
    pub fn remove_entry(&self, name: &str) -> Result<()> {
        let mut entries = self.0.entries.write().expect("settings lock");
        entries.retain(|entry| entry.name != name);
        write_json(&self.0.data_dir.join("escrow.json"), &*entries)?;
        drop(entries);
        self.remove_secret(name)
    }

    pub fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        let mut secrets = self.0.secrets.write().expect("settings lock");
        let mut updated = secrets.clone();
        updated.insert(name.to_owned(), value.to_owned());
        write_json_private(&self.0.data_dir.join("secrets.json"), &updated)?;
        *secrets = updated;
        Ok(())
    }

    pub fn secret(&self, name: &str) -> Option<String> {
        self.0
            .secrets
            .read()
            .expect("settings lock")
            .get(name)
            .cloned()
    }

    pub fn remove_secret(&self, name: &str) -> Result<()> {
        let mut secrets = self.0.secrets.write().expect("settings lock");
        let mut updated = secrets.clone();
        updated.remove(name);
        write_json_private(&self.0.data_dir.join("secrets.json"), &updated)?;
        *secrets = updated;
        Ok(())
    }

    /// Real value for an entry: secrets store first, then env fallback.
    pub fn real_value(&self, entry: &EscrowEntry) -> Option<String> {
        let value = self.secret(&entry.name).or_else(|| {
            entry
                .real_env
                .as_ref()
                .and_then(|var| std::env::var(var).ok())
        })?;
        // Cline's auth adapter prefixes OAuth access tokens with workos:.
        // Static API keys remain unchanged. Handle existing stored sessions
        // too, without requiring a new login after upgrading the broker.
        Some(
            if crate::oauth::ClineSession::load(self, &entry.name).is_some()
                && !value.to_ascii_lowercase().starts_with("workos:")
            {
                format!("workos:{value}")
            } else {
                value
            },
        )
    }

    /// Shell lines the guest sources: fake keys under their guest names.
    pub fn guest_env_lines(&self) -> String {
        let mut out =
            String::from("# Friendzone fake credentials; real values stay on the host.\n");
        for entry in self.entries() {
            if let Some(var) = &entry.guest_env {
                out.push_str(&format!("export {var}={}\n", entry.fake));
            }
        }
        out
    }
}

/// Outcome of checking one request's headers against escrow.
pub enum Substitution {
    /// No fake value present: pass through unchanged.
    None,
    /// Exact fake found, host pinned, real value known: replace
    /// `header` with `value`.
    Replace { header: String, value: String },
    /// A fake appeared toward a non-pinned host, or the real value is
    /// missing: block and say why.
    Block(String),
}

/// HTTP Basic is an encoding of user:password, not a token prefix. Decode only
/// Authorization (never Proxy-Authorization); preserve the username's bytes.
/// RFC 7617 forbids control characters and splits on the first colon, so a
/// password may itself contain colons. Malformed credentials are not escrow.
fn basic_credentials(value: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = STANDARD.decode(encoded.trim_start_matches(' ')).ok()?;
    if decoded.iter().any(u8::is_ascii_control) {
        return None;
    }
    let colon = decoded.iter().position(|byte| *byte == b':')?;
    Some((decoded[..colon].to_vec(), decoded[colon + 1..].to_vec()))
}

impl Settings {
    /// The single substitution resolver. Looks for each entry's exact
    /// fake in its declared header or the password of HTTP Basic Authorization.
    /// Both transports share the host pin and current-secret resolver. Rotation
    /// takes effect on the next substitution; no real credential is cached here.
    pub fn substitute(
        &self,
        host: &str,
        get_header: impl Fn(&str) -> Option<String>,
    ) -> Substitution {
        for entry in self.entries() {
            let Some(value) = get_header(&entry.header) else {
                continue;
            };
            let presented = value.strip_prefix(entry.prefix.as_str()).unwrap_or(&value);
            let basic = entry
                .header
                .eq_ignore_ascii_case("authorization")
                .then(|| basic_credentials(&value))
                .flatten()
                .filter(|(_, password)| {
                    !entry.fake.is_empty() && password == entry.fake.as_bytes()
                });
            let literal_match = presented == entry.fake;
            // GitHub CLI sends `token <PAT>`, not Bearer. Match only an exact
            // fake in an Authorization entry configured for token escrow; keep
            // the same pin/secret checks and configured upstream prefix.
            let github_token = entry.header.eq_ignore_ascii_case("authorization")
                && entry.prefix == "Bearer "
                && entry.hosts.iter().any(|host| host == "api.github.com")
                && value.split_once(' ').is_some_and(|(scheme, token)| {
                    scheme.eq_ignore_ascii_case("token")
                        && !entry.fake.is_empty()
                        && token == entry.fake
                });
            if !literal_match && !github_token && basic.is_none() {
                continue;
            }
            if !entry.hosts.iter().any(|h| h == host) {
                return Substitution::Block(format!(
                    "friendzone: fake credential '{}' sent to non-pinned host {host}",
                    entry.name
                ));
            }
            let Some(real) = self.real_value(&entry) else {
                return Substitution::Block(format!(
                    "friendzone: no real value for '{}' (connect it in settings)",
                    entry.name
                ));
            };
            let replacement = if literal_match || github_token {
                // Preserve existing raw/prefixed (including whole-header) fakes.
                format!("{}{real}", entry.prefix)
            } else {
                if real.is_empty() || real.bytes().any(|byte| byte.is_ascii_control()) {
                    return Substitution::Block(format!(
                        "friendzone: real value for '{}' is invalid for Basic authentication",
                        entry.name
                    ));
                }
                let (mut username, _) = basic.expect("matched Basic password");
                username.push(b':');
                username.extend_from_slice(real.as_bytes());
                format!("Basic {}", STANDARD.encode(username))
            };
            return Substitution::Replace {
                header: entry.header.clone(),
                value: replacement,
            };
        }
        Substitution::None
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(Some(
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?,
    ))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(value)?)
        .with_context(|| format!("write {}", path.display()))
}

fn write_json_private<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    // Stage owner-only on Unix and rename atomically. Concurrent refreshes
    // cannot expose a partial secrets file or publish failed disk writes.
    crate::storage::atomic_write(path, &serde_json::to_vec_pretty(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_settings() -> (Settings, PathBuf) {
        let dir = std::env::temp_dir().join(format!("fz-basic-{}", Uuid::new_v4()));
        let settings = Settings::load(&dir).unwrap();
        settings
            .add_entry(EscrowEntry {
                name: "github".into(),
                hosts: vec!["github.com".into(), "api.github.com".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fake-github-token".into(),
                real_env: None,
                guest_env: Some("GITHUB_TOKEN".into()),
            })
            .unwrap();
        settings.set_secret("github", "real-token").unwrap();
        (settings, dir)
    }

    fn basic_substitution(settings: &Settings, host: &str, value: &str) -> Substitution {
        settings.substitute(host, |name| (name == "authorization").then(|| value.into()))
    }

    #[test]
    fn github_cli_token_scheme_uses_same_exact_fake_pin_and_rotation() {
        let (settings, dir) = basic_settings();
        for scheme in ["token", "Token", "TOKEN"] {
            let auth = format!("{scheme} fake-github-token");
            let Substitution::Replace { value, .. } =
                basic_substitution(&settings, "api.github.com", &auth)
            else {
                panic!("gh token substitution");
            };
            assert_eq!(value, "Bearer real-token");
            assert!(matches!(
                basic_substitution(&settings, "evil.example", &auth),
                Substitution::Block(_)
            ));
        }
        for auth in [
            "token fake-github-token-extra",
            "token wrong",
            "token  fake-github-token",
            "Digest fake-github-token",
        ] {
            assert!(matches!(
                basic_substitution(&settings, "api.github.com", auth),
                Substitution::None
            ));
        }
        settings.set_secret("github", "rotated").unwrap();
        let Substitution::Replace { value, .. } =
            basic_substitution(&settings, "api.github.com", "token fake-github-token")
        else {
            panic!("rotation");
        };
        assert_eq!(value, "Bearer rotated");
        settings.remove_secret("github").unwrap();
        assert!(matches!(
            basic_substitution(&settings, "api.github.com", "token fake-github-token"),
            Substitution::Block(_)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn basic_password_substitution_preserves_username_and_reads_rotated_secret() {
        let (settings, dir) = basic_settings();
        for username in ["x-access-token", "octocat", "", "naïve"] {
            for scheme in ["Basic ", "basic ", "bAsIc   "] {
                let auth = format!(
                    "{scheme}{}",
                    STANDARD.encode(format!("{username}:fake-github-token"))
                );
                let Substitution::Replace { header, value } =
                    basic_substitution(&settings, "github.com", &auth)
                else {
                    panic!("Basic substitution expected")
                };
                assert_eq!(header, "authorization");
                assert_eq!(
                    STANDARD
                        .decode(value.strip_prefix("Basic ").unwrap())
                        .unwrap(),
                    format!("{username}:real-token").as_bytes()
                );
            }
        }
        let auth = format!("Basic {}", STANDARD.encode(b"octocat:fake-github-token"));
        settings.set_secret("github", "rotated:token").unwrap();
        let Substitution::Replace { value, .. } =
            basic_substitution(&settings, "github.com", &auth)
        else {
            panic!("rotated Basic substitution")
        };
        assert_eq!(
            value,
            format!("Basic {}", STANDARD.encode(b"octocat:rotated:token"))
        );
        for presented in ["Bearer fake-github-token", "fake-github-token"] {
            let Substitution::Replace { value, .. } =
                basic_substitution(&settings, "api.github.com", presented)
            else {
                panic!("existing API auth")
            };
            assert_eq!(value, "Bearer rotated:token");
        }
        // Split only the first colon; never substring-match a password.
        let mut entry = settings.entries()[0].clone();
        entry.name = "colon".into();
        entry.fake = "fake:with:colons".into();
        settings.add_entry(entry).unwrap();
        settings.set_secret("colon", "replacement").unwrap();
        let auth = format!("Basic {}", STANDARD.encode(b"user:fake:with:colons"));
        let Substitution::Replace { value, .. } =
            basic_substitution(&settings, "github.com", &auth)
        else {
            panic!("colon password")
        };
        assert_eq!(
            value,
            format!("Basic {}", STANDARD.encode(b"user:replacement"))
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn basic_fake_keeps_host_pin_and_missing_or_invalid_secret_denials() {
        let (settings, dir) = basic_settings();
        let auth = format!("Basic {}", STANDARD.encode(b"octocat:fake-github-token"));
        for host in ["evil.example", "github.com.evil.example", "github.com."] {
            let Substitution::Block(reason) = basic_substitution(&settings, host, &auth) else {
                panic!("pin bypass")
            };
            assert!(reason.contains("non-pinned host"));
            assert!(!reason.contains("real-token"));
            assert!(!reason.contains(&auth));
        }
        settings.remove_secret("github").unwrap();
        assert!(matches!(
            basic_substitution(&settings, "github.com", &auth),
            Substitution::Block(_)
        ));
        for secret in ["", "private\r\nsecret", "private\0secret"] {
            settings.set_secret("github", secret).unwrap();
            let Substitution::Block(reason) = basic_substitution(&settings, "github.com", &auth)
            else {
                panic!("invalid secret")
            };
            assert!(!reason.contains("private"));
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn basic_nonmatches_and_malformed_values_do_not_inject_credentials() {
        let (settings, dir) = basic_settings();
        assert!(matches!(
            settings.substitute("github.com", |_| None),
            Substitution::None
        ));
        let mut values = vec![
            "Basic !!!".into(),
            "Basic".into(),
            "Basic ".into(),
            "Bearer unrelated".into(),
            "Digest fake-github-token".into(),
        ];
        for decoded in [
            b"user".as_slice(),
            b"user:wrong-token",
            b"fake-github-token:x",
            b"user:fake-github-token-extra",
            b"user:Bearer fake-github-token",
            b"user\n:fake-github-token",
            b"user:fake-github-token\0",
            b"user:\xff",
        ] {
            values.push(format!("Basic {}", STANDARD.encode(decoded)));
        }
        for value in values {
            assert!(matches!(
                basic_substitution(&settings, "github.com", &value),
                Substitution::None
            ));
        }
        // Don't reinterpret an x-api-key or proxy identity as HTTP origin auth.
        let mut entry = settings.entries()[0].clone();
        entry.name = "custom".into();
        entry.header = "x-api-key".into();
        entry.prefix = String::new();
        settings.add_entry(entry).unwrap();
        let auth = format!("Basic {}", STANDARD.encode(b"guest:fake-github-token"));
        assert!(matches!(
            settings.substitute("github.com", |name| (name == "x-api-key"
                || name == "proxy-authorization")
                .then(|| auth.clone())),
            Substitution::None
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_secret_write_keeps_last_good_memory_value() {
        let dir = std::env::temp_dir().join(format!("fz-secret-failure-{}", Uuid::new_v4()));
        let settings = Settings::load(&dir).unwrap();
        settings.set_secret("test", "last-good").unwrap();
        let path = dir.join("secrets.json");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap(); // Atomic replacement must fail, without publishing.
        assert!(settings.set_secret("test", "new").is_err());
        assert_eq!(settings.secret("test").as_deref(), Some("last-good"));
        assert!(settings.remove_secret("test").is_err());
        assert_eq!(settings.secret("test").as_deref(), Some("last-good"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cline_oauth_substitution_uses_workos_prefix_but_static_keys_do_not() {
        let (settings, dir) = temp_settings();
        let entry = settings.entries().pop().unwrap();
        settings.set_secret(&entry.name, "access").unwrap();
        assert_eq!(settings.real_value(&entry).as_deref(), Some("access"));
        settings.set_secret(&crate::oauth::ClineSession::secret_name(&entry.name), &serde_json::json!({"refresh_token":"refresh", "expires_at":4_000_000_000_i64, "api_base_url":"https://api.cline.bot"}).to_string()).unwrap();
        assert_eq!(
            settings.real_value(&entry).as_deref(),
            Some("workos:access")
        );
        settings.set_secret(&entry.name, "workos:access").unwrap();
        assert_eq!(
            settings.real_value(&entry).as_deref(),
            Some("workos:access")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    fn temp_settings() -> (Settings, PathBuf) {
        let dir = std::env::temp_dir().join(format!("fz-settings-{}", Uuid::new_v4()));
        let settings = Settings::load(&dir).unwrap();
        settings
            .add_entry(EscrowEntry {
                name: "anthropic".into(),
                hosts: vec!["api.anthropic.com".into()],
                header: "x-api-key".into(),
                prefix: String::new(),
                fake: "fz-fake-anthropic".into(),
                real_env: None,
                guest_env: Some("ANTHROPIC_API_KEY".into()),
            })
            .unwrap();
        settings.set_secret("anthropic", "sk-ant-real").unwrap();
        (settings, dir)
    }

    #[test]
    fn exact_fake_substitutes_on_pinned_host() {
        let (settings, dir) = temp_settings();
        let result = settings.substitute("api.anthropic.com", |h| {
            (h == "x-api-key").then(|| "fz-fake-anthropic".to_owned())
        });
        match result {
            Substitution::Replace { header, value } => {
                assert_eq!(header, "x-api-key");
                assert_eq!(value, "sk-ant-real");
            }
            _ => panic!("expected replace"),
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn non_matching_value_passes_through() {
        // A random string is NOT a fake: no substitution, no block.
        let (settings, dir) = temp_settings();
        let result = settings.substitute("api.anthropic.com", |h| {
            (h == "x-api-key").then(|| "some-other-key".to_owned())
        });
        assert!(matches!(result, Substitution::None));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fake_toward_wrong_host_blocks() {
        let (settings, dir) = temp_settings();
        let result = settings.substitute("evil.example.com", |h| {
            (h == "x-api-key").then(|| "fz-fake-anthropic".to_owned())
        });
        assert!(matches!(result, Substitution::Block(_)));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn update_entry_fixes_fields_but_keeps_the_fake() {
        let (settings, dir) = temp_settings();
        let fake_before = settings.entries()[0].fake.clone();
        // The accident this exists for: wrong header/prefix on Anthropic.
        let updated = settings
            .update_entry(
                "anthropic",
                vec!["api.anthropic.com".into()],
                "x-api-key".into(),
                String::new(),
                Some("ANTHROPIC_API_KEY".into()),
            )
            .unwrap();
        assert_eq!(
            updated.fake, fake_before,
            "guests keep their fake across edits"
        );
        assert_eq!(updated.header, "x-api-key");
        // Editing routing fields must never touch the stored real key:
        // an edit with no key pasted keeps the credential working.
        assert_eq!(
            settings.secret("anthropic").as_deref(),
            Some("sk-ant-real"),
            "real key survives an edit"
        );
        assert!(
            settings
                .update_entry("missing", vec![], "h".into(), String::new(), None)
                .is_err()
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn remove_entry_takes_its_secret_with_it() {
        let (settings, dir) = temp_settings();
        assert!(settings.secret("anthropic").is_some());
        settings.remove_entry("anthropic").unwrap();
        assert!(settings.entries().is_empty());
        assert!(
            settings.secret("anthropic").is_none(),
            "secret must not orphan"
        );
        // Removal persists across reload.
        let reloaded = Settings::load(&dir).unwrap();
        assert!(reloaded.entries().is_empty());
        assert!(reloaded.secret("anthropic").is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn settings_persist_and_guest_env_renders() {
        let (settings, dir) = temp_settings();
        let reloaded = Settings::load(&dir).unwrap();
        assert_eq!(reloaded.entries().len(), 1);
        assert_eq!(reloaded.secret("anthropic").as_deref(), Some("sk-ant-real"));
        let env = reloaded.guest_env_lines();
        assert!(env.contains("export ANTHROPIC_API_KEY=fz-fake-anthropic"));
        assert!(!env.contains("sk-ant-real"), "real value must never render");
        fs::remove_dir_all(dir).unwrap();
    }
}
