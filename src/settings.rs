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
        secrets.insert(name.to_owned(), value.to_owned());
        write_json_private(&self.0.data_dir.join("secrets.json"), &*secrets)
    }

    pub fn secret(&self, name: &str) -> Option<String> {
        self.0.secrets.read().expect("settings lock").get(name).cloned()
    }

    pub fn remove_secret(&self, name: &str) -> Result<()> {
        let mut secrets = self.0.secrets.write().expect("settings lock");
        secrets.remove(name);
        write_json_private(&self.0.data_dir.join("secrets.json"), &*secrets)
    }

    /// Real value for an entry: secrets store first, then env fallback.
    pub fn real_value(&self, entry: &EscrowEntry) -> Option<String> {
        self.secret(&entry.name)
            .or_else(|| entry.real_env.as_ref().and_then(|var| std::env::var(var).ok()))
    }

    /// Shell lines the guest sources: fake keys under their guest names.
    pub fn guest_env_lines(&self) -> String {
        let mut out = String::from("# Friendzone fake credentials; real values stay on the host.\n");
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

impl Settings {
    /// The single substitution resolver. Looks for each entry's exact
    /// fake in its declared header; only an exact match substitutes,
    /// and only toward a pinned host.
    pub fn substitute(&self, host: &str, get_header: impl Fn(&str) -> Option<String>) -> Substitution {
        for entry in self.entries() {
            let Some(value) = get_header(&entry.header) else {
                continue;
            };
            let presented = value.strip_prefix(entry.prefix.as_str()).unwrap_or(&value);
            if presented != entry.fake {
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
            return Substitution::Replace {
                header: entry.header.clone(),
                value: format!("{}{real}", entry.prefix),
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
    Ok(Some(serde_json::from_str(&text).with_context(|| {
        format!("parse {}", path.display())
    })?))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(value)?)
        .with_context(|| format!("write {}", path.display()))
}

#[cfg(unix)]
fn write_json_private<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    write_json(path, value)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict {}", path.display()))
}

#[cfg(not(unix))]
fn write_json_private<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_json(path, value)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(updated.fake, fake_before, "guests keep their fake across edits");
        assert_eq!(updated.header, "x-api-key");
        // Editing routing fields must never touch the stored real key:
        // an edit with no key pasted keeps the credential working.
        assert_eq!(
            settings.secret("anthropic").as_deref(),
            Some("sk-ant-real"),
            "real key survives an edit"
        );
        assert!(settings.update_entry("missing", vec![], "h".into(), String::new(), None).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn remove_entry_takes_its_secret_with_it() {
        let (settings, dir) = temp_settings();
        assert!(settings.secret("anthropic").is_some());
        settings.remove_entry("anthropic").unwrap();
        assert!(settings.entries().is_empty());
        assert!(settings.secret("anthropic").is_none(), "secret must not orphan");
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
