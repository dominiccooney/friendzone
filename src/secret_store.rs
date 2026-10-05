//! Persist secret snapshots without changing the broker's synchronous readers.
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) type Values = HashMap<String, String>;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum Mode {
    Os,
    File,
}

pub(crate) trait Persistence: Send + Sync {
    fn load(&mut self) -> Result<Option<Values>>;
    fn save(&mut self, values: &Values) -> Result<()>;
}

#[cfg(not(test))]
struct LockedStore {
    inner: Box<dyn Persistence>,
    _lock: fs::File,
}
#[cfg(not(test))]
impl Persistence for LockedStore {
    fn load(&mut self) -> Result<Option<Values>> {
        self.inner.load()
    }
    fn save(&mut self, values: &Values) -> Result<()> {
        self.inner.save(values)
    }
}

fn lock_directory(data_dir: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(data_dir.join("secret-store.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("another broker owns this data directory's secret store; stop it before starting a replacement")?;
    Ok(lock)
}

struct FileStore(PathBuf);
impl Persistence for FileStore {
    fn load(&mut self) -> Result<Option<Values>> {
        read_legacy(&self.0)
    }
    fn save(&mut self, values: &Values) -> Result<()> {
        crate::storage::atomic_write(&self.0, &serde_json::to_vec(values)?)
    }
}

pub(crate) fn open(data_dir: &Path, mode: Mode) -> Result<(Box<dyn Persistence>, Values)> {
    #[cfg(not(test))]
    let lock = lock_directory(data_dir)?;
    let legacy = data_dir.join("secrets.json");
    let marker = data_dir.join("os-secret-store.json");
    if matches!(mode, Mode::File) && marker.exists() {
        bail!(
            "this data directory uses OS credentials; file mode cannot reopen it. Use a separate data directory for explicit plaintext storage"
        );
    }
    let store: Box<dyn Persistence> = match mode {
        Mode::File => {
            tracing::warn!(
                "plaintext secret storage explicitly enabled; protect the data directory and backups"
            );
            Box::new(FileStore(legacy.clone()))
        }
        Mode::Os => Box::new(Vault::new(platform_entries(data_dir)?)),
    };
    #[cfg(not(test))]
    let mut store: Box<dyn Persistence> = Box::new(LockedStore {
        inner: store,
        _lock: lock,
    });
    #[cfg(test)]
    let mut store = store;
    let values = match mode {
        Mode::File => store.load()?.unwrap_or_default(),
        Mode::Os => migrate(store.as_mut(), &legacy, &marker)?,
    };
    Ok((store, values))
}

fn read_legacy(path: &Path) -> Result<Option<Values>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            anyhow::anyhow!("invalid legacy secrets.json; repair it before migration")
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("read legacy secrets.json"),
    }
}

fn migrate(store: &mut dyn Persistence, legacy: &Path, marker: &Path) -> Result<Values> {
    // Read and validate both sources before writing. An interrupted migration
    // can resume only if the complete OS snapshot agrees with the legacy file.
    let saved = store.load()?;
    if marker.exists() {
        let bytes = fs::read(marker)?;
        if bytes != b"{\"version\":1}\n" {
            bail!("invalid OS credential-store marker");
        }
        if saved.is_none() {
            bail!(
                "OS credentials are missing for this initialized data directory; restore the credential store or reconfigure a new profile. No empty or plaintext fallback was used"
            );
        }
    }
    let old = read_legacy(legacy)?;
    let Some(old) = old else {
        let values = match saved {
            Some(values) => values,
            None => {
                let values = Values::new();
                store.save(&values)?;
                values
            }
        };
        if !marker.exists() {
            crate::storage::atomic_write(marker, b"{\"version\":1}\n")?;
        }
        return Ok(values);
    };
    if let Some(saved) = &saved {
        if saved != &old {
            bail!(
                "OS credentials conflict with secrets.json; neither source was overwritten. Resolve the duplicate stores before restarting"
            );
        }
    } else {
        store
            .save(&old)
            .context("migrate credentials to OS store; secrets.json retained")?;
    }
    if store.load()?.as_ref() != Some(&old) {
        bail!("OS credential migration verification failed; secrets.json retained");
    }
    if !marker.exists() {
        crate::storage::atomic_write(marker, b"{\"version\":1}\n")?;
    }
    fs::remove_file(legacy).context(
        "credentials copied to OS store, but secrets.json could not be removed; startup stopped",
    )?;
    Ok(old)
}

/// Byte-entry adapter; implementations never format or log credential payloads.
trait Entries: Send + Sync {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn write(&self, key: &str, bytes: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

struct NativeEntries {
    store: Arc<keyring_core::CredentialStore>,
    service: String,
}
impl NativeEntries {
    fn new(data_dir: &Path) -> Result<Self> {
        let path = fs::canonicalize(data_dir).context("canonicalize credential namespace")?;
        // Directories travel independently: moving one requires an explicit
        // credential migration, not accidental sharing between broker profiles.
        let namespace = format!("{:x}", Sha256::digest(path.as_os_str().as_encoded_bytes()));
        #[cfg(target_os = "windows")]
        let store = windows_native_keyring_store::Store::new().map_err(safe_error)?;
        #[cfg(target_os = "macos")]
        let store = apple_native_keyring_store::keychain::Store::new().map_err(safe_error)?;
        #[cfg(target_os = "linux")]
        let store = zbus_secret_service_keyring_store::Store::new()
            .map_err(|_| anyhow::anyhow!("Linux Secret Service is unavailable; start and unlock the login keyring. Headless hosts must explicitly select --secret-store=file until a cloud backend is configured"))?;
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        let store: Arc<keyring_core::CredentialStore> =
            { bail!("OS credential storage is unsupported on this platform") };
        Ok(Self {
            store,
            service: format!("friendzone-{namespace}"),
        })
    }
    fn entry(&self, key: &str) -> Result<keyring_core::Entry> {
        #[cfg(target_os = "windows")]
        let modifiers = Some(HashMap::from([("persistence", "Local")]));
        #[cfg(not(target_os = "windows"))]
        let modifiers: Option<HashMap<&str, &str>> = None;
        self.store
            .build(&self.service, key, modifiers.as_ref())
            .map_err(safe_error)
    }
}

fn safe_error(error: keyring_core::Error) -> anyhow::Error {
    // Several provider errors carry raw bytes or arbitrary strings. Report
    // categories, not their Debug/Display text, to keep secrets out of logs/UI.
    let reason = match error {
        keyring_core::Error::NoStorageAccess(_) => "store is locked or access was denied",
        keyring_core::Error::NoEntry => "credential is missing",
        keyring_core::Error::TooLong(_, _) => "credential exceeds the OS limit",
        keyring_core::Error::Ambiguous(_) => "duplicate matching credentials",
        keyring_core::Error::BadEncoding(_) | keyring_core::Error::BadDataFormat(_, _) => {
            "invalid credential encoding"
        }
        _ => "credential provider failed",
    };
    anyhow::anyhow!("OS secret store: {reason}; no plaintext fallback was used")
}
impl Entries for NativeEntries {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.entry(key)?.get_secret() {
            Ok(value) => Ok(Some(value)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(safe_error(error)),
        }
    }
    fn write(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.entry(key)?.set_secret(bytes).map_err(safe_error)
    }
    fn delete(&self, key: &str) -> Result<()> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(safe_error(error)),
        }
    }
}

#[cfg(not(test))]
fn platform_entries(data_dir: &Path) -> Result<Box<dyn Entries>> {
    Ok(Box::new(NativeEntries::new(data_dir)?))
}

// Unit tests never connect to the developer's real OS store. Binary integration
// tests select file mode explicitly; native acceptance tests are opt-in.
#[cfg(test)]
fn platform_entries(data_dir: &Path) -> Result<Box<dyn Entries>> {
    tests::memory_entries(data_dir)
}

// Windows allows 2,560 bytes per blob. Base64 chunks also work with KDE
// providers that require UTF-8 secrets. The snapshot has a bounded total size.
const CHUNK_BYTES: usize = 2_000;
const MAX_CHUNKS: usize = 4_096;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    id: Uuid,
    chunks: usize,
    digest: String,
}
impl Generation {
    fn key(&self, index: usize) -> String {
        format!("{}-{index}", self.id)
    }
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    current: Option<Generation>,
    pending: Option<Generation>,
    retired: Option<Generation>,
}

struct Vault {
    entries: Box<dyn Entries>,
}
impl Vault {
    fn new(entries: Box<dyn Entries>) -> Self {
        Self { entries }
    }
    fn manifest(&self) -> Result<Manifest> {
        let Some(bytes) = self.entries.read("manifest")? else {
            return Ok(Manifest {
                version: 1,
                ..Manifest::default()
            });
        };
        let manifest: Manifest = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid OS secret manifest"))?;
        if manifest.version != 1 {
            bail!("unsupported OS secret manifest version");
        }
        for generation in [&manifest.current, &manifest.pending, &manifest.retired]
            .into_iter()
            .flatten()
        {
            if generation.chunks == 0
                || generation.chunks > MAX_CHUNKS
                || generation.digest.len() != 64
                || !generation
                    .digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                bail!("invalid OS secret generation");
            }
        }
        let mut ids = std::collections::HashSet::new();
        for generation in [&manifest.current, &manifest.pending, &manifest.retired]
            .into_iter()
            .flatten()
        {
            if !ids.insert(generation.id) {
                bail!("OS secret manifest aliases active and discarded generations");
            }
        }
        Ok(manifest)
    }
    fn publish(&self, manifest: &Manifest) -> Result<()> {
        self.entries
            .write("manifest", &serde_json::to_vec(manifest)?)
    }
    fn bytes(&self, generation: &Generation) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        for index in 0..generation.chunks {
            let chunk = self
                .entries
                .read(&generation.key(index))?
                .context("OS secret snapshot is incomplete")?;
            if chunk.len() > CHUNK_BYTES {
                bail!("invalid OS secret chunk size");
            }
            encoded.extend(chunk);
        }
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("invalid OS secret snapshot encoding"))?;
        if format!("{:x}", Sha256::digest(&bytes)) != generation.digest {
            bail!("OS secret snapshot digest mismatch");
        }
        Ok(bytes)
    }
    fn cleanup(&self, manifest: &mut Manifest) -> Result<()> {
        for generation in [&manifest.pending, &manifest.retired].into_iter().flatten() {
            for index in 0..generation.chunks {
                self.entries.delete(&generation.key(index))?;
            }
        }
        if manifest.pending.is_some() || manifest.retired.is_some() {
            manifest.pending = None;
            manifest.retired = None;
            self.publish(manifest)?;
        }
        Ok(())
    }
}
impl Persistence for Vault {
    fn load(&mut self) -> Result<Option<Values>> {
        let mut manifest = self.manifest()?;
        let values = manifest
            .current
            .as_ref()
            .map(|generation| {
                serde_json::from_slice(&self.bytes(generation)?)
                    .map_err(|_| anyhow::anyhow!("invalid OS credential snapshot"))
            })
            .transpose()?;
        self.cleanup(&mut manifest)?;
        Ok(values)
    }
    fn save(&mut self, values: &Values) -> Result<()> {
        let mut manifest = self.manifest()?;
        self.cleanup(&mut manifest)?;
        let bytes = serde_json::to_vec(values)?;
        let encoded = STANDARD.encode(&bytes);
        let chunks = encoded.len().div_ceil(CHUNK_BYTES);
        if chunks > MAX_CHUNKS {
            bail!("credential snapshot exceeds OS store safety limit");
        }
        let generation = Generation {
            id: Uuid::new_v4(),
            chunks,
            digest: format!("{:x}", Sha256::digest(&bytes)),
        };
        // Journal the whole allocation before writing chunks. Startup can
        // delete staging after error, cancellation, or process termination.
        manifest.pending = Some(generation.clone());
        self.publish(&manifest)?;
        for (index, chunk) in encoded.as_bytes().chunks(CHUNK_BYTES).enumerate() {
            self.entries.write(&generation.key(index), chunk)?;
        }
        if self.bytes(&generation)? != bytes {
            bail!("OS credential write verification failed");
        }
        // This single entry replacement is the persistence consistency boundary.
        // Settings publishes its cache only after this succeeds; OS calls are
        // serialized by that same write lock and never straddle an await.
        manifest.retired = manifest.current.replace(generation);
        manifest.pending = None;
        self.publish(&manifest)?;
        if self.cleanup(&mut manifest).is_err() {
            tracing::warn!(
                "OS credential snapshot committed; obsolete entries will be cleaned on the next save or restart"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    #[derive(Default)]
    struct State {
        data: HashMap<String, Vec<u8>>,
        writes: usize,
        fail_write: Option<usize>,
        fail_delete: bool,
        fail_read: bool,
    }
    #[derive(Clone, Default)]
    struct Memory(Arc<Mutex<State>>);
    impl Entries for Memory {
        fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
            let state = self.0.lock().unwrap();
            if state.fail_read {
                bail!("simulated locked store");
            }
            Ok(state.data.get(key).cloned())
        }
        fn write(&self, key: &str, bytes: &[u8]) -> Result<()> {
            assert!(
                bytes.len() <= 2_560,
                "Windows credential blob limit exceeded"
            );
            let mut state = self.0.lock().unwrap();
            state.writes += 1;
            if state.fail_write == Some(state.writes) {
                bail!("simulated write failure");
            }
            state.data.insert(key.into(), bytes.into());
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<()> {
            let mut state = self.0.lock().unwrap();
            if state.fail_delete {
                bail!("simulated delete failure");
            }
            state.data.remove(key);
            Ok(())
        }
    }

    fn memory(data_dir: &Path) -> Result<Memory> {
        static STORES: OnceLock<Mutex<HashMap<PathBuf, Memory>>> = OnceLock::new();
        let path = fs::canonicalize(data_dir)?;
        Ok(STORES
            .get_or_init(Mutex::default)
            .lock()
            .unwrap()
            .entry(path)
            .or_default()
            .clone())
    }
    pub(super) fn memory_entries(data_dir: &Path) -> Result<Box<dyn Entries>> {
        Ok(Box::new(memory(data_dir)?))
    }

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("fz-vault-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn values(token: &str) -> Values {
        HashMap::from([("credential".into(), token.into())])
    }

    #[test]
    fn complete_large_unicode_oauth_snapshots_survive_restart_and_delete() {
        let memory = Memory::default();
        let mut vault = Vault::new(Box::new(memory.clone()));
        let mut secrets = values(&"large 🔑 refresh token".repeat(900));
        secrets.insert("empty".into(), String::new());
        secrets.insert("oauth".into(), serde_json::json!({"access_token":"access", "refresh_token":"refresh", "expires_at":4_000_000_000_i64}).to_string());
        vault.save(&secrets).unwrap();
        drop(vault);
        let mut reloaded = Vault::new(Box::new(memory.clone()));
        assert_eq!(reloaded.load().unwrap(), Some(secrets));
        reloaded.save(&Values::new()).unwrap();
        assert_eq!(reloaded.load().unwrap(), Some(Values::new()));
        assert_eq!(
            memory.0.lock().unwrap().data.len(),
            2,
            "only the current empty snapshot and manifest remain"
        );
    }

    #[test]
    fn every_failed_write_before_commit_preserves_previous_snapshot() {
        let updated = values(&"new secret".repeat(1_000));
        let chunks = STANDARD
            .encode(serde_json::to_vec(&updated).unwrap())
            .len()
            .div_ceil(CHUNK_BYTES);
        // Each chunk, allocation journal, and final manifest are actual writes.
        for step in 1..=chunks + 2 {
            let memory = Memory::default();
            let mut vault = Vault::new(Box::new(memory.clone()));
            vault.save(&values("old secret")).unwrap();
            {
                let mut state = memory.0.lock().unwrap();
                state.fail_write = Some(state.writes + step);
            }
            assert!(vault.save(&updated).is_err(), "step {step}");
            memory.0.lock().unwrap().fail_write = None;
            drop(vault);
            let mut restarted = Vault::new(Box::new(memory.clone()));
            assert_eq!(
                restarted.load().unwrap(),
                Some(values("old secret")),
                "step {step}"
            );
            assert_eq!(
                memory.0.lock().unwrap().data.len(),
                2,
                "staging was reclaimed"
            );
        }
    }

    #[test]
    fn committed_snapshot_survives_cleanup_failure_and_restart_reclaims_retired() {
        let memory = Memory::default();
        let mut vault = Vault::new(Box::new(memory.clone()));
        vault.save(&values("old")).unwrap();
        memory.0.lock().unwrap().fail_delete = true;
        vault.save(&values("new")).unwrap();
        memory.0.lock().unwrap().fail_delete = false;
        let mut restarted = Vault::new(Box::new(memory.clone()));
        assert_eq!(restarted.load().unwrap(), Some(values("new")));
        assert_eq!(memory.0.lock().unwrap().data.len(), 2);
    }

    #[test]
    fn migration_verifies_before_removing_file_and_preserves_conflicts() {
        let temp = Temp::new();
        let path = temp.0.join("secrets.json");
        let marker = temp.0.join("os-secret-store.json");
        fs::write(&path, serde_json::to_vec(&values("legacy")).unwrap()).unwrap();
        let memory = Memory::default();
        let mut vault = Vault::new(Box::new(memory.clone()));
        memory.0.lock().unwrap().fail_write = Some(2);
        assert!(migrate(&mut vault, &path, &marker).is_err());
        assert!(path.exists());
        memory.0.lock().unwrap().fail_write = None;
        assert_eq!(
            migrate(&mut vault, &path, &marker).unwrap(),
            values("legacy")
        );
        assert!(!path.exists());
        // Retry after a successful OS copy but before legacy-file removal.
        fs::write(&path, serde_json::to_vec(&values("legacy")).unwrap()).unwrap();
        assert_eq!(
            migrate(&mut vault, &path, &marker).unwrap(),
            values("legacy")
        );
        fs::write(&path, serde_json::to_vec(&values("different")).unwrap()).unwrap();
        assert!(migrate(&mut vault, &path, &marker).is_err());
        assert_eq!(read_legacy(&path).unwrap(), Some(values("different")));
        assert_eq!(vault.load().unwrap(), Some(values("legacy")));
    }

    #[test]
    fn locked_missing_and_corrupt_stores_never_fall_back_or_delete_legacy() {
        let temp = Temp::new();
        let path = temp.0.join("secrets.json");
        let marker = temp.0.join("os-secret-store.json");
        fs::write(
            &path,
            serde_json::to_vec(&values("sensitive-value")).unwrap(),
        )
        .unwrap();
        let memory = Memory::default();
        let mut vault = Vault::new(Box::new(memory.clone()));
        memory.0.lock().unwrap().fail_read = true;
        assert!(migrate(&mut vault, &path, &marker).is_err());
        assert!(path.exists());
        memory.0.lock().unwrap().fail_read = false;
        vault.save(&values("sensitive-value")).unwrap();
        let manifest = vault.manifest().unwrap();
        memory
            .0
            .lock()
            .unwrap()
            .data
            .remove(&manifest.current.unwrap().key(0));
        let error = migrate(&mut vault, &path, &marker).unwrap_err().to_string();
        assert!(!error.contains("sensitive-value"));
        assert!(path.exists());
        assert!(!temp.0.join("secrets.json.tmp").exists());
    }

    #[test]
    fn settings_publish_only_committed_values_and_namespaces_are_independent() {
        let a = Temp::new();
        let b = Temp::new();
        let settings = crate::settings::Settings::load(&a.0).unwrap();
        settings.set_secret("test", "old").unwrap();
        let memory = memory(&a.0).unwrap();
        memory.0.lock().unwrap().fail_read = true;
        assert!(settings.set_secret("test", "new").is_err());
        assert!(settings.remove_secret("test").is_err());
        assert_eq!(settings.secret("test").as_deref(), Some("old"));
        memory.0.lock().unwrap().fail_read = false;
        assert_eq!(
            crate::settings::Settings::load(&a.0)
                .unwrap()
                .secret("test")
                .as_deref(),
            Some("old")
        );
        assert!(
            crate::settings::Settings::load(&b.0)
                .unwrap()
                .secret("test")
                .is_none()
        );
        assert!(!a.0.join("secrets.json").exists());
    }

    #[test]
    fn data_directory_lock_prevents_concurrent_brokers() {
        let temp = Temp::new();
        let first = lock_directory(&temp.0).unwrap();
        assert!(lock_directory(&temp.0).is_err());
        drop(first);
        assert!(lock_directory(&temp.0).is_ok());
    }

    #[test]
    fn initialized_profiles_reject_missing_os_store_and_file_mode() {
        let temp = Temp::new();
        let _settings = crate::settings::Settings::load(&temp.0).unwrap();
        assert!(crate::settings::Settings::load_with_mode(&temp.0, Mode::File).is_err());
        let memory = memory(&temp.0).unwrap();
        memory.0.lock().unwrap().data.clear();
        assert!(crate::settings::Settings::load(&temp.0).is_err());
        assert!(!temp.0.join("secrets.json").exists());
    }

    #[test]
    fn malformed_legacy_and_failed_removal_leave_recoverable_sources() {
        let temp = Temp::new();
        let path = temp.0.join("secrets.json");
        let marker = temp.0.join("os-secret-store.json");
        let memory = Memory::default();
        let mut vault = Vault::new(Box::new(memory.clone()));
        for input in ["null", "[]", "{\"key\":null}", "{\"key\":123}", "{invalid"] {
            fs::write(&path, input).unwrap();
            assert!(migrate(&mut vault, &path, &marker).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), input);
            assert!(memory.0.lock().unwrap().data.is_empty());
        }
        fs::write(&path, serde_json::to_vec(&values("legacy")).unwrap()).unwrap();
        // On Windows an open handle without delete-sharing prevents removal.
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let held = fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&path)
                .unwrap();
            assert!(migrate(&mut vault, &path, &marker).is_err());
            assert_eq!(vault.load().unwrap(), Some(values("legacy")));
            assert!(path.exists());
            drop(held);
        }
        assert_eq!(
            migrate(&mut vault, &path, &marker).unwrap(),
            values("legacy")
        );
        assert!(!path.exists());
    }

    #[test]
    fn settings_startup_migrates_all_legacy_records_before_serving() {
        let temp = Temp::new();
        let path = temp.0.join("secrets.json");
        let old: Values = HashMap::from([
            ("provider".into(), "api-key".into()),
            ("cline-oauth:provider".into(), "refresh-record".into()),
            ("mcp-oauth:server".into(), "mcp-record".into()),
        ]);
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        let settings = crate::settings::Settings::load(&temp.0).unwrap();
        for (name, value) in &old {
            assert_eq!(settings.secret(name).as_ref(), Some(value));
        }
        assert!(!path.exists());
        let reloaded = crate::settings::Settings::load(&temp.0).unwrap();
        for (name, value) in &old {
            assert_eq!(reloaded.secret(name).as_ref(), Some(value));
        }
    }

    #[test]
    fn entry_removal_reports_failed_metadata_without_restoring_revoked_secrets() {
        let temp = Temp::new();
        let settings = crate::settings::Settings::load(&temp.0).unwrap();
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "test".into(),
                hosts: vec!["example.com".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fake".into(),
                real_env: None,
                guest_env: None,
            })
            .unwrap();
        settings.set_secret("test", "token").unwrap();
        settings.set_secret("cline-oauth:test", "refresh").unwrap();
        let escrow = temp.0.join("escrow.json");
        fs::remove_file(&escrow).unwrap();
        fs::create_dir(&escrow).unwrap();
        assert!(settings.remove_entry("test").is_err());
        assert_eq!(settings.entries().len(), 1);
        assert!(settings.secret("test").is_none());
        assert!(settings.secret("cline-oauth:test").is_none());
    }

    #[test]
    fn corrupted_manifest_cannot_delete_an_active_snapshot() {
        let memory = Memory::default();
        let mut vault = Vault::new(Box::new(memory.clone()));
        vault.save(&values("active")).unwrap();
        let mut manifest = vault.manifest().unwrap();
        manifest.retired = manifest.current.clone();
        vault.publish(&manifest).unwrap();
        let before = memory.0.lock().unwrap().data.clone();
        assert!(vault.load().is_err());
        assert_eq!(memory.0.lock().unwrap().data, before);
    }

    #[test]
    #[ignore = "opt-in native credential-store acceptance; uses only a disposable Friendzone namespace"]
    fn native_store_large_snapshot_and_cleanup() {
        let temp = Temp::new();
        let _lock = lock_directory(&temp.0).unwrap();
        let mut vault = Vault::new(Box::new(NativeEntries::new(&temp.0).unwrap()));
        let result = (|| -> Result<()> {
            vault.save(&values(&"native test 🔑".repeat(900)))?;
            let mut restarted = Vault::new(Box::new(NativeEntries::new(&temp.0)?));
            assert_eq!(
                restarted.load()?,
                Some(values(&"native test 🔑".repeat(900)))
            );
            #[cfg(windows)]
            {
                let native = NativeEntries::new(&temp.0)?;
                assert_eq!(
                    native
                        .entry("manifest")?
                        .get_attributes()
                        .map_err(safe_error)?["persistence"],
                    "Local"
                );
            }
            vault.save(&Values::new())?;
            assert_eq!(vault.load()?, Some(Values::new()));
            Ok(())
        })();
        let manifest = vault.manifest().unwrap();
        for generation in [&manifest.current, &manifest.pending, &manifest.retired]
            .into_iter()
            .flatten()
        {
            for index in 0..generation.chunks {
                vault.entries.delete(&generation.key(index)).unwrap();
            }
        }
        vault.entries.delete("manifest").unwrap();
        result.unwrap();
    }
}
