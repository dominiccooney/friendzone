//! Durable, tool-submitted Git branch publication.
//!
//! The guest uploads a Git v2 bundle. Git itself validates/imports the bundle
//! into a broker-owned bare repository; the review is derived from those exact
//! objects. Approval permits one `git push` attempt guarded by force-with-lease.
//! Ordinary receive-pack proxy requests remain blocked.

use crate::{
    github::Binding,
    graphql::Facts,
    review::{Detail, Status, Summary},
    settings::Settings,
    state::AppState,
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

pub const MAX_BUNDLE: usize = 32 * 1024 * 1024;
const MAX_STORAGE: u64 = 256 * 1024 * 1024;
const MAX_PATCH: usize = 2 * 1024 * 1024;
const MAX_GIT_OUTPUT: usize = 2 * 1024 * 1024;
const MAX_OBJECTS: usize = 20_000;
const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OBJECT_SIZE: u64 = 16 * 1024 * 1024;
const MAX_COMMITS: usize = 100;
const MAX_FILES: usize = 1_000;
const MAX_JOBS: usize = 32;
const REVIEW_HOURS: i64 = 24;
const ZERO_OID: &str = "0000000000000000000000000000000000000000";

pub fn upload_slots() -> &'static Arc<tokio::sync::Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4)))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub request_key: String,
    pub session_id: String,
    pub repository: String,
    pub branch: String,
    /// Exact bundle prerequisite and review boundary. It must match the
    /// bundle header; branch names have no role in selecting this commit.
    pub base_oid: String,
    pub expected_oid: String,
}

pub struct UploadedBundle {
    pub submission: Submission,
    pub staging: PathBuf,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitReview {
    pub oid: String,
    pub parents: Vec<String>,
    pub author: String,
    pub email: String,
    pub authored_at: String,
    pub subject: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileReview {
    pub commit_oid: String,
    pub status: String,
    pub path: String,
    pub old_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub repository: String,
    pub branch: String,
    pub expected_oid: String,
    pub base_oid: String,
    pub head_oid: String,
    pub bundle_sha256: String,
    pub bundle_bytes: u64,
    pub commits: Vec<CommitReview>,
    pub files: Vec<FileReview>,
    pub patch: String,
}

#[derive(Clone, Debug)]
struct BundleHeader {
    base_oid: String,
    head_oid: String,
    reference: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    id: Uuid,
    container: String,
    instance: Uuid,
    epoch: Uuid,
    peer: IpAddr,
    submission: Submission,
    review: Option<Review>,
    bundle_sha256: String,
    bundle_bytes: u64,
    fingerprint: String,
    binding: Binding,
    status: Status,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    outcome: String,
    result: Option<String>,
}

impl Job {
    fn terminal(&self) -> bool {
        !matches!(
            self.status,
            Status::Preparing | Status::Pending | Status::Approved | Status::Sending
        )
    }

    fn set(&mut self, status: Status, outcome: impl Into<String>) {
        self.status = status;
        self.outcome = outcome.into();
        self.updated_at = Utc::now();
    }

    fn summary(&self) -> Summary {
        Summary {
            id: self.id,
            container: self.container.clone(),
            method: "GIT PUSH".into(),
            url: remote_url(&self.submission.repository),
            created_at: self.created_at,
            expires_at: self.expires_at,
            fingerprint: self.fingerprint.clone(),
            body_bytes: self.bundle_bytes as usize,
            reason: if self.status == Status::Preparing {
                "Validating Git bundle before review."
            } else {
                "Git branch publication requires approval."
            }
            .into(),
            status: self.status,
            updated_at: self.updated_at,
            http_status: None,
            outcome: Some(self.outcome.clone()),
            asynchronous: true,
            facts: self.review.as_ref().map(|_| Facts {
                operation_name: Some("Publish Git branch".into()),
                operation_type: "git_push".into(),
                fields: vec!["git-receive-pack".into()],
                repositories: vec![self.submission.repository.clone()],
                targets: vec![format!("branch {}", self.submission.branch)],
                artifacts: vec![],
                more: false,
            }),
            request_key: Some(self.submission.request_key.clone()),
            upstream: None,
        }
    }

    fn detail(&self) -> Detail {
        let review = self.review.as_ref();
        Detail {
            summary: self.summary(),
            headers: vec![],
            body: format!(
                "Repository: {}\nTarget: refs/heads/{}\nExpected remote OID: {}\nReview base OID: {}\nHead: {}\nBundle SHA-256: {}",
                self.submission.repository,
                self.submission.branch,
                self.submission.expected_oid,
                review
                    .map(|review| review.base_oid.as_str())
                    .unwrap_or("(preparing)"),
                review
                    .map(|review| review.head_oid.as_str())
                    .unwrap_or("(preparing)"),
                self.bundle_sha256,
            ),
            graphql: None,
            git_push: self.review.clone(),
            graphql_read: false,
            comment_permission_supported: false,
            resolved_target: None,
            resolution_id: None,
            comment_context: None,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u32,
    jobs: BTreeMap<Uuid, Job>,
}

#[derive(Deserialize)]
struct SavedVersion {
    version: u32,
}

struct Inner {
    data: Mutex<Saved>,
    metadata_path: Option<PathBuf>,
    artifacts: Option<PathBuf>,
    changes: tokio::sync::watch::Sender<u64>,
}

#[derive(Clone)]
pub struct Pushes(Arc<Inner>);

impl Pushes {
    pub fn new(changes: tokio::sync::watch::Sender<u64>) -> Self {
        Self(Arc::new(Inner {
            data: Mutex::new(Saved {
                version: 2,
                ..Default::default()
            }),
            metadata_path: None,
            artifacts: None,
            changes,
        }))
    }

    pub fn load(dir: &Path, changes: tokio::sync::watch::Sender<u64>) -> Result<Self> {
        let metadata_path = dir.join("git-push-jobs.json");
        let artifacts = dir.join("git-push-jobs");
        let recovery = || {
            format!(
                "Move {} and {} into a backup directory together, then restart Friendzone. Nothing was changed.",
                metadata_path.display(),
                artifacts.display()
            )
        };
        let mut saved: Saved = match std::fs::read(&metadata_path) {
            Ok(bytes) => {
                if bytes.len() > 64 * 1024 * 1024 {
                    bail!(
                        "Saved Git push history at {} exceeds the 64 MiB limit. {}",
                        metadata_path.display(),
                        recovery()
                    );
                }
                let version: SavedVersion = serde_json::from_slice(&bytes).with_context(|| {
                    format!(
                        "Saved Git push history at {} is unreadable. {}",
                        metadata_path.display(),
                        recovery()
                    )
                })?;
                if version.version == 1 {
                    let archive = archive_version_one(dir, &metadata_path, &artifacts)?;
                    tracing::warn!(
                        archive = %archive.display(),
                        "older Git push history was archived and will not be executed; starting with an empty push history"
                    );
                    Saved {
                        version: 2,
                        ..Default::default()
                    }
                } else if version.version == 2 {
                    serde_json::from_slice(&bytes).with_context(|| {
                        format!(
                            "Saved Git push history at {} is invalid. {}",
                            metadata_path.display(),
                            recovery()
                        )
                    })?
                } else {
                    bail!(
                        "Saved Git push history at {} uses an unsupported format (version {}). {}",
                        metadata_path.display(),
                        version.version,
                        recovery()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Saved {
                version: 2,
                ..Default::default()
            },
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Could not read saved Git push history at {}. {}",
                        metadata_path.display(),
                        recovery()
                    )
                });
            }
        };
        private_dir(&artifacts).with_context(|| {
            format!("create Git push artifact directory {}", artifacts.display())
        })?;
        (|| -> Result<()> {
            if saved.version != 2 {
                bail!("unexpected format version {}", saved.version);
            }
            if saved.jobs.len() > MAX_JOBS {
                bail!("more than {MAX_JOBS} saved publications");
            }
            let mut stored_bytes = 0u64;
            for (id, job) in &saved.jobs {
                if job.id != *id {
                    bail!("publication {id} has a mismatched ID");
                }
                validate_submission(&job.submission)
                    .with_context(|| format!("publication {id} has invalid request metadata"))?;
                if job.bundle_bytes == 0 || job.bundle_bytes > MAX_BUNDLE as u64 {
                    bail!("publication {id} has an invalid bundle size");
                }
                stored_bytes = stored_bytes
                    .checked_add(job.bundle_bytes)
                    .context("saved bundle sizes overflow")?;
                if stored_bytes > MAX_STORAGE {
                    bail!("saved bundles exceed the storage limit");
                }
                let job_root = artifacts.join(id.to_string());
                let root_metadata = std::fs::symlink_metadata(&job_root).with_context(|| {
                    format!("publication {id} is missing its artifact directory")
                })?;
                if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
                    bail!("publication {id} has an unsafe artifact directory");
                }
                let bundle = job_root.join("submission.bundle");
                let metadata = std::fs::symlink_metadata(&bundle)
                    .with_context(|| format!("publication {id} is missing its Git bundle"))?;
                if !metadata.file_type().is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() != job.bundle_bytes
                {
                    bail!("publication {id} has a Git bundle that does not match its metadata");
                }
                validate_sha256(&job.bundle_sha256)?;
                let digest = sha256_file_sync(&bundle)
                    .with_context(|| format!("could not verify publication {id}'s Git bundle"))?;
                if digest != job.bundle_sha256
                    || fingerprint(&job.submission, &digest, &job.binding) != job.fingerprint
                {
                    bail!("publication {id} failed its integrity check");
                }
                match (&job.review, job.status) {
                    (None, Status::Preparing | Status::Blocked | Status::Cancelled) => {}
                    (Some(review), _) => {
                        if review.repository != job.submission.repository
                            || review.branch != job.submission.branch
                            || !job
                                .submission
                                .base_oid
                                .eq_ignore_ascii_case(&review.base_oid)
                            || review.expected_oid
                                != job.submission.expected_oid.to_ascii_lowercase()
                            || review.bundle_sha256 != job.bundle_sha256
                            || review.bundle_bytes != job.bundle_bytes
                        {
                            bail!("publication {id}'s review does not match its request");
                        }
                    }
                    _ => bail!("publication {id} is missing its derived review"),
                }
            }
            Ok(())
        })()
        .with_context(|| {
            format!(
                "Saved Git push history in {} and {} cannot be used safely. {}",
                metadata_path.display(),
                artifacts.display(),
                recovery()
            )
        })?;
        for job in saved.jobs.values_mut() {
            match job.status {
                Status::Sending => job.set(
                    Status::Unknown,
                    "Broker restarted during Git push. Not retried; inspect the remote branch.",
                ),
                Status::Preparing | Status::Pending | Status::Approved => job.set(
                    Status::Cancelled,
                    "Broker restarted before Git push. Not sent; submit a new bundle if still needed.",
                ),
                _ => {}
            }
        }
        let pushes = Self(Arc::new(Inner {
            data: Mutex::new(saved),
            metadata_path: Some(metadata_path),
            artifacts: Some(artifacts.clone()),
            changes,
        }));
        pushes.transaction(|_| Ok(()))?;
        pushes.remove_orphans();
        Ok(pushes)
    }

    fn transaction<T>(&self, edit: impl FnOnce(&mut Saved) -> Result<T>) -> Result<T> {
        let mut current = self.0.data.lock().expect("push jobs lock");
        let mut next = current.clone();
        let result = edit(&mut next)?;
        let bytes = serde_json::to_vec(&next)?;
        if bytes.len() > 64 * 1024 * 1024 {
            bail!("Git push metadata storage full; remove completed jobs");
        }
        if let Some(path) = &self.0.metadata_path {
            crate::storage::atomic_write(path, &bytes)?;
        }
        *current = next;
        drop(current);
        self.0
            .changes
            .send_modify(|version| *version = version.wrapping_add(1));
        Ok(result)
    }

    fn remove_orphans(&self) {
        let Some(root) = &self.0.artifacts else {
            return;
        };
        let ids: HashSet<_> = self
            .0
            .data
            .lock()
            .expect("push jobs lock")
            .jobs
            .keys()
            .map(ToString::to_string)
            .collect();
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                if !ids.contains(&entry.file_name().to_string_lossy().into_owned()) {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
    }

    pub fn staging_path(&self) -> Result<PathBuf> {
        let root = self
            .0
            .artifacts
            .as_ref()
            .context("Git push storage is unavailable")?;
        let staging = root.join("staging");
        private_dir(&staging)?;
        Ok(staging.join(format!("{}.bundle", Uuid::new_v4())))
    }

    pub fn submit(
        &self,
        app: &AppState,
        settings: &Settings,
        container: &str,
        peer: IpAddr,
        upload: UploadedBundle,
    ) -> Result<serde_json::Value> {
        let UploadedBundle {
            submission: input,
            staging,
            bytes: bundle_bytes,
        } = upload;
        let cleanup = scopeguard::guard(staging.clone(), |path| {
            let _ = std::fs::remove_file(path);
        });
        validate_submission(&input)?;
        if bundle_bytes == 0 || bundle_bytes > MAX_BUNDLE as u64 {
            bail!("Git bundle must be a nonempty file up to 32 MiB");
        }
        let (instance, epoch) = app
            .async_identity(container, peer)
            .context("guest is not authorized")?;
        app.persist_guest_identity()?;
        let (binding, _) = git_credential(settings)?;
        let bundle_sha256 = sha256_file_sync(&staging).context("hash uploaded Git bundle")?;
        let fingerprint = fingerprint(&input, &bundle_sha256, &binding);
        let id = Uuid::new_v4();
        let root = self
            .0
            .artifacts
            .as_ref()
            .context("Git push storage is unavailable")?
            .join(id.to_string());
        private_dir(&root)?;
        let bundle = root.join("submission.bundle");
        if let Err(error) = std::fs::rename(&*cleanup, &bundle) {
            let _ = std::fs::remove_dir_all(&root);
            return Err(error).context("publish uploaded Git bundle");
        }
        let staging = scopeguard::ScopeGuard::into_inner(cleanup);
        debug_assert!(!staging.exists());
        let now = Utc::now();
        let job = Job {
            id,
            container: container.into(),
            instance,
            epoch,
            peer,
            submission: input,
            review: None,
            fingerprint,
            bundle_sha256,
            bundle_bytes,
            binding,
            status: Status::Preparing,
            created_at: now,
            updated_at: now,
            expires_at: now + chrono::Duration::hours(REVIEW_HOURS),
            outcome: "Validating bundle and deriving review".into(),
            result: None,
        };
        let result = self.transaction(|saved| {
            let stored_bytes: u64 = saved.jobs.values().map(|job| job.bundle_bytes).sum();
            if stored_bytes.saturating_add(bundle_bytes) > MAX_STORAGE {
                bail!("Git push artifact storage full; remove completed jobs");
            }
            if saved.jobs.len() >= MAX_JOBS
                || saved.jobs.values().filter(|job| !job.terminal()).count() >= 8
                || saved
                    .jobs
                    .values()
                    .filter(|job| job.container == container && !job.terminal())
                    .count()
                    >= 4
            {
                bail!("Git push job capacity reached; finish/cancel or remove existing jobs");
            }
            let value = guest_value(&job, false);
            saved.jobs.insert(job.id, job);
            Ok(value)
        });
        if result.is_err() {
            let _ = std::fs::remove_dir_all(root);
        }
        result
    }

    pub fn contains(&self, id: Uuid) -> bool {
        self.0
            .data
            .lock()
            .expect("push jobs lock")
            .jobs
            .contains_key(&id)
    }

    pub fn inspect(&self, id: Uuid) -> Option<Detail> {
        self.0
            .data
            .lock()
            .expect("push jobs lock")
            .jobs
            .get(&id)
            .map(Job::detail)
    }

    pub fn summaries(&self) -> (Vec<Summary>, Vec<Summary>) {
        self.0
            .data
            .lock()
            .expect("push jobs lock")
            .jobs
            .values()
            .map(Job::summary)
            .partition(|summary| matches!(summary.status, Status::Preparing | Status::Pending))
    }

    pub fn list(&self, container: &str, instance: Uuid, session: &str) -> Vec<serde_json::Value> {
        self.0
            .data
            .lock()
            .expect("push jobs lock")
            .jobs
            .values()
            .filter(|job| {
                job.container == container
                    && job.instance == instance
                    && job.submission.session_id == session
            })
            .map(|job| guest_value(job, false))
            .collect()
    }

    pub fn get(
        &self,
        container: &str,
        instance: Uuid,
        id: Uuid,
        session: &str,
    ) -> Result<serde_json::Value> {
        let data = self.0.data.lock().expect("push jobs lock");
        let job = data
            .jobs
            .get(&id)
            .filter(|job| {
                job.container == container
                    && job.instance == instance
                    && job.submission.session_id == session
            })
            .context("job not found")?;
        Ok(guest_value(job, true))
    }

    pub fn cancel(&self, container: &str, instance: Uuid, id: Uuid, session: &str) -> Result<()> {
        self.transaction(|saved| {
            let job = owned_job_mut(saved, container, instance, id, session)?;
            if !matches!(
                job.status,
                Status::Preparing | Status::Pending | Status::Approved
            ) {
                bail!("cannot cancel job after execution starts");
            }
            job.set(
                Status::Cancelled,
                "Cancelled by submitting guest. Not sent.",
            );
            Ok(())
        })
    }

    pub fn delete(&self, container: &str, instance: Uuid, id: Uuid, session: &str) -> Result<()> {
        self.transaction(|saved| {
            let job = saved
                .jobs
                .get(&id)
                .filter(|job| {
                    job.container == container
                        && job.instance == instance
                        && job.submission.session_id == session
                })
                .context("job not found")?;
            if !job.terminal() {
                bail!("cancel or finish job before removing it");
            }
            saved.jobs.remove(&id);
            Ok(())
        })?;
        if let Some(root) = &self.0.artifacts {
            match std::fs::remove_dir_all(root.join(id.to_string())) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("remove Git push artifact"),
            }
        }
        Ok(())
    }

    pub fn decide(
        &self,
        id: Uuid,
        fingerprint: &str,
        decision: crate::review::Decision,
    ) -> Result<()> {
        self.transaction(|saved| {
            let job = saved.jobs.get_mut(&id).context("job not found")?;
            if job.status != Status::Pending
                || job.fingerprint != fingerprint
                || job.expires_at <= Utc::now()
            {
                bail!("job no longer pending or fingerprint changed");
            }
            match decision {
                crate::review::Decision::Approve => {
                    job.set(Status::Approved, "Approved; queued for Git push")
                }
                crate::review::Decision::Deny => {
                    job.set(Status::Denied, "Denied by host. Not sent.")
                }
            }
            Ok(())
        })
    }

    pub async fn run(&self, app: AppState, settings: Settings) {
        loop {
            if let Err(error) = self.tick(&app, &settings).await {
                tracing::error!(%error, "Git push worker paused");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn tick(&self, app: &AppState, settings: &Settings) -> Result<()> {
        self.tick_remote(app, settings, None).await
    }

    async fn tick_remote(
        &self,
        app: &AppState,
        settings: &Settings,
        remote_override: Option<&str>,
    ) -> Result<()> {
        let jobs: Vec<_> = self
            .0
            .data
            .lock()
            .expect("push jobs lock")
            .jobs
            .values()
            .filter(|job| {
                matches!(
                    job.status,
                    Status::Preparing | Status::Pending | Status::Approved
                )
            })
            .cloned()
            .collect();
        for job in jobs {
            if job.expires_at <= Utc::now()
                || app.async_identity(&job.container, job.peer) != Some((job.instance, job.epoch))
            {
                self.transaction(|saved| {
                    if let Some(current) = saved.jobs.get_mut(&job.id)
                        && matches!(
                            current.status,
                            Status::Preparing | Status::Pending | Status::Approved
                        )
                    {
                        if current.expires_at <= Utc::now() {
                            current
                                .set(Status::Expired, "Review expired after 24 hours. Not sent.");
                        } else {
                            current.set(Status::Cancelled, "Guest permissions changed. Not sent.");
                        }
                    }
                    Ok(())
                })?;
                continue;
            }
            if job.status == Status::Preparing {
                let Some(token) = current_git_token(settings, &job.binding) else {
                    self.transaction(|saved| {
                        if let Some(current) = saved.jobs.get_mut(&job.id)
                            && current.status == Status::Preparing
                        {
                            current.set(Status::Blocked, "GitHub credential changed. Not sent.");
                        }
                        Ok(())
                    })?;
                    continue;
                };
                let root = self
                    .0
                    .artifacts
                    .as_ref()
                    .context("Git push storage unavailable")?
                    .join(job.id.to_string());
                let production_remote = remote_url(&job.submission.repository);
                let remote = remote_override.unwrap_or(&production_remote);
                let prepared = prepare_remote(
                    &root,
                    &root.join("submission.bundle"),
                    &job.submission,
                    &token,
                    job.bundle_bytes,
                    remote,
                )
                .await;
                let transitioned = app.with_async_identity(
                    &job.container,
                    job.peer,
                    job.instance,
                    job.epoch,
                    || {
                        self.transaction(|saved| {
                            let current = saved
                                .jobs
                                .get_mut(&job.id)
                                .context("Git push job disappeared")?;
                            if current.status != Status::Preparing {
                                return Ok(true);
                            }
                            if current.expires_at <= Utc::now() {
                                current.set(
                                    Status::Expired,
                                    "Review expired after 24 hours. Not sent.",
                                );
                                return Ok(true);
                            }
                            match prepared {
                                Ok(review) => {
                                    if review.bundle_sha256 != current.bundle_sha256 {
                                        current.set(
                                            Status::Blocked,
                                            "Stored Git bundle digest changed. Not sent.",
                                        );
                                    } else {
                                        current.review = Some(review);
                                        current.set(Status::Pending, "Awaiting host approval");
                                    }
                                }
                                Err(error) => current
                                    .set(Status::Blocked, format!("Bundle rejected: {error}")),
                            }
                            Ok(true)
                        })
                    },
                )?;
                if !transitioned {
                    self.transaction(|saved| {
                        if let Some(current) = saved.jobs.get_mut(&job.id)
                            && current.status == Status::Preparing
                        {
                            current.set(
                                Status::Cancelled,
                                "Guest permissions changed during bundle validation. Not sent.",
                            );
                        }
                        Ok(())
                    })?;
                }
                continue;
            }
            if job.status != Status::Approved {
                continue;
            }
            let Some(token) = current_git_token(settings, &job.binding) else {
                self.transaction(|saved| {
                    if let Some(current) = saved.jobs.get_mut(&job.id)
                        && current.status == Status::Approved
                    {
                        current.set(Status::Blocked, "GitHub credential changed. Not sent.");
                    }
                    Ok(())
                })?;
                continue;
            };
            // This is the consistency boundary: durable Sending and current
            // guest policy are committed before the first upstream byte.
            let admitted =
                app.with_async_identity(&job.container, job.peer, job.instance, job.epoch, || {
                    self.transaction(|saved| {
                        let Some(current) = saved.jobs.get_mut(&job.id) else {
                            return Ok(false);
                        };
                        if current.status != Status::Approved || current.expires_at <= Utc::now() {
                            return Ok(false);
                        }
                        current.set(Status::Sending, "Publishing branch to GitHub");
                        Ok(true)
                    })
                })?;
            if !admitted {
                continue;
            }
            let root = self
                .0
                .artifacts
                .as_ref()
                .context("Git push storage unavailable")?
                .join(job.id.to_string());
            let production_remote = remote_url(&job.submission.repository);
            let remote = remote_override.unwrap_or(&production_remote);
            let result = execute_remote(&root, &job, &token, remote).await;
            self.transaction(|saved| {
                let current = saved.jobs.get_mut(&job.id).context("Git push job disappeared")?;
                match result {
                    Ok(output) => {
                        current.set(
                            Status::ResponseReceived,
                            format!(
                                "Published {} at {}",
                                current.submission.branch,
                                current.review.as_ref().expect("approved review").head_oid
                            ),
                        );
                        current.result = Some(output);
                    }
                    Err(error) => {
                        current.set(
                            Status::Unknown,
                            "Git push did not produce a verified result. Inspect the remote branch before retrying.",
                        );
                        current.result = Some(error.to_string());
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    }
}

fn owned_job_mut<'a>(
    saved: &'a mut Saved,
    container: &str,
    instance: Uuid,
    id: Uuid,
    session: &str,
) -> Result<&'a mut Job> {
    saved
        .jobs
        .get_mut(&id)
        .filter(|job| {
            job.container == container
                && job.instance == instance
                && job.submission.session_id == session
        })
        .context("job not found")
}

fn guest_value(job: &Job, include_result: bool) -> serde_json::Value {
    serde_json::json!({
        "id": job.id,
        "kind": "git_push",
        "request_key": job.submission.request_key,
        "session_id": job.submission.session_id,
        "status": job.status,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "http_status": null,
        "outcome": job.outcome,
        "terminal": job.terminal(),
        "result": if include_result { job.result.as_deref() } else { None },
        "repository": job.submission.repository,
        "branch": job.submission.branch,
            "head_oid": job.review.as_ref().map(|review| review.head_oid.as_str()),
    })
}

pub(crate) fn validate_submission(input: &Submission) -> Result<()> {
    if input.request_key.is_empty()
        || input.request_key.len() > 128
        || input.session_id.is_empty()
        || input.session_id.len() > 256
    {
        bail!("request_key and session_id required (128/256 byte limits)");
    }
    validate_repository(&input.repository)?;
    validate_branch(&input.branch)?;
    validate_oid(&input.base_oid, false)?;
    validate_oid(&input.expected_oid, true)?;
    Ok(())
}

fn validate_repository(repository: &str) -> Result<()> {
    let parts: Vec<_> = repository.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || part.len() > 100
                || part.starts_with('.')
                || part.ends_with('.')
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        })
    {
        bail!("repository must be an owner/name GitHub repository");
    }
    Ok(())
}

fn validate_branch(branch: &str) -> Result<()> {
    if branch.is_empty()
        || branch.len() > 240
        || branch.starts_with("refs/")
        || branch.starts_with(['/', '.'])
        || branch.ends_with(['/', '.'])
        || branch.contains("..")
        || branch.contains("//")
        || branch.contains("@{")
        || branch.ends_with(".lock")
        || branch.split('/').any(|part| {
            part.is_empty()
                || part.starts_with('.')
                || part.ends_with('.')
                || part.ends_with(".lock")
        })
        || !branch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/-_.".contains(&byte))
    {
        bail!("branch contains unsupported characters or ref syntax");
    }
    Ok(())
}

fn validate_sha256(digest: &str) -> Result<()> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expected a 64-character SHA-256 digest");
    }
    Ok(())
}

fn validate_oid(oid: &str, zero_allowed: bool) -> Result<()> {
    if oid.len() != 40
        || !oid.bytes().all(|byte| byte.is_ascii_hexdigit())
        || (!zero_allowed && oid == ZERO_OID)
    {
        bail!("expected a 40-character SHA-1 object ID");
    }
    Ok(())
}

fn remote_url(repository: &str) -> String {
    format!("https://github.com/{repository}.git")
}

fn git_credential(settings: &Settings) -> Result<(Binding, String)> {
    let credentials: Vec<_> = settings
        .entries()
        .into_iter()
        .filter(|entry| entry.hosts.iter().any(|host| host == "github.com"))
        .filter_map(|entry| {
            let credential = crate::github::Credential::from_entry(settings, &entry)?;
            let token = settings.real_value(&entry)?;
            Some((credential.binding, token))
        })
        .collect();
    if credentials.len() != 1 {
        bail!("configure exactly one GitHub escrow credential for api.github.com and github.com");
    }
    if credentials[0].1.is_empty() || credentials[0].1.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("GitHub credential is invalid for Git HTTPS");
    }
    Ok(credentials.into_iter().next().unwrap())
}

fn current_git_token(settings: &Settings, binding: &Binding) -> Option<String> {
    crate::github::Credential::current(settings, binding)?;
    let entry = settings.entries().into_iter().find(|entry| {
        entry.name == binding.entry && entry.hosts.iter().any(|host| host == "github.com")
    })?;
    let token = settings.real_value(&entry)?;
    (!token.is_empty() && !token.bytes().any(|byte| byte.is_ascii_control())).then_some(token)
}

fn fingerprint(input: &Submission, bundle_sha256: &str, binding: &Binding) -> String {
    let mut hash = Sha256::new();
    for value in [
        input.repository.as_bytes(),
        input.branch.as_bytes(),
        input.base_oid.as_bytes(),
        input.expected_oid.as_bytes(),
        bundle_sha256.as_bytes(),
        binding.entry.as_bytes(),
        binding.digest.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    format!("{:x}", hash.finalize())
}

async fn prepare_remote(
    root: &Path,
    bundle: &Path,
    input: &Submission,
    token: &str,
    bundle_bytes: u64,
    remote: &str,
) -> Result<Review> {
    let header = read_bundle_header(bundle, &input.branch).await?;
    if !input.base_oid.eq_ignore_ascii_case(&header.base_oid) {
        bail!("base_oid must exactly match the bundle's sole prerequisite OID");
    }
    let bundle_sha256 = sha256_file(bundle).await?;
    let repo = root.join("repository.git");
    let _ = std::fs::remove_dir_all(&repo);
    private_dir(&repo)?;
    private_dir(&repo.join("empty-hooks"))?;
    git(
        &repo,
        &["init", "--bare", "--template=", "--object-format=sha1", "."],
        None,
        None,
        Duration::from_secs(15),
        128 * 1024,
    )
    .await?
    .success("initialize isolated Git repository")?;
    let target_ref = format!("refs/heads/{}", input.branch);
    let remote_refs = git(
        &repo,
        &["ls-remote", "--heads", remote, &target_ref],
        Some(token),
        None,
        Duration::from_secs(60),
        128 * 1024,
    )
    .await?
    .success("read current GitHub branch")?;
    let current = parse_ls_remote(&remote_refs.stdout, &target_ref)?;
    if input.expected_oid == ZERO_OID {
        if current.is_some() {
            bail!("target branch already exists; submit an update with its exact expected OID");
        }
    } else if current.as_deref() != Some(input.expected_oid.as_str()) {
        bail!("target branch does not match expected_oid; refresh before submitting");
    }
    let base_destination = "refs/friendzone/base";
    git(
        &repo,
        &[
            "-c",
            "transfer.fsckObjects=true",
            "fetch",
            "--depth=1",
            "--no-tags",
            remote,
            &format!("{}:{base_destination}", header.base_oid),
        ],
        Some(token),
        None,
        Duration::from_secs(90),
        MAX_GIT_OUTPUT,
    )
    .await?
    .success("fetch exact bundle prerequisite from repository")?;
    if rev_parse(&repo, base_destination).await? != header.base_oid
        || rev_type(&repo, base_destination).await? != "commit"
    {
        bail!("bundle prerequisite is not the exact repository commit requested");
    }
    let baseline_objects = all_objects(&repo).await?;
    let bundle_text = bundle.to_string_lossy().into_owned();
    git(
        &repo,
        &["bundle", "verify", &bundle_text],
        None,
        None,
        Duration::from_secs(30),
        MAX_GIT_OUTPUT,
    )
    .await?
    .success("verify Git bundle prerequisites")?;
    git(
        &repo,
        &[
            "-c",
            "transfer.fsckObjects=true",
            "fetch",
            "--no-tags",
            &bundle_text,
            &format!("{}:refs/friendzone/head", header.reference),
        ],
        None,
        None,
        Duration::from_secs(60),
        MAX_GIT_OUTPUT,
    )
    .await?
    .success("import Git bundle")?;
    let head_oid = rev_parse(&repo, "refs/friendzone/head").await?;
    if head_oid != header.head_oid {
        bail!("imported bundle head does not match its advertised object ID");
    }
    if rev_type(&repo, &head_oid).await? != "commit" {
        bail!("bundle head must be a commit");
    }
    if header.base_oid == head_oid {
        bail!(
            "Git publication has no commits after prerequisite {}; choose an exact ancestor commit strictly before the submitted head",
            header.base_oid
        );
    }
    if !is_ancestor(&repo, &header.base_oid, &head_oid).await? {
        bail!("bundle head must descend from its exact prerequisite commit");
    }
    validate_objects(&repo, &header.base_oid, &head_oid, &baseline_objects).await?;
    let commits = commits(&repo, &header.base_oid, &head_oid).await?;
    let files = changed_files(&repo, &commits).await?;
    let patch = diff(&repo, &commits).await?;
    Ok(Review {
        repository: input.repository.clone(),
        branch: input.branch.clone(),
        expected_oid: input.expected_oid.to_ascii_lowercase(),
        base_oid: header.base_oid,
        head_oid,
        bundle_sha256,
        bundle_bytes,
        commits,
        files,
        patch,
    })
}

async fn execute_remote(root: &Path, job: &Job, token: &str, remote: &str) -> Result<String> {
    let repo = root.join("repository.git");
    let review = job
        .review
        .as_ref()
        .context("approved Git push has no review")?;
    if sha256_file(&root.join("submission.bundle")).await? != review.bundle_sha256 {
        bail!("stored Git bundle digest changed; not sent");
    }
    let target = format!("refs/heads/{}", job.submission.branch);
    let before = git(
        &repo,
        &["ls-remote", "--heads", remote, &target],
        Some(token),
        None,
        Duration::from_secs(60),
        128 * 1024,
    )
    .await?
    .success("recheck GitHub branch before publishing")?;
    let before = parse_ls_remote(&before.stdout, &target)?;
    let expected =
        (job.submission.expected_oid != ZERO_OID).then_some(job.submission.expected_oid.as_str());
    if before.as_deref() != expected {
        bail!("target branch changed after review; not sent");
    }
    let lease = if job.submission.expected_oid == ZERO_OID {
        format!("--force-with-lease={target}:")
    } else {
        format!(
            "--force-with-lease={target}:{}",
            job.submission.expected_oid
        )
    };
    let output = git(
        &repo,
        &[
            "push",
            "--porcelain",
            "--no-verify",
            &lease,
            remote,
            &format!("refs/friendzone/head:{target}"),
        ],
        Some(token),
        None,
        Duration::from_secs(120),
        MAX_GIT_OUTPUT,
    )
    .await?;
    let result = output.redacted(token);
    if !output.status.success() {
        bail!("Git push did not report success; inspect remote before retrying.\n{result}");
    }
    let observed = git(
        &repo,
        &["ls-remote", "--heads", remote, &target],
        Some(token),
        None,
        Duration::from_secs(60),
        128 * 1024,
    )
    .await?
    .success("verify published GitHub branch")?;
    if parse_ls_remote(&observed.stdout, &target)?.as_deref() != Some(review.head_oid.as_str()) {
        bail!("GitHub branch did not verify at the reviewed head; inspect before retrying");
    }
    Ok(if result.is_empty() {
        format!(
            "Verified refs/heads/{} at {}",
            job.submission.branch, review.head_oid
        )
    } else {
        format!(
            "{result}\nVerified refs/heads/{} at {}",
            job.submission.branch, review.head_oid
        )
    })
}

async fn read_bundle_header(path: &Path, branch: &str) -> Result<BundleHeader> {
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes).await?;
    let end = bytes
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .map(|index| index + 2)
        .context("Git bundle header exceeds 64 KiB or is incomplete")?;
    let header = std::str::from_utf8(&bytes[..end]).context("Git bundle header is not UTF-8")?;
    let mut lines = header.lines();
    if lines.next() != Some("# v2 git bundle") {
        bail!("only Git bundle version 2 with SHA-1 object IDs is supported");
    }
    let mut prerequisite = None;
    let mut reference = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('-') {
            let oid = rest.split_once(' ').map_or(rest, |(oid, _)| oid);
            validate_oid(oid, false)?;
            if prerequisite.replace(oid.to_ascii_lowercase()).is_some() {
                bail!("bundle must declare exactly one prerequisite");
            }
        } else {
            let (oid, name) = line
                .split_once(' ')
                .context("invalid Git bundle reference")?;
            validate_oid(oid, false)?;
            if reference
                .replace((oid.to_ascii_lowercase(), name.to_owned()))
                .is_some()
            {
                bail!("bundle must advertise exactly one reference");
            }
        }
    }
    let base_oid = prerequisite.context("bundle must declare exactly one prerequisite")?;
    let (head_oid, reference) = reference.context("bundle must advertise exactly one reference")?;
    if reference != format!("refs/heads/{branch}") {
        bail!("bundle reference must exactly match refs/heads/{branch}");
    }
    Ok(BundleHeader {
        base_oid,
        head_oid,
        reference,
    })
}

async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn sha256_file_sync(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

async fn rev_parse(repo: &Path, reference: &str) -> Result<String> {
    let output = git(
        repo,
        &["rev-parse", "--verify", reference],
        None,
        None,
        Duration::from_secs(10),
        4096,
    )
    .await?
    .success("resolve Git object")?;
    let oid = std::str::from_utf8(&output.stdout)?
        .trim()
        .to_ascii_lowercase();
    validate_oid(&oid, false)?;
    Ok(oid)
}

async fn rev_type(repo: &Path, oid: &str) -> Result<String> {
    let output = git(
        repo,
        &["cat-file", "-t", oid],
        None,
        None,
        Duration::from_secs(10),
        4096,
    )
    .await?
    .success("read Git object type")?;
    Ok(std::str::from_utf8(&output.stdout)?.trim().to_owned())
}

async fn is_ancestor(repo: &Path, ancestor: &str, descendant: &str) -> Result<bool> {
    let output = git(
        repo,
        &["merge-base", "--is-ancestor", ancestor, descendant],
        None,
        None,
        Duration::from_secs(15),
        4096,
    )
    .await?;
    if output.status.success() {
        Ok(true)
    } else if output.status.code() == Some(1) {
        Ok(false)
    } else {
        bail!("Git could not verify commit ancestry: {}", output.text())
    }
}

async fn all_objects(repo: &Path) -> Result<HashSet<String>> {
    let output = git(
        repo,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
        None,
        None,
        Duration::from_secs(30),
        MAX_GIT_OUTPUT,
    )
    .await?
    .success("enumerate Git objects")?;
    let mut result = HashSet::new();
    for line in String::from_utf8(output.stdout)?.lines() {
        validate_oid(line, false)?;
        result.insert(line.to_ascii_lowercase());
    }
    Ok(result)
}

async fn validate_objects(
    repo: &Path,
    base: &str,
    head: &str,
    baseline: &HashSet<String>,
) -> Result<()> {
    git(
        repo,
        &["fsck", "--strict", "--no-reflogs", head],
        None,
        None,
        Duration::from_secs(45),
        MAX_GIT_OUTPUT,
    )
    .await?
    .success("validate uploaded Git objects")?;
    let range = format!("{base}..{head}");
    let objects = git(
        repo,
        &["rev-list", "--objects", &range],
        None,
        None,
        Duration::from_secs(30),
        MAX_GIT_OUTPUT,
    )
    .await?
    .success("enumerate uploaded Git objects")?;
    let mut allowed = HashSet::new();
    for line in objects.stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let oid = line.split(|byte| *byte == b' ').next().unwrap_or_default();
        let oid = std::str::from_utf8(oid)?;
        validate_oid(oid, false)?;
        allowed.insert(oid.to_ascii_lowercase());
    }
    let sizes = git(
        repo,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        None,
        None,
        Duration::from_secs(30),
        MAX_GIT_OUTPUT,
    )
    .await?
    .success("measure uploaded Git objects")?;
    let mut total = 0u64;
    let mut count = 0usize;
    for line in String::from_utf8(sizes.stdout)?.lines() {
        let mut fields = line.split(' ');
        let oid = fields
            .next()
            .context("missing object ID")?
            .to_ascii_lowercase();
        let _kind = fields.next().context("missing object type")?;
        let size: u64 = fields.next().context("missing object size")?.parse()?;
        if baseline.contains(&oid) {
            continue;
        }
        if !allowed.contains(&oid) {
            bail!("Git bundle contains an object outside the reviewed branch history");
        }
        count += 1;
        if count > MAX_OBJECTS {
            bail!("Git publication contains more than {MAX_OBJECTS} objects");
        }
        if size > MAX_OBJECT_SIZE {
            bail!("Git publication contains an object larger than 16 MiB");
        }
        total = total
            .checked_add(size)
            .context("Git object size overflow")?;
        if total > MAX_OBJECT_BYTES {
            bail!("Git publication expands to more than 64 MiB of objects");
        }
    }
    Ok(())
}

async fn commits(repo: &Path, base: &str, head: &str) -> Result<Vec<CommitReview>> {
    let range = format!("{base}..{head}");
    let listed = git(
        repo,
        &["rev-list", "--reverse", &range],
        None,
        None,
        Duration::from_secs(15),
        16 * 1024,
    )
    .await?
    .success("enumerate commits")?;
    let oids: Vec<_> = String::from_utf8(listed.stdout)?
        .lines()
        .map(str::to_owned)
        .collect();
    if oids.is_empty() {
        bail!(
            "Git publication has no commits after prerequisite {base}; choose an exact ancestor commit strictly before submitted head {head}"
        );
    }
    if oids.len() > MAX_COMMITS {
        bail!("Git publication contains more than {MAX_COMMITS} commits");
    }
    let mut result = Vec::with_capacity(oids.len());
    let mut expected_parent = base.to_owned();
    for oid in oids {
        validate_oid(&oid, false)?;
        let output = git(
            repo,
            &[
                "show",
                "-s",
                "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%B",
                &oid,
            ],
            None,
            None,
            Duration::from_secs(10),
            64 * 1024,
        )
        .await?
        .success("inspect commit")?;
        let fields: Vec<_> = output.stdout.split(|byte| *byte == 0).collect();
        if fields.len() != 6 {
            bail!("Git returned an unexpected commit representation");
        }
        let oid = review_text("commit OID", fields[0], false, 40)?;
        let parents: Vec<_> = review_text("commit parents", fields[1], false, 200)?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if parents != [expected_parent.as_str()] {
            bail!(
                "v1 Git publication requires linear, merge-free commits based directly on the exact prerequisite"
            );
        }
        let message = review_text("commit message", fields[5], true, 32 * 1024)?;
        let subject = message.lines().next().unwrap_or_default().to_owned();
        result.push(CommitReview {
            oid: oid.clone(),
            parents,
            author: review_text("commit author", fields[2], false, 1000)?,
            email: review_text("commit email", fields[3], false, 1000)?,
            authored_at: review_text("commit date", fields[4], false, 100)?,
            subject,
            message,
        });
        expected_parent = oid;
    }
    Ok(result)
}

fn review_text(label: &str, bytes: &[u8], multiline: bool, limit: usize) -> Result<String> {
    if bytes.len() > limit {
        bail!("{label} exceeds the review limit");
    }
    let text = std::str::from_utf8(bytes)
        .with_context(|| format!("{label} is not UTF-8 and cannot be faithfully reviewed"))?
        .trim_end_matches(['\r', '\n']);
    if text.chars().any(|character| {
        character.is_control() && !(multiline && matches!(character, '\n' | '\r' | '\t'))
    }) {
        bail!("{label} contains control characters and cannot be faithfully reviewed");
    }
    Ok(text.to_owned())
}

async fn changed_files(repo: &Path, commits: &[CommitReview]) -> Result<Vec<FileReview>> {
    let mut files = Vec::new();
    for commit in commits {
        let parent = commit.parents.first().context("commit has no parent")?;
        let output = git(
            repo,
            &[
                "diff",
                "--name-status",
                "-z",
                "--find-renames",
                "--no-ext-diff",
                parent,
                &commit.oid,
            ],
            None,
            None,
            Duration::from_secs(30),
            MAX_GIT_OUTPUT,
        )
        .await?
        .success("enumerate changed files")?;
        let fields: Vec<_> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|value| !value.is_empty())
            .collect();
        let mut index = 0;
        while index < fields.len() {
            let status = std::str::from_utf8(fields[index]).context("invalid Git file status")?;
            index += 1;
            let old_path = if status.starts_with('R') || status.starts_with('C') {
                let path = fields.get(index).context("missing renamed source path")?;
                index += 1;
                Some(display_path(path))
            } else {
                None
            };
            let path = fields.get(index).context("missing changed path")?;
            index += 1;
            files.push(FileReview {
                commit_oid: commit.oid.clone(),
                status: status.to_owned(),
                path: display_path(path),
                old_path,
            });
            if files.len() > MAX_FILES {
                bail!("Git publication touches more than {MAX_FILES} commit/path entries");
            }
        }
    }
    if files.is_empty() {
        bail!("Git publication has no file changes");
    }
    Ok(files)
}

fn display_path(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes)
        && !text.chars().any(char::is_control)
    {
        return text.to_owned();
    }
    bytes.iter().map(|byte| format!("\\x{byte:02x}")).collect()
}

async fn diff(repo: &Path, commits: &[CommitReview]) -> Result<String> {
    let mut patch = String::new();
    for commit in commits {
        let remaining = MAX_PATCH
            .checked_sub(patch.len())
            .context("Git patch exceeds the 2 MiB review limit")?;
        let output = git(
            repo,
            &[
                "-c",
                "core.quotePath=true",
                "show",
                "--format=fuller",
                "--binary",
                "--full-index",
                "--find-renames",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                &commit.oid,
            ],
            None,
            None,
            Duration::from_secs(45),
            remaining,
        )
        .await?
        .success("render Git commit patch")?;
        patch.push_str(
            std::str::from_utf8(&output.stdout).context(
                "Git patch is not UTF-8; this publication cannot be faithfully reviewed",
            )?,
        );
        if !patch.ends_with('\n') {
            patch.push('\n');
        }
    }
    Ok(patch)
}

fn parse_ls_remote(bytes: &[u8], expected_ref: &str) -> Result<Option<String>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(bytes)?;
    let mut result = None;
    for line in text.lines() {
        let (oid, reference) = line
            .split_once('\t')
            .context("invalid ls-remote response")?;
        validate_oid(oid, false)?;
        if reference != expected_ref || result.replace(oid.to_ascii_lowercase()).is_some() {
            bail!("GitHub returned an unexpected branch advertisement");
        }
    }
    Ok(result)
}

struct GitOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl GitOutput {
    fn success(self, action: &str) -> Result<Self> {
        if self.status.success() {
            Ok(self)
        } else {
            bail!("{action} failed: {}", self.text())
        }
    }

    fn text(&self) -> String {
        let mut output = String::from_utf8_lossy(&self.stdout).into_owned();
        if !self.stderr.is_empty() {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(&String::from_utf8_lossy(&self.stderr));
        }
        output.trim().to_owned()
    }

    fn redacted(&self, token: &str) -> String {
        if token.is_empty() {
            return self.text();
        }
        let basic = STANDARD.encode(format!("x-access-token:{token}"));
        self.text()
            .replace(token, "[redacted]")
            .replace(&basic, "[redacted]")
    }

    fn scrub(&mut self, token: &str) {
        if token.is_empty() {
            return;
        }
        let basic = STANDARD.encode(format!("x-access-token:{token}"));
        for bytes in [&mut self.stdout, &mut self.stderr] {
            let text = String::from_utf8_lossy(bytes)
                .replace(token, "[redacted]")
                .replace(&basic, "[redacted]");
            *bytes = text.into_bytes();
        }
    }
}

async fn drain<R: AsyncRead + Unpin>(mut reader: R, limit: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        if result.len() + read <= limit {
            result.extend_from_slice(&buffer[..read]);
        } else {
            exceeded = true;
        }
    }
    if exceeded {
        bail!("Git command output exceeds the review limit");
    }
    Ok(result)
}

async fn git(
    repo: &Path,
    args: &[&str],
    token: Option<&str>,
    input: Option<Vec<u8>>,
    timeout: Duration,
    output_limit: usize,
) -> Result<GitOutput> {
    let mut command = tokio::process::Command::new("git");
    command
        .env_clear()
        .current_dir(repo)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .args([
            "-c",
            "credential.helper=",
            "-c",
            "core.hooksPath=empty-hooks",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.file.allow=always",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.sslVerify=true",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "Never")
        .env("LC_ALL", "C");
    for key in [
        "PATH",
        "SystemRoot",
        "WINDIR",
        "SystemDrive",
        "COMSPEC",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if let Some(token) = token {
        let value = format!(
            "Authorization: Basic {}",
            STANDARD.encode(format!("x-access-token:{token}"))
        );
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.https://github.com/.extraHeader")
            .env("GIT_CONFIG_VALUE_0", value);
    }
    let mut child = command.spawn().context("start isolated Git command")?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let writer = tokio::spawn(async move {
        if let Some(input) = input {
            stdin.write_all(&input).await?;
        }
        stdin.shutdown().await
    });
    let stdout = tokio::spawn(drain(
        child.stdout.take().expect("piped stdout"),
        output_limit,
    ));
    let stderr = tokio::spawn(drain(
        child.stderr.take().expect("piped stderr"),
        output_limit,
    ));
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            let _ = child.kill().await;
            bail!("Git command timed out; inspect remote state before retrying")
        }
    };
    writer.await.context("join Git stdin writer")??;
    let mut output = GitOutput {
        status,
        stdout: stdout.await.context("join Git stdout reader")??,
        stderr: stderr.await.context("join Git stderr reader")??,
    };
    if let Some(token) = token {
        output.scrub(token);
    }
    Ok(output)
}

fn private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Version 1 used the removed named-base schema. Keep its bytes available for
/// audit, but make it impossible for the current worker to execute them. Both
/// paths move into one unique sibling directory before a fresh v2 store starts.
fn archive_version_one(dir: &Path, metadata: &Path, artifacts: &Path) -> Result<PathBuf> {
    let archive = dir.join(format!(
        "git-push-jobs-v1-archive-{}-{}",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&archive).with_context(|| {
        format!(
            "create archive {} for obsolete Git push store {}; nothing was moved",
            archive.display(),
            metadata.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("secure legacy Git push archive {}", archive.display()))?;
    }
    let archived_metadata = archive.join("git-push-jobs.json");
    if let Err(error) = std::fs::rename(metadata, &archived_metadata) {
        let _ = std::fs::remove_dir(&archive);
        return Err(error).with_context(|| {
            format!(
                "archive obsolete Git push metadata {} to {}; nothing was moved",
                metadata.display(),
                archived_metadata.display()
            )
        });
    }
    if artifacts.exists() {
        let archived_artifacts = archive.join("git-push-jobs");
        if let Err(error) = std::fs::rename(artifacts, &archived_artifacts) {
            let rollback = std::fs::rename(&archived_metadata, metadata);
            let _ = std::fs::remove_dir(&archive);
            return match rollback {
                Ok(()) => Err(error).with_context(|| {
                    format!(
                        "archive obsolete Git push artifacts {} to {}; metadata move was rolled back and startup made no change",
                        artifacts.display(),
                        archived_artifacts.display()
                    )
                }),
                Err(rollback_error) => anyhow::bail!(
                    "could not archive obsolete Git push artifacts {} to {} ({error}); metadata is preserved at {}, but restoring it to {} also failed ({rollback_error})",
                    artifacts.display(),
                    archived_artifacts.display(),
                    archived_metadata.display(),
                    metadata.display()
                ),
            };
        }
    }
    Ok(archive)
}

// Small local equivalent avoids adding a runtime dependency for one cleanup guard.
mod scopeguard {
    pub struct ScopeGuard<T, F: FnOnce(T)> {
        value: Option<T>,
        drop: Option<F>,
    }
    pub fn guard<T, F: FnOnce(T)>(value: T, drop: F) -> ScopeGuard<T, F> {
        ScopeGuard {
            value: Some(value),
            drop: Some(drop),
        }
    }
    impl<T, F: FnOnce(T)> std::ops::Deref for ScopeGuard<T, F> {
        type Target = T;
        fn deref(&self) -> &T {
            self.value.as_ref().unwrap()
        }
    }
    impl<T, F: FnOnce(T)> ScopeGuard<T, F> {
        pub fn into_inner(mut this: Self) -> T {
            this.drop = None;
            this.value.take().unwrap()
        }
    }
    impl<T, F: FnOnce(T)> Drop for ScopeGuard<T, F> {
        fn drop(&mut self) {
            if let (Some(value), Some(drop)) = (self.value.take(), self.drop.take()) {
                drop(value)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("fz-git-push-{}", Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_git(directory: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(directory)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn publication_fixture() -> (TestDir, PathBuf, PathBuf, String, String) {
        let temp = TestDir::new();
        let remote = temp.0.join("remote.git");
        let work = temp.0.join("work");
        std::fs::create_dir(&remote).unwrap();
        std::fs::create_dir(&work).unwrap();
        fixture_git(&remote, &["init", "--bare", "--initial-branch=master"]);
        fixture_git(&work, &["init", "--initial-branch=master"]);
        fixture_git(&work, &["config", "user.name", "Bundle Author"]);
        fixture_git(&work, &["config", "user.email", "bundle@example.test"]);
        std::fs::write(work.join("one.txt"), "base\n").unwrap();
        fixture_git(&work, &["add", "one.txt"]);
        fixture_git(&work, &["commit", "-m", "base"]);
        let remote_text = remote.to_string_lossy().into_owned();
        fixture_git(&work, &["push", &remote_text, "master"]);
        let base = fixture_git(&work, &["rev-parse", "HEAD"]);
        fixture_git(&work, &["switch", "-c", "feature"]);
        std::fs::write(work.join("one.txt"), "changed\n").unwrap();
        std::fs::write(work.join("two.txt"), "new\n").unwrap();
        fixture_git(&work, &["add", "one.txt", "two.txt"]);
        fixture_git(&work, &["commit", "-m", "publish feature"]);
        let head = fixture_git(&work, &["rev-parse", "HEAD"]);
        let bundle = temp.0.join("feature.bundle");
        let bundle_text = bundle.to_string_lossy().into_owned();
        fixture_git(
            &work,
            &[
                "bundle",
                "create",
                &bundle_text,
                "refs/heads/feature",
                &format!("^{base}"),
            ],
        );
        (temp, remote, bundle, base, head)
    }

    fn rebased_publication_fixture() -> (TestDir, PathBuf, PathBuf, String, String, String) {
        let temp = TestDir::new();
        let remote = temp.0.join("remote.git");
        let work = temp.0.join("work");
        std::fs::create_dir(&remote).unwrap();
        std::fs::create_dir(&work).unwrap();
        fixture_git(&remote, &["init", "--bare", "--initial-branch=master"]);
        fixture_git(&work, &["init", "--initial-branch=master"]);
        fixture_git(&work, &["config", "user.name", "Rebase Author"]);
        fixture_git(&work, &["config", "user.email", "rebase@example.test"]);
        std::fs::write(work.join("base.txt"), "base\n").unwrap();
        fixture_git(&work, &["add", "base.txt"]);
        fixture_git(&work, &["commit", "-m", "initial base"]);
        let remote_text = remote.to_string_lossy().into_owned();
        fixture_git(&work, &["push", &remote_text, "master"]);

        fixture_git(&work, &["switch", "-c", "feature"]);
        std::fs::write(work.join("feature.txt"), "feature before rebase\n").unwrap();
        fixture_git(&work, &["add", "feature.txt"]);
        fixture_git(&work, &["commit", "-m", "feature change"]);
        let old_target = fixture_git(&work, &["rev-parse", "HEAD"]);
        fixture_git(&work, &["push", &remote_text, "feature"]);

        fixture_git(&work, &["switch", "master"]);
        std::fs::write(work.join("main.txt"), "new main base\n").unwrap();
        fixture_git(&work, &["add", "main.txt"]);
        fixture_git(&work, &["commit", "-m", "advance main"]);
        let base = fixture_git(&work, &["rev-parse", "HEAD"]);
        fixture_git(&work, &["push", &remote_text, "master"]);

        fixture_git(&work, &["switch", "feature"]);
        fixture_git(&work, &["rebase", "master"]);
        let head = fixture_git(&work, &["rev-parse", "HEAD"]);
        assert_ne!(head, old_target);
        let bundle = temp.0.join("rebased-feature.bundle");
        let bundle_text = bundle.to_string_lossy().into_owned();
        fixture_git(
            &work,
            &[
                "bundle",
                "create",
                &bundle_text,
                "refs/heads/feature",
                &format!("^{base}"),
            ],
        );
        // Model the practical race: main advances after the rebase and bundle
        // creation, while the exact prerequisite remains in repository history.
        fixture_git(&work, &["switch", "master"]);
        std::fs::write(work.join("later-main.txt"), "main advanced again\n").unwrap();
        fixture_git(&work, &["add", "later-main.txt"]);
        fixture_git(&work, &["commit", "-m", "advance main after bundle"]);
        fixture_git(&work, &["push", &remote_text, "master"]);
        assert_ne!(
            fixture_git(&remote, &["rev-parse", "refs/heads/master"]),
            base
        );
        (temp, remote, bundle, base, old_target, head)
    }

    fn sending_job(input: Submission, review: Review) -> Job {
        Job {
            id: Uuid::new_v4(),
            container: "guest".into(),
            instance: Uuid::new_v4(),
            epoch: Uuid::new_v4(),
            peer: "127.0.0.1".parse().unwrap(),
            submission: input,
            bundle_sha256: review.bundle_sha256.clone(),
            bundle_bytes: review.bundle_bytes,
            review: Some(review),
            fingerprint: "test".into(),
            binding: Binding {
                entry: "test".into(),
                digest: "0".repeat(64),
            },
            status: Status::Sending,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            outcome: String::new(),
            result: None,
        }
    }

    #[tokio::test]
    async fn real_bundle_derives_exact_review_and_creation_lease_publishes_once() {
        let (temp, remote, bundle, base, head) = publication_fixture();
        let input = Submission {
            request_key: "publish-feature".into(),
            session_id: "session".into(),
            repository: "fixture/repository".into(),
            branch: "feature".into(),
            base_oid: base.clone(),
            expected_oid: ZERO_OID.into(),
        };
        let root = temp.0.join("inspect");
        private_dir(&root).unwrap();
        let remote_text = remote.to_string_lossy().into_owned();
        let review = prepare_remote(
            &root,
            &bundle,
            &input,
            "",
            std::fs::metadata(&bundle).unwrap().len(),
            &remote_text,
        )
        .await
        .unwrap();
        assert_eq!(review.base_oid, base);
        assert_eq!(review.head_oid, head);
        assert_eq!(review.commits.len(), 1);
        assert_eq!(review.commits[0].subject, "publish feature");
        assert_eq!(review.commits[0].author, "Bundle Author");
        assert_eq!(
            review
                .files
                .iter()
                .map(|file| (file.status.as_str(), file.path.as_str()))
                .collect::<Vec<_>>(),
            vec![("M", "one.txt"), ("A", "two.txt")]
        );
        assert!(review.patch.contains("diff --git a/one.txt b/one.txt"));
        assert!(review.patch.contains("+changed"));
        assert!(review.patch.contains("diff --git a/two.txt b/two.txt"));
        let job = Job {
            id: Uuid::new_v4(),
            container: "guest".into(),
            instance: Uuid::new_v4(),
            epoch: Uuid::new_v4(),
            peer: "127.0.0.1".parse().unwrap(),
            submission: input,
            review: Some(review.clone()),
            bundle_sha256: review.bundle_sha256.clone(),
            bundle_bytes: review.bundle_bytes,
            fingerprint: "test".into(),
            binding: Binding {
                entry: "test".into(),
                digest: "0".repeat(64),
            },
            status: Status::Sending,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            outcome: String::new(),
            result: None,
        };
        // Production moved the accepted bundle to this exact artifact path.
        std::fs::copy(&bundle, root.join("submission.bundle")).unwrap();
        let result = execute_remote(&root, &job, "", &remote_text).await.unwrap();
        assert!(result.contains("feature"));
        assert_eq!(
            fixture_git(&remote, &["rev-parse", "refs/heads/feature"]),
            head
        );
        assert!(
            execute_remote(&root, &job, "", &remote_text).await.is_err(),
            "creation lease must reject a second send after the ref exists"
        );
    }

    #[tokio::test]
    async fn rebased_update_uses_base_prerequisite_and_independent_target_lease() {
        let (temp, remote, bundle, base, old_target, head) = rebased_publication_fixture();
        let input = Submission {
            request_key: "publish-rebased-feature".into(),
            session_id: "session".into(),
            repository: "fixture/repository".into(),
            branch: "feature".into(),
            base_oid: base.clone(),
            expected_oid: old_target.clone(),
        };
        validate_submission(&input).unwrap();
        let root = temp.0.join("inspect");
        private_dir(&root).unwrap();
        let remote_text = remote.to_string_lossy().into_owned();
        let review = prepare_remote(
            &root,
            &bundle,
            &input,
            "",
            std::fs::metadata(&bundle).unwrap().len(),
            &remote_text,
        )
        .await
        .unwrap();
        assert_eq!(review.expected_oid, old_target);
        assert_eq!(review.base_oid, base);
        assert_eq!(review.head_oid, head);
        assert_eq!(review.commits.len(), 1);
        assert_eq!(review.commits[0].parents, vec![base.clone()]);
        assert_eq!(review.commits[0].subject, "feature change");
        std::fs::copy(&bundle, root.join("submission.bundle")).unwrap();
        let job = sending_job(input, review);
        let result = execute_remote(&root, &job, "", &remote_text).await.unwrap();
        assert!(result.contains("feature"));
        assert_eq!(
            fixture_git(&remote, &["rev-parse", "refs/heads/feature"]),
            head
        );

        let (stale_temp, stale_remote, stale_bundle, stale_base, stale_target, _) =
            rebased_publication_fixture();
        let stale_input = Submission {
            request_key: "stale-target".into(),
            session_id: "session".into(),
            repository: "fixture/repository".into(),
            branch: "feature".into(),
            base_oid: stale_base.clone(),
            expected_oid: stale_target.clone(),
        };
        let stale_root = stale_temp.0.join("inspect");
        private_dir(&stale_root).unwrap();
        let stale_remote_text = stale_remote.to_string_lossy().into_owned();
        let stale_review = prepare_remote(
            &stale_root,
            &stale_bundle,
            &stale_input,
            "",
            std::fs::metadata(&stale_bundle).unwrap().len(),
            &stale_remote_text,
        )
        .await
        .unwrap();
        std::fs::copy(&stale_bundle, stale_root.join("submission.bundle")).unwrap();
        fixture_git(
            &stale_remote,
            &["update-ref", "refs/heads/feature", &stale_base],
        );
        let error = execute_remote(
            &stale_root,
            &sending_job(stale_input, stale_review),
            "",
            &stale_remote_text,
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("target branch changed after review")
        );
        assert_eq!(
            fixture_git(&stale_remote, &["rev-parse", "refs/heads/feature"]),
            stale_base
        );

        let (base_temp, base_remote, base_bundle, base_tip, base_target, _) =
            rebased_publication_fixture();
        let base_root = base_temp.0.join("inspect");
        private_dir(&base_root).unwrap();
        let base_remote_text = base_remote.to_string_lossy().into_owned();
        let review = prepare_remote(
            &base_root,
            &base_bundle,
            &Submission {
                request_key: "advanced-base".into(),
                session_id: "session".into(),
                repository: "fixture/repository".into(),
                branch: "feature".into(),
                base_oid: base_tip.clone(),
                expected_oid: base_target.clone(),
            },
            "",
            std::fs::metadata(&base_bundle).unwrap().len(),
            &base_remote_text,
        )
        .await
        .unwrap();
        assert_eq!(review.base_oid, base_tip);
        assert_ne!(
            fixture_git(&base_remote, &["rev-parse", "refs/heads/master"]),
            base_tip
        );

        let mismatched_root = base_temp.0.join("mismatched-base");
        private_dir(&mismatched_root).unwrap();
        let error = prepare_remote(
            &mismatched_root,
            &base_bundle,
            &Submission {
                request_key: "mismatched-base".into(),
                session_id: "session".into(),
                repository: "fixture/repository".into(),
                branch: "feature".into(),
                base_oid: "1".repeat(40),
                expected_oid: base_target.clone(),
            },
            "",
            std::fs::metadata(&base_bundle).unwrap().len(),
            &base_remote_text,
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("base_oid must exactly match the bundle's sole prerequisite")
        );

        let unpublished = TestDir::new();
        let unpublished_remote = unpublished.0.join("remote.git");
        let unpublished_work = unpublished.0.join("work");
        std::fs::create_dir(&unpublished_remote).unwrap();
        std::fs::create_dir(&unpublished_work).unwrap();
        fixture_git(
            &unpublished_remote,
            &["init", "--bare", "--initial-branch=master"],
        );
        fixture_git(&unpublished_work, &["init", "--initial-branch=master"]);
        fixture_git(&unpublished_work, &["config", "user.name", "Local Author"]);
        fixture_git(
            &unpublished_work,
            &["config", "user.email", "local@example.test"],
        );
        std::fs::write(unpublished_work.join("base.txt"), "remote base\n").unwrap();
        fixture_git(&unpublished_work, &["add", "base.txt"]);
        fixture_git(&unpublished_work, &["commit", "-m", "remote base"]);
        let unpublished_remote_text = unpublished_remote.to_string_lossy().into_owned();
        fixture_git(
            &unpublished_work,
            &["push", &unpublished_remote_text, "master"],
        );
        std::fs::write(unpublished_work.join("local.txt"), "local only\n").unwrap();
        fixture_git(&unpublished_work, &["add", "local.txt"]);
        fixture_git(
            &unpublished_work,
            &["commit", "-m", "unpublished prerequisite"],
        );
        let unpublished_base = fixture_git(&unpublished_work, &["rev-parse", "HEAD"]);
        fixture_git(&unpublished_work, &["switch", "-c", "feature"]);
        std::fs::write(unpublished_work.join("feature.txt"), "feature\n").unwrap();
        fixture_git(&unpublished_work, &["add", "feature.txt"]);
        fixture_git(&unpublished_work, &["commit", "-m", "feature"]);
        let unpublished_bundle = unpublished.0.join("feature.bundle");
        fixture_git(
            &unpublished_work,
            &[
                "bundle",
                "create",
                &unpublished_bundle.to_string_lossy(),
                "refs/heads/feature",
                &format!("^{unpublished_base}"),
            ],
        );
        let unpublished_root = unpublished.0.join("inspect");
        private_dir(&unpublished_root).unwrap();
        let error = prepare_remote(
            &unpublished_root,
            &unpublished_bundle,
            &Submission {
                request_key: "unpublished-base".into(),
                session_id: "session".into(),
                repository: "fixture/repository".into(),
                branch: "feature".into(),
                base_oid: unpublished_base.clone(),
                expected_oid: ZERO_OID.into(),
            },
            "",
            std::fs::metadata(&unpublished_bundle).unwrap().len(),
            &unpublished_remote_text,
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fetch exact bundle prerequisite from repository")
        );
    }

    #[tokio::test]
    async fn durable_job_reviews_approves_publishes_once_and_never_replays_after_restart() {
        let (temp, remote, bundle, base, head) = publication_fixture();
        let data = temp.0.join("broker");
        std::fs::create_dir(&data).unwrap();
        let settings = Settings::load(&data).unwrap();
        settings
            .add_entry(crate::settings::EscrowEntry {
                name: "github".into(),
                hosts: vec!["api.github.com".into(), "github.com".into()],
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                fake: "fixture-fake-token".into(),
                real_env: None,
                guest_env: Some("GITHUB_TOKEN".into()),
            })
            .unwrap();
        settings.set_secret("github", "fixture-real-token").unwrap();
        let app = AppState::load(&data).unwrap();
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            app.authorize("guest", peer),
            crate::state::Authorization::Pending
        );
        app.approve_container("guest", true).unwrap();
        let input = Submission {
            request_key: "durable-publication".into(),
            session_id: "session".into(),
            repository: "fixture/repository".into(),
            branch: "feature".into(),
            base_oid: base.clone(),
            expected_oid: ZERO_OID.into(),
        };
        let submit = |app: &AppState, request_key: &str| {
            let staging = app.pushes.staging_path().unwrap();
            std::fs::copy(&bundle, &staging).unwrap();
            let mut input = input.clone();
            input.request_key = request_key.into();
            app.pushes
                .submit(
                    app,
                    &settings,
                    "guest",
                    peer,
                    UploadedBundle {
                        submission: input,
                        staging,
                        bytes: std::fs::metadata(&bundle).unwrap().len(),
                    },
                )
                .unwrap()
        };
        let accepted = submit(&app, "durable-publication");
        assert_eq!(accepted["status"], "preparing");
        let id = Uuid::parse_str(accepted["id"].as_str().unwrap()).unwrap();
        let accepted_detail = app.pushes.inspect(id).unwrap();
        assert!(accepted_detail.git_push.is_none());
        assert_eq!(accepted_detail.summary.status, Status::Preparing);
        assert_eq!(accepted_detail.summary.fingerprint.len(), 64);
        assert!(
            app.pushes
                .decide(
                    id,
                    &accepted_detail.summary.fingerprint,
                    crate::review::Decision::Approve
                )
                .is_err(),
            "preparing content must never be approvable"
        );

        let remote_text = remote.to_string_lossy().into_owned();
        app.pushes
            .tick_remote(&app, &settings, Some(&remote_text))
            .await
            .unwrap();
        let reviewed = app.pushes.inspect(id).unwrap();
        assert_eq!(reviewed.summary.status, Status::Pending);
        let review = reviewed.git_push.as_ref().unwrap();
        assert_eq!(review.base_oid, base);
        assert_eq!(review.head_oid, head);
        assert_eq!(
            review.bundle_sha256,
            accepted_detail
                .body
                .lines()
                .last()
                .unwrap()
                .trim_start_matches("Bundle SHA-256: ")
        );
        assert!(!review.patch.is_empty());
        assert!(
            app.pushes
                .decide(id, "wrong-fingerprint", crate::review::Decision::Approve)
                .is_err()
        );
        app.pushes
            .decide(
                id,
                &reviewed.summary.fingerprint,
                crate::review::Decision::Approve,
            )
            .unwrap();
        app.pushes
            .tick_remote(&app, &settings, Some(&remote_text))
            .await
            .unwrap();
        let finished = app.pushes.inspect(id).unwrap();
        assert_eq!(finished.summary.status, Status::ResponseReceived);
        let (instance, _) = app.async_identity("guest", peer).unwrap();
        let result = app.pushes.get("guest", instance, id, "session").unwrap();
        assert_eq!(result["terminal"], true);
        assert!(
            result["result"]
                .as_str()
                .unwrap()
                .contains("Verified refs/heads/feature")
        );
        assert_eq!(
            fixture_git(&remote, &["rev-parse", "refs/heads/feature"]),
            head
        );
        let metadata = std::fs::read_to_string(data.join("git-push-jobs.json")).unwrap();
        assert!(!metadata.contains("fixture-real-token"));

        let reloaded = AppState::load(&data).unwrap();
        reloaded
            .pushes
            .tick_remote(&reloaded, &settings, Some(&remote_text))
            .await
            .unwrap();
        assert_eq!(
            reloaded.pushes.inspect(id).unwrap().summary.status,
            Status::ResponseReceived,
            "completed publication must not replay after restart"
        );
        assert_eq!(
            fixture_git(&remote, &["rev-parse", "refs/heads/feature"]),
            head
        );

        let interrupted = submit(&reloaded, "restart-before-review");
        let interrupted_id = Uuid::parse_str(interrupted["id"].as_str().unwrap()).unwrap();
        let restarted = AppState::load(&data).unwrap();
        assert_eq!(
            restarted
                .pushes
                .inspect(interrupted_id)
                .unwrap()
                .summary
                .status,
            Status::Cancelled
        );
        restarted
            .pushes
            .tick_remote(&restarted, &settings, Some(&remote_text))
            .await
            .unwrap();
        assert_eq!(
            restarted
                .pushes
                .inspect(interrupted_id)
                .unwrap()
                .summary
                .status,
            Status::Cancelled,
            "pre-send restart must never resume publication"
        );
    }

    #[tokio::test]
    async fn bundle_header_rejects_extra_refs_wrong_branch_and_missing_prerequisite() {
        let temp = TestDir::new();
        for (name, text, branch) in [
            (
                "extra.bundle",
                format!(
                    "# v2 git bundle\n-{} base\n{} refs/heads/feature\n{} refs/heads/other\n\n",
                    "1".repeat(40),
                    "2".repeat(40),
                    "3".repeat(40)
                ),
                "feature",
            ),
            (
                "wrong.bundle",
                format!(
                    "# v2 git bundle\n-{} base\n{} refs/heads/wrong\n\n",
                    "1".repeat(40),
                    "2".repeat(40)
                ),
                "feature",
            ),
            (
                "full.bundle",
                format!("# v2 git bundle\n{} refs/heads/feature\n\n", "2".repeat(40)),
                "feature",
            ),
        ] {
            let path = temp.0.join(name);
            std::fs::write(&path, text).unwrap();
            assert!(read_bundle_header(&path, branch).await.is_err(), "{name}");
        }
    }

    #[test]
    fn submission_accepts_rebased_update_and_rejects_invalid_ref_shapes() {
        let valid = Submission {
            request_key: "key".into(),
            session_id: "session".into(),
            repository: "owner/repo".into(),
            branch: "feature/topic".into(),
            base_oid: "1".repeat(40),
            expected_oid: ZERO_OID.into(),
        };
        validate_submission(&valid).unwrap();
        for branch in ["refs/heads/x", "../x", "x.lock", "x~1", "x y", "x//y"] {
            let mut invalid = valid.clone();
            invalid.branch = branch.into();
            assert!(validate_submission(&invalid).is_err(), "{branch}");
        }
        let mut update = valid.clone();
        update.expected_oid = "1".repeat(40);
        validate_submission(&update).unwrap();

        assert!(
            serde_json::from_value::<Submission>(serde_json::json!({
                "request_key":"old-plugin",
                "session_id":"session",
                "repository":"owner/repo",
                "branch":"feature",
                "base_branch":"main",
                "expected_oid":ZERO_OID
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<Submission>(serde_json::json!({
                "request_key":"mixed-schema",
                "session_id":"session",
                "repository":"owner/repo",
                "branch":"feature",
                "base_oid":"1111111111111111111111111111111111111111",
                "base_branch":"main",
                "expected_oid":ZERO_OID
            }))
            .is_err()
        );
    }

    #[test]
    fn version_one_push_store_is_archived_intact_and_replaced_with_empty_v2() {
        let temp = TestDir::new();
        let legacy = br#"{"version":1,"jobs":{"legacy":"retained verbatim"}}"#;
        let metadata = temp.0.join("git-push-jobs.json");
        let artifacts = temp.0.join("git-push-jobs");
        std::fs::write(&metadata, legacy).unwrap();
        std::fs::create_dir(&artifacts).unwrap();
        std::fs::write(artifacts.join("legacy.bundle"), b"legacy artifact").unwrap();
        let (changes, _) = tokio::sync::watch::channel(0);
        let pushes = Pushes::load(&temp.0, changes).unwrap();
        assert!(
            pushes
                .0
                .data
                .lock()
                .expect("push jobs lock")
                .jobs
                .is_empty()
        );
        let current: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&metadata).unwrap()).unwrap();
        assert_eq!(current["version"], 2);
        assert_eq!(current["jobs"], serde_json::json!({}));
        assert!(artifacts.is_dir());
        let archives: Vec<_> = std::fs::read_dir(&temp.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("git-push-jobs-v1-archive-")
            })
            .collect();
        assert_eq!(archives.len(), 1);
        assert_eq!(
            std::fs::read(archives[0].join("git-push-jobs.json")).unwrap(),
            legacy
        );
        assert_eq!(
            std::fs::read(archives[0].join("git-push-jobs/legacy.bundle")).unwrap(),
            b"legacy artifact"
        );
    }

    #[test]
    fn version_one_archive_allows_missing_artifacts_and_rolls_back_partial_move() {
        let temp = TestDir::new();
        let metadata = temp.0.join("git-push-jobs.json");
        let legacy = br#"{"version":1,"jobs":{}}"#;
        std::fs::write(&metadata, legacy).unwrap();
        let (changes, _) = tokio::sync::watch::channel(0);
        Pushes::load(&temp.0, changes).unwrap();
        assert!(temp.0.join("git-push-jobs").is_dir());

        let rollback = TestDir::new();
        let rollback_metadata = rollback.0.join("git-push-jobs.json");
        std::fs::write(&rollback_metadata, legacy).unwrap();
        let error = archive_version_one(&rollback.0, &rollback_metadata, &rollback.0)
            .expect_err("moving a directory into its own child must fail");
        assert!(error.to_string().contains("metadata move was rolled back"));
        assert_eq!(std::fs::read(&rollback_metadata).unwrap(), legacy);
        assert_eq!(
            std::fs::read_dir(&rollback.0)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("git-push-jobs-v1-archive-"))
                .count(),
            0
        );
    }

    #[test]
    fn unknown_or_corrupt_push_store_names_absolute_path_and_is_untouched() {
        for bytes in [br#"{"version":3,"jobs":{}}"#.as_slice(), b"not json"] {
            let temp = TestDir::new();
            let metadata = temp.0.join("git-push-jobs.json");
            std::fs::write(&metadata, bytes).unwrap();
            let (changes, _) = tokio::sync::watch::channel(0);
            let error = match Pushes::load(&temp.0, changes) {
                Ok(_) => panic!("unsupported store must not load"),
                Err(error) => error,
            };
            assert!(metadata.is_absolute());
            let message = error.to_string();
            assert!(message.contains(&metadata.display().to_string()));
            assert!(message.contains(&temp.0.join("git-push-jobs").display().to_string()));
            assert!(message.contains("Move "));
            assert!(message.contains("Nothing was changed"));
            assert_eq!(std::fs::read(&metadata).unwrap(), bytes);
            assert_eq!(
                std::fs::read_dir(&temp.0)
                    .unwrap()
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("git-push-jobs-v1-archive-"))
                    .count(),
                0
            );
        }
    }
}
