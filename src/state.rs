use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allowed,
    Blocked,
    Pending,
}

#[derive(Clone, Debug, Serialize)]
pub struct RequestEvent {
    pub id: Uuid,
    pub sequence: u64,
    pub at: DateTime<Utc>,
    pub container: String,
    pub method: String,
    pub url: String,
    pub verdict: Verdict,
    /// Upstream HTTP status, once the response was seen.
    pub status: Option<u16>,
    /// Parsed summary for known providers, e.g. token counts.
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ContainerView {
    pub id: String,
    pub name: String,
    pub state: &'static str,
    /// Only observed guest traffic, not approval time or broker startup.
    pub last_activity: Option<DateTime<Utc>>,
    pub request_count: usize,
    pub approved: bool,
    /// None = any address (wildcard).
    pub pinned_ip: Option<String>,
}

/// Verdict of the container gate, checked before any policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorization {
    Allowed,
    /// Unknown or not yet approved: a join request exists in the UI.
    Pending,
    /// Known name from the wrong address.
    IpMismatch,
}

#[derive(Clone, Debug, Serialize)]
pub struct StateView {
    pub containers: Vec<ContainerView>,
    pub requests: Vec<RequestEvent>,
    pub pending_requests: Vec<crate::review::Summary>,
    pub comment_permissions: Vec<CommentPermissionView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CommentPermissionView {
    pub id: Uuid,
    pub container: String,
    pub target: crate::github::Target,
    pub credential: String,
    pub credential_active: Option<bool>,
}

#[derive(Clone, Debug)]
struct ContainerRecord {
    last_activity: Option<DateTime<Utc>>,
    /// Unapproved containers are join requests: traffic denied.
    approved: bool,
    /// Approved traffic must come from this IP; None = any.
    pinned_ip: Option<IpAddr>,
    /// Last source address seen, to make pinning one click.
    last_ip: Option<IpAddr>,
    /// Explicit host policy is durable; unreviewed join requests are not.
    managed: bool,
    /// Changes to authorization invalidate one-shot reviews, even if a kill
    /// is subsequently resumed or a removed guest is re-added under its name.
    policy_epoch: Uuid,
    comment_permissions: Vec<crate::github::Grant>,
    comment_revision: Uuid,
}

impl Default for ContainerRecord {
    fn default() -> Self {
        Self {
            last_activity: None,
            approved: false,
            pinned_ip: None,
            last_ip: None,
            managed: false,
            policy_epoch: Uuid::new_v4(),
            comment_permissions: Vec::new(),
            comment_revision: Uuid::new_v4(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedContainers {
    version: u32,
    containers: Vec<SavedContainer>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedContainer {
    name: String,
    approved: bool,
    killed: bool,
    // The explicit null is meaningful (any IP). Missing a security field
    // must not silently convert a restricted entry into a wildcard grant.
    #[serde(deserialize_with = "required_pin")]
    pinned_ip: Option<IpAddr>,
    /// Legacy policies contain no automatic comment grants.
    #[serde(default)]
    comment_permissions: Vec<crate::github::Grant>,
}

fn required_pin<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<IpAddr>, D::Error> {
    Option::<IpAddr>::deserialize(deserializer)
}

#[derive(Default)]
struct StateData {
    requests: VecDeque<RequestEvent>,
    next_sequence: u64,
    killed: HashSet<String>,
    /// First-class container registry: containers appear on first
    /// traffic or explicit add, and exist independently of the request
    /// log's retention.
    containers: HashMap<String, ContainerRecord>,
}

pub const LOG_CAPACITY: usize = 10_000;

#[derive(Default, serde::Deserialize)]
pub struct LogQuery {
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub container: String,
    #[serde(default)]
    pub verdict: String,
    pub before: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct LogPage {
    pub requests: Vec<RequestEvent>,
    pub next_before: Option<u64>,
    pub retained: usize,
    pub capacity: usize,
    pub evicted: u64,
}

impl StateData {
    /// Records activity. A previously unknown name becomes a *pending*
    /// container (a join request), never an approved one.
    fn touch_container(&mut self, name: &str, ip: Option<IpAddr>) {
        let record = self.containers.entry(name.to_owned()).or_default();
        record.last_activity = Some(Utc::now());
        if ip.is_some() {
            record.last_ip = ip;
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    data: Arc<RwLock<StateData>>,
    policy_path: Option<Arc<PathBuf>>,
    /// Bumped on every mutation; SSE subscribers wake on change and
    /// fetch a fresh view. watch coalesces bursts automatically.
    changes: tokio::sync::watch::Sender<u64>,
    pub reviews: crate::review::Queue,
    pub github: crate::github::Client,
}

impl Default for AppState {
    fn default() -> Self {
        let changes = tokio::sync::watch::Sender::new(0);
        Self {
            data: Arc::new(RwLock::new(StateData::default())),
            policy_path: None,
            reviews: crate::review::Queue::new(changes.clone()),
            github: crate::github::Client::default(),
            changes,
        }
    }
}

impl AppState {
    /// Restore only durable host decisions. Unknown/malformed formats stop
    /// startup; request logs and traffic observations remain session-local.
    pub fn load(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir).context("create container policy directory")?;
        let path = data_dir.join("containers.json");
        let saved: SavedContainers = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "invalid container policy in {} (restore or repair this file before starting)",
                    path.display()
                )
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => SavedContainers {
                version: 1,
                containers: vec![],
            },
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        if saved.version != 1 {
            anyhow::bail!(
                "unsupported container policy version {} in {}",
                saved.version,
                path.display()
            );
        }
        let mut data = StateData::default();
        for entry in saved.containers {
            if entry.name.trim().is_empty() || data.containers.contains_key(&entry.name) {
                anyhow::bail!("empty or duplicate container name in {}", path.display());
            }
            if entry.killed {
                data.killed.insert(entry.name.clone());
            }
            if entry.comment_permissions.len() > 32 {
                anyhow::bail!("too many saved comment permissions");
            }
            let mut ids = HashSet::new();
            for grant in &entry.comment_permissions {
                grant.validate()?;
                if !ids.insert(grant.id) {
                    anyhow::bail!("duplicate comment permission ID");
                }
            }
            data.containers.insert(
                entry.name,
                ContainerRecord {
                    approved: entry.approved,
                    pinned_ip: entry.pinned_ip,
                    managed: true,
                    comment_permissions: entry.comment_permissions,
                    ..Default::default()
                },
            );
        }
        let changes = tokio::sync::watch::Sender::new(0);
        Ok(Self {
            data: Arc::new(RwLock::new(data)),
            policy_path: Some(Arc::new(path)),
            reviews: crate::review::Queue::new(changes.clone()),
            github: crate::github::Client::default(),
            changes,
        })
    }

    /// All policy writers share this transaction. Disk commits before
    /// publication/notification while holding the state lock. On failure,
    /// no new grant, pin, kill/resume or removal is visible to any reader.
    fn update_policy(
        &self,
        update: impl FnOnce(&mut HashMap<String, ContainerRecord>, &mut HashSet<String>) -> Result<()>,
    ) -> Result<()> {
        let mut state = self.data.write().expect("state lock poisoned");
        let mut containers = state.containers.clone();
        let mut killed = state.killed.clone();
        update(&mut containers, &mut killed)?;
        if let Some(path) = &self.policy_path {
            let mut entries: Vec<_> = containers
                .iter()
                .filter(|(_, record)| record.managed)
                .map(|(name, record)| SavedContainer {
                    name: name.clone(),
                    approved: record.approved,
                    killed: killed.contains(name),
                    pinned_ip: record.pinned_ip,
                    comment_permissions: record.comment_permissions.clone(),
                })
                .collect();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            crate::storage::atomic_write(
                path,
                &serde_json::to_vec_pretty(&SavedContainers {
                    version: 1,
                    containers: entries,
                })?,
            )
            .context("container policy change was not applied")?;
        }
        for (name, old) in &state.containers {
            let changed = containers
                .get(name)
                .is_none_or(|new| new.approved != old.approved || new.pinned_ip != old.pinned_ip)
                || state.killed.contains(name) != killed.contains(name);
            if changed {
                if let Some(record) = containers.get_mut(name) {
                    record.policy_epoch = Uuid::new_v4();
                }
                self.reviews.cancel_container(name);
            }
        }
        state.containers = containers;
        state.killed = killed;
        drop(state);
        self.notify();
        Ok(())
    }

    /// Wakes SSE subscribers; call after every visible mutation.
    fn notify(&self) {
        self.changes.send_modify(|version| *version += 1);
    }

    /// A receiver that wakes whenever state changes.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    pub fn record(&self, container: String, method: String, url: String, verdict: Verdict) -> Uuid {
        self.record_activity(container, method, url, verdict, true)
    }
    fn record_activity(
        &self,
        container: String,
        method: String,
        url: String,
        verdict: Verdict,
        guest_traffic: bool,
    ) -> Uuid {
        let mut state = self.data.write().expect("state lock poisoned");
        if guest_traffic {
            state.touch_container(&container, None);
        }
        let id = Uuid::new_v4();
        state.next_sequence += 1;
        let sequence = state.next_sequence;
        state.requests.push_back(RequestEvent {
            id,
            sequence,
            at: Utc::now(),
            container,
            method,
            url,
            verdict,
            status: None,
            detail: None,
        });
        if state.requests.len() > LOG_CAPACITY {
            state.requests.pop_front();
        }
        drop(state);
        self.notify();
        id
    }

    /// Backfills response facts onto a logged request.
    pub fn annotate(&self, id: Uuid, status: Option<u16>, detail: Option<String>) {
        let mut state = self.data.write().expect("state lock poisoned");
        if let Some(event) = state.requests.iter_mut().rev().find(|e| e.id == id) {
            if status.is_some() {
                event.status = status;
            }
            if detail.is_some() {
                event.detail = detail;
            }
        }
        drop(state);
        self.notify();
    }

    pub fn mark_blocked(&self, id: Uuid, status: u16, detail: String) {
        let mut state = self.data.write().expect("state lock poisoned");
        if let Some(event) = state.requests.iter_mut().rev().find(|e| e.id == id) {
            event.verdict = Verdict::Blocked;
            event.status = Some(status);
            event.detail = Some(detail);
        }
        drop(state);
        self.notify();
    }

    /// Admission is the consistency boundary: policy changes before this
    /// check cancel the review. Already-admitted upstream work is not undone.
    pub fn admit_review(&self, id: Uuid, container: &str, peer: IpAddr, epoch: Uuid) -> bool {
        let mut state = self.data.write().expect("state lock poisoned");
        if state.killed.contains(container)
            || state.containers.get(container).is_none_or(|record| {
                !record.approved
                    || record.policy_epoch != epoch
                    || record.pinned_ip.is_some_and(|pin| pin != peer)
            })
        {
            return false;
        }
        if let Some(event) = state.requests.iter_mut().rev().find(|event| event.id == id) {
            event.verdict = Verdict::Allowed;
            event.detail = Some("approved once by host; forwarding original request".into());
        }
        drop(state);
        self.notify();
        true
    }

    pub fn review_epoch(&self, container: &str, peer: IpAddr) -> Option<Uuid> {
        let state = self.data.read().expect("state lock poisoned");
        let record = state.containers.get(container)?;
        (record.approved
            && !state.killed.contains(container)
            && record.pinned_ip.is_none_or(|pin| pin == peer))
        .then_some(record.policy_epoch)
    }

    pub fn add_comment_permission(
        &self,
        container: &str,
        context: &crate::github::CommentContext,
        target: crate::github::Target,
    ) -> Result<Uuid> {
        target.validate()?;
        let id = Uuid::new_v4();
        self.update_policy(|containers, killed| {
            let record = containers
                .get_mut(container)
                .context("container was removed")?;
            if !record.approved
                || killed.contains(container)
                || record.policy_epoch != context.epoch
                || record.comment_revision != context.revision
            {
                anyhow::bail!("container authorization changed; resolve a new request");
            }
            if record.comment_permissions.len() >= 32 {
                anyhow::bail!(
                    "container has 32 comment permissions; revoke unused permissions first"
                );
            }
            record.comment_permissions.retain(|grant| {
                !(grant.target.node_id == target.node_id && grant.binding == context.binding)
            });
            record.comment_permissions.push(crate::github::Grant {
                id,
                target,
                binding: context.binding.clone(),
                created_at: Utc::now(),
            });
            record.comment_revision = Uuid::new_v4();
            record.managed = true;
            Ok(())
        })?;
        self.record_activity(
            container.into(),
            "GRANT".into(),
            format!("friendzone:comment-permission/{id}"),
            Verdict::Allowed,
            false,
        );
        Ok(id)
    }

    pub fn grant_reviewed_comment(
        &self,
        request_id: Uuid,
        fingerprint: &str,
        resolution_id: Uuid,
        target: crate::github::Target,
    ) -> Result<Uuid> {
        // Acquire the current review snapshot just before durable policy
        // publication; the revision/epoch transaction prevents stale grants
        // from reviving a revoked permission or a removed/re-added guest.
        let detail = self
            .reviews
            .detail(request_id)
            .context("request no longer waiting")?;
        if detail.summary.fingerprint != fingerprint
            || detail.resolution_id != Some(resolution_id)
            || !detail
                .resolved_target
                .as_ref()
                .is_some_and(|r| r.target.same_identity(&target))
        {
            anyhow::bail!("review or resolved target changed");
        }
        self.add_comment_permission(
            &detail.summary.container,
            detail
                .comment_context
                .as_ref()
                .context("request has no comment command")?,
            target,
        )
    }
    pub fn revoke_comment_permission(&self, container: &str, id: Uuid) -> Result<()> {
        self.update_policy(|containers, _| {
            let record = containers.get_mut(container).context("unknown container")?;
            if !record.comment_permissions.iter().any(|g| g.id == id) {
                anyhow::bail!("permission already removed");
            }
            record.comment_permissions.retain(|g| g.id != id);
            record.comment_revision = Uuid::new_v4();
            Ok(())
        })?;
        self.record_activity(
            container.into(),
            "REVOKE".into(),
            format!("friendzone:comment-permission/{id}"),
            Verdict::Allowed,
            false,
        );
        Ok(())
    }
    pub fn comment_permissions(
        &self,
        container: &str,
        binding: &crate::github::Binding,
    ) -> Vec<crate::github::Grant> {
        self.data
            .read()
            .expect("state lock")
            .containers
            .get(container)
            .map(|r| {
                r.comment_permissions
                    .iter()
                    .filter(|g| g.binding == *binding)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn comment_revision(&self, container: &str) -> Option<Uuid> {
        self.data
            .read()
            .expect("state lock")
            .containers
            .get(container)
            .map(|r| r.comment_revision)
    }
    /// Atomic admission with revoke/kill/pin/removal. A later change cannot
    /// retract an upstream mutation already admitted under this boundary.
    pub fn admit_comment(
        &self,
        event: Uuid,
        container: &str,
        peer: IpAddr,
        epoch: Uuid,
        grant: &crate::github::Grant,
        target: &crate::github::Target,
    ) -> bool {
        let mut state = self.data.write().expect("state lock");
        if state.killed.contains(container)
            || state.containers.get(container).is_none_or(|r| {
                !r.approved
                    || r.policy_epoch != epoch
                    || r.pinned_ip.is_some_and(|ip| ip != peer)
                    || !r.comment_permissions.iter().any(|g| g == grant)
            })
            || !grant.target.same_identity(target)
        {
            return false;
        }
        if let Some(row) = state.requests.iter_mut().rev().find(|row| row.id == event) {
            row.verdict = Verdict::Allowed;
            row.detail = Some(format!(
                "comment permission {}: {} #{}; broker-reconstructed addComment",
                grant.id, target.repository, target.number
            ));
        }
        drop(state);
        self.notify();
        true
    }

    pub fn enqueue_review(
        &self,
        detail: crate::review::Detail,
        peer: IpAddr,
        epoch: Uuid,
    ) -> Result<crate::review::Ticket> {
        let state = self.data.read().expect("state lock poisoned");
        let name = &detail.summary.container;
        let record = state
            .containers
            .get(name)
            .context("container removed before review")?;
        if record.policy_epoch != epoch
            || !record.approved
            || state.killed.contains(name)
            || record.pinned_ip.is_some_and(|pin| pin != peer)
        {
            anyhow::bail!("container policy changed before review");
        }
        self.reviews.enqueue(detail)
    }

    /// Search the retained history before paginating, not just the live
    /// snapshot. Sequence cursors stay stable when new traffic arrives.
    pub fn log_page(&self, query: &LogQuery) -> LogPage {
        let state = self.data.read().expect("state lock poisoned");
        let search = query.search.to_lowercase();
        let limit = query.limit.unwrap_or(200).clamp(1, 500);
        let mut matches = state.requests.iter().rev().filter(|event| {
            let verdict = match event.verdict {
                Verdict::Allowed => "allowed",
                Verdict::Blocked => "blocked",
                Verdict::Pending => "pending",
            };
            query.before.is_none_or(|before| event.sequence < before)
                && (query.container.is_empty() || query.container == event.container)
                && (query.verdict.is_empty() || query.verdict == verdict)
                && (search.is_empty()
                    || format!(
                        "{} {} {} {} {}",
                        event.container,
                        event.method,
                        event.url,
                        event.status.map(|s| s.to_string()).unwrap_or_default(),
                        event.detail.as_deref().unwrap_or_default()
                    )
                    .to_lowercase()
                    .contains(&search))
        });
        let requests: Vec<_> = matches.by_ref().take(limit).cloned().collect();
        let next_before = matches
            .next()
            .and_then(|_| requests.last().map(|r| r.sequence));
        LogPage {
            requests,
            next_before,
            retained: state.requests.len(),
            capacity: LOG_CAPACITY,
            evicted: state
                .next_sequence
                .saturating_sub(state.requests.len() as u64),
        }
    }

    /// The container gate: known + approved + right address, checked
    /// before any policy. Unknown names become pending join requests.
    pub fn authorize(&self, container: &str, peer_ip: IpAddr) -> Authorization {
        let mut state = self.data.write().expect("state lock poisoned");
        state.touch_container(container, Some(peer_ip));
        let record = state.containers.get(container).expect("just touched");
        let verdict = if !record.approved {
            Authorization::Pending
        } else {
            match record.pinned_ip {
                Some(pinned) if pinned != peer_ip => Authorization::IpMismatch,
                _ => Authorization::Allowed,
            }
        };
        drop(state);
        // A pending gate check is a join request appearing: wake the UI.
        self.notify();
        verdict
    }

    /// Registers a pre-approved container from the UI (wildcard IP
    /// until pinned).
    pub fn add_container(&self, name: &str) -> Result<()> {
        self.update_policy(|containers, _| {
            let record = containers.entry(name.to_owned()).or_default();
            record.approved = true;
            record.managed = true;
            Ok(())
        })
    }

    /// Approves a join request, optionally pinning it to the address it
    /// last connected from.
    pub fn approve_container(&self, name: &str, pin_to_last_ip: bool) -> Result<()> {
        self.update_policy(|containers, _| {
            let record = containers.get_mut(name).context("unknown container; no approval changed")?;
            if pin_to_last_ip {
                record.pinned_ip = Some(record.last_ip.context("no guest address observed this session; set an explicit IP pin or wait for the guest to connect")?);
            }
            record.approved = true;
            record.managed = true;
            Ok(())
        })
    }

    /// Sets or clears (None = wildcard) a container's pinned IP.
    pub fn set_pinned_ip(&self, name: &str, ip: Option<IpAddr>) -> Result<()> {
        self.update_policy(|containers, _| {
            let record = containers
                .get_mut(name)
                .context("unknown container; no IP pin changed")?;
            record.pinned_ip = ip;
            record.managed = true;
            Ok(())
        })
    }

    /// Removes a container: registry entry, kill flag, and connection
    /// identities go; log rows stay for audit. If it reconnects it is a
    /// new container (and will re-appear live — kill first to stop it).
    pub fn remove_container(&self, name: &str) -> Result<()> {
        self.update_policy(|containers, killed| {
            containers.remove(name);
            killed.remove(name);
            Ok(())
        })
    }

    pub fn is_killed(&self, container: &str) -> bool {
        self.data
            .read()
            .expect("state lock poisoned")
            .killed
            .contains(container)
    }

    pub fn set_killed(&self, container: String, killed: bool) -> Result<()> {
        self.update_policy(|containers, killed_names| {
            containers.entry(container.clone()).or_default().managed = true;
            if killed {
                killed_names.insert(container);
            } else {
                killed_names.remove(&container);
            }
            Ok(())
        })
    }

    pub fn view(&self) -> StateView {
        let state = self.data.read().expect("state lock poisoned");
        let mut request_counts: HashMap<&str, usize> = HashMap::new();
        for event in &state.requests {
            *request_counts.entry(event.container.as_str()).or_default() += 1;
        }
        let mut containers: Vec<_> = state
            .containers
            .iter()
            .map(|(id, record)| ContainerView {
                id: id.clone(),
                name: id.clone(),
                state: if state.killed.contains(id) {
                    "killed"
                } else if !record.approved {
                    "pending"
                } else {
                    "approved"
                },
                last_activity: record.last_activity,
                request_count: request_counts.get(id.as_str()).copied().unwrap_or(0),
                approved: record.approved,
                pinned_ip: record
                    .pinned_ip
                    .map(|ip| ip.to_string())
                    .or_else(|| record.last_ip.map(|ip| format!("~{ip}"))),
            })
            .collect();
        containers.sort_by(|a, b| {
            b.last_activity
                .cmp(&a.last_activity)
                .then_with(|| a.id.cmp(&b.id))
        });
        StateView {
            containers,
            comment_permissions: state
                .containers
                .iter()
                .flat_map(|(name, r)| {
                    r.comment_permissions.iter().map(|g| CommentPermissionView {
                        id: g.id,
                        container: name.clone(),
                        target: g.target.clone(),
                        credential: g.binding.entry.clone(),
                        credential_active: None,
                    })
                })
                .collect(),
            pending_requests: self.reviews.summaries(),
            requests: state.requests.iter().rev().take(200).cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_permissions_are_durable_revocable_and_transactional_with_guest_policy() {
        let dir = TestDir::new();
        let state = AppState::load(&dir.0).unwrap();
        let peer = "127.0.0.1".parse().unwrap();
        state.authorize("guest", peer);
        state.approve_container("guest", true).unwrap();
        let binding = crate::github::Binding {
            entry: "github".into(),
            digest: "a".repeat(64),
        };
        let context = crate::github::CommentContext {
            binding: binding.clone(),
            subject_id: "legacy".into(),
            epoch: state.review_epoch("guest", peer).unwrap(),
            revision: state.comment_revision("guest").unwrap(),
        };
        let target = crate::github::tests::target();
        let last_activity = state.view().containers[0].last_activity;
        let id = state
            .add_comment_permission("guest", &context, target.clone())
            .unwrap();
        assert_eq!(
            state.view().containers[0].last_activity,
            last_activity,
            "grant is not guest traffic"
        );
        assert!(
            state
                .add_comment_permission("guest", &context, target.clone())
                .is_err(),
            "stale grant cannot replay"
        );
        let loaded = AppState::load(&dir.0).unwrap();
        let grant = loaded.comment_permissions("guest", &binding).pop().unwrap();
        assert_eq!(grant.id, id);
        let snapshot = serde_json::to_string(&loaded.view()).unwrap();
        assert!(!snapshot.contains(&binding.digest));
        let epoch = loaded.review_epoch("guest", peer).unwrap();
        assert!(loaded.admit_comment(Uuid::new_v4(), "guest", peer, epoch, &grant, &target));
        assert!(!loaded.admit_comment(
            Uuid::new_v4(),
            "guest",
            "127.0.0.2".parse().unwrap(),
            epoch,
            &grant,
            &target
        ));
        let path = dir.0.join("containers.json");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(loaded.revoke_comment_permission("guest", id).is_err());
        assert_eq!(loaded.comment_permissions("guest", &binding).len(), 1);
        fs::remove_dir(&path).unwrap();
        loaded.revoke_comment_permission("guest", id).unwrap();
        let stale = crate::github::CommentContext {
            epoch: loaded.review_epoch("guest", peer).unwrap(),
            ..context.clone()
        };
        assert!(
            loaded
                .add_comment_permission("guest", &stale, target.clone())
                .is_err(),
            "revocation must prevent stale UI from restoring grant"
        );
        assert!(!loaded.admit_comment(Uuid::new_v4(), "guest", peer, epoch, &grant, &target));
        assert!(
            AppState::load(&dir.0)
                .unwrap()
                .comment_permissions("guest", &binding)
                .is_empty()
        );
        let context = crate::github::CommentContext {
            epoch: loaded.review_epoch("guest", peer).unwrap(),
            revision: loaded.comment_revision("guest").unwrap(),
            ..context
        };
        loaded
            .add_comment_permission("guest", &context, target.clone())
            .unwrap();
        loaded.set_killed("guest".into(), true).unwrap();
        assert!(!loaded.admit_comment(Uuid::new_v4(), "guest", peer, epoch, &grant, &target));
        assert!(
            loaded
                .add_comment_permission("guest", &context, target.clone())
                .is_err()
        );
        loaded.remove_container("guest").unwrap();
        loaded.add_container("guest").unwrap();
        assert!(
            AppState::load(&dir.0)
                .unwrap()
                .comment_permissions("guest", &binding)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn restart_restores_guest_permission_but_never_pending_request_or_grant() {
        let dir = TestDir::new();
        let state = AppState::load(&dir.0).unwrap();
        state.add_container("guest").unwrap();
        let peer = "127.0.0.1".parse().unwrap();
        let epoch = state.review_epoch("guest", peer).unwrap();
        let detail = crate::review::Detail::from_request(
            "guest",
            &hudsucker::hyper::Request::builder()
                .method("DELETE")
                .uri("https://api.github.com/repos/x/y")
                .body(hudsucker::Body::empty())
                .unwrap(),
            b"",
        )
        .unwrap();
        let id = detail.summary.id;
        let ticket = state.enqueue_review(detail.clone(), peer, epoch).unwrap();
        let reloaded = AppState::load(&dir.0).unwrap();
        assert!(reloaded.view().containers[0].approved);
        assert!(reloaded.view().pending_requests.is_empty());
        assert!(
            reloaded
                .reviews
                .decide(
                    id,
                    &detail.summary.fingerprint,
                    crate::review::Decision::Approve
                )
                .is_err()
        );
        assert!(!reloaded.admit_review(id, "guest", peer, epoch));
        drop(ticket);
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("fz-container-policy-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn persisted_policy_keeps_approval_pin_and_kill_but_not_traffic() {
        let dir = TestDir::new();
        let state = AppState::load(&dir.0).unwrap();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        state.authorize("guest", ip);
        state.approve_container("guest", true).unwrap();
        state.set_killed("guest".into(), true).unwrap();
        state.add_container("preapproved").unwrap();
        assert!(
            state
                .view()
                .containers
                .iter()
                .find(|c| c.id == "preapproved")
                .unwrap()
                .last_activity
                .is_none(),
            "administration is not guest activity"
        );
        state.authorize("unreviewed", ip);
        let resumed = AppState::load(&dir.0).unwrap();
        assert!(resumed.is_killed("guest"));
        let view = resumed.view();
        assert!(view.requests.is_empty());
        assert_eq!(view.containers.len(), 2, "unreviewed joins are not durable");
        assert!(view.containers.iter().all(|c| c.last_activity.is_none()));
        let guest = view.containers.iter().find(|c| c.id == "guest").unwrap();
        assert!(guest.approved);
        assert_eq!(guest.pinned_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(
            resumed.authorize("guest", "10.0.0.6".parse().unwrap()),
            Authorization::IpMismatch
        );
        resumed.set_killed("guest".into(), false).unwrap();
        resumed.set_pinned_ip("guest", None).unwrap();
        let reloaded = AppState::load(&dir.0).unwrap();
        assert!(!reloaded.is_killed("guest"));
        assert_eq!(
            reloaded.authorize("guest", "10.0.0.6".parse().unwrap()),
            Authorization::Allowed
        );
        reloaded.remove_container("guest").unwrap();
        let removed = AppState::load(&dir.0).unwrap();
        assert!(!removed.view().containers.iter().any(|c| c.id == "guest"));
        assert_eq!(removed.authorize("guest", ip), Authorization::Pending);
    }

    #[test]
    fn failed_policy_save_does_not_publish_or_notify_any_change() {
        let dir = TestDir::new();
        let state = AppState::load(&dir.0).unwrap();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        state.authorize("guest", ip);
        state.approve_container("guest", true).unwrap();
        state.set_killed("guest".into(), true).unwrap();
        state.authorize("pending", ip);
        let path = dir.0.join("containers.json");
        let saved = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let before = serde_json::to_value(state.view()).unwrap();
        let changes = state.subscribe();
        assert!(state.set_killed("guest".into(), false).is_err());
        assert!(state.set_pinned_ip("guest", None).is_err());
        assert!(state.remove_container("guest").is_err());
        assert!(state.add_container("new").is_err());
        assert!(state.approve_container("pending", false).is_err());
        assert_eq!(serde_json::to_value(state.view()).unwrap(), before);
        assert!(!changes.has_changed().unwrap());
        fs::remove_dir(&path).unwrap();
        fs::write(path, saved).unwrap();
        assert!(AppState::load(&dir.0).unwrap().is_killed("guest"));
    }

    #[test]
    fn invalid_or_incomplete_policy_is_never_treated_as_empty() {
        let dir = TestDir::new();
        for value in [
            "{",
            r#"{"version":2,"containers":[]}"#,
            r#"{"version":1,"containers":[{"name":"guest","approved":true,"killed":false}]}"#,
            r#"{"version":1,"containers":[{"name":"guest","approved":true,"killed":false,"pinned_ip":"not-an-ip"}]}"#,
            r#"{"version":1,"containers":[{"name":"guest","approved":true,"killed":false,"pinned_ip":null},{"name":"guest","approved":false,"killed":false,"pinned_ip":null}]}"#,
        ] {
            fs::write(dir.0.join("containers.json"), value).unwrap();
            assert!(
                AppState::load(&dir.0).is_err(),
                "accepted invalid policy {value}"
            );
        }
    }

    #[test]
    fn approvals_do_not_claim_work_or_synthesize_guest_traffic() {
        let state = AppState::default();
        state.add_container("guest").unwrap();
        assert_eq!(state.view().containers[0].state, "approved");
        assert!(state.view().containers[0].last_activity.is_none());
        assert!(
            state.approve_container("guest", true).is_err(),
            "pinning without observed IP must not become wildcard approval"
        );
        state.authorize("guest", "10.0.0.5".parse().unwrap());
        let seen = state.view().containers[0].last_activity;
        state.approve_container("guest", true).unwrap();
        state.set_killed("guest".into(), true).unwrap();
        state.set_killed("guest".into(), false).unwrap();
        assert_eq!(state.view().containers[0].last_activity, seen);
        assert_eq!(state.view().containers[0].state, "approved");
    }

    #[test]
    fn retained_log_searches_before_paging_with_stable_cursors() {
        let state = AppState::default();
        for index in 0..(LOG_CAPACITY + 50) {
            let id = state.record(
                "guest".into(),
                "GET".into(),
                format!("https://example.test/{index}"),
                Verdict::Allowed,
            );
            if index == 100 {
                state.mark_blocked(id, 403, "unique denial".into());
            }
        }
        let found = state.log_page(&LogQuery {
            search: "unique denial".into(),
            verdict: "blocked".into(),
            ..Default::default()
        });
        assert_eq!(found.requests.len(), 1);
        assert_eq!(found.retained, LOG_CAPACITY);
        assert_eq!(found.evicted, 50);
        let first = state.log_page(&LogQuery {
            limit: Some(2),
            ..Default::default()
        });
        state.record("guest".into(), "GET".into(), "new".into(), Verdict::Allowed);
        let next = state.log_page(&LogQuery {
            before: first.next_before,
            limit: Some(2),
            ..Default::default()
        });
        assert_eq!(next.requests[0].sequence + 1, first.requests[1].sequence);
        assert_eq!(
            state
                .log_page(&LogQuery {
                    search: "https://example.test/0".into(),
                    ..Default::default()
                })
                .requests
                .len(),
            0
        );
    }

    #[test]
    fn container_gate_denies_unknown_and_wrong_ip() {
        let state = AppState::default();
        let ip1: IpAddr = "10.0.0.5".parse().unwrap();
        let ip2: IpAddr = "10.0.0.6".parse().unwrap();
        // Unknown container: pending join request, denied.
        assert_eq!(state.authorize("stranger", ip1), Authorization::Pending);
        assert!(
            state
                .view()
                .containers
                .iter()
                .any(|c| c.id == "stranger" && c.state == "pending")
        );
        // Approve and pin to the IP it came from.
        state.approve_container("stranger", true).unwrap();
        assert_eq!(state.authorize("stranger", ip1), Authorization::Allowed);
        // Same name from a different address: name-guessing is denied.
        assert_eq!(state.authorize("stranger", ip2), Authorization::IpMismatch);
        // Clearing the pin allows any address again.
        state.set_pinned_ip("stranger", None).unwrap();
        assert_eq!(state.authorize("stranger", ip2), Authorization::Allowed);
        // UI-added containers are pre-approved with wildcard IP.
        state.add_container("reviewer").unwrap();
        assert_eq!(state.authorize("reviewer", ip2), Authorization::Allowed);
    }

    #[test]
    fn containers_add_and_remove_dynamically() {
        let state = AppState::default();
        // Appear via explicit add and via traffic, independently.
        state.add_container("reviewer").unwrap();
        state.record(
            "triager".into(),
            "GET".into(),
            "https://x/".into(),
            Verdict::Allowed,
        );
        let view = state.view();
        let names: Vec<&str> = view.containers.iter().map(|c| c.id.as_str()).collect();
        assert!(names.contains(&"reviewer") && names.contains(&"triager"));
        // Removal drops the container and clears its kill flag, but
        // keeps its log rows for audit.
        state.set_killed("triager".into(), true).unwrap();
        state.remove_container("triager").unwrap();
        let view = state.view();
        assert!(!view.containers.iter().any(|c| c.id == "triager"));
        assert!(view.requests.iter().any(|r| r.container == "triager"));
        assert!(!state.is_killed("triager"));
    }

    #[test]
    fn kill_state_is_reversible() {
        let state = AppState::default();
        state.set_killed("reviewer".into(), true).unwrap();
        assert!(state.is_killed("reviewer"));
        state.set_killed("reviewer".into(), false).unwrap();
        assert!(!state.is_killed("reviewer"));
    }
}
