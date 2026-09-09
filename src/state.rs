use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allowed,
    Blocked,
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
    pub last_activity: DateTime<Utc>,
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
}

#[derive(Clone, Debug)]
struct ContainerRecord {
    #[allow(dead_code)]
    created: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    /// Unapproved containers are join requests: traffic denied.
    approved: bool,
    /// Approved traffic must come from this IP; None = any.
    pinned_ip: Option<IpAddr>,
    /// Last source address seen, to make pinning one click.
    last_ip: Option<IpAddr>,
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
        let now = Utc::now();
        let record = self
            .containers
            .entry(name.to_owned())
            .or_insert(ContainerRecord {
                created: now,
                last_activity: now,
                approved: false,
                pinned_ip: None,
                last_ip: None,
            });
        record.last_activity = now;
        if ip.is_some() {
            record.last_ip = ip;
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    data: Arc<RwLock<StateData>>,
    /// Bumped on every mutation; SSE subscribers wake on change and
    /// fetch a fresh view. watch coalesces bursts automatically.
    changes: tokio::sync::watch::Sender<u64>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            data: Arc::new(RwLock::new(StateData::default())),
            changes: tokio::sync::watch::Sender::new(0),
        }
    }
}

impl AppState {
    /// Wakes SSE subscribers; call after every visible mutation.
    fn notify(&self) {
        self.changes.send_modify(|version| *version += 1);
    }

    /// A receiver that wakes whenever state changes.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    pub fn record(&self, container: String, method: String, url: String, verdict: Verdict) -> Uuid {
        let mut state = self.data.write().expect("state lock poisoned");
        state.touch_container(&container, None);
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
    pub fn add_container(&self, name: &str) {
        let mut state = self.data.write().expect("state lock poisoned");
        state.touch_container(name, None);
        state
            .containers
            .get_mut(name)
            .expect("just touched")
            .approved = true;
        drop(state);
        self.notify();
    }

    /// Approves a join request, optionally pinning it to the address it
    /// last connected from.
    pub fn approve_container(&self, name: &str, pin_to_last_ip: bool) {
        let mut state = self.data.write().expect("state lock poisoned");
        if let Some(record) = state.containers.get_mut(name) {
            record.approved = true;
            if pin_to_last_ip {
                record.pinned_ip = record.last_ip;
            }
        }
        drop(state);
        self.notify();
    }

    /// Sets or clears (None = wildcard) a container's pinned IP.
    pub fn set_pinned_ip(&self, name: &str, ip: Option<IpAddr>) {
        let mut state = self.data.write().expect("state lock poisoned");
        if let Some(record) = state.containers.get_mut(name) {
            record.pinned_ip = ip;
        }
        drop(state);
        self.notify();
    }

    /// Removes a container: registry entry, kill flag, and connection
    /// identities go; log rows stay for audit. If it reconnects it is a
    /// new container (and will re-appear live — kill first to stop it).
    pub fn remove_container(&self, name: &str) {
        let mut state = self.data.write().expect("state lock poisoned");
        state.containers.remove(name);
        state.killed.remove(name);
        drop(state);
        self.notify();
    }

    pub fn is_killed(&self, container: &str) -> bool {
        self.data
            .read()
            .expect("state lock poisoned")
            .killed
            .contains(container)
    }

    pub fn set_killed(&self, container: String, killed: bool) {
        let mut state = self.data.write().expect("state lock poisoned");
        if killed {
            state.killed.insert(container);
        } else {
            state.killed.remove(&container);
        }
        drop(state);
        self.notify();
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
                    "working"
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
        containers.sort_by_key(|container| std::cmp::Reverse(container.last_activity));
        StateView {
            containers,
            requests: state.requests.iter().rev().take(200).cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        state.approve_container("stranger", true);
        assert_eq!(state.authorize("stranger", ip1), Authorization::Allowed);
        // Same name from a different address: name-guessing is denied.
        assert_eq!(state.authorize("stranger", ip2), Authorization::IpMismatch);
        // Clearing the pin allows any address again.
        state.set_pinned_ip("stranger", None);
        assert_eq!(state.authorize("stranger", ip2), Authorization::Allowed);
        // UI-added containers are pre-approved with wildcard IP.
        state.add_container("reviewer");
        assert_eq!(state.authorize("reviewer", ip2), Authorization::Allowed);
    }

    #[test]
    fn containers_add_and_remove_dynamically() {
        let state = AppState::default();
        // Appear via explicit add and via traffic, independently.
        state.add_container("reviewer");
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
        state.set_killed("triager".into(), true);
        state.remove_container("triager");
        let view = state.view();
        assert!(!view.containers.iter().any(|c| c.id == "triager"));
        assert!(view.requests.iter().any(|r| r.container == "triager"));
        assert!(!state.is_killed("triager"));
    }

    #[test]
    fn kill_state_is_reversible() {
        let state = AppState::default();
        state.set_killed("reviewer".into(), true);
        assert!(state.is_killed("reviewer"));
        state.set_killed("reviewer".into(), false);
        assert!(!state.is_killed("reviewer"));
    }
}
