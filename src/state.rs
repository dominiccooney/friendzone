use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
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
    requests: Vec<RequestEvent>,
    killed: HashSet<String>,
    /// First-class container registry: containers appear on first
    /// traffic or explicit add, and exist independently of the request
    /// log's retention.
    containers: HashMap<String, ContainerRecord>,
    connection_identities: HashMap<SocketAddr, (String, Instant)>,
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

#[derive(Clone, Default)]
pub struct AppState(Arc<RwLock<StateData>>);

impl AppState {
    pub fn record(&self, container: String, method: String, url: String, verdict: Verdict) -> Uuid {
        let mut state = self.0.write().expect("state lock poisoned");
        state.touch_container(&container, None);
        let id = Uuid::new_v4();
        state.requests.push(RequestEvent {
            id,
            at: Utc::now(),
            container,
            method,
            url,
            verdict,
            status: None,
            detail: None,
        });
        if state.requests.len() > 1000 {
            state.requests.drain(..100);
        }
        id
    }

    /// Backfills response facts onto a logged request.
    pub fn annotate(&self, id: Uuid, status: Option<u16>, detail: Option<String>) {
        let mut state = self.0.write().expect("state lock poisoned");
        if let Some(event) = state.requests.iter_mut().rev().find(|e| e.id == id) {
            if status.is_some() {
                event.status = status;
            }
            if detail.is_some() {
                event.detail = detail;
            }
        }
    }

    pub fn identify_connection(
        &self,
        peer: SocketAddr,
        presented_username: Option<String>,
    ) -> String {
        let mut state = self.0.write().expect("state lock poisoned");
        if let Some(username) = presented_username {
            state.touch_container(&username, Some(peer.ip()));
            state
                .connection_identities
                .insert(peer, (username.clone(), Instant::now()));
            if state.connection_identities.len() > 4096 {
                state
                    .connection_identities
                    .retain(|_, (_, seen)| seen.elapsed() < Duration::from_secs(60 * 60));
            }
            username
        } else {
            state
                .connection_identities
                .get(&peer)
                .map(|(username, _)| username.clone())
                .unwrap_or_else(|| peer.ip().to_string())
        }
    }

    /// The container gate: known + approved + right address, checked
    /// before any policy. Unknown names become pending join requests.
    pub fn authorize(&self, container: &str, peer_ip: IpAddr) -> Authorization {
        let mut state = self.0.write().expect("state lock poisoned");
        state.touch_container(container, Some(peer_ip));
        let record = state.containers.get(container).expect("just touched");
        if !record.approved {
            return Authorization::Pending;
        }
        match record.pinned_ip {
            Some(pinned) if pinned != peer_ip => Authorization::IpMismatch,
            _ => Authorization::Allowed,
        }
    }

    /// Approval check without an address (used where the peer IP is
    /// not available, e.g. the MCP endpoint).
    pub fn is_approved(&self, container: &str) -> bool {
        self.0
            .read()
            .expect("state lock poisoned")
            .containers
            .get(container)
            .is_some_and(|record| record.approved)
    }

    /// Registers a pre-approved container from the UI (wildcard IP
    /// until pinned).
    pub fn add_container(&self, name: &str) {
        let mut state = self.0.write().expect("state lock poisoned");
        state.touch_container(name, None);
        state
            .containers
            .get_mut(name)
            .expect("just touched")
            .approved = true;
    }

    /// Approves a join request, optionally pinning it to the address it
    /// last connected from.
    pub fn approve_container(&self, name: &str, pin_to_last_ip: bool) {
        let mut state = self.0.write().expect("state lock poisoned");
        if let Some(record) = state.containers.get_mut(name) {
            record.approved = true;
            if pin_to_last_ip {
                record.pinned_ip = record.last_ip;
            }
        }
    }

    /// Sets or clears (None = wildcard) a container's pinned IP.
    pub fn set_pinned_ip(&self, name: &str, ip: Option<IpAddr>) {
        let mut state = self.0.write().expect("state lock poisoned");
        if let Some(record) = state.containers.get_mut(name) {
            record.pinned_ip = ip;
        }
    }

    /// Removes a container: registry entry, kill flag, and connection
    /// identities go; log rows stay for audit. If it reconnects it is a
    /// new container (and will re-appear live — kill first to stop it).
    pub fn remove_container(&self, name: &str) {
        let mut state = self.0.write().expect("state lock poisoned");
        state.containers.remove(name);
        state.killed.remove(name);
        state
            .connection_identities
            .retain(|_, (identity, _)| identity != name);
    }

    pub fn is_killed(&self, container: &str) -> bool {
        self.0
            .read()
            .expect("state lock poisoned")
            .killed
            .contains(container)
    }

    pub fn set_killed(&self, container: String, killed: bool) {
        let mut state = self.0.write().expect("state lock poisoned");
        if killed {
            state.killed.insert(container);
        } else {
            state.killed.remove(&container);
        }
    }

    pub fn view(&self) -> StateView {
        let state = self.0.read().expect("state lock poisoned");
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
    fn container_gate_denies_unknown_and_wrong_ip() {
        let state = AppState::default();
        let ip1: IpAddr = "10.0.0.5".parse().unwrap();
        let ip2: IpAddr = "10.0.0.6".parse().unwrap();
        // Unknown container: pending join request, denied.
        assert_eq!(state.authorize("stranger", ip1), Authorization::Pending);
        assert!(state.view().containers.iter().any(|c| c.id == "stranger" && c.state == "pending"));
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
        state.record("triager".into(), "GET".into(), "https://x/".into(), Verdict::Allowed);
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
