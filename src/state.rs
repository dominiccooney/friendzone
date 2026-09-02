use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
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
}

#[derive(Clone, Debug, Serialize)]
pub struct ContainerView {
    pub id: String,
    pub name: String,
    pub state: &'static str,
    pub last_activity: DateTime<Utc>,
    pub request_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct StateView {
    pub containers: Vec<ContainerView>,
    pub requests: Vec<RequestEvent>,
}

#[derive(Clone, Debug)]
struct ContainerRecord {
    created: DateTime<Utc>,
    last_activity: DateTime<Utc>,
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
    fn touch_container(&mut self, name: &str) {
        let now = Utc::now();
        self.containers
            .entry(name.to_owned())
            .and_modify(|record| record.last_activity = now)
            .or_insert(ContainerRecord {
                created: now,
                last_activity: now,
            });
    }
}

#[derive(Clone, Default)]
pub struct AppState(Arc<RwLock<StateData>>);

impl AppState {
    pub fn record(&self, container: String, method: String, url: String, verdict: Verdict) {
        let mut state = self.0.write().expect("state lock poisoned");
        state.touch_container(&container);
        state.requests.push(RequestEvent {
            id: Uuid::new_v4(),
            at: Utc::now(),
            container,
            method,
            url,
            verdict,
        });
        if state.requests.len() > 1000 {
            state.requests.drain(..100);
        }
    }

    pub fn identify_connection(
        &self,
        peer: SocketAddr,
        presented_username: Option<String>,
    ) -> String {
        let mut state = self.0.write().expect("state lock poisoned");
        if let Some(username) = presented_username {
            state.touch_container(&username);
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

    /// Registers a container before any traffic, e.g. from the UI.
    pub fn add_container(&self, name: &str) {
        let mut state = self.0.write().expect("state lock poisoned");
        state.touch_container(name);
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
                } else {
                    "working"
                },
                last_activity: record.last_activity,
                request_count: request_counts.get(id.as_str()).copied().unwrap_or(0),
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
