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

#[derive(Default)]
struct StateData {
    requests: Vec<RequestEvent>,
    killed: HashSet<String>,
    connection_identities: HashMap<SocketAddr, (String, Instant)>,
}

#[derive(Clone, Default)]
pub struct AppState(Arc<RwLock<StateData>>);

impl AppState {
    pub fn record(&self, container: String, method: String, url: String, verdict: Verdict) {
        let mut state = self.0.write().expect("state lock poisoned");
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
        let mut grouped: HashMap<&str, Vec<&RequestEvent>> = HashMap::new();
        for event in &state.requests {
            grouped.entry(&event.container).or_default().push(event);
        }
        let mut containers: Vec<_> = grouped
            .into_iter()
            .map(|(id, events)| ContainerView {
                id: id.to_owned(),
                name: id.to_owned(),
                state: if state.killed.contains(id) {
                    "killed"
                } else {
                    "working"
                },
                last_activity: events.last().expect("nonempty group").at,
                request_count: events.len(),
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
    fn kill_state_is_reversible() {
        let state = AppState::default();
        state.set_killed("reviewer".into(), true);
        assert!(state.is_killed("reviewer"));
        state.set_killed("reviewer".into(), false);
        assert!(!state.is_killed("reviewer"));
    }
}
