use std::time::Duration;

use anyhow::{Context, Result};

/// Guest-to-broker bootstrap and health requests must work before the
/// container is approved, even after sourcing friendzone-env.sh. Do not
/// send them through the environment's proxy and its container gate.
pub fn broker_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build direct broker client")
}
