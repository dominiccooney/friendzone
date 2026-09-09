//! Cline account device-code OAuth. MCP server OAuth lives in mcp_oauth.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::settings::Settings;

// ---------------------------------------------------------------------
// Cline account sign-in via the WorkOS device-code flow — the current
// method (the SDK defaults useWorkOSDeviceAuth to true; the legacy
// callback flow redirects into the editor extension, which we are not).
// Contract from cline/cline sdk/packages/core/src/auth/cline.ts:
//   device:   POST https://api.workos.com/user_management/authorize/device
//               form: client_id
//               -> {device_code, user_code, verification_uri,
//                   verification_uri_complete?, expires_in?, interval?}
//   poll:     POST https://api.workos.com/user_management/authenticate
//               form: grant_type=urn:ietf:params:oauth:grant-type:device_code,
//                     device_code, client_id
//               -> {access_token, refresh_token} | {"error":
//                  "authorization_pending" | "slow_down" | terminal}
//   register: POST {base}/api/v1/auth/register
//               json: {accessToken, refreshToken}
//   refresh:  POST {base}/api/v1/auth/refresh
//               json: {"refreshToken":..,"grantType":"refresh_token"}
// Cline responses: {"success":true,"data":{"accessToken","refreshToken",
//                   "expiresAt"(ISO 8601),..}}
// ---------------------------------------------------------------------

pub const CLINE_API_BASE: &str = "https://api.cline.bot";
const WORKOS_API_BASE: &str = "https://api.workos.com";
/// Cline's production WorkOS client id (cline/cline
/// sdk/packages/shared/src/runtime/cline-environment.ts).
const CLINE_WORKOS_CLIENT_ID: &str = "client_01K3A541FN8TA3EPPHTD2325AR";

/// A Cline account session backing an escrow entry. The current access
/// token is mirrored into the entry's secret so the proxy's synchronous
/// substitution path never waits on a refresh.
#[derive(Clone, Debug, serde::Serialize, Deserialize)]
pub struct ClineSession {
    pub refresh_token: String,
    pub expires_at: i64,
    pub api_base_url: String,
}

impl ClineSession {
    pub fn secret_name(entry: &str) -> String {
        format!("cline-oauth:{entry}")
    }

    pub fn load(settings: &Settings, entry: &str) -> Option<Self> {
        settings
            .secret(&Self::secret_name(entry))
            .and_then(|text| serde_json::from_str(&text).ok())
    }

    pub fn expires_soon(&self) -> bool {
        // Cline's own SDK refreshes 5 minutes early; match it.
        self.expires_at - 300 <= chrono::Utc::now().timestamp()
    }
}

/// Device-flow login state, per escrow entry, for the UI to poll.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ClineLoginState {
    /// Show this code; the user confirms it in the browser.
    WaitingForUser {
        user_code: String,
        verification_uri: String,
    },
    Connected,
    Failed {
        error: String,
    },
}

#[derive(Clone, Default)]
pub struct ClineFlows(Arc<Mutex<HashMap<String, ClineLoginState>>>);

impl ClineFlows {
    pub fn status(&self, entry: &str) -> Option<ClineLoginState> {
        self.0.lock().expect("cline flows lock").get(entry).cloned()
    }

    fn set(&self, entry: &str, state: ClineLoginState) {
        self.0
            .lock()
            .expect("cline flows lock")
            .insert(entry.to_owned(), state);
    }

    /// Starts the device flow: requests a device authorization, records
    /// the user code for display, and spawns the background poller that
    /// completes the login without any callback into this process.
    pub async fn start(&self, entry: &str, settings: &Settings) -> Result<ClineLoginState> {
        let device = request_device_authorization().await?;
        let shown = ClineLoginState::WaitingForUser {
            user_code: device.user_code.clone(),
            verification_uri: device
                .verification_uri_complete
                .clone()
                .unwrap_or_else(|| device.verification_uri.clone()),
        };
        self.set(entry, shown.clone());

        let flows = self.clone();
        let settings = settings.clone();
        let entry = entry.to_owned();
        tokio::spawn(async move {
            match poll_and_register(&device, &settings, &entry).await {
                Ok(()) => flows.set(&entry, ClineLoginState::Connected),
                Err(error) => flows.set(
                    &entry,
                    ClineLoginState::Failed {
                        error: format!("{error:#}"),
                    },
                ),
            }
        });
        Ok(shown)
    }
}

struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

async fn request_device_authorization() -> Result<DeviceAuthorization> {
    let response = reqwest::Client::new()
        .post(format!(
            "{WORKOS_API_BASE}/user_management/authorize/device"
        ))
        .form(&[("client_id", CLINE_WORKOS_CLIENT_ID)])
        .send()
        .await
        .context("device authorization request")?;
    let status = response.status();
    let json: serde_json::Value = response
        .json()
        .await
        .context("parse device authorization")?;
    if !status.is_success() {
        anyhow::bail!("device authorization returned {status}: {json}");
    }
    let field = |name: &str| {
        json.get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .with_context(|| format!("no {name} in device authorization"))
    };
    Ok(DeviceAuthorization {
        device_code: field("device_code")?,
        user_code: field("user_code")?,
        verification_uri: field("verification_uri")?,
        verification_uri_complete: json
            .get("verification_uri_complete")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        expires_in: json
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(300),
        interval: json
            .get("interval")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(5)
            .max(1),
    })
}

/// Polls WorkOS until the user confirms the code, then registers the
/// WorkOS tokens with Cline's backend and stores the session.
async fn poll_and_register(
    device: &DeviceAuthorization,
    settings: &Settings,
    entry: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(device.expires_in);
    let mut interval = device.interval;
    let (workos_access, workos_refresh) = loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("device authorization timed out; start the sign-in again");
        }
        let response = client
            .post(format!("{WORKOS_API_BASE}/user_management/authenticate"))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device.device_code),
                ("client_id", CLINE_WORKOS_CLIENT_ID),
            ])
            .send()
            .await
            .context("token poll")?;
        let ok = response.status().is_success();
        let json: serde_json::Value = response.json().await.unwrap_or_default();
        if ok {
            let access = json
                .get("access_token")
                .and_then(serde_json::Value::as_str)
                .context("no access_token from WorkOS")?;
            let refresh = json
                .get("refresh_token")
                .and_then(serde_json::Value::as_str)
                .context("no refresh_token from WorkOS")?;
            break (access.to_owned(), refresh.to_owned());
        }
        match json.get("error").and_then(serde_json::Value::as_str) {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 1,
            Some(terminal) => anyhow::bail!(
                "authorization failed: {terminal}{}",
                json.get("error_description")
                    .and_then(serde_json::Value::as_str)
                    .map(|d| format!(" - {d}"))
                    .unwrap_or_default()
            ),
            None => anyhow::bail!("unexpected poll response: {json}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    };
    // Exchange WorkOS tokens for a Cline session.
    let data = cline_token_request(
        &format!("{CLINE_API_BASE}/api/v1/auth/register"),
        &serde_json::json!({
            "accessToken": workos_access,
            "refreshToken": workos_refresh,
        }),
    )
    .await
    .context("Cline token registration")?;
    store_cline_session(settings, entry, &data, CLINE_API_BASE)
}

/// Refreshes a Cline session and re-mirrors the access token into the
/// entry's secret. Returns the new access token.
pub async fn refresh_cline(settings: &Settings, entry: &str) -> Result<String> {
    let session = ClineSession::load(settings, entry).context("no Cline session to refresh")?;
    let body = serde_json::json!({
        "refreshToken": session.refresh_token,
        "grantType": "refresh_token",
    });
    let data = cline_token_request(
        &format!("{}/api/v1/auth/refresh", session.api_base_url),
        &body,
    )
    .await
    .context("Cline token refresh (reconnect in settings if this persists)")?;
    store_cline_session(settings, entry, &data, &session.api_base_url)?;
    data.get("accessToken")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .context("no accessToken after refresh")
}

async fn cline_token_request(url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let response = reqwest::Client::new()
        .post(url)
        .json(body)
        .send()
        .await
        .context("request")?;
    let status = response.status();
    let json: serde_json::Value = response.json().await.context("parse response")?;
    if !status.is_success()
        || json.get("success").and_then(serde_json::Value::as_bool) != Some(true)
    {
        anyhow::bail!("{url} returned {status}: {json}");
    }
    json.get("data").cloned().context("no data in response")
}

fn store_cline_session(
    settings: &Settings,
    entry: &str,
    data: &serde_json::Value,
    api_base_url: &str,
) -> Result<()> {
    let access = data
        .get("accessToken")
        .and_then(serde_json::Value::as_str)
        .context("no accessToken")?;
    let refresh = data
        .get("refreshToken")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        // Rotation optional: keep the old refresh token when absent.
        .or_else(|| ClineSession::load(settings, entry).map(|s| s.refresh_token))
        .context("no refreshToken")?;
    let expires_at = data
        .get("expiresAt")
        .and_then(serde_json::Value::as_str)
        .and_then(|iso| chrono::DateTime::parse_from_rfc3339(iso).ok())
        .map(|dt| dt.timestamp())
        .context("no parseable expiresAt")?;
    let session = ClineSession {
        refresh_token: refresh,
        expires_at,
        api_base_url: api_base_url.to_owned(),
    };
    settings.set_secret(
        &ClineSession::secret_name(entry),
        &serde_json::to_string(&session)?,
    )?;
    // Mirror for the synchronous substitution path.
    settings.set_secret(entry, access)
}

/// Background maintenance: refresh any Cline session nearing expiry so
/// the mirrored access token stays valid without blocking the proxy.
pub async fn refresh_expiring_cline_sessions(settings: &Settings) {
    for entry in settings.entries() {
        if let Some(session) = ClineSession::load(settings, &entry.name)
            && session.expires_soon()
            && let Err(error) = refresh_cline(settings, &entry.name).await
        {
            tracing::warn!(%error, entry = %entry.name, "Cline session refresh failed");
        }
    }
}
