//! Host-side OAuth 2.1 for MCP forwards: discovery (RFC 8414), dynamic
//! client registration (RFC 7591), and PKCE. The browser opens on the
//! host, the callback lands on the loopback UI listener, and the token
//! is stored as secret `mcp:{name}`. No secret is typed or pasted, and
//! nothing token-shaped ever reaches a container.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::settings::Settings;

/// A stored OAuth session for one MCP forward: everything needed to
/// authenticate and to refresh without user involvement. Persisted as
/// JSON in secret `mcp-oauth:{forward}`.
#[derive(Clone, Debug, serde::Serialize, Deserialize)]
pub struct TokenRecord {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix seconds; None = server did not state a lifetime.
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub token_endpoint: String,
    pub client_id: String,
}

impl TokenRecord {
    pub fn secret_name(forward: &str) -> String {
        format!("mcp-oauth:{forward}")
    }

    pub fn load(settings: &Settings, forward: &str) -> Option<Self> {
        settings
            .secret(&Self::secret_name(forward))
            .and_then(|text| serde_json::from_str(&text).ok())
    }

    pub fn store(&self, settings: &Settings, forward: &str) -> Result<()> {
        settings.set_secret(&Self::secret_name(forward), &serde_json::to_string(self)?)
    }

    /// True within 60 seconds of expiry: refresh early, never race.
    pub fn expires_soon(&self) -> bool {
        self.expires_at
            .is_some_and(|at| at - 60 <= chrono::Utc::now().timestamp())
    }
}

/// Exchanges the stored refresh token for a new access token, persists
/// the rotated record, and returns the fresh access token.
pub async fn refresh(settings: &Settings, forward: &str) -> Result<String> {
    let record = TokenRecord::load(settings, forward).context("no OAuth session to refresh")?;
    let refresh_token = record
        .refresh_token
        .clone()
        .context("server issued no refresh token; reconnect in settings")?;
    let response = reqwest::Client::new()
        .post(&record.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &record.client_id),
        ])
        .send()
        .await
        .context("token refresh request")?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.context("parse refresh response")?;
    if !status.is_success() {
        anyhow::bail!("refresh failed {status}: {body} (reconnect in settings)");
    }
    let access_token = body
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .context("no access_token in refresh response")?
        .to_owned();
    let rotated = TokenRecord {
        access_token: access_token.clone(),
        // Servers may rotate the refresh token; keep the old one if not.
        refresh_token: body
            .get("refresh_token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .or(Some(refresh_token)),
        expires_at: body
            .get("expires_in")
            .and_then(serde_json::Value::as_i64)
            .map(|seconds| chrono::Utc::now().timestamp() + seconds),
        ..record
    };
    rotated.store(settings, forward)?;
    Ok(access_token)
}

/// One login attempt awaiting its callback, keyed by `state`.
struct PendingLogin {
    forward_name: String,
    token_endpoint: String,
    client_id: String,
    code_verifier: String,
    redirect_uri: String,
}

#[derive(Clone, Default)]
pub struct OauthFlows(Arc<Mutex<HashMap<String, PendingLogin>>>);

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
}

fn random_urlsafe() -> String {
    URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
}

impl OauthFlows {
    /// Starts a login: discovers endpoints from the MCP server's origin,
    /// registers a client, and returns the authorization URL for the
    /// host browser. `redirect_uri` must be this broker's loopback UI.
    pub async fn start(
        &self,
        forward_name: &str,
        server_url: &str,
        redirect_uri: &str,
        scope: Option<&str>,
    ) -> Result<String> {
        let origin = origin_of(server_url)?;
        let discovery = discover(&origin).await?;
        let registration_endpoint = discovery
            .registration_endpoint
            .context("server does not support dynamic client registration")?;
        let client_id = register_client(&registration_endpoint, redirect_uri).await?;

        let code_verifier = format!("{}{}", random_urlsafe(), random_urlsafe());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let state = random_urlsafe();

        let mut authorize_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256",
            discovery.authorization_endpoint,
            urlencode(&client_id),
            urlencode(redirect_uri),
            urlencode(&state),
            urlencode(&challenge),
        );
        if let Some(scope) = scope.filter(|s| !s.is_empty()) {
            authorize_url.push_str(&format!("&scope={}", urlencode(scope)));
        }

        self.0.lock().expect("oauth lock").insert(
            state,
            PendingLogin {
                forward_name: forward_name.to_owned(),
                token_endpoint: discovery.token_endpoint,
                client_id,
                code_verifier,
                redirect_uri: redirect_uri.to_owned(),
            },
        );
        Ok(authorize_url)
    }

    /// Completes a login from the callback: exchanges the code, stores
    /// the token as `mcp:{forward}`. Returns the forward name.
    pub async fn finish(&self, state: &str, code: &str, settings: &Settings) -> Result<String> {
        let login = self
            .0
            .lock()
            .expect("oauth lock")
            .remove(state)
            .context("unknown or expired OAuth state")?;
        let response = reqwest::Client::new()
            .post(&login.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &login.redirect_uri),
                ("client_id", &login.client_id),
                ("code_verifier", &login.code_verifier),
            ])
            .send()
            .await
            .context("token exchange")?;
        let status = response.status();
        let body: serde_json::Value = response.json().await.context("parse token response")?;
        if !status.is_success() {
            anyhow::bail!("token endpoint returned {status}: {body}");
        }
        let access_token = body
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .context("no access_token in response")?
            .to_owned();
        let record = TokenRecord {
            access_token,
            refresh_token: body
                .get("refresh_token")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            expires_at: body
                .get("expires_in")
                .and_then(serde_json::Value::as_i64)
                .map(|seconds| chrono::Utc::now().timestamp() + seconds),
            token_endpoint: login.token_endpoint,
            client_id: login.client_id,
        };
        record.store(settings, &login.forward_name)?;
        Ok(login.forward_name)
    }
}

/// Forgets a stored OAuth session.
pub fn disconnect(settings: &Settings, forward: &str) -> Result<()> {
    settings.remove_secret(&TokenRecord::secret_name(forward))
}

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
        .post(format!("{WORKOS_API_BASE}/user_management/authorize/device"))
        .form(&[("client_id", CLINE_WORKOS_CLIENT_ID)])
        .send()
        .await
        .context("device authorization request")?;
    let status = response.status();
    let json: serde_json::Value = response.json().await.context("parse device authorization")?;
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
    if !status.is_success() || json.get("success").and_then(serde_json::Value::as_bool) != Some(true)
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
    settings.set_secret(&ClineSession::secret_name(entry), &serde_json::to_string(&session)?)?;
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

fn origin_of(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .context("MCP server URL must be http(s)")?;
    let scheme_len = url.len() - rest.len();
    let authority_end = rest.find('/').unwrap_or(rest.len());
    Ok(url[..scheme_len + authority_end].to_owned())
}

async fn discover(origin: &str) -> Result<Discovery> {
    let url = format!("{origin}/.well-known/oauth-authorization-server");
    reqwest::get(&url)
        .await
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .context("authorization server metadata")?
        .json()
        .await
        .context("parse authorization server metadata")
}

async fn register_client(registration_endpoint: &str, redirect_uri: &str) -> Result<String> {
    let response: serde_json::Value = reqwest::Client::new()
        .post(registration_endpoint)
        .json(&json!({
            "client_name": "Friendzone broker",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .context("dynamic client registration")?
        .json()
        .await
        .context("parse registration response")?;
    response
        .get("client_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .context("no client_id in registration response")
}

fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_extraction() {
        assert_eq!(
            origin_of("https://mcp.linear.app/mcp").unwrap(),
            "https://mcp.linear.app"
        );
        assert_eq!(
            origin_of("http://127.0.0.1:9000/mcp").unwrap(),
            "http://127.0.0.1:9000"
        );
        assert!(origin_of("ftp://x").is_err());
    }

    #[test]
    fn urlencode_reserved() {
        assert_eq!(urlencode("http://a/b?c=d"), "http%3A%2F%2Fa%2Fb%3Fc%3Dd");
        assert_eq!(urlencode("safe-._~123"), "safe-._~123");
    }

    #[test]
    fn token_record_round_trips_and_disconnects() {
        let dir = std::env::temp_dir().join(format!("fz-oauth-{}", Uuid::new_v4()));
        let settings = Settings::load(&dir).unwrap();
        let record = TokenRecord {
            access_token: "at-1".into(),
            refresh_token: Some("rt-1".into()),
            expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            token_endpoint: "https://auth.example/token".into(),
            client_id: "client-1".into(),
        };
        record.store(&settings, "linear").unwrap();
        let loaded = TokenRecord::load(&settings, "linear").unwrap();
        assert_eq!(loaded.access_token, "at-1");
        assert_eq!(loaded.refresh_token.as_deref(), Some("rt-1"));
        assert!(!loaded.expires_soon());
        disconnect(&settings, "linear").unwrap();
        assert!(TokenRecord::load(&settings, "linear").is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn near_expiry_counts_as_expiring() {
        let record = TokenRecord {
            access_token: "at".into(),
            refresh_token: None,
            expires_at: Some(chrono::Utc::now().timestamp() + 30),
            token_endpoint: String::new(),
            client_id: String::new(),
        };
        assert!(record.expires_soon(), "within the 60s early-refresh window");
        let no_expiry = TokenRecord {
            expires_at: None,
            ..record
        };
        assert!(!no_expiry.expires_soon(), "no stated lifetime never expires");
    }
}
