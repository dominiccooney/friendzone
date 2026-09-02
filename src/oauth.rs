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

        let authorize_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256",
            discovery.authorization_endpoint,
            urlencode(&client_id),
            urlencode(redirect_uri),
            urlencode(&state),
            urlencode(&challenge),
        );

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
        let token = body
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .context("no access_token in response")?;
        settings.set_secret(&format!("mcp:{}", login.forward_name), token)?;
        Ok(login.forward_name)
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
}
