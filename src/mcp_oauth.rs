//! Broker-owned MCP OAuth. The shared Session is the consistency boundary:
//! refresh is single-flight, and every credential write checks its generation.
//! Disconnect/reconfiguration cancels old callbacks and in-flight refreshes.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::settings::Settings;

const LOGIN_LIFETIME: Duration = Duration::from_secs(600);

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?)
}

fn secure_url(raw: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).context("invalid OAuth URL")?;
    let loopback = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        bail!(
            "OAuth endpoints require HTTPS (HTTP is allowed only on loopback), without credentials or fragments"
        );
    }
    Ok(url)
}

/// No Debug: never accidentally log tokens or the client secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
    pub token_endpoint: String,
    pub client_id: String,
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub scope: Option<String>,
}

impl TokenRecord {
    fn key(name: &str) -> String {
        format!("mcp-oauth:{name}")
    }
    pub fn load(settings: &Settings, name: &str) -> Option<Self> {
        settings
            .secret(&Self::key(name))
            .and_then(|text| serde_json::from_str(&text).ok())
    }
    pub fn expires_soon(&self) -> bool {
        self.expires_at
            .is_some_and(|expiry| expiry.saturating_sub(60) <= chrono::Utc::now().timestamp())
    }
}

struct Lifecycle {
    generation: Uuid,
    connection_epoch: Uuid,
    retired: bool,
}

pub struct Session {
    name: String,
    url: String,
    settings: Settings,
    lifecycle: Mutex<Lifecycle>,
    refresh: tokio::sync::Mutex<()>,
}

impl Session {
    pub fn new(name: String, url: String, settings: Settings) -> Self {
        Self {
            name,
            url,
            settings,
            lifecycle: Mutex::new(Lifecycle {
                generation: Uuid::new_v4(),
                connection_epoch: Uuid::new_v4(),
                retired: false,
            }),
            refresh: tokio::sync::Mutex::new(()),
        }
    }
    pub fn generation(&self) -> Uuid {
        self.lifecycle.lock().expect("OAuth lifecycle").generation
    }
    pub fn connection_epoch(&self) -> Uuid {
        self.lifecycle
            .lock()
            .expect("OAuth lifecycle")
            .connection_epoch
    }
    fn check(&self, generation: Uuid) -> Result<()> {
        let state = self.lifecycle.lock().expect("OAuth lifecycle");
        if state.retired || state.generation != generation {
            bail!("OAuth operation superseded; authorize again in the host Friendzone UI");
        }
        Ok(())
    }
    async fn begin(&self) -> Result<Uuid> {
        let _flight = self.refresh.lock().await;
        let mut state = self.lifecycle.lock().expect("OAuth lifecycle");
        if state.retired {
            bail!("forward changed; start authorization again");
        }
        state.generation = Uuid::new_v4();
        Ok(state.generation)
    }
    fn store(&self, generation: Uuid, record: &TokenRecord, new_login: bool) -> Result<()> {
        let mut state = self.lifecycle.lock().expect("OAuth lifecycle");
        if state.retired || state.generation != generation {
            bail!("OAuth operation superseded; tokens were not saved");
        }
        self.settings.set_secret(
            &TokenRecord::key(&self.name),
            &serde_json::to_string(record)?,
        )?;
        if new_login {
            state.connection_epoch = Uuid::new_v4();
        }
        Ok(())
    }
    pub fn disconnect(&self) -> Result<()> {
        let mut state = self.lifecycle.lock().expect("OAuth lifecycle");
        if state.retired {
            bail!("Forward changed; disconnect the current forward instead");
        }
        state.generation = Uuid::new_v4();
        state.connection_epoch = Uuid::new_v4();
        self.settings.remove_secret(&TokenRecord::key(&self.name))
    }
    pub fn retire(&self) -> Result<()> {
        let mut state = self.lifecycle.lock().expect("OAuth lifecycle");
        self.settings.remove_secret(&TokenRecord::key(&self.name))?;
        state.retired = true;
        state.generation = Uuid::new_v4();
        Ok(())
    }

    /// rejected is the token that received 401. A waiter reuses an already
    /// rotated token rather than spending the same refresh token twice.
    pub async fn token(&self, rejected: Option<&str>) -> Result<String> {
        let _flight = self.refresh.lock().await;
        let generation = self.generation();
        self.check(generation)?;
        let mut record = TokenRecord::load(&self.settings, &self.name)
            .context("Upstream OAuth is not connected. Use Authorize in Friendzone on the host, not in the guest")?;
        if record.server_url != self.url || record.resource.is_empty() {
            bail!(
                "Stored OAuth session is not bound to this upstream URL. Reauthorize in the host Friendzone UI"
            );
        }
        if !record.expires_soon() && rejected.is_none_or(|token| token != record.access_token) {
            return Ok(record.access_token);
        }
        let refresh = record
            .refresh_token
            .as_deref()
            .context("OAuth token expired/rejected and cannot refresh; reauthorize on the host")?;
        let url = secure_url(&record.token_endpoint)?;
        let response = client()?
            .post(url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &record.client_id),
                ("resource", &record.resource),
            ])
            .send()
            .await
            .context("OAuth refresh request failed")?;
        let tokens = token_response(response).await?;
        record.access_token = tokens.access_token;
        record.refresh_token = tokens.refresh_token.or(record.refresh_token);
        record.expires_at = expiry(tokens.expires_in)?;
        record.scope = tokens.scope.or(record.scope);
        self.store(generation, &record, false)?;
        Ok(record.access_token)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

fn expiry(seconds: Option<u64>) -> Result<Option<i64>> {
    seconds
        .map(|seconds| {
            chrono::Utc::now()
                .timestamp()
                .checked_add(i64::try_from(seconds).context("invalid OAuth token lifetime")?)
                .context("invalid OAuth token lifetime")
        })
        .transpose()
}

async fn token_response(response: reqwest::Response) -> Result<TokenResponse> {
    if !response.status().is_success() {
        // Never expose an endpoint response body (it may echo credentials).
        bail!(
            "OAuth token endpoint returned {}; reauthorize in the host Friendzone UI",
            response.status()
        );
    }
    let body: Value = response
        .json()
        .await
        .context("invalid OAuth token response")?;
    let tokens: TokenResponse = serde_json::from_value(body)
        .map_err(|_| anyhow::anyhow!("invalid OAuth token response fields"))?;
    if tokens.access_token.is_empty()
        || !tokens.token_type.eq_ignore_ascii_case("bearer")
        || tokens.refresh_token.as_ref().is_some_and(String::is_empty)
    {
        bail!("OAuth endpoint did not issue valid Bearer credentials");
    }
    Ok(tokens)
}

#[derive(Deserialize)]
struct ResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
}

#[derive(Deserialize)]
struct AuthorizationMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

struct Discovery {
    resource: String,
    metadata: AuthorizationMetadata,
}

fn well_known(base: &reqwest::Url, kind: &str, with_path: bool) -> reqwest::Url {
    let mut url = base.clone();
    let suffix = if with_path {
        base.path().trim_end_matches('/')
    } else {
        ""
    };
    url.set_path(&format!("/.well-known/{kind}{suffix}"));
    url.set_query(None);
    url
}

fn resource_metadata_hint(headers: &reqwest::header::HeaderMap) -> Option<String> {
    // RFC 9728 resource_metadata is a quoted URI. Do not interpret arbitrary
    // error text or follow redirects. The fetched metadata must bind our URL.
    headers
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|value| {
            let (_, params) = value.split_once(' ')?;
            params.split(',').find_map(|param| {
                let (key, value) = param.trim().split_once('=')?;
                if !key.eq_ignore_ascii_case("resource_metadata") {
                    return None;
                }
                Some(value.trim().trim_matches('"').to_owned())
            })
        })
}

async fn get_metadata<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: reqwest::Url,
) -> Result<Option<T>> {
    secure_url(url.as_str())?;
    let response = http
        .get(url)
        .send()
        .await
        .context("OAuth metadata request failed")?;
    if matches!(response.status().as_u16(), 404 | 405) {
        return Ok(None);
    }
    if !response.status().is_success() {
        bail!("OAuth metadata returned {}", response.status());
    }
    let json: Value = response
        .json()
        .await
        .context("invalid OAuth metadata JSON")?;
    Ok(Some(serde_json::from_value(json).map_err(|_| {
        anyhow::anyhow!("invalid OAuth metadata fields")
    })?))
}

async fn discover(server: &str) -> Result<Discovery> {
    let target = secure_url(server)?;
    let http = client()?;
    let probe = http
        .get(target.clone())
        .send()
        .await
        .context("MCP authorization discovery failed")?;
    let hint = resource_metadata_hint(probe.headers());
    let mut candidates = match hint {
        Some(hint) => vec![secure_url(&hint)?],
        None => vec![
            well_known(&target, "oauth-protected-resource", true),
            well_known(&target, "oauth-protected-resource", false),
        ],
    };
    candidates.dedup();
    let mut resource = None;
    for url in candidates {
        if let Some(found) = get_metadata::<ResourceMetadata>(&http, url).await? {
            resource = Some(found);
            break;
        }
    }
    let resource = resource.context("MCP server did not publish protected-resource metadata")?;
    let resource_url = secure_url(&resource.resource)?;
    let prefix = format!("{}/", resource_url.path().trim_end_matches('/'));
    if resource_url.origin() != target.origin()
        || !(target.path() == resource_url.path() || target.path().starts_with(&prefix))
    {
        bail!("Protected-resource metadata does not describe this MCP endpoint");
    }
    let issuer = secure_url(
        resource
            .authorization_servers
            .first()
            .context("No OAuth authorization server advertised")?,
    )?;
    let metadata: AuthorizationMetadata = get_metadata(
        &http,
        well_known(&issuer, "oauth-authorization-server", true),
    )
    .await?
    .context("Authorization server did not publish OAuth metadata")?;
    if secure_url(&metadata.issuer)? != issuer {
        bail!("OAuth metadata issuer mismatch");
    }
    if !metadata
        .code_challenge_methods_supported
        .iter()
        .any(|method| method == "S256")
    {
        bail!("Authorization server does not advertise PKCE S256");
    }
    if metadata
        .token_endpoint_auth_methods_supported
        .as_ref()
        .is_some_and(|methods| !methods.iter().any(|method| method == "none"))
    {
        bail!(
            "This server requires a confidential OAuth client; public-client registration is not supported"
        );
    }
    secure_url(&metadata.authorization_endpoint)?;
    secure_url(&metadata.token_endpoint)?;
    Ok(Discovery {
        resource: resource.resource,
        metadata,
    })
}

#[derive(Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LoginStatus {
    WaitingForUser,
    Connected,
    Failed { message: String },
}

struct PendingLogin {
    session: Arc<Session>,
    generation: Uuid,
    deadline: Instant,
    redirect: String,
    verifier: String,
    client_id: String,
    discovery: Discovery,
    scope: Option<String>,
}

#[derive(Default)]
struct FlowState {
    pending: HashMap<String, PendingLogin>,
    status: HashMap<String, (Uuid, LoginStatus)>,
}

#[derive(Clone, Default)]
pub struct OauthFlows(Arc<Mutex<FlowState>>);

impl OauthFlows {
    pub fn status(&self, session: &Session) -> Option<LoginStatus> {
        let mut state = self.0.lock().expect("OAuth flows");
        let generation = session.generation();
        if state.pending.values().any(|login| {
            login.session.name == session.name
                && login.generation == generation
                && login.deadline <= Instant::now()
        }) {
            state.pending.retain(|_, login| {
                !(login.session.name == session.name && login.generation == generation)
            });
            state.status.insert(
                session.name.clone(),
                (
                    generation,
                    LoginStatus::Failed {
                        message: "OAuth login expired; start again on the host".into(),
                    },
                ),
            );
        }
        state
            .status
            .get(&session.name)
            .filter(|(g, _)| *g == generation)
            .map(|(_, status)| status.clone())
    }
    fn set_status(&self, session: &Session, generation: Uuid, status: LoginStatus) {
        let mut state = self.0.lock().expect("OAuth flows");
        if session.check(generation).is_err() {
            return;
        }
        state
            .status
            .insert(session.name.clone(), (generation, status));
    }
    pub async fn start(
        &self,
        session: Arc<Session>,
        redirect: &str,
        scope: Option<String>,
    ) -> Result<String> {
        let generation = session.begin().await?;
        let result = self
            .start_inner(session.clone(), generation, redirect, scope)
            .await;
        if result.is_err() {
            self.set_status(
                &session,
                generation,
                LoginStatus::Failed {
                    message: "Could not start authorization. Check the displayed error and retry."
                        .into(),
                },
            );
        }
        result
    }
    async fn start_inner(
        &self,
        session: Arc<Session>,
        generation: Uuid,
        redirect: &str,
        scope: Option<String>,
    ) -> Result<String> {
        let redirect_url = secure_url(redirect)?;
        if !redirect_url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }) {
            bail!("OAuth callback must use the host loopback UI listener");
        }
        let discovery = discover(&session.url).await?;
        let registration = secure_url(
            discovery
                .metadata
                .registration_endpoint
                .as_deref()
                .context("Authorization server does not support dynamic client registration")?,
        )?;
        let response = client()?
            .post(registration)
            .json(&json!({
                "client_name":"Friendzone broker", "redirect_uris":[redirect],
                "grant_types":["authorization_code","refresh_token"], "response_types":["code"],
                "token_endpoint_auth_method":"none"
            }))
            .send()
            .await
            .context("OAuth client registration failed")?;
        if !response.status().is_success() {
            bail!("OAuth client registration returned {}", response.status());
        }
        let registration: Value = response
            .json()
            .await
            .context("invalid OAuth registration response")?;
        if registration
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .is_some_and(|method| method != "none")
        {
            bail!("Registration did not accept public-client authentication");
        }
        let client_id = registration
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .context("Registration did not return a client ID")?
            .to_owned();
        // Three independently random v4 UUIDs give >256 bits of entropy
        // and 96 unreserved characters (PKCE permits 43..128).
        let verifier = format!(
            "{}{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let state_id = Uuid::new_v4().simple().to_string();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut authorize = secure_url(&discovery.metadata.authorization_endpoint)?;
        // Preserve provider-specific parameters (e.g. tenant), but never
        // allow metadata to supply a second redirect/state/resource value.
        let provider_query: Vec<_> = authorize
            .query_pairs()
            .filter(|(key, _)| {
                !matches!(
                    key.as_ref(),
                    "response_type"
                        | "client_id"
                        | "redirect_uri"
                        | "state"
                        | "code_challenge"
                        | "code_challenge_method"
                        | "resource"
                        | "scope"
                )
            })
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        authorize.set_query(None);
        authorize.query_pairs_mut().extend_pairs(provider_query);
        authorize.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect),
            ("state", &state_id),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("resource", &discovery.resource),
        ]);
        if let Some(scope) = &scope {
            authorize.query_pairs_mut().append_pair("scope", scope);
        }
        let mut state = self.0.lock().expect("OAuth flows");
        session.check(generation)?;
        state.pending.retain(|_, pending| {
            pending.deadline > Instant::now() && pending.session.name != session.name
        });
        if state.pending.len() >= 128 {
            bail!("Too many pending OAuth logins; try again later");
        }
        state.status.insert(
            session.name.clone(),
            (generation, LoginStatus::WaitingForUser),
        );
        state.pending.insert(
            state_id,
            PendingLogin {
                session,
                generation,
                deadline: Instant::now() + LOGIN_LIFETIME,
                redirect: redirect.into(),
                verifier,
                client_id,
                discovery,
                scope,
            },
        );
        Ok(authorize.into())
    }
    pub async fn finish(
        &self,
        state: &str,
        code: Option<&str>,
        error: Option<&str>,
    ) -> Result<String> {
        let login = self
            .0
            .lock()
            .expect("OAuth flows")
            .pending
            .remove(state)
            .context("Unknown, expired or already-used OAuth state")?;
        let result = self.finish_inner(&login, code, error).await;
        self.set_status(
            &login.session,
            login.generation,
            match &result {
                Ok(()) => LoginStatus::Connected,
                Err(error) => LoginStatus::Failed {
                    message: error.to_string(),
                },
            },
        );
        result?;
        Ok(login.session.name.clone())
    }
    async fn finish_inner(
        &self,
        login: &PendingLogin,
        code: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        // Serialize login replacement against refresh so a late rotation
        // cannot overwrite credentials from a newly authorized account.
        let _flight = login.session.refresh.lock().await;
        login.session.check(login.generation)?;
        if login.deadline <= Instant::now() {
            bail!("OAuth login expired; start again on the host");
        }
        if error.is_some() {
            bail!("Authorization was denied or cancelled; no credentials changed");
        }
        let code = code
            .filter(|code| !code.is_empty())
            .context("OAuth callback did not include a code")?;
        let response = client()?
            .post(&login.discovery.metadata.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &login.redirect),
                ("client_id", &login.client_id),
                ("code_verifier", &login.verifier),
                ("resource", &login.discovery.resource),
            ])
            .send()
            .await
            .context("OAuth code exchange failed")?;
        let tokens = token_response(response).await?;
        login.session.store(
            login.generation,
            &TokenRecord {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_at: expiry(tokens.expires_in)?,
                token_endpoint: login.discovery.metadata.token_endpoint.clone(),
                client_id: login.client_id.clone(),
                server_url: login.session.url.clone(),
                resource: login.discovery.resource.clone(),
                scope: tokens.scope.or(login.scope.clone()),
            },
            true,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{
        Form, Json, Router,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::{get, post},
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    pub(crate) struct Fixture {
        pub(crate) url: String,
        pub(crate) settings: Settings,
        dir: PathBuf,
        task: tokio::task::JoinHandle<()>,
        refreshes: Arc<AtomicUsize>,
        reject_once: Arc<AtomicBool>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        hold: Arc<AtomicBool>,
        verifier: Arc<Mutex<Option<String>>>,
        calls: Arc<AtomicUsize>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    impl Fixture {
        pub(crate) async fn new() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let url = format!("{base}/mcp");
            let refreshes = Arc::new(AtomicUsize::new(0));
            let reject_once = Arc::new(AtomicBool::new(false));
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let hold = Arc::new(AtomicBool::new(false));
            let verifier = Arc::new(Mutex::new(None));
            let calls = Arc::new(AtomicUsize::new(0));
            let resource =
                json!({"resource":url, "authorization_servers":[format!("{base}/auth")]});
            let metadata = json!({"issuer":format!("{base}/auth"), "authorization_endpoint":format!("{base}/authorize?tenant=test&state=wrong&redirect_uri=wrong"), "token_endpoint":format!("{base}/token"), "registration_endpoint":format!("{base}/register"), "code_challenge_methods_supported":["S256"], "token_endpoint_auth_methods_supported":["none"]});
            let probe_hint = format!("Bearer resource_metadata=\"{base}/metadata\"");
            let app = Router::new()
                .route("/mcp", get(move || {let hint=probe_hint.clone(); async move {(StatusCode::UNAUTHORIZED, [("www-authenticate",hint)])}})
                    .post({ let reject=reject_once.clone(); let calls=calls.clone(); move |headers:HeaderMap, Json(message):Json<Value>| {
                        let reject=reject.clone(); let calls=calls.clone(); async move {
                            let bearer=headers.get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("");
                            if !bearer.starts_with("Bearer access-") || reject.swap(false, Ordering::SeqCst) { return (StatusCode::UNAUTHORIZED,"upstream secret must not escape").into_response(); }
                            assert_ne!(bearer,"Bearer cline-token");
                            let result=match message["method"].as_str().unwrap() {
                                "initialize"=>json!({"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}),
                                "tools/list"=>json!({"tools":[{"name":"read"},{"name":"write"}]}),
                                "tools/call"=>{calls.fetch_add(1,Ordering::SeqCst);json!({"content":[]})},
                                _=>json!({}),
                            };
                            Json(json!({"jsonrpc":"2.0","id":message["id"],"result":result})).into_response()
                        }
                    }}))
                .route("/metadata",get(move || {let value=resource.clone();async move{Json(value)}}))
                .route("/token-error",post(||async{(StatusCode::UNAUTHORIZED,"upstream secret must not escape")}))
                .route("/.well-known/oauth-authorization-server/auth",get(move || {let value=metadata.clone();async move{Json(value)}}))
                .route("/register",post(|Json(body):Json<Value>|async move{
                    assert_eq!(body["grant_types"],json!(["authorization_code","refresh_token"]));
                    assert_eq!(body["token_endpoint_auth_method"],"none");
                    assert_eq!(body["redirect_uris"][0],"http://127.0.0.1:8081/oauth/callback");
                    Json(json!({"client_id":"broker-client","token_endpoint_auth_method":"none"}))
                }))
                .route("/token",post({let expected=url.clone();let refreshes=refreshes.clone();let entered=entered.clone();let release=release.clone();let hold=hold.clone();let verifier=verifier.clone(); move |Form(body):Form<HashMap<String,String>>|{
                    let expected=expected.clone();let refreshes=refreshes.clone();let entered=entered.clone();let release=release.clone();let hold=hold.clone();let verifier=verifier.clone();async move {
                        assert_eq!(body["resource"],expected);
                        assert_eq!(body["client_id"],"broker-client");
                        let version=if body["grant_type"]=="refresh_token"{
                            let count=refreshes.fetch_add(1,Ordering::SeqCst)+1;
                            if hold.load(Ordering::SeqCst){entered.notify_one();release.notified().await;}
                            count+1
                        }else{
                            assert_eq!(body["redirect_uri"],"http://127.0.0.1:8081/oauth/callback");
                            *verifier.lock().unwrap()=Some(body["code_verifier"].clone());
                            1
                        };
                        Json(json!({"access_token":format!("access-{version}"),"refresh_token":format!("refresh-{version}"),"token_type":"Bearer","expires_in":3600,"scope":"read"}))
                    }
                }}));
            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let dir = std::env::temp_dir().join(format!("fz-mcp-oauth-{}", Uuid::new_v4()));
            let settings = Settings::load(&dir).unwrap();
            Self {
                url,
                settings,
                dir,
                task,
                refreshes,
                reject_once,
                entered,
                release,
                hold,
                verifier,
                calls,
            }
        }
        fn session(&self) -> Arc<Session> {
            Arc::new(Session::new(
                "Linear".into(),
                self.url.clone(),
                self.settings.clone(),
            ))
        }
        async fn login(&self, flows: &OauthFlows, session: Arc<Session>) -> String {
            let authorize = flows
                .start(
                    session,
                    "http://127.0.0.1:8081/oauth/callback",
                    Some("read".into()),
                )
                .await
                .unwrap();
            let url = reqwest::Url::parse(&authorize).unwrap();
            let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(
                url.query_pairs().filter(|(key, _)| key == "state").count(),
                1
            );
            assert_eq!(
                url.query_pairs()
                    .filter(|(key, _)| key == "redirect_uri")
                    .count(),
                1
            );
            assert_eq!(params["resource"], self.url);
            assert_eq!(params["scope"], "read");
            assert_eq!(params["tenant"], "test");
            assert_eq!(params["code_challenge_method"], "S256");
            flows
                .finish(&params["state"], Some("authorization-code"), None)
                .await
                .unwrap();
            let verifier = self.verifier.lock().unwrap().clone().unwrap();
            assert_eq!(
                params["code_challenge"],
                URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
            );
            params["state"].clone()
        }
    }

    #[tokio::test]
    async fn authorization_code_pkce_persistence_and_single_flight_refresh() {
        let fixture = Fixture::new().await;
        let flows = OauthFlows::default();
        let session = fixture.session();
        let state = fixture.login(&flows, session.clone()).await;
        assert!(flows.finish(&state, Some("replay"), None).await.is_err());
        let saved = TokenRecord::load(&fixture.settings, "Linear").unwrap();
        assert_eq!(saved.server_url, fixture.url);
        assert_eq!(saved.refresh_token.as_deref(), Some("refresh-1"));
        let reloaded = Settings::load(&fixture.dir).unwrap();
        assert!(TokenRecord::load(&reloaded, "Linear").is_some());
        let before_epoch = session.connection_epoch();
        let (a, b) = tokio::join!(
            session.token(Some("access-1")),
            session.token(Some("access-1"))
        );
        assert_eq!(a.unwrap(), "access-2");
        assert_eq!(b.unwrap(), "access-2");
        assert_eq!(fixture.refreshes.load(Ordering::SeqCst), 1);
        assert_eq!(
            session.connection_epoch(),
            before_epoch,
            "refresh preserves MCP session"
        );
        let mut expiring = TokenRecord::load(&fixture.settings, "Linear").unwrap();
        expiring.expires_at = Some(chrono::Utc::now().timestamp() + 20);
        session
            .store(session.generation(), &expiring, false)
            .unwrap();
        assert_eq!(
            session.token(None).await.unwrap(),
            "access-3",
            "refresh before expiry"
        );
        session.disconnect().unwrap();
        assert!(TokenRecord::load(&fixture.settings, "Linear").is_none());
        assert!(session.token(None).await.is_err());
    }

    #[tokio::test]
    async fn pending_login_cancel_expiry_reconfigure_and_disconnect_fail_closed() {
        let fixture = Fixture::new().await;
        let flows = OauthFlows::default();
        let session = fixture.session();
        let start = |session| flows.start(session, "http://127.0.0.1:8081/oauth/callback", None);
        let state_of = |url: String| {
            reqwest::Url::parse(&url)
                .unwrap()
                .query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1
                .into_owned()
        };
        let cancelled = state_of(start(session.clone()).await.unwrap());
        assert!(
            flows
                .finish(&cancelled, None, Some("access_denied"))
                .await
                .is_err()
        );
        let old = state_of(start(session.clone()).await.unwrap());
        let current = state_of(start(session.clone()).await.unwrap());
        assert!(flows.finish(&old, Some("code"), None).await.is_err());
        flows
            .0
            .lock()
            .unwrap()
            .pending
            .get_mut(&current)
            .unwrap()
            .deadline = Instant::now() - Duration::from_secs(1);
        assert!(matches!(
            flows.status(&session),
            Some(LoginStatus::Failed { .. })
        ));
        assert!(flows.finish(&current, Some("code"), None).await.is_err());
        let late = state_of(start(session.clone()).await.unwrap());
        session.disconnect().unwrap();
        assert!(flows.finish(&late, Some("code"), None).await.is_err());
        let removed = state_of(start(session.clone()).await.unwrap());
        session.retire().unwrap();
        assert!(flows.finish(&removed, Some("code"), None).await.is_err());
        assert!(TokenRecord::load(&fixture.settings, "Linear").is_none());
    }

    #[tokio::test]
    async fn disconnect_during_refresh_does_not_restore_tokens() {
        let fixture = Fixture::new().await;
        let flows = OauthFlows::default();
        let session = fixture.session();
        fixture.login(&flows, session.clone()).await;
        fixture.hold.store(true, Ordering::SeqCst);
        let worker = {
            let session = session.clone();
            tokio::spawn(async move { session.token(Some("access-1")).await })
        };
        fixture.entered.notified().await;
        session.disconnect().unwrap();
        fixture.release.notify_one();
        assert!(worker.await.unwrap().is_err());
        assert!(TokenRecord::load(&fixture.settings, "Linear").is_none());
    }

    #[tokio::test]
    async fn oauth_errors_do_not_echo_tokens_or_silently_replace_credentials() {
        let fixture = Fixture::new().await;
        let flows = OauthFlows::default();
        let session = fixture.session();
        fixture.login(&flows, session.clone()).await;
        let mut record = TokenRecord::load(&fixture.settings, "Linear").unwrap();
        record.token_endpoint = fixture.url.replace("/mcp", "/token-error");
        record.expires_at = Some(1);
        session.store(session.generation(), &record, false).unwrap();
        let error = session.token(None).await.unwrap_err().to_string();
        assert!(error.contains("401"));
        assert!(!error.contains("secret must not escape"));
        assert!(!error.contains("access-1"));
        assert_eq!(
            TokenRecord::load(&fixture.settings, "Linear")
                .unwrap()
                .access_token,
            "access-1"
        );
        record.server_url = "https://different.invalid/mcp".into();
        session.store(session.generation(), &record, false).unwrap();
        assert!(
            session
                .token(None)
                .await
                .unwrap_err()
                .to_string()
                .contains("not bound")
        );
    }

    #[tokio::test]
    async fn imported_forward_owns_oauth_and_filters_tools_after_401_refresh() {
        let fixture = Fixture::new().await;
        let registry =
            crate::mcp::ForwardRegistry::load(&fixture.dir, fixture.settings.clone()).unwrap();
        let missing = fixture.dir.join("cline-file-does-not-need-to-exist.json");
        registry
            .save(vec![crate::mcp::ForwardConfig {
                name: "Linear".into(),
                url: fixture.url.clone(),
                bearer_env: String::new(),
                scope: None,
                tools: vec!["read".into()],
                guests: Some(vec!["guest".into()]),
                cline: Some(crate::mcp_import::ClineSource {
                    path: missing.to_str().unwrap().into(),
                    server: "Linear".into(),
                }),
                oauth: false,
            }])
            .unwrap();
        let forward = registry
            .enable_oauth("Linear", Some("read".into()))
            .unwrap();
        let flows = OauthFlows::default();
        fixture.login(&flows, forward.oauth_session.clone()).await;
        let app = crate::state::AppState::default();
        app.add_container("guest");
        let state = crate::mcp::McpState::new(app, registry.clone());
        fixture.reject_once.store(true, Ordering::SeqCst);
        let reply = crate::mcp::handle_message(
            &state,
            "Linear",
            "guest",
            "127.0.0.1".parse().unwrap(),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await;
        assert_eq!(reply["result"]["tools"], json!([{"name":"read"}]));
        assert!(!reply.to_string().contains("access-"));
        assert_eq!(fixture.refreshes.load(Ordering::SeqCst), 1);
        let denied = crate::mcp::handle_message(
            &state,
            "Linear",
            "guest",
            "127.0.0.1".parse().unwrap(),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write"}}),
        )
        .await;
        assert!(denied.get("error").is_some());
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
        assert_eq!(registry.configs()[0].guests, Some(vec!["guest".into()]));
        assert!(!missing.exists());
        assert!(Arc::ptr_eq(
            &registry
                .validation_forward(registry.configs()[0].clone())
                .unwrap()
                .oauth_session,
            &forward.oauth_session
        ));
        let mut changed = registry.configs();
        changed[0].url = "https://other.invalid/mcp".into();
        registry.save(changed).unwrap();
        assert!(forward.oauth_session.token(None).await.is_err());
        assert!(TokenRecord::load(&fixture.settings, "Linear").is_none());
    }

    #[test]
    fn oauth_urls_and_resource_metadata_hint_are_validated() {
        for url in [
            "http://auth.example/token",
            "ftp://example/token",
            "https://user:pass@example/token",
            "https://example/token#fragment",
        ] {
            assert!(secure_url(url).is_err());
        }
        assert!(secure_url("https://auth.example/token").is_ok());
        assert!(secure_url("http://127.0.0.1:1234/token").is_ok());
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("www-authenticate","Bearer realm=\"OAuth\", resource_metadata=\"https://mcp.linear.app/.well-known/oauth-protected-resource/mcp\"".parse().unwrap());
        assert_eq!(
            resource_metadata_hint(&headers).as_deref(),
            Some("https://mcp.linear.app/.well-known/oauth-protected-resource/mcp")
        );
        assert!(expiry(Some(u64::MAX)).is_err());
    }

    #[tokio::test]
    #[ignore = "public Linear metadata only; opt-in network contract check"]
    async fn linear_public_discovery_contract() {
        let discovery = discover("https://mcp.linear.app/mcp").await.unwrap();
        assert_eq!(discovery.resource, "https://mcp.linear.app/mcp");
        assert_eq!(
            discovery.metadata.token_endpoint,
            "https://mcp.linear.app/token"
        );
    }
}
