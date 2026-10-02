//! Upload files first, then reference the returned provider URL in Markdown.
//! Upload approval never authorizes creation or editing of an issue or comment.
use std::{net::IpAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{review, settings::Settings, state::AppState};

pub const MAX_FILE: usize = 25 * 1024 * 1024;
const GITHUB_IMAGE_LIMIT: usize = 10_000_000;
const MAX_RESPONSE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    Github,
    Linear,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub destination: Destination,
    pub filename: String,
    pub content_type: String,
    pub session_id: String,
    pub repository: Option<String>,
}

impl Submission {
    pub fn validate(&self) -> Result<()> {
        if self.filename.is_empty()
            || self.filename.len() > 255
            || self
                .filename
                .chars()
                .any(|c| c.is_control() || "/\\".contains(c))
            || matches!(self.filename.as_str(), "." | "..")
        {
            bail!("filename must be a basename up to 255 bytes without controls");
        }
        if self.session_id.is_empty() || self.session_id.len() > 256 {
            bail!("session_id required (up to 256 bytes)");
        }
        let Some((kind, subtype)) = self.content_type.split_once('/') else {
            bail!("content_type must be a MIME type");
        };
        if [kind, subtype].iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
        }) {
            bail!("content_type must be a MIME type without parameters");
        }
        match self.destination {
            Destination::Github => {
                let parts: Vec<_> = self
                    .repository
                    .as_deref()
                    .unwrap_or("")
                    .split('/')
                    .collect();
                if parts.len() != 2
                    || parts.iter().any(|part| {
                        part.is_empty()
                            || matches!(*part, "." | "..")
                            || !part
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    })
                {
                    bail!("GitHub uploads require repository: owner/repository");
                }
                if !matches!(
                    self.content_type.as_str(),
                    "image/png"
                        | "image/jpeg"
                        | "image/gif"
                        | "image/svg+xml"
                        | "video/mp4"
                        | "video/quicktime"
                        | "video/webm"
                ) {
                    bail!(
                        "GitHub attachments support PNG, JPEG, GIF, SVG, MP4, MOV and WebM; use Linear for other files"
                    );
                }
            }
            Destination::Linear if self.repository.is_some() => {
                bail!("repository applies only to GitHub; Linear uploads need no issue ID")
            }
            Destination::Linear => {}
        }
        Ok(())
    }

    pub fn max_bytes(&self) -> usize {
        // A conservative 10 MB limit also works for video on free GitHub plans.
        if self.destination == Destination::Github {
            GITHUB_IMAGE_LIMIT
        } else {
            MAX_FILE
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Review {
    #[serde(flatten)]
    pub submission: Submission,
    pub sha256: String,
    pub bytes: usize,
    pub credential: String,
    pub url: Option<String>,
    #[serde(skip)]
    pub instance: Uuid,
    #[serde(skip)]
    pub content: Option<Bytes>,
}

pub struct UploadRequest<'a> {
    pub container: &'a str,
    pub peer: IpAddr,
    pub fake: &'a str,
    pub submission: Submission,
    pub content: Bytes,
    pub epoch: Uuid,
}

pub fn slots() -> &'static Arc<tokio::sync::Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4)))
}

struct Credential {
    entry: String,
    digest: String,
    header: String,
}

impl Credential {
    fn resolve(settings: &Settings, destination: Destination, fake: &str) -> Result<Self> {
        let host = match destination {
            Destination::Github => "uploads.github.com",
            Destination::Linear => "api.linear.app",
        };
        let mut matches = settings.entries().into_iter().filter(|entry| {
            entry.fake == fake
                && !fake.is_empty()
                && entry.header == "authorization"
                && entry.hosts.iter().any(|pinned| pinned == host)
        });
        let entry = matches.next().with_context(|| format!("No matching host credential pinned to {host}. Configure it in host Settings > Credentials; never put a real token in the guest."))?;
        if matches.next().is_some() {
            bail!("ambiguous upload credential");
        }
        if destination == Destination::Github
            && !entry.hosts.iter().any(|host| host == "api.github.com")
        {
            bail!(
                "GitHub upload credential must also pin api.github.com for the repository lookup"
            );
        }
        let real = settings
            .real_value(&entry)
            .context("Upload credential is disconnected; connect it in host Settings")?;
        let header = format!("{}{real}", entry.prefix);
        header
            .parse::<reqwest::header::HeaderValue>()
            .context("invalid host upload credential")?;
        if destination == Destination::Github
            && !["ghp_", "gho_", "github_pat_"]
                .iter()
                .any(|prefix| real.starts_with(prefix))
        {
            bail!(
                "GitHub attachments require a personal access or OAuth token, not an installation token"
            );
        }
        let digest = Sha256::digest(serde_json::to_vec(&json!([
            entry.name,
            entry.fake,
            entry.hosts,
            entry.header,
            entry.prefix,
            real
        ]))?);
        Ok(Self {
            entry: entry.name,
            digest: format!("{digest:x}"),
            header,
        })
    }
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    github_api: String,
    github_upload: String,
    linear_api: String,
    #[cfg(test)]
    storage_endpoint: Option<String>,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(60))
                .user_agent("Friendzone file upload")
                .build()
                .expect("upload client"),
            github_api: "https://api.github.com/graphql".into(),
            github_upload: "https://uploads.github.com/user-attachments/assets".into(),
            linear_api: "https://api.linear.app/graphql".into(),
            #[cfg(test)]
            storage_endpoint: None,
        }
    }
}

struct Outcome {
    app: AppState,
    id: Uuid,
    sending: bool,
    finished: bool,
}
impl Drop for Outcome {
    fn drop(&mut self) {
        if !self.finished {
            self.app.reviews.observe(self.id, if self.sending { review::Status::Unknown } else { review::Status::Cancelled }, None,
                if self.sending { "Upload interrupted; outcome unknown. Not retried. Inspect existing uploads before retrying." } else { "Upload cancelled. Not sent." });
        }
    }
}

impl Client {
    #[cfg(test)]
    pub(crate) fn for_test(http: reqwest::Client, base: &str) -> Self {
        Self {
            http,
            github_api: format!("{base}/graphql"),
            github_upload: format!("{base}/assets"),
            linear_api: format!("{base}/linear"),
            storage_endpoint: Some(format!("{base}/storage")),
        }
    }
    pub async fn upload(
        &self,
        app: &AppState,
        settings: &Settings,
        request: UploadRequest<'_>,
    ) -> Result<Value> {
        let UploadRequest { container, peer, fake, submission: input, content, epoch } = request;
        input.validate()?;
        if content.is_empty() || content.len() > input.max_bytes() {
            bail!("File is empty or exceeds the destination upload limit");
        }
        let (instance, current_epoch) = app
            .async_identity(container, peer)
            .context("guest no longer authorized")?;
        if current_epoch != epoch {
            bail!("guest policy changed while uploading");
        }
        let credential = Credential::resolve(settings, input.destination, fake)?;
        let sha256 = format!("{:x}", Sha256::digest(&content));
        let view = Review {
            submission: input.clone(),
            sha256,
            bytes: content.len(),
            credential: credential.entry.clone(),
            url: None,
            instance,
            content: Some(content.clone()),
        };
        let metadata = serde_json::to_vec(&view)?;
        let endpoint = match input.destination {
            Destination::Github => &self.github_upload,
            Destination::Linear => &self.linear_api,
        };
        let request = hudsucker::hyper::Request::builder()
            .method("POST")
            .uri(endpoint)
            .header("content-type", "application/json")
            .body(hudsucker::Body::empty())?;
        let mut detail = review::Detail::from_request(container, &request, &metadata)?;
        detail.summary.body_bytes = content.len();
        detail.summary.reason = "File upload only. Use the returned URL in a separate description or comment request. File content and metadata may contain private information.".into();
        detail.file_upload = Some(view);
        let id = detail.summary.id;
        let mut outcome = Outcome {
            app: app.clone(),
            id,
            sending: false,
            finished: false,
        };
        let ticket = app.enqueue_review(detail, peer, epoch)?;
        if ticket.wait().await? != review::Decision::Approve {
            bail!("File upload denied by host");
        }
        // Approval freezes bytes/metadata and credential binding. Changes take
        // effect at the next admission; nothing can revoke an already sent request.
        let admitted = || -> Result<()> {
            if app.review_epoch(container, peer) != Some(epoch) {
                bail!("Guest policy changed; upload not sent");
            }
            if Credential::resolve(settings, input.destination, fake)?.digest != credential.digest {
                bail!("Upload credential changed; submit again for review");
            }
            Ok(())
        };
        admitted()?;
        let result = async {
            let repository_id = if input.destination == Destination::Github {
                let parts: Vec<_> = input.repository.as_deref().expect("validated repository").split('/').collect();
                let response = self.http.post(&self.github_api).header("authorization", &credential.header).json(&json!({
                    "query": "query FriendzoneUploadRepository($owner:String!,$name:String!){repository(owner:$owner,name:$name){databaseId viewerPermission}}",
                    "variables": {"owner": parts[0], "name": parts[1]}
                })).send().await.map_err(|_| anyhow::anyhow!("GitHub repository lookup failed"))?;
                let json = response_json(response).await?;
                if json.get("errors").is_some_and(|errors| errors.as_array().is_none_or(|values| !values.is_empty())) { bail!("GitHub repository lookup returned errors"); }
                let repository = &json["data"]["repository"];
                if !matches!(repository["viewerPermission"].as_str(), Some("WRITE" | "MAINTAIN" | "ADMIN")) { bail!("GitHub attachments require write access to the repository"); }
                Some(repository["databaseId"].as_u64().filter(|id| *id > 0).context("GitHub repository ID unavailable")?)
            } else { None };
            admitted()?;
            if !app.admit_review(id, container, peer, epoch) { bail!("Guest policy changed; upload not sent"); }
            outcome.sending = true;
            match input.destination {
                Destination::Github => {
                    let response = self.http.post(&self.github_upload).query(&[
                        ("name", input.filename.clone()), ("content_type", input.content_type.clone()), ("repository_id", repository_id.expect("GitHub ID").to_string())
                    ]).header("authorization", &credential.header).header("accept", "application/vnd.github+json")
                        .header("content-type", "application/octet-stream").body(content).send().await
                        .map_err(|_| anyhow::anyhow!("GitHub upload interrupted; inspect existing uploads before retrying"))?;
                    let json = response_json(response).await?;
                    let url = json["url"].as_str().context("GitHub returned no asset URL")?;
                    validate_asset(url, Destination::Github)?;
                    Ok(url.to_owned())
                }
                Destination::Linear => {
                    let response = self.http.post(&self.linear_api).header("authorization", &credential.header).json(&json!({
                        "query": "mutation FriendzoneFileUpload($type:String!,$name:String!,$size:Int!){fileUpload(contentType:$type,filename:$name,size:$size,makePublic:false){success uploadFile{uploadUrl assetUrl headers{key value}}}}",
                        "variables": {"type": input.content_type, "name": input.filename, "size": content.len()}
                    })).send().await.map_err(|_| anyhow::anyhow!("Linear upload preparation failed"))?;
                    let prepared = linear_prepared(response_json(response).await?)?;
                    admitted()?;
                    let headers = signed_headers(prepared.headers, &input.content_type, content.len())?;
                    // Signed storage headers are copied exactly; broker credentials
                    // are never attached to this separate, unauthenticated client call.
                    let storage_url = &prepared.upload_url;
                    #[cfg(test)]
                    let storage_url = self.storage_endpoint.as_ref().unwrap_or(storage_url);
                    let response = self.http.put(storage_url).headers(headers).body(content).send().await
                        .map_err(|_| anyhow::anyhow!("Linear upload interrupted; inspect existing uploads before retrying"))?;
                    if !response.status().is_success() { bail!("Linear storage upload returned HTTP {}", response.status().as_u16()); }
                    Ok(prepared.asset_url)
                }
            }
        }.await;
        match result {
            Ok(url) => {
                app.reviews.upload_result(id, url.clone());
                app.reviews.observe(
                    id,
                    review::Status::ResponseReceived,
                    None,
                    "File uploaded. Use the returned URL in a separate description or comment.",
                );
                outcome.finished = true;
                Ok(result_value(&input, &url, id))
            }
            Err(error) => {
                app.reviews.observe(
                    id,
                    if outcome.sending {
                        review::Status::Unknown
                    } else {
                        review::Status::Blocked
                    },
                    None,
                    &error.to_string(),
                );
                outcome.finished = true;
                Err(error)
            }
        }
    }
}

fn result_value(input: &Submission, url: &str, id: Uuid) -> Value {
    let label = input.filename.replace(['[', ']', '\\', '\n', '\r'], "_");
    let markdown = format!(
        "{}[{label}](<{url}>)",
        if input.content_type.starts_with("image/") {
            "!"
        } else {
            ""
        }
    );
    json!({"id": id, "url": url, "markdown": markdown, "filename": input.filename, "destination": input.destination,
        "guidance": "Upload complete. Use this URL in the issue/PR description or comment body; uploading did not create or edit one. Linear URLs are private to Linear, not GitHub image hosting."})
}

pub fn guest_result(
    detail: &review::Detail,
    container: &str,
    instance: Uuid,
    session: &str,
) -> Option<Value> {
    let upload = detail.file_upload.as_ref()?;
    if detail.summary.container != container
        || upload.instance != instance
        || upload.submission.session_id != session
    {
        return None;
    }
    Some(
        json!({"id": detail.summary.id, "kind": "file_upload", "session_id": session, "status": detail.summary.status, "terminal": !matches!(detail.summary.status, review::Status::Pending | review::Status::Approved | review::Status::Sending), "updated_at": detail.summary.updated_at,
        "outcome": detail.summary.outcome, "result": upload.url.as_ref().map(|url| result_value(&upload.submission, url, detail.summary.id).to_string())}),
    )
}

async fn response_json(mut response: reqwest::Response) -> Result<Value> {
    if !response.status().is_success() {
        bail!(
            "Upload service returned HTTP {} (check credential access and file limits)",
            response.status().as_u16()
        );
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("Upload response interrupted"))?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE {
            bail!("Upload response exceeds limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Invalid upload response JSON"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Prepared {
    upload_url: String,
    asset_url: String,
    headers: Vec<SignedHeader>,
}
#[derive(Deserialize)]
struct SignedHeader {
    key: String,
    value: String,
}

fn signed_headers(signed: Vec<SignedHeader>, content_type: &str, bytes: usize) -> Result<reqwest::header::HeaderMap> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("content-type", content_type.parse()?);
    headers.insert("cache-control", "public, max-age=31536000".parse()?);
    let mut seen = std::collections::HashSet::new();
    for header in signed {
        let name: reqwest::header::HeaderName = header.key.parse()?;
        if !seen.insert(name.clone()) || matches!(name.as_str(), "authorization" | "proxy-authorization" | "cookie" | "host" | "transfer-encoding" | "connection") {
            bail!("Linear returned an unsafe or duplicate upload header");
        }
        if (name == "content-type" && header.value != content_type)
            || (name == "content-length" && header.value != bytes.to_string())
        {
            bail!("Linear signed headers disagree with the reviewed file");
        }
        headers.insert(name, header.value.parse()?);
    }
    Ok(headers)
}

fn linear_prepared(json: Value) -> Result<Prepared> {
    if json
        .get("errors")
        .is_some_and(|errors| errors.as_array().is_none_or(|values| !values.is_empty()))
        || json["data"]["fileUpload"]["success"] != true
    {
        bail!("Linear could not prepare this upload");
    }
    // uploadFile is nullable in the authoritative Linear UploadPayload schema.
    let prepared: Prepared =
        serde_json::from_value(json["data"]["fileUpload"]["uploadFile"].clone())
            .map_err(|_| anyhow::anyhow!("Linear returned incomplete upload details"))?;
    let url = reqwest::Url::parse(&prepared.upload_url).context("invalid Linear storage URL")?;
    if url.scheme() != "https"
        || !matches!(
            url.host_str(),
            Some("uploads.linear.app" | "storage.googleapis.com")
        )
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!(
            "Linear signed upload must target uploads.linear.app or storage.googleapis.com over HTTPS; arbitrary storage destinations are not allowed"
        );
    }
    if prepared.headers.len() > 32
        || prepared
            .headers
            .iter()
            .map(|header| header.key.len() + header.value.len())
            .sum::<usize>()
            > review::MAX_HEADERS
    {
        bail!("Linear signed headers exceed limit");
    }
    validate_asset(&prepared.asset_url, Destination::Linear)?;
    Ok(prepared)
}

fn validate_asset(raw: &str, destination: Destination) -> Result<()> {
    let url = reqwest::Url::parse(raw).context("invalid asset URL")?;
    let valid = match destination {
        Destination::Github => {
            url.host_str() == Some("github.com")
                && url.path().starts_with("/user-attachments/assets/")
        }
        Destination::Linear => url.host_str() == Some("uploads.linear.app") && url.path() != "/",
    };
    if !valid
        || url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || raw
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>'))
    {
        bail!("Upload service returned an unexpected asset URL");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_headers_cannot_override_file_identity_or_inject_credentials() {
        for headers in [
            vec![("authorization", "secret")],
            vec![("content-type", "text/html")],
            vec![("content-length", "999")],
            vec![("X-Required", "one"), ("x-required", "two")],
        ] {
            assert!(signed_headers(headers.into_iter().map(|(key,value)| SignedHeader { key:key.into(),value:value.into() }).collect(), "image/png", 12).is_err());
        }
        let headers=signed_headers(vec![SignedHeader { key:"Content-Disposition".into(),value:"attachment; filename=\"shot.png\"".into() }], "image/png", 12).unwrap();
        assert_eq!(headers["content-disposition"], "attachment; filename=\"shot.png\"");
        assert_eq!(headers["content-type"], "image/png");
    }

    #[test]
    fn linear_nullable_upload_and_signed_destinations_follow_the_contract() {
        let prepared = |upload_url: &str| {
            json!({"data":{"fileUpload":{"success":true,"uploadFile":{
                "uploadUrl":upload_url,"assetUrl":"https://uploads.linear.app/workspace/file",
                "headers":[{"key":"x-goog-content-length-range","value":"12,12"}]
            }}}})
        };
        for url in [
            "https://uploads.linear.app/workspace/file?signature=x",
            "https://storage.googleapis.com/linear-storage/file?X-Goog-Signature=x",
        ] {
            assert!(linear_prepared(prepared(url)).is_ok());
        }
        for url in [
            "http://uploads.linear.app/file",
            "https://uploads.linear.app.evil.test/file",
            "https://localhost/file",
            "https://127.0.0.1/file",
            "https://storage.googleapis.com:8081/file",
            "https://token@uploads.linear.app/file",
        ] {
            assert!(linear_prepared(prepared(url)).is_err(), "{url}");
        }
        for value in [
            json!({"data":{"fileUpload":{"success":true,"uploadFile":null}}}),
            json!({"data":{"fileUpload":{"success":false,"uploadFile":null}}}),
            json!({"errors":[{"message":"private"}]}),
        ] {
            assert!(linear_prepared(value).is_err());
        }
        assert!(
            validate_asset(
                "https://github.com/user-attachments/assets/file",
                Destination::Github
            )
            .is_ok()
        );
        assert!(
            validate_asset(
                "https://evil.test/user-attachments/assets/file",
                Destination::Github
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn upload_response_rejects_redirects_oversize_and_non_json_without_exposing_bodies() {
        use axum::{Router, response::IntoResponse, routing::post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route(
                        "/redirect",
                        post(|| async {
                            (
                                axum::http::StatusCode::TEMPORARY_REDIRECT,
                                [("location", "http://localhost/private")],
                                "secret echo",
                            )
                                .into_response()
                        }),
                    )
                    .route("/large", post(|| async { vec![b'x'; MAX_RESPONSE + 1] }))
                    .route("/invalid", post(|| async { "not json secret" })),
            )
            .await
            .unwrap();
        });
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for route in ["redirect", "large", "invalid"] {
            let error = response_json(http.post(format!("{base}/{route}")).send().await.unwrap())
                .await
                .unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
        server.abort();
    }
}
