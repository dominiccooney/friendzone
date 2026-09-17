//! Strict Git LFS batch-download recognition. Both LFS reads and writes use
//! POST; only a bounded, unambiguous current-schema `operation: download`
//! envelope may cross the GitHub write gate automatically.
use std::collections::HashSet;

use hudsucker::{Body, hyper::Request};
use serde::Deserialize;

const MEDIA_TYPE: &str = "application/vnd.git-lfs+json";
const MAX_OBJECTS: usize = 1_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    operation: String,
    #[serde(default)]
    transfers: Option<Vec<String>>,
    #[serde(default)]
    r#ref: Option<BatchRef>,
    objects: Vec<Object>,
    #[serde(default)]
    hash_algo: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRef {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    oid: String,
    size: u64,
}

pub fn is_download(request: &Request<Body>, body: &[u8]) -> bool {
    if !download_transport(request) {
        return false;
    }
    let Ok(batch) = serde_json::from_slice::<Batch>(body) else {
        return false;
    };
    let invalid_transfers = batch.transfers.as_ref().is_some_and(|values| {
        let mut seen = HashSet::new();
        values.is_empty()
            || values.len() > 16
            || values.iter().any(|value| {
                value.is_empty()
                    || value.len() > 64
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
                    || !seen.insert(value)
            })
    });
    if batch.operation != "download"
        || batch.objects.is_empty()
        || batch.objects.len() > MAX_OBJECTS
        || batch
            .hash_algo
            .as_deref()
            .is_some_and(|algo| algo != "sha256")
        || invalid_transfers
        || batch
            .r#ref
            .as_ref()
            .is_some_and(|reference| reference.name.is_empty() || reference.name.len() > 1024)
    {
        return false;
    }
    let mut seen = HashSet::new();
    batch.objects.iter().all(|object| {
        object.oid.len() == 64
            && object.oid.bytes().all(|byte| byte.is_ascii_hexdigit())
            && seen.insert(object.oid.to_ascii_lowercase())
            && object.size <= i64::MAX as u64
    })
}

pub fn is_batch_route(request: &Request<Body>) -> bool {
    let uri = request.uri();
    request.method() == hudsucker::hyper::Method::POST
        && uri.scheme_str() == Some("https")
        && uri
            .host()
            .is_some_and(|host| host.eq_ignore_ascii_case("github.com"))
        && uri.port_u16().is_none_or(|port| port == 443)
        && uri.path().ends_with(".git/info/lfs/objects/batch")
        && uri.query().is_none()
}

fn download_transport(request: &Request<Body>) -> bool {
    if !is_batch_route(request) || request.headers().contains_key("content-encoding") {
        return false;
    }
    let mut names = HashSet::new();
    for (name, _) in request.headers() {
        if !names.insert(name.as_str())
            || !matches!(
                name.as_str(),
                "authorization"
                    | "content-type"
                    | "content-length"
                    | "transfer-encoding"
                    | "host"
                    | "user-agent"
                    | "accept"
                    | "accept-encoding"
                    | "connection"
            )
        {
            return false;
        }
    }
    if request.headers().get("host").is_some_and(|value| {
        !value.to_str().is_ok_and(|host| {
            host.eq_ignore_ascii_case("github.com") || host.eq_ignore_ascii_case("github.com:443")
        })
    }) {
        return false;
    }
    if request.headers().get("connection").is_some_and(|value| {
        !value.to_str().is_ok_and(|text| {
            text.eq_ignore_ascii_case("keep-alive") || text.eq_ignore_ascii_case("close")
        })
    }) {
        return false;
    }
    request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(valid_media_type)
        && request
            .headers()
            .get("accept")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(',').any(|part| valid_media_type(part.trim())))
}

fn valid_media_type(value: &str) -> bool {
    let mut parts = value.split(';').map(str::trim);
    parts
        .next()
        .is_some_and(|media| media.eq_ignore_ascii_case(MEDIA_TYPE))
        && parts.all(|parameter| {
            parameter.eq_ignore_ascii_case("charset=utf-8")
                || parameter.eq_ignore_ascii_case("charset=\"utf-8\"")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("https://github.com/cline/cline.git/info/lfs/objects/batch")
            .header("accept", MEDIA_TYPE)
            .header("content-type", format!("{MEDIA_TYPE}; charset=utf-8"))
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    #[test]
    fn only_current_unambiguous_download_envelopes_are_reads() {
        let oid = "a".repeat(64);
        let download = format!(
            r#"{{"operation":"download","transfers":["ssh","lfs-standalone-file","basic"],"ref":{{"name":"refs/heads/main"}},"objects":[{{"oid":"{oid}","size":12}}],"hash_algo":"sha256"}}"#
        );
        assert!(is_download(&request(&download), download.as_bytes()));
        for body in [
            download.replace("download", "upload"),
            download.replace(
                r#""operation":"download""#,
                r#""operation":"download","operation":"download""#,
            ),
            download.replace(r#""hash_algo":"sha256""#, r#""hash_algo":"sha1""#),
            download.replace(r#""size":12"#, r#""size":-1"#),
            download.replace(r#""size":12"#, r#""size":12,"action":"download""#),
        ] {
            assert!(!is_download(&request(&body), body.as_bytes()), "{body}");
        }
        let mut wrong = request(&download);
        *wrong.uri_mut() = "https://api.github.com/cline/cline.git/info/lfs/objects/batch"
            .parse()
            .unwrap();
        assert!(!is_download(&wrong, download.as_bytes()));
        wrong = request(&download);
        wrong
            .headers_mut()
            .insert("x-http-method-override", "PUT".parse().unwrap());
        assert!(!is_download(&wrong, download.as_bytes()));
        assert!(is_batch_route(&request(&download)));
    }
}
