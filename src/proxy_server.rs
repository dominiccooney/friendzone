use std::{future::pending, net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use hudsucker::{
    Proxy,
    certificate_authority::RcgenAuthority,
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};

use crate::{proxy::EventHandler, state::AppState};

/// One shared Hyper client is built by Hudsucker at broker startup. Its clones
/// share this pool across every guest connection. TLS ALPN selects HTTP/2 when
/// available and retains HTTP/1.1 fallback through Hudsucker's Rustls connector.
pub(crate) fn upstream_client() -> hudsucker::hyper_util::client::legacy::Builder {
    use hudsucker::hyper_util::rt::{TokioExecutor, TokioTimer};

    let mut client = hudsucker::hyper_util::client::legacy::Client::builder(TokioExecutor::new());
    client
        .timer(TokioTimer::new())
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(Duration::from_secs(5 * 60))
        .pool_max_idle_per_host(16)
        .http2_adaptive_window(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .http2_keep_alive_while_idle(true);
    client
}

/// Hudsucker's default server builder preserves HTTP/1 header casing but has
/// no timer. HTTP/2 requires a timer for protocol background work, so keep the
/// existing HTTP/1 behavior and supply Tokio's timer for intercepted h2.
fn downstream_server()
-> hudsucker::hyper_util::server::conn::auto::Builder<hudsucker::hyper_util::rt::TokioExecutor> {
    use hudsucker::hyper_util::rt::{TokioExecutor, TokioTimer};

    let mut server = hudsucker::hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    server
        .http1()
        .title_case_headers(true)
        .preserve_header_case(true);
    server.http2().timer(TokioTimer::new());
    server
}

pub async fn serve(
    addr: SocketAddr,
    state: AppState,
    issuer: Issuer<'static, KeyPair>,
    settings: crate::settings::Settings,
    management_port: u16,
    bootstrap_port: u16,
) -> Result<()> {
    let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());
    tracing::info!(%addr, "proxy listening");
    Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_client(upstream_client())
        .with_server(downstream_server())
        .with_http_handler(EventHandler::new(
            state,
            settings,
            management_port,
            bootstrap_port,
        ))
        .with_graceful_shutdown(pending())
        .build()
        .context("build proxy")?
        .start()
        .await
        .context("run proxy")
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use hudsucker::{
        Body, Proxy,
        certificate_authority::RcgenAuthority,
        hyper::{Request, Response, Version, service::service_fn},
        hyper_util::rt::{TokioExecutor, TokioIo},
        rcgen::{CertificateParams, KeyPair, SanType},
        rustls::{
            ClientConfig, RootCertStore, ServerConfig,
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
        },
    };
    use tokio_rustls::TlsAcceptor;

    use super::{downstream_server, upstream_client};

    #[tokio::test]
    async fn real_proxy_multiplexes_http2_upstream_and_streams_json_immediately() {
        let dir = std::env::temp_dir().join(format!("fz-h2-{}", uuid::Uuid::new_v4()));
        let files = crate::ca::AuthorityFiles::load_or_create(&dir).unwrap();
        let issuer = files.issuer().unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let leaf_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(
            hudsucker::rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], leaf_key)
        .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let h2_requests = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let origin_task = {
            let connections = connections.clone();
            let h2_requests = h2_requests.clone();
            let active = active.clone();
            let maximum = maximum.clone();
            tokio::spawn(async move {
                loop {
                    let (socket, _) = origin.accept().await.unwrap();
                    connections.fetch_add(1, Ordering::SeqCst);
                    let acceptor = acceptor.clone();
                    let h2_requests = h2_requests.clone();
                    let active = active.clone();
                    let maximum = maximum.clone();
                    tokio::spawn(async move {
                        let tls = acceptor.accept(socket).await.unwrap();
                        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                        let service = service_fn(
                            move |request: Request<hudsucker::hyper::body::Incoming>| {
                                let active = active.clone();
                                let maximum = maximum.clone();
                                let h2_requests = h2_requests.clone();
                                async move {
                                    assert_eq!(request.version(), Version::HTTP_2);
                                    h2_requests.fetch_add(1, Ordering::SeqCst);
                                    if request.uri().path() == "/stream" {
                                        let stream =
                                            futures_util::stream::unfold(0, |part| async move {
                                                match part {
                                                    0 => Some((
                                                        Ok::<_, std::io::Error>("{\"first\":"),
                                                        1,
                                                    )),
                                                    1 => {
                                                        tokio::time::sleep(Duration::from_secs(1))
                                                            .await;
                                                        Some((Ok("true}"), 2))
                                                    }
                                                    _ => None,
                                                }
                                            });
                                        return Ok::<_, std::convert::Infallible>(
                                            Response::builder()
                                                .header("content-type", "application/json")
                                                .body(Body::from_stream(stream))
                                                .unwrap(),
                                        );
                                    }
                                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                                    maximum.fetch_max(now, Ordering::SeqCst);
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    active.fetch_sub(1, Ordering::SeqCst);
                                    Ok(Response::new(Body::from("ok")))
                                }
                            },
                        );
                        let mut server = hudsucker::hyper::server::conn::http2::Builder::new(
                            TokioExecutor::new(),
                        );
                        server.timer(hudsucker::hyper_util::rt::TokioTimer::new());
                        server
                            .serve_connection(TokioIo::new(tls), service)
                            .await
                            .unwrap();
                    });
                }
            })
        };

        let ca = CertificateDer::from_pem_slice(files.cert_pem.as_bytes()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        let client_config = ClientConfig::builder_with_provider(Arc::new(
            hudsucker::rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let fixed = tower::service_fn(move |_uri| {
            let address = origin_addr;
            async move {
                tokio::net::TcpStream::connect(address)
                    .await
                    .map(TokioIo::new)
            }
        });
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .with_server_name_resolver(hyper_rustls::FixedServerNameResolver::new(
                "127.0.0.1".try_into().unwrap(),
            ))
            .enable_http1()
            .enable_http2()
            .wrap_connector(fixed);

        let app = crate::state::AppState::default();
        app.add_container("guest").unwrap();
        app.set_pinned_ip("guest", Some("127.0.0.1".parse().unwrap()))
            .unwrap();
        let settings = crate::settings::Settings::load(&dir).unwrap();
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(
            Proxy::builder()
                .with_listener(proxy_listener)
                .with_ca(RcgenAuthority::new(
                    files.issuer().unwrap(),
                    16,
                    hudsucker::rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_http_connector(connector)
                .with_client(upstream_client())
                .with_server(downstream_server())
                .with_http_handler(crate::proxy::EventHandler::new(app, settings, 8081, 8082))
                .build()
                .unwrap()
                .start(),
        );
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap())
            .add_root_certificate(
                reqwest::Certificate::from_pem(files.cert_pem.as_bytes()).unwrap(),
            )
            .build()
            .unwrap();
        let url = "https://api.cline.bot/slow";

        let warm = client.get(url).send().await.unwrap();
        assert_eq!(warm.text().await.unwrap(), "ok");
        let requests = (0..8).map(|_| client.get(url).send());
        let responses = futures_util::future::join_all(requests).await;
        for response in responses {
            let response = response.unwrap();
            assert_eq!(response.text().await.unwrap(), "ok");
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert_eq!(h2_requests.load(Ordering::SeqCst), 9);
        assert!(maximum.load(Ordering::SeqCst) > 1);

        let mut response = client
            .get("https://api.cline.bot/stream")
            .send()
            .await
            .unwrap();
        let first = tokio::time::timeout(Duration::from_millis(500), response.chunk())
            .await
            .expect("first JSON chunk was buffered")
            .unwrap()
            .unwrap();
        assert_eq!(first, "{\"first\":");
        let second = response.chunk().await.unwrap().unwrap();
        assert_eq!(second, "true}");
        assert_eq!(h2_requests.load(Ordering::SeqCst), 10);

        proxy_task.abort();
        origin_task.abort();
        let _ = std::fs::remove_dir_all(dir);
    }
}
