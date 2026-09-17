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
        // Avoid application PINGs: some provider edges enforce minimum ping
        // intervals and answer aggressive keepalives with GOAWAY. Short-lived
        // idle pooling still reuses active inference connections without
        // carrying a silent connection indefinitely.
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(16)
        .http2_adaptive_window(true);
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

    #[tokio::test(flavor = "current_thread")]
    async fn real_proxy_multiplexes_http2_upstream_and_streams_json_immediately() {
        use tracing_subscriber::{Layer as _, layer::SubscriberExt as _};

        let diagnostic_lines = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let diagnostics = crate::diagnostics::H2SettingsLayer::capturing(diagnostic_lines.clone())
            .with_filter(tracing_subscriber::filter::filter_fn(
                crate::diagnostics::h2_settings_metadata,
            ));
        let subscriber = tracing_subscriber::registry().with(diagnostics);
        let _diagnostic_guard = tracing::subscriber::set_default(subscriber);
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
        let post_bytes = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let origin_task = {
            let connections = connections.clone();
            let h2_requests = h2_requests.clone();
            let post_bytes = post_bytes.clone();
            let active = active.clone();
            let maximum = maximum.clone();
            tokio::spawn(async move {
                loop {
                    let (socket, _) = origin.accept().await.unwrap();
                    connections.fetch_add(1, Ordering::SeqCst);
                    let acceptor = acceptor.clone();
                    let h2_requests = h2_requests.clone();
                    let post_bytes = post_bytes.clone();
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
                                let post_bytes = post_bytes.clone();
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
                                    if request.uri().path() == "/post" {
                                        use http_body_util::BodyExt;
                                        let body =
                                            request.into_body().collect().await.unwrap().to_bytes();
                                        post_bytes.fetch_add(body.len(), Ordering::SeqCst);
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
                        server
                            .timer(hudsucker::hyper_util::rt::TokioTimer::new())
                            .header_table_size(Some(3_210))
                            .max_concurrent_streams(Some(17))
                            .initial_stream_window_size(Some(123_456))
                            .max_frame_size(Some(32_768))
                            .max_header_list_size(99_999);
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

        let payload = vec![b'x'; 128 * 1024];
        let requests = (0..8).map(|_| {
            client
                .post("https://api.cline.bot/post")
                .body(payload.clone())
                .send()
        });
        let responses = futures_util::future::join_all(requests).await;
        for response in responses {
            let response = response.unwrap();
            assert_eq!(response.text().await.unwrap(), "ok");
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert_eq!(post_bytes.load(Ordering::SeqCst), payload.len() * 8);
        assert_eq!(h2_requests.load(Ordering::SeqCst), 17);

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
        assert_eq!(h2_requests.load(Ordering::SeqCst), 18);

        let diagnostics = diagnostic_lines.lock().unwrap().join("\n");
        let upstream_settings = diagnostics
            .lines()
            .find(|line| {
                line.contains("h2_peer_settings")
                    && line.contains("direction=upstream")
                    && line.contains("max_concurrent_streams=17")
            })
            .unwrap_or_else(|| panic!("upstream peer SETTINGS were not captured:\n{diagnostics}"));
        for fact in [
            "header_table_size=3210",
            "initial_window_size=123456",
            "max_frame_size=32768",
            "max_header_list_size=99999",
        ] {
            assert!(upstream_settings.contains(fact), "{upstream_settings}");
        }
        assert!(diagnostics.contains("h2_connection_open"), "{diagnostics}");
        assert!(!diagnostics.contains("authorization"), "{diagnostics}");
        assert!(!diagnostics.contains("/post"), "{diagnostics}");

        proxy_task.abort();
        origin_task.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn real_proxy_reports_remote_http2_stream_reset_without_replaying_post() {
        let dir = std::env::temp_dir().join(format!("fz-h2-reset-{}", uuid::Uuid::new_v4()));
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
        let received = Arc::new(AtomicUsize::new(0));
        let origin_task = {
            let received = received.clone();
            tokio::spawn(async move {
                let (socket, _) = origin.accept().await.unwrap();
                let tls = acceptor.accept(socket).await.unwrap();
                let mut connection = h2::server::handshake(tls).await.unwrap();
                while let Some(stream) = connection.accept().await {
                    let (_request, mut response) = stream.unwrap();
                    received.fetch_add(1, Ordering::SeqCst);
                    response.send_reset(h2::Reason::REFUSED_STREAM);
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
                .with_http_handler(crate::proxy::EventHandler::new(
                    app.clone(),
                    settings,
                    8081,
                    8082,
                ))
                .build()
                .unwrap()
                .start(),
        );
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap())
            .add_root_certificate(
                reqwest::Certificate::from_pem(files.cert_pem.as_bytes()).unwrap(),
            )
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let response = client
            .post("https://api.cline.bot/reset")
            .body("inference request must not be replayed")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
        let text = response.text().await.unwrap();
        for fact in [
            "upstream send failed",
            "protocol=h2",
            "h2=remote_stream_reset",
            "h2_reason=REFUSED_STREAM(7)",
            "delivery=uncertain",
            "friendzone_retry=disabled",
        ] {
            assert!(text.contains(fact), "missing {fact}: {text}");
        }
        assert_eq!(received.load(Ordering::SeqCst), 1);
        let events = app.view().requests;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, Some(502));
        assert_eq!(
            events[0].detail.as_deref(),
            text.strip_prefix("friendzone: ")
        );

        proxy_task.abort();
        origin_task.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn real_proxy_reports_refused_upstream_connect_as_not_started() {
        let dir = std::env::temp_dir().join(format!("fz-connect-error-{}", uuid::Uuid::new_v4()));
        let files = crate::ca::AuthorityFiles::load_or_create(&dir).unwrap();
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);

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
        let fixed = tower::service_fn(move |_uri| async move {
            tokio::net::TcpStream::connect(closed_addr)
                .await
                .map(TokioIo::new)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "private connector diagnostic",
                    )
                })
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
                .with_http_handler(crate::proxy::EventHandler::new(
                    app.clone(),
                    settings,
                    8081,
                    8082,
                ))
                .build()
                .unwrap()
                .start(),
        );
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap())
            .add_root_certificate(
                reqwest::Certificate::from_pem(files.cert_pem.as_bytes()).unwrap(),
            )
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let response = client
            .post("https://api.cline.bot/connect-error")
            .body("not delivered")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
        let text = response.text().await.unwrap();
        for fact in [
            "upstream connect failed",
            "io=ConnectionRefused",
            "delivery=not_started",
            "friendzone_retry=disabled",
        ] {
            assert!(text.contains(fact), "missing {fact}: {text}");
        }
        assert!(!text.contains("SendRequest"), "{text}");
        assert!(!text.contains("private connector diagnostic"), "{text}");
        assert!(!text.contains("not delivered"), "{text}");
        assert!(!text.contains("delivery=uncertain"), "{text}");
        let events = app.view().requests;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, Some(502));
        assert_eq!(
            events[0].detail.as_deref(),
            text.strip_prefix("friendzone: ")
        );

        proxy_task.abort();
        let _ = std::fs::remove_dir_all(dir);
    }
}
