//! Privacy-bounded transport diagnostics. The h2 crate's general TRACE output
//! includes HEADERS frames, so never enable or forward it wholesale here.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

static NEXT_H2_CONNECTION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
struct H2Connection {
    id: u64,
    peer: &'static str,
    opened_at: Instant,
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[derive(Default)]
struct DebugField {
    name: &'static str,
    value: Option<String>,
}

impl DebugField {
    fn named(name: &'static str) -> Self {
        Self { name, value: None }
    }
}

impl Visit for DebugField {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == self.name {
            self.value = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == self.name {
            self.value = Some(value.to_owned());
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PeerSettings {
    ack: bool,
    header_table_size: Option<u32>,
    enable_push: Option<u32>,
    max_concurrent_streams: Option<u32>,
    initial_window_size: Option<u32>,
    max_frame_size: Option<u32>,
    max_header_list_size: Option<u32>,
    enable_connect_protocol: Option<u32>,
}

fn parse_peer_settings(debug: &str) -> Option<PeerSettings> {
    if !debug.starts_with("Settings {") || !debug.ends_with('}') {
        return None;
    }
    let value = |name: &str| {
        let marker = format!("{name}: ");
        let start = debug.find(&marker)? + marker.len();
        let digits: String = debug[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        (!digits.is_empty())
            .then(|| digits.parse::<u32>().ok())
            .flatten()
    };
    Some(PeerSettings {
        ack: debug.contains("ACK"),
        header_table_size: value("header_table_size"),
        enable_push: value("enable_push"),
        max_concurrent_streams: value("max_concurrent_streams"),
        initial_window_size: value("initial_window_size"),
        max_frame_size: value("max_frame_size"),
        max_header_list_size: value("max_header_list_size"),
        enable_connect_protocol: value("enable_connect_protocol"),
    })
}

fn value(value: Option<u32>) -> String {
    value.map_or_else(|| "not_advertised".into(), |value| value.to_string())
}

fn settings_line(connection: &H2Connection, settings: &PeerSettings) -> String {
    format!(
        "friendzone h2_peer_settings observed_unix_ms={} connection_age_ms={} h2_connection={} direction={} header_table_size={} enable_push={} max_concurrent_streams={} initial_window_size={} max_frame_size={} max_header_list_size={} enable_connect_protocol={}",
        unix_ms(),
        connection.opened_at.elapsed().as_millis(),
        connection.id,
        if connection.peer == "client" {
            "upstream"
        } else {
            "downstream"
        },
        value(settings.header_table_size),
        value(settings.enable_push),
        value(settings.max_concurrent_streams),
        value(settings.initial_window_size),
        value(settings.max_frame_size),
        value(settings.max_header_list_size),
        value(settings.enable_connect_protocol),
    )
}

/// Enables exactly the pinned h2 0.4.19 Connection span and recv-SETTINGS
/// callsite. In particular, HEADERS and generic frame decoder events stay off.
pub fn h2_settings_metadata(metadata: &Metadata<'_>) -> bool {
    if metadata.target() != "h2::proto::connection" {
        return false;
    }
    if metadata.is_span() {
        return metadata.name() == "Connection";
    }
    metadata.is_event()
        && metadata.level() == &tracing::Level::TRACE
        && metadata.line() == Some(560)
        && metadata.file().is_some_and(|file| {
            file.ends_with("src/proto/connection.rs") || file.ends_with("src\\proto\\connection.rs")
        })
        && metadata.fields().field("frame").is_some()
}

#[derive(Clone)]
pub struct H2SettingsLayer {
    emit: Arc<dyn Fn(String) + Send + Sync>,
}

impl Default for H2SettingsLayer {
    fn default() -> Self {
        Self {
            emit: Arc::new(|line| eprintln!("{line}")),
        }
    }
}

#[cfg(test)]
impl H2SettingsLayer {
    pub(crate) fn capturing(lines: Arc<std::sync::Mutex<Vec<String>>>) -> Self {
        Self {
            emit: Arc::new(move |line| lines.lock().unwrap().push(line)),
        }
    }
}

impl<S> Layer<S> for H2SettingsLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if attrs.metadata().target() != "h2::proto::connection"
            || attrs.metadata().name() != "Connection"
        {
            return;
        }
        let mut peer = DebugField::named("peer");
        attrs.record(&mut peer);
        let peer = match peer.value.as_deref().map(|value| value.trim_matches('"')) {
            // Exact h2 0.4.19 Peer::NAME values; do not retain arbitrary span text.
            Some("Client") => "client",
            Some("Server") => "server",
            _ => return,
        };
        let connection = H2Connection {
            id: NEXT_H2_CONNECTION.fetch_add(1, Ordering::Relaxed),
            peer,
            opened_at: Instant::now(),
        };
        (self.emit)(format!(
            "friendzone h2_connection_open observed_unix_ms={} h2_connection={} direction={}",
            unix_ms(),
            connection.id,
            if peer == "client" {
                "upstream"
            } else {
                "downstream"
            }
        ));
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(connection);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if !h2_settings_metadata(event.metadata()) {
            return;
        }
        let Some(connection) = ctx.event_scope(event).and_then(|mut scope| {
            scope.find_map(|span| span.extensions().get::<H2Connection>().cloned())
        }) else {
            return;
        };
        let mut frame = DebugField::named("frame");
        event.record(&mut frame);
        let Some(settings) = frame.value.as_deref().and_then(parse_peer_settings) else {
            return;
        };
        if !settings.ack {
            (self.emit)(settings_line(&connection, &settings));
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let extensions = span.extensions();
        let Some(connection) = extensions.get::<H2Connection>() else {
            return;
        };
        (self.emit)(format!(
            "friendzone h2_connection_close observed_unix_ms={} lifetime_ms={} h2_connection={} direction={}",
            unix_ms(),
            connection.opened_at.elapsed().as_millis(),
            connection.id,
            if connection.peer == "client" {
                "upstream"
            } else {
                "downstream"
            }
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn parses_only_recognized_numeric_settings_and_never_copies_unknown_debug_text() {
        let debug = "Settings { flags: (0x0), header_table_size: 4096, enable_push: 0, max_concurrent_streams: 2147483647, initial_window_size: 268435456, max_frame_size: 16384, max_header_list_size: 4294967295, enable_connect_protocol: 1, secret: token-value }";
        let settings = parse_peer_settings(debug).unwrap();
        assert_eq!(settings.max_concurrent_streams, Some(2_147_483_647));
        assert_eq!(settings.initial_window_size, Some(268_435_456));
        let line = settings_line(
            &H2Connection {
                id: 7,
                peer: "client",
                opened_at: Instant::now(),
            },
            &settings,
        );
        assert!(line.contains("direction=upstream"));
        assert!(line.contains("max_concurrent_streams=2147483647"));
        assert!(!line.contains("secret"));
        assert!(!line.contains("token-value"));
        assert!(parse_peer_settings("Headers { authorization: secret }").is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_h2_handshake_logs_peer_settings_without_header_events() {
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = lines.clone();
        let layer = H2SettingsLayer {
            emit: Arc::new(move |line| captured.lock().unwrap().push(line)),
        }
        .with_filter(tracing_subscriber::filter::filter_fn(h2_settings_metadata));
        let normal = tracing_subscriber::fmt::layer()
            .with_writer(std::io::sink)
            .with_filter(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(tracing_subscriber::filter::LevelFilter::OFF.into())
                    .from_env_lossy()
                    .add_directive("h2=off".parse().unwrap()),
            );
        let subscriber = tracing_subscriber::registry().with(normal).with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let mut server = h2::server::Builder::new();
        server
            .header_table_size(3_210)
            .max_concurrent_streams(17)
            .initial_window_size(123_456)
            .max_frame_size(32_768)
            .max_header_list_size(99_999);
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            tokio::join!(
                async move {
                    let connection = server
                        .handshake::<_, hudsucker::hyper::body::Bytes>(server_io)
                        .await
                        .unwrap();
                    tokio::task::yield_now().await;
                    drop(connection);
                },
                async move {
                    let (_sender, connection) = h2::client::handshake(client_io).await.unwrap();
                    let _ = connection.await;
                }
            )
        })
        .await;
        assert!(result.is_ok(), "h2 fixture timed out");

        // This resembles a sensitive library event but is a different callsite;
        // the exact SETTINGS filter must never pass or format it.
        tracing::trace!(
            target: "h2::proto::connection",
            frame = ?"Headers { authorization: sentinel-secret }",
            "recv HEADERS"
        );

        let text = lines.lock().unwrap().join("\n");
        assert!(text.contains("direction=upstream"), "{text}");
        assert!(text.contains("max_concurrent_streams=17"), "{text}");
        assert!(text.contains("initial_window_size=123456"), "{text}");
        assert!(text.contains("max_frame_size=32768"), "{text}");
        assert!(!text.contains("authorization"), "{text}");
        assert!(!text.contains("sentinel-secret"), "{text}");
    }
}
