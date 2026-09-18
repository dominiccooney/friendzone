//! OpenTelemetry startup and W3C HTTP context propagation.
//!
//! Configuration is snapshotted once at process startup. Standard `OTEL_*`
//! environment changes therefore take effect on the next broker restart.

use anyhow::{Context as _, Result};
use opentelemetry::{
    Context,
    propagation::{Extractor, Injector, TextMapPropagator as _},
};

const TRACE_RELAY_ENABLED: &str = "FZ_TRACE_RELAY_ENABLED";
pub(crate) const MAX_RELAY_BODY: usize = 4 * 1024 * 1024;

pub(crate) fn proxy_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.target() == "fz::proxy" && *metadata.level() <= tracing::Level::INFO
}

struct HeaderExtractor<'a>(&'a hudsucker::hyper::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|name| name.as_str()).collect()
    }
}

struct HeaderInjector<'a>(&'a mut hudsucker::hyper::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        let Ok(name) = hudsucker::hyper::header::HeaderName::try_from(key) else {
            return;
        };
        let Ok(value) = hudsucker::hyper::header::HeaderValue::try_from(value) else {
            return;
        };
        self.0.insert(name, value);
    }
}

pub(crate) fn extract(headers: &hudsucker::hyper::HeaderMap) -> Context {
    opentelemetry_sdk::propagation::TraceContextPropagator::new().extract(&HeaderExtractor(headers))
}

pub(crate) fn inject(context: &Context, headers: &mut hudsucker::hyper::HeaderMap) {
    use opentelemetry::trace::TraceContextExt as _;

    // Never retain an invalid incoming tracestate when extraction created a new
    // root. The fixed W3C propagator writes the exact child context afresh.
    headers.remove("traceparent");
    headers.remove("tracestate");
    if !context.span().span_context().is_valid() {
        return;
    }
    opentelemetry_sdk::propagation::TraceContextPropagator::new()
        .inject_context(context, &mut HeaderInjector(headers));
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn sdk_disabled() -> bool {
    nonempty_env("OTEL_SDK_DISABLED").is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn export_configured() -> bool {
    !nonempty_env("OTEL_TRACES_EXPORTER").is_some_and(|value| value.eq_ignore_ascii_case("none"))
        && (nonempty_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some()
            || nonempty_env("OTEL_EXPORTER_OTLP_ENDPOINT").is_some())
}

fn trace_endpoint_from_env() -> Result<Option<reqwest::Url>> {
    let Some(raw) = nonempty_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .or_else(|| nonempty_env("OTEL_EXPORTER_OTLP_ENDPOINT"))
    else {
        return Ok(None);
    };
    let signal_specific = nonempty_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some();
    let mut endpoint = reqwest::Url::parse(&raw).context("invalid OTLP trace endpoint")?;
    if !signal_specific {
        let path = format!("{}/v1/traces", endpoint.path().trim_end_matches('/'));
        endpoint.set_path(&path);
    }
    Ok(Some(endpoint))
}

#[derive(Clone)]
pub(crate) struct TraceRelay {
    endpoint: reqwest::Url,
    client: reqwest::Client,
    slots: std::sync::Arc<tokio::sync::Semaphore>,
}

impl TraceRelay {
    pub(crate) fn from_env() -> Result<Option<Self>> {
        if !nonempty_env(TRACE_RELAY_ENABLED)
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            return Ok(None);
        }
        let endpoint = trace_endpoint_from_env()?
            .context("FZ_TRACE_RELAY_ENABLED requires an OTLP trace endpoint")?;
        Self::new(endpoint).map(Some)
    }

    pub(crate) fn new(endpoint: reqwest::Url) -> Result<Self> {
        let loopback = endpoint.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if endpoint.scheme() != "http"
            || !loopback
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/v1/traces"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            anyhow::bail!(
                "trace relay target must be an unauthenticated loopback HTTP /v1/traces endpoint"
            );
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("build loopback OTLP trace relay client")?;
        Ok(Self {
            endpoint,
            client,
            slots: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        })
    }

    pub(crate) fn try_reserve(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.slots
            .clone()
            .try_acquire_owned()
            .context("trace relay busy")
    }

    pub(crate) async fn forward(
        &self,
        body: axum::body::Bytes,
        _slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<()> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .body(body)
            .send()
            .await
            .context("send trace batch to loopback collector")?;
        if !response.status().is_success() {
            anyhow::bail!("loopback collector returned HTTP {}", response.status());
        }
        Ok(())
    }
}

/// Build the provider attached to the process subscriber. A provider without an
/// exporter still creates child context, so propagation works without making an
/// unconfigured localhost collector a runtime dependency.
pub(crate) fn provider_from_env() -> Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>> {
    if sdk_disabled() {
        return Ok(None);
    }

    let service_name = nonempty_env("OTEL_SERVICE_NAME").unwrap_or_else(|| "friendzone".into());
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name)
        .build();
    let builder = opentelemetry_sdk::trace::SdkTracerProvider::builder().with_resource(resource);
    let provider = if export_configured() {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
            .context("configure OTLP/HTTP trace exporter from OTEL_* environment")?;
        builder.with_batch_exporter(exporter).build()
    } else {
        builder.build()
    };
    Ok(Some(provider))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceContextExt as _;

    #[test]
    fn trace_relay_target_is_fixed_to_loopback_otlp_http() {
        for valid in [
            "http://127.0.0.1:4318/v1/traces",
            "http://localhost:4318/v1/traces",
            "http://[::1]:4318/v1/traces",
        ] {
            assert!(TraceRelay::new(valid.parse().unwrap()).is_ok(), "{valid}");
        }
        for invalid in [
            "https://127.0.0.1:4318/v1/traces",
            "http://192.0.2.1:4318/v1/traces",
            "http://user:secret@127.0.0.1:4318/v1/traces",
            "http://127.0.0.1:4318/other",
            "http://127.0.0.1:4318/v1/traces?token=secret",
        ] {
            assert!(
                TraceRelay::new(invalid.parse().unwrap()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn exporter_filter_excludes_dependency_and_raw_h2_diagnostics() {
        assert!(proxy_metadata(
            tracing::info_span!(target: "fz::proxy", "proxy-safe")
                .metadata()
                .unwrap()
        ));
        assert!(!proxy_metadata(
            tracing::info_span!(target: "h2::proto", "headers")
                .metadata()
                .unwrap()
        ));
        assert!(!proxy_metadata(
            tracing::info_span!(target: "fz::web", "management")
                .metadata()
                .unwrap()
        ));
    }

    #[test]
    fn w3c_headers_extract_and_invalid_context_is_not_forwarded() {
        let mut headers = hudsucker::hyper::HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        headers.insert("tracestate", "vendor=value".parse().unwrap());
        let context = extract(&headers);
        assert_eq!(
            context.span().span_context().trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert!(context.span().span_context().is_remote());

        let mut forwarded = hudsucker::hyper::HeaderMap::new();
        inject(&context, &mut forwarded);
        assert_eq!(
            forwarded["traceparent"].to_str().unwrap(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
        assert_eq!(forwarded["tracestate"], "vendor=value");

        headers.insert(
            "traceparent",
            "attacker-controlled-invalid".parse().unwrap(),
        );
        let invalid = extract(&headers);
        assert!(!invalid.span().span_context().is_valid());
        let mut sanitized = headers.clone();
        inject(&invalid, &mut sanitized);
        assert!(!sanitized.contains_key("traceparent"));
        assert!(!sanitized.contains_key("tracestate"));
    }
}
