mod bootstrap;
mod browser;
mod ca;
mod diagnostics;
mod doctor;
mod github;
mod graphql;
mod guest_http;
mod jobs;
mod lfs;
mod mcp;
mod mcp_import;
mod mcp_oauth;
mod oauth;
mod policy;
mod proxy;
mod proxy_server;
mod pushes;
mod review;
mod settings;
mod state;
mod storage;
mod telemetry;
mod web;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use ca::{AuthorityFiles, default_data_dir};
use clap::{Parser, Subcommand};
use state::AppState;

#[derive(Parser)]
#[command(
    name = "fz",
    version,
    about = "Secure network broker for agent containers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy, bootstrap server, and web UI.
    Broker {
        #[arg(long, default_value = "127.0.0.1:8080")]
        proxy_addr: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:8081")]
        ui_addr: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:8082")]
        bootstrap_addr: SocketAddr,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Check this guest's Friendzone network setup.
    Doctor {
        #[arg(long, default_value = "http://127.0.0.1:8082")]
        broker: String,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        proxy: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::{Layer as _, layer::SubscriberExt as _, util::SubscriberInitExt as _};

    let normal = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("fz=info".parse()?)
            // Raw h2 TRACE events include HEADERS frames. The dedicated layer
            // below exposes only normalized numeric peer SETTINGS.
            .add_directive("h2=off".parse()?),
    );
    let h2_settings = diagnostics::H2SettingsLayer::default().with_filter(
        tracing_subscriber::filter::filter_fn(diagnostics::h2_settings_metadata),
    );
    let tracer_provider = telemetry::provider_from_env()?;
    let otel = tracer_provider.as_ref().map(|provider| {
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("friendzone-proxy"))
            .with_filter(tracing_subscriber::filter::filter_fn(
                telemetry::proxy_metadata,
            ))
    });
    tracing_subscriber::registry()
        .with(normal)
        .with(h2_settings)
        .with(otel)
        .init();

    let result = match Cli::parse().command {
        Command::Broker {
            proxy_addr,
            ui_addr,
            bootstrap_addr,
            data_dir,
        } => {
            run_broker(
                proxy_addr,
                ui_addr,
                bootstrap_addr,
                data_dir.unwrap_or_else(default_data_dir),
            )
            .await
        }
        Command::Doctor { broker, proxy } => doctor::run(&broker, &proxy).await,
    };
    if let Some(provider) = tracer_provider
        && let Err(error) = provider.shutdown()
    {
        tracing::warn!(%error, "could not flush OpenTelemetry traces during shutdown");
    }
    result
}

async fn run_broker(
    proxy_addr: SocketAddr,
    ui_addr: SocketAddr,
    bootstrap_addr: SocketAddr,
    data_dir: PathBuf,
) -> Result<()> {
    validate_listeners(proxy_addr, ui_addr, bootstrap_addr)?;
    let data_dir = if data_dir.is_absolute() {
        data_dir
    } else {
        std::env::current_dir()
            .context("resolve current directory for --data-dir")?
            .join(data_dir)
    };
    // Print this before loading any store so every startup failure is
    // actionable even when the UI never starts.
    println!("Friendzone data:      {}", data_dir.display());
    let files = AuthorityFiles::load_or_create(&data_dir)?;
    let issuer = files.issuer()?;
    let state = AppState::load(&data_dir)?;
    let settings = settings::Settings::load(&data_dir)?;
    let registry = mcp::ForwardRegistry::load(&data_dir, settings.clone())?;
    let trace_relay = telemetry::TraceRelay::from_env()?;
    if trace_relay.is_some() {
        println!(
            "Guest trace relay:     http://{bootstrap_addr}/v1/traces -> loopback OTLP collector"
        );
    }
    let forwards = registry.configs();
    if forwards.is_empty() {
        println!(
            "MCP forwards:         none (to add some, create {} or use Settings in the UI)",
            registry.config_path().display()
        );
    }
    for forward in &forwards {
        println!(
            "MCP forward:          /mcp/{} -> {} ({} tools)",
            forward.name,
            forward.url,
            forward.tools.len()
        );
    }
    let mcp_state = mcp::McpState::new(state.clone(), registry.clone());
    let guest_binaries = web::discover_guest_binaries(&data_dir);
    if guest_binaries.is_empty() {
        println!(
            "Optional doctor binaries: host only ({}-{}); additional builds may be placed in {}. Guest setup uses scripts, not binaries.",
            std::env::consts::OS,
            std::env::consts::ARCH,
            data_dir.join("guest-bin").display()
        );
    } else {
        let mut names: Vec<_> = guest_binaries.keys().cloned().collect();
        names.sort();
        println!("Guest binaries:       {}", names.join(", "));
    }
    println!("Friendzone proxy:     http://{proxy_addr}");
    println!("Friendzone UI:        http://{ui_addr}");
    println!("Friendzone bootstrap: http://{bootstrap_addr}");

    // Keep Cline (and future) sessions fresh so the proxy's synchronous
    // substitution always sees a valid mirrored token.
    let refresher = {
        let settings = settings.clone();
        async move {
            loop {
                oauth::refresh_expiring_cline_sessions(&settings).await;
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    };
    // Keep the large Git validation/publishing future off the Windows main
    // thread's small stack. The task owns the future on Tokio's heap-backed
    // scheduler; this select holds only its join handle.
    let push_worker = {
        let pushes = state.pushes.clone();
        let state = state.clone();
        let settings = settings.clone();
        tokio::spawn(async move { pushes.run(state, settings).await })
    };

    tokio::select! {
        _ = state.jobs.run(state.clone(), settings.clone()) => unreachable!("job worker never returns"),
        result = push_worker => match result {
            Ok(()) => anyhow::bail!("Git push worker stopped unexpectedly"),
            Err(error) => Err(error).context("Git push worker stopped"),
        },
        _ = refresher => unreachable!("refresher loop never returns"),
        result = proxy_server::serve(proxy_addr, state.clone(), issuer, settings.clone(), ui_addr.port(), bootstrap_addr.port()) => result,
        result = web::serve_ui(ui_addr, state.clone(), settings.clone(), registry, bootstrap_addr) => result,
        result = web::serve_bootstrap(bootstrap_addr, files.cert_pem, mcp_state, settings, proxy_addr.port(), trace_relay) => result,
        signal = tokio::signal::ctrl_c() => signal.context("wait for Ctrl+C"),
    }
}

fn validate_listeners(proxy: SocketAddr, ui: SocketAddr, bootstrap: SocketAddr) -> Result<()> {
    if !ui.ip().is_loopback() {
        anyhow::bail!(
            "management UI must bind to loopback (127.0.0.1 or ::1); never expose it to guests"
        );
    }
    if ui.port() == 0 || ui.port() == proxy.port() || ui.port() == bootstrap.port() {
        anyhow::bail!(
            "management UI requires a fixed port distinct from the proxy and bootstrap ports"
        );
    }
    Ok(())
}

#[cfg(test)]
mod listener_tests {
    use super::*;

    #[test]
    fn management_listener_cannot_be_exposed_or_share_guest_ports() {
        let proxy = "172.30.240.1:8080".parse().unwrap();
        let bootstrap = "172.30.240.1:8082".parse().unwrap();
        for ui in [
            "0.0.0.0:8081",
            "[::]:8081",
            "172.30.240.1:8081",
            "127.0.0.1:0",
            "127.0.0.1:8080",
            "127.0.0.1:8082",
        ] {
            assert!(
                validate_listeners(proxy, ui.parse().unwrap(), bootstrap).is_err(),
                "accepted {ui}"
            );
        }
        for ui in ["127.0.0.1:8081", "[::1]:8081"] {
            assert!(validate_listeners(proxy, ui.parse().unwrap(), bootstrap).is_ok());
        }
    }
}
