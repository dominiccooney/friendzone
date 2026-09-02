mod ca;
mod doctor;
mod mcp;
mod oauth;
mod policy;
mod proxy;
mod proxy_server;
mod settings;
mod setup;
mod state;
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
    /// Fetch the broker CA certificate into this guest.
    Setup {
        #[arg(long, default_value = "http://127.0.0.1:8082")]
        broker: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        install: bool,
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("friendzone=info".parse()?),
        )
        .init();

    match Cli::parse().command {
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
        Command::Setup {
            broker,
            output,
            install,
        } => setup::run(&broker, output, install).await,
        Command::Doctor { broker, proxy } => doctor::run(&broker, &proxy).await,
    }
}

async fn run_broker(
    proxy_addr: SocketAddr,
    ui_addr: SocketAddr,
    bootstrap_addr: SocketAddr,
    data_dir: PathBuf,
) -> Result<()> {
    let files = AuthorityFiles::load_or_create(&data_dir)?;
    let issuer = files.issuer()?;
    let state = AppState::default();
    let forwards = mcp::load_forwards(&data_dir)?;
    for forward in &forwards {
        println!(
            "MCP forward:          /mcp/{} -> {} ({} tools)",
            forward.name,
            forward.url,
            forward.tools.len()
        );
    }
    let settings = settings::Settings::load(&data_dir)?;
    let mcp_state = mcp::McpState::new(state.clone(), forwards.clone(), settings.clone());
    println!("Friendzone proxy:     http://{proxy_addr}");
    println!("Friendzone UI:        http://{ui_addr}");
    println!("Friendzone bootstrap: http://{bootstrap_addr}");

    tokio::select! {
        result = proxy_server::serve(proxy_addr, state.clone(), issuer, settings.clone()) => result,
        result = web::serve_ui(ui_addr, state, settings.clone(), forwards) => result,
        result = web::serve_bootstrap(bootstrap_addr, files.cert_pem, mcp_state, settings) => result,
        signal = tokio::signal::ctrl_c() => signal.context("wait for Ctrl+C"),
    }
}
