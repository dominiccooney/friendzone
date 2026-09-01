use std::{future::pending, net::SocketAddr};

use anyhow::{Context, Result};
use hudsucker::{
    Proxy,
    certificate_authority::RcgenAuthority,
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};

use crate::{proxy::EventHandler, state::AppState};

pub async fn serve(
    addr: SocketAddr,
    state: AppState,
    issuer: Issuer<'static, KeyPair>,
) -> Result<()> {
    let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());
    tracing::info!(%addr, "proxy listening");
    Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(EventHandler::new(state))
        .with_graceful_shutdown(pending())
        .build()
        .context("build proxy")?
        .start()
        .await
        .context("run proxy")
}
