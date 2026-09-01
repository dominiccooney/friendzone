use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use anyhow::Result;

pub async fn run(broker: &str, proxy: &str) -> Result<()> {
    println!("Friendzone doctor\n");
    let mut failed = false;
    check_http(
        "broker reachable",
        format!("{}/health", broker.trim_end_matches('/')),
        &mut failed,
    )
    .await;
    check_proxy(proxy, &mut failed);
    println!("[INFO] CA trust per language runtime is not tested yet");
    println!(
        "[INFO] UDP, DNS, and direct-IP bypass tests require platform network setup and are not tested yet"
    );
    if failed {
        anyhow::bail!("one or more checks failed")
    }
    println!("\nAll implemented checks passed.");
    Ok(())
}

async fn check_http(name: &str, url: String, failed: &mut bool) {
    match reqwest::get(&url).await.and_then(|r| r.error_for_status()) {
        Ok(_) => println!("[PASS] {name}"),
        Err(error) => {
            println!("[FAIL] {name}: {error}");
            *failed = true;
        }
    }
}

fn check_proxy(proxy: &str, failed: &mut bool) {
    let authority = proxy
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .rsplit('@')
        .next()
        .unwrap_or(proxy)
        .trim_end_matches('/');
    let address = authority
        .to_socket_addrs()
        .ok()
        .and_then(|mut values| values.next());
    match address.and_then(connect) {
        Some(Ok(())) => println!("[PASS] proxy reachable at {authority}"),
        Some(Err(error)) => {
            println!("[FAIL] proxy reachable: {error}");
            *failed = true;
        }
        None => {
            println!("[FAIL] proxy address is invalid: {authority}");
            *failed = true;
        }
    }
}

fn connect(address: SocketAddr) -> Option<std::io::Result<()>> {
    Some(TcpStream::connect_timeout(&address, Duration::from_secs(2)).map(drop))
}
