// simple ble echo listener using the custom transport
use std::time::Duration;

use anyhow::Result;
use iroh::{
    Endpoint, SecretKey,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_ble::BleUserTransport;

const ALPN: &[u8] = b"iroh-ble/echo/0";

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
        println!("echoed {bytes_sent} byte(s)");
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let secret_key = SecretKey::from([0u8; 32]);
    let transport = BleUserTransport::builder().build(secret_key.clone()).await?;
    let endpoint = Endpoint::empty_builder(iroh::RelayMode::Disabled)
        .secret_key(secret_key)
        .preset(transport.preset())
        .clear_ip_transports()
        .clear_relay_transports()
        .bind()
        .await?;

    println!("ble endpoint id: {}", endpoint.id());
    let _router = Router::builder(endpoint).accept(ALPN, Echo).spawn();

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
