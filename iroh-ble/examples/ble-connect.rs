// simple ble client that connects and sends a payload
use std::str::FromStr;

use anyhow::Result;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};
use iroh_ble::{BleUserTransport, ble_user_addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALPN: &[u8] = b"iroh-ble/echo/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let mut args = std::env::args().skip(1);
    let remote = args.next().ok_or_else(|| {
        anyhow::anyhow!("usage: cargo run --example ble-connect -- <endpoint-id>")
    })?;
    let remote_id = EndpointId::from_str(&remote)?;

    let secret_key = SecretKey::from([1u8; 32]);
    let transport = BleUserTransport::builder().build(secret_key.clone()).await?;
    let endpoint = Endpoint::empty_builder(iroh::RelayMode::Disabled)
        .secret_key(secret_key)
        .preset(transport.preset())
        .clear_ip_transports()
        .clear_relay_transports()
        .bind()
        .await?;

    let addr = EndpointAddr::from_parts(
        remote_id,
        [TransportAddr::User(ble_user_addr(remote_id))],
    );
    let connection = endpoint.connect(addr, ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(b"hello over ble").await?;
    send.finish()?;
    let response = recv.read_to_end(1024).await?;
    println!("response: {}", String::from_utf8_lossy(&response));
    connection.close(0u32.into(), b"done");
    Ok(())
}
