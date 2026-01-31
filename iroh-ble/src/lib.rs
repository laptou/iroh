//! ble custom transport for iroh using gatt ids and writes

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};

use ble_peripheral_rust::{
    Peripheral as GattPeripheral,
    gatt::{
        characteristic::Characteristic,
        peripheral_event::{
            PeripheralEvent, ReadRequestResponse, RequestResponse, WriteRequestResponse,
        },
        properties::{AttributePermission, CharacteristicProperty},
        service::Service,
    },
};
use btleplug::{
    api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType},
    platform::{Adapter, Manager, Peripheral as CentralPeripheral},
};
use bytes::Bytes;
use iroh::{
    EndpointId, SecretKey, TransportAddr,
    address_lookup::{self, AddressLookup, EndpointData, EndpointInfo, Item},
    endpoint::{
        Builder,
        presets::Preset,
        transports::{Addr, CustomEndpoint, CustomSender, CustomTransport, Transmit},
    },
};
use iroh_base::CustomAddr;
use n0_future::stream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

const BLE_USER_TRANSPORT_ID: u64 = 0x424c45;
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RECV_CAPACITY: usize = 64 * 1024;
const DEFAULT_EVENT_CAPACITY: usize = 256;
const DEFAULT_SEND_CAPACITY: usize = 256;
const MAX_BLE_FRAME_LEN: usize = 180;
const FLAG_SEGMENT_SIZE: u8 = 0x01;
const FLAG_TOTAL_LEN: u8 = 0x02;

const BLE_SERVICE_UUID: Uuid = Uuid::from_u128(0x4edb2f47_2c08_4c0f_9f63_6a8f2f2d2f5a);
const BLE_ID_CHAR_UUID: Uuid = Uuid::from_u128(0x6d7d2220_1f24_4e23_a6e9_6c9c1389a350);
const BLE_DATA_CHAR_UUID: Uuid = Uuid::from_u128(0x1b415f1b_6f93_4c2d_9a87_1b3b4df0b9c0);
const BLE_BOUNDARY_CHAR_UUID: Uuid = Uuid::from_u128(0x2f6f25b0_9b5e_4f1c_9f6b_1a8c3e8fb50c);

/// ble packet format for over-the-air payloads
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlePacket {
    from: EndpointId,
    data: Bytes,
    segment_size: Option<u16>,
}

/// ble boundary marker for datagram completion
#[derive(Debug, Clone, PartialEq, Eq)]
struct BleBoundary {
    from: EndpointId,
    segment_size: Option<u16>,
    total_len: Option<u32>,
}

#[derive(Debug, Default)]
struct PendingDatagram {
    data: Vec<u8>,
    segment_size: Option<u16>,
}

/// build the ble user address for a given endpoint id
pub fn ble_user_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from_parts(BLE_USER_TRANSPORT_ID, endpoint.as_bytes())
}

fn parse_user_addr(addr: &CustomAddr) -> io::Result<EndpointId> {
    if addr.id() != BLE_USER_TRANSPORT_ID {
        warn!("ble address has unexpected transport id");
        return Err(io::Error::other("unexpected transport id"));
    }
    let data = addr.data();
    if data.len() != 32 {
        warn!("ble address has unexpected length: {}", data.len());
        return Err(io::Error::other("unexpected endpoint id length"));
    }
    let bytes: [u8; 32] = data
        .try_into()
        .map_err(|_| io::Error::other("endpoint id bytes"))?;
    EndpointId::from_bytes(&bytes).map_err(io::Error::other)
}

fn encode_packet(packet: &BlePacket) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 32 + 2 + 2 + packet.data.len());
    let mut flags = 0u8;
    if packet.segment_size.is_some() {
        flags |= FLAG_SEGMENT_SIZE;
    }
    out.push(flags);
    out.extend_from_slice(packet.from.as_bytes());
    if let Some(segment_size) = packet.segment_size {
        out.extend_from_slice(&segment_size.to_be_bytes());
    }
    let len = u16::try_from(packet.data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
    debug!(
        "encode ble packet: from={} len={}",
        packet.from.fmt_short(),
        len
    );
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&packet.data);
    Ok(out)
}

fn encode_boundary(boundary: &BleBoundary) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 32 + 2 + 4);
    let mut flags = 0u8;
    if boundary.segment_size.is_some() {
        flags |= FLAG_SEGMENT_SIZE;
    }
    if boundary.total_len.is_some() {
        flags |= FLAG_TOTAL_LEN;
    }
    out.push(flags);
    out.extend_from_slice(boundary.from.as_bytes());
    if let Some(segment_size) = boundary.segment_size {
        out.extend_from_slice(&segment_size.to_be_bytes());
    }
    if let Some(total_len) = boundary.total_len {
        out.extend_from_slice(&total_len.to_be_bytes());
    }
    Ok(out)
}

fn decode_packet(buf: &[u8]) -> io::Result<BlePacket> {
    let mut offset = 0;
    let flags = *buf
        .get(offset)
        .ok_or_else(|| io::Error::other("missing flags"))?;
    offset += 1;

    let from = buf
        .get(offset..offset + 32)
        .ok_or_else(|| io::Error::other("missing from id"))?;
    offset += 32;
    let from: [u8; 32] = from
        .try_into()
        .map_err(|_| io::Error::other("invalid from id"))?;
    let from = EndpointId::from_bytes(&from).map_err(io::Error::other)?;

    let segment_size = if flags & FLAG_SEGMENT_SIZE != 0 {
        let bytes = buf
            .get(offset..offset + 2)
            .ok_or_else(|| io::Error::other("missing segment size"))?;
        offset += 2;
        Some(u16::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| io::Error::other("segment size"))?,
        ))
    } else {
        None
    };

    let len_bytes = buf
        .get(offset..offset + 2)
        .ok_or_else(|| io::Error::other("missing payload length"))?;
    offset += 2;
    let len = u16::from_be_bytes(
        len_bytes
            .try_into()
            .map_err(|_| io::Error::other("payload length"))?,
    ) as usize;
    let data = buf
        .get(offset..offset + len)
        .ok_or_else(|| io::Error::other("missing payload"))?;
    debug!("decode ble packet: from={} len={}", from.fmt_short(), len);
    Ok(BlePacket {
        from,
        data: Bytes::copy_from_slice(data),
        segment_size,
    })
}

fn decode_boundary(buf: &[u8]) -> io::Result<BleBoundary> {
    let mut offset = 0;
    let flags = *buf
        .get(offset)
        .ok_or_else(|| io::Error::other("missing boundary flags"))?;
    offset += 1;

    let from = buf
        .get(offset..offset + 32)
        .ok_or_else(|| io::Error::other("missing boundary from id"))?;
    offset += 32;
    let from: [u8; 32] = from
        .try_into()
        .map_err(|_| io::Error::other("invalid boundary from id"))?;
    let from = EndpointId::from_bytes(&from).map_err(io::Error::other)?;

    let segment_size = if flags & FLAG_SEGMENT_SIZE != 0 {
        let bytes = buf
            .get(offset..offset + 2)
            .ok_or_else(|| io::Error::other("missing boundary segment size"))?;
        offset += 2;
        Some(u16::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| io::Error::other("boundary segment size"))?,
        ))
    } else {
        None
    };

    let total_len = if flags & FLAG_TOTAL_LEN != 0 {
        let bytes = buf
            .get(offset..offset + 4)
            .ok_or_else(|| io::Error::other("missing boundary total len"))?;
        offset += 4;
        Some(u32::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| io::Error::other("boundary total len"))?,
        ))
    } else {
        None
    };

    Ok(BleBoundary {
        from,
        segment_size,
        total_len,
    })
}

fn build_ble_service(local_id: EndpointId) -> Service {
    Service {
        uuid: BLE_SERVICE_UUID,
        primary: true,
        characteristics: vec![
            Characteristic {
                uuid: BLE_ID_CHAR_UUID,
                properties: vec![CharacteristicProperty::Read],
                permissions: vec![AttributePermission::Readable],
                value: Some(local_id.as_bytes().to_vec()),
                descriptors: Vec::new(),
            },
            Characteristic {
                uuid: BLE_DATA_CHAR_UUID,
                properties: vec![
                    CharacteristicProperty::WriteWithoutResponse,
                    CharacteristicProperty::Write,
                    CharacteristicProperty::Notify,
                ],
                permissions: vec![AttributePermission::Writeable],
                value: None,
                descriptors: Vec::new(),
            },
            Characteristic {
                uuid: BLE_BOUNDARY_CHAR_UUID,
                properties: vec![
                    CharacteristicProperty::WriteWithoutResponse,
                    CharacteristicProperty::Write,
                ],
                permissions: vec![AttributePermission::Writeable],
                value: None,
                descriptors: Vec::new(),
            },
        ],
    }
}

#[derive(Clone)]
struct BlePeer {
    peripheral: CentralPeripheral,
    data_char: btleplug::api::Characteristic,
}

struct BleCentral {
    adapter: Adapter,
    peers: tokio::sync::Mutex<HashMap<EndpointId, BlePeer>>,
    scan_timeout: Duration,
    outbound_tx: mpsc::Sender<OutboundPacket>,
}

#[derive(Debug)]
enum OutboundPacket {
    Data { to: EndpointId, packet: BlePacket },
    Boundary { to: EndpointId, boundary: BleBoundary },
}

impl BleCentral {
    fn new(adapter: Adapter, scan_timeout: Duration) -> Arc<Self> {
        let (outbound_tx, outbound_rx) = mpsc::channel(DEFAULT_SEND_CAPACITY);
        let central = Arc::new(Self {
            adapter,
            peers: tokio::sync::Mutex::new(HashMap::new()),
            scan_timeout,
            outbound_tx,
        });
        BleCentral::spawn_sender(central.clone(), outbound_rx);
        central
    }

    fn spawn_sender(this: Arc<Self>, mut outbound_rx: mpsc::Receiver<OutboundPacket>) {
        // process outbound packets sequentially to preserve order
        tokio::spawn(async move {
            while let Some(outbound) = outbound_rx.recv().await {
                match outbound {
                    OutboundPacket::Data { to, packet } => {
                        if let Err(err) = this.send_packet(to, packet).await {
                            error!("ble send failed: {err}");
                        }
                    }
                    OutboundPacket::Boundary { to, boundary } => {
                        if let Err(err) = this.send_boundary(to, boundary).await {
                            error!("ble boundary send failed: {err}");
                        }
                    }
                }
            }
        });
    }

    fn enqueue_packet(&self, to: EndpointId, packet: BlePacket) -> io::Result<()> {
        self.outbound_tx
            .try_send(OutboundPacket::Data { to, packet })
            .map_err(|err| io::Error::other(err.to_string()))
    }

    fn enqueue_boundary(&self, to: EndpointId, boundary: BleBoundary) -> io::Result<()> {
        self.outbound_tx
            .try_send(OutboundPacket::Boundary { to, boundary })
            .map_err(|err| io::Error::other(err.to_string()))
    }

    async fn send_packet(&self, to: EndpointId, packet: BlePacket) -> io::Result<()> {
        let peer = self.connect_peer(to).await?;
        let frame = encode_packet(&packet)?;
        peer.peripheral
            .write(&peer.data_char, &frame, WriteType::WithoutResponse)
            .await
            .map_err(io::Error::other)?;
        debug!("ble write sent to {}", to.fmt_short());
        Ok(())
    }

    async fn send_boundary(&self, to: EndpointId, boundary: BleBoundary) -> io::Result<()> {
        let peer = self.connect_peer(to).await?;
        let frame = encode_boundary(&boundary)?;
        let boundary_char = peer
            .peripheral
            .characteristics()
            .iter()
            .find(|ch| ch.uuid == BLE_BOUNDARY_CHAR_UUID)
            .cloned()
            .ok_or_else(|| io::Error::other("missing boundary characteristic"))?;
        peer.peripheral
            .write(&boundary_char, &frame, WriteType::WithoutResponse)
            .await
            .map_err(io::Error::other)?;
        debug!("ble boundary sent to {}", to.fmt_short());
        Ok(())
    }

    async fn connect_peer(&self, to: EndpointId) -> io::Result<BlePeer> {
        if let Some(existing) = self.peers.lock().await.get(&to).cloned() {
            if existing
                .peripheral
                .is_connected()
                .await
                .map_err(io::Error::other)?
            {
                debug!("ble peer already connected: {}", to.fmt_short());
                return Ok(existing);
            }
        }

        let peer = self.find_peer(to).await?;
        self.peers.lock().await.insert(to, peer.clone());
        info!("ble peer connected: {}", to.fmt_short());
        Ok(peer)
    }

    async fn find_peer(&self, to: EndpointId) -> io::Result<BlePeer> {
        info!("ble scan starting for {}", to.fmt_short());
        self.adapter
            .start_scan(ScanFilter {
                services: vec![BLE_SERVICE_UUID],
            })
            .await
            .map_err(io::Error::other)?;
        let deadline = tokio::time::Instant::now() + self.scan_timeout;
        while tokio::time::Instant::now() < deadline {
            let peripherals = self.adapter.peripherals().await.map_err(io::Error::other)?;
            for peripheral in peripherals {
                if !peripheral_advertises(&peripheral).await? {
                    continue;
                }
                if peripheral
                    .connect()
                    .await
                    .map_err(io::Error::other)
                    .is_err()
                {
                    debug!("ble peripheral connect failed");
                    continue;
                }
                peripheral
                    .discover_services()
                    .await
                    .map_err(io::Error::other)?;
                let remote_id = read_endpoint_id(&peripheral).await?;
                debug!("ble discovered id {}", remote_id.fmt_short());
                if remote_id == to {
                    let data_char = peripheral
                        .characteristics()
                        .iter()
                        .find(|ch| ch.uuid == BLE_DATA_CHAR_UUID)
                        .cloned()
                        .ok_or_else(|| io::Error::other("missing data characteristic"))?;
                    let _ = self.adapter.stop_scan().await;
                    info!("ble scan found {}", to.fmt_short());
                    return Ok(BlePeer {
                        peripheral,
                        data_char,
                    });
                }
                let _ = peripheral.disconnect().await;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let _ = self.adapter.stop_scan().await;
        warn!("ble scan timed out for {}", to.fmt_short());
        Err(io::Error::other("ble peer not found"))
    }
}

async fn peripheral_advertises(peripheral: &CentralPeripheral) -> io::Result<bool> {
    let props = peripheral.properties().await.map_err(io::Error::other)?;
    let Some(props) = props else {
        return Ok(false);
    };
    Ok(props.services.contains(&BLE_SERVICE_UUID))
}

async fn read_endpoint_id(peripheral: &CentralPeripheral) -> io::Result<EndpointId> {
    let id_char = peripheral
        .characteristics()
        .iter()
        .find(|ch| ch.uuid == BLE_ID_CHAR_UUID)
        .cloned()
        .ok_or_else(|| io::Error::other("missing id characteristic"))?;
    let bytes = peripheral.read(&id_char).await.map_err(io::Error::other)?;
    let data: [u8; 32] = bytes
        .try_into()
        .map_err(|_| io::Error::other("invalid id length"))?;
    debug!("ble read endpoint id");
    EndpointId::from_bytes(&data).map_err(io::Error::other)
}

/// discovery service mapping endpoint ids to ble user addrs
#[derive(Debug, Clone)]
struct BleAddressLookup;

impl AddressLookup for BleAddressLookup {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<n0_future::boxed::BoxStream<Result<Item, address_lookup::Error>>> {
        let info = EndpointInfo {
            endpoint_id,
            data: EndpointData::new([TransportAddr::Custom(ble_user_addr(endpoint_id))]),
        };
        Some(Box::pin(stream::once(Ok(Item::new(
            info,
            "ble-user-addr",
            None,
        )))))
    }
}

struct BleState {
    incoming_rx: Mutex<Option<mpsc::Receiver<BlePacket>>>,
    central: Arc<BleCentral>,
}

/// builder for the ble transport
#[derive(Clone)]
pub struct BleUserTransportBuilder {
    advertise_name: String,
    scan_timeout: Duration,
    adapter_index: usize,
}

impl BleUserTransportBuilder {
    /// set the advertise name for peripheral mode
    pub fn advertise_name(mut self, name: impl Into<String>) -> Self {
        self.advertise_name = name.into();
        self
    }

    /// set the scan timeout for discovering peers
    pub fn scan_timeout(mut self, timeout: Duration) -> Self {
        self.scan_timeout = timeout;
        self
    }

    /// choose which bt adapter to use
    pub fn adapter_index(mut self, index: usize) -> Self {
        self.adapter_index = index;
        self
    }

    /// build the transport and start advertising
    pub async fn build(self, secret_key: SecretKey) -> io::Result<Arc<BleUserTransport>> {
        let local_id = secret_key.public();
        info!("ble transport build: {}", local_id.fmt_short());

        let manager = Manager::new().await.map_err(io::Error::other)?;
        let adapters = manager.adapters().await.map_err(io::Error::other)?;
        let adapter = adapters
            .into_iter()
            .nth(self.adapter_index)
            .ok_or_else(|| io::Error::other("no ble adapter found"))?;
        info!("ble using adapter index {}", self.adapter_index);

        let (incoming_tx, incoming_rx) = mpsc::channel(DEFAULT_RECV_CAPACITY);
        spawn_peripheral_task(local_id, self.advertise_name, incoming_tx.clone());

        Ok(Arc::new(BleUserTransport {
            local_id,
            state: Arc::new(BleState {
                incoming_rx: Mutex::new(Some(incoming_rx)),
                central: BleCentral::new(adapter, self.scan_timeout),
            }),
        }))
    }
}

/// ble-backed user transport factory for iroh
#[derive(Clone)]
pub struct BleUserTransport {
    local_id: EndpointId,
    state: Arc<BleState>,
}

impl BleUserTransport {
    /// create a builder for configuring a ble transport
    pub fn builder() -> BleUserTransportBuilder {
        BleUserTransportBuilder {
            advertise_name: "iroh-ble".to_string(),
            scan_timeout: DEFAULT_SCAN_TIMEOUT,
            adapter_index: 0,
        }
    }

    /// returns a discovery service for this transport
    pub fn discovery(&self) -> impl AddressLookup {
        BleAddressLookup
    }

    /// returns a preset that configures an endpoint to use this transport
    pub fn preset(self: &Arc<Self>) -> impl Preset {
        BlePreset {
            factory: self.clone(),
        }
    }
}

impl std::fmt::Debug for BleUserTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BleUserTransport")
            .field("local_id", &self.local_id)
            .finish()
    }
}

impl CustomTransport for BleUserTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        debug!("ble transport binding");
        let incoming_rx = self
            .state
            .incoming_rx
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| io::Error::other("ble receiver already bound"))?;
        info!("ble transport bound: {}", self.local_id.fmt_short());

        Ok(Box::new(BleUserEndpoint {
            local_id: self.local_id,
            watchable: n0_watcher::Watchable::new(vec![ble_user_addr(self.local_id)]),
            receiver: incoming_rx,
            sender: Arc::new(BleUserSender {
                local_id: self.local_id,
                central: self.state.central.clone(),
            }),
        }))
    }
}

/// internal preset for the ble transport
struct BlePreset {
    factory: Arc<dyn CustomTransport>,
}

impl Preset for BlePreset {
    fn apply(self, builder: Builder) -> Builder {
        builder
            .add_custom_transport(self.factory)
            .address_lookup(BleAddressLookup)
    }
}

/// active ble user endpoint created by bind
struct BleUserEndpoint {
    local_id: EndpointId,
    watchable: n0_watcher::Watchable<Vec<CustomAddr>>,
    receiver: mpsc::Receiver<BlePacket>,
    sender: Arc<BleUserSender>,
}

impl std::fmt::Debug for BleUserEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BleUserEndpoint")
            .field("local_id", &self.local_id)
            .finish()
    }
}

struct BleUserSender {
    local_id: EndpointId,
    central: Arc<BleCentral>,
}

impl std::fmt::Debug for BleUserSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BleUserSender")
            .field("local_id", &self.local_id)
            .finish()
    }
}

impl CustomSender for BleUserSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == BLE_USER_TRANSPORT_ID && addr.data().len() == 32
    }

    fn poll_send(
        &self,
        _cx: &mut std::task::Context,
        dst: &CustomAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let to = parse_user_addr(&dst)?;
        trace!(
            "ble send requested: to={} len={}",
            to.fmt_short(),
            transmit.contents.len()
        );
        let requested = transmit
            .segment_size
            .and_then(|size| u16::try_from(size).ok());
        let segment_size = requested.map(|size| size.min(MAX_BLE_FRAME_LEN as u16));
        let chunk_size = segment_size
            .map(|size| size as usize)
            .unwrap_or(MAX_BLE_FRAME_LEN)
            .min(MAX_BLE_FRAME_LEN)
            .max(1);

        let central = self.central.clone();
        let local_id = self.local_id;
        if transmit.contents.is_empty() {
            let packet = BlePacket {
                from: local_id,
                data: Bytes::new(),
                segment_size,
            };
            central.enqueue_packet(to, packet)?;
            central.enqueue_boundary(
                to,
                BleBoundary {
                    from: local_id,
                    segment_size,
                    total_len: Some(0),
                },
            )?;
            return Poll::Ready(Ok(()));
        }

        for chunk in transmit.contents.chunks(chunk_size) {
            trace!(
                "ble sending chunk: to={} len={} data={:?}",
                to.fmt_short(),
                chunk.len(),
                data_encoding::HEXLOWER.encode(chunk)
            );
            let packet = BlePacket {
                from: local_id,
                data: Bytes::copy_from_slice(chunk),
                segment_size,
            };
            central.enqueue_packet(to, packet)?;
        }
        central.enqueue_boundary(
            to,
            BleBoundary {
                from: local_id,
                segment_size,
                total_len: Some(transmit.contents.len() as u32),
            },
        )?;
        Poll::Ready(Ok(()))
    }
}

impl CustomEndpoint for BleUserEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.watchable.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        self.sender.clone()
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        let n = bufs.len().min(metas.len()).min(source_addrs.len());
        if n == 0 {
            return Poll::Ready(Ok(0));
        }

        let mut filled = 0usize;
        while filled < n {
            match self.receiver.poll_recv(cx) {
                Poll::Pending => {
                    if filled == 0 {
                        return Poll::Pending;
                    }
                    break;
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("ble receive channel closed")));
                }
                Poll::Ready(Some(packet)) => {
                    if bufs[filled].len() < packet.data.len() {
                        trace!(
                            "ble receive rejected: buffer too small: filled={} len={} data={:02x?}",
                            filled,
                            packet.data.len(),
                            data_encoding::HEXLOWER.encode(packet.data.as_ref())
                        );
                        continue;
                    }
                    trace!("ble receive accepted: filled={} len={} data={:?}",
                        filled,
                        packet.data.len(),
                        data_encoding::HEXLOWER.encode(packet.data.as_ref())
                    );
                    bufs[filled][..packet.data.len()].copy_from_slice(&packet.data);
                    metas[filled].len = packet.data.len();
                    metas[filled].stride = packet
                        .segment_size
                        .map(|size| size as usize)
                        .unwrap_or(packet.data.len());
                    source_addrs[filled] = Addr::Custom(ble_user_addr(packet.from));
                    filled += 1;
                }
            }
        }

        if filled > 0 {
            Poll::Ready(Ok(filled))
        } else {
            Poll::Pending
        }
    }
}

fn spawn_peripheral_task(
    local_id: EndpointId,
    advertise_name: String,
    incoming_tx: mpsc::Sender<BlePacket>,
) {
    // run the gatt peripheral on a dedicated thread to avoid send/sync bounds
    info!("ble peripheral starting for {}", local_id.fmt_short());
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)
            .and_then(|rt| rt.block_on(run_peripheral_task(local_id, advertise_name, incoming_tx)))
            .unwrap();
    });
}

async fn run_peripheral_task(
    local_id: EndpointId,
    advertise_name: String,
    incoming_tx: mpsc::Sender<BlePacket>,
) -> io::Result<()> {
    let (event_tx, mut event_rx) = mpsc::channel(DEFAULT_EVENT_CAPACITY);
    let mut peripheral = GattPeripheral::new(event_tx)
        .await
        .map_err(io::Error::other)?;
    while !peripheral.is_powered().await.map_err(io::Error::other)? {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    info!("ble peripheral powered on");
    peripheral
        .add_service(&build_ble_service(local_id))
        .await
        .map_err(io::Error::other)?;
    peripheral
        .start_advertising(&advertise_name, &[BLE_SERVICE_UUID])
        .await
        .map_err(io::Error::other)?;
    info!("ble advertising started: {}", advertise_name);

    let mut pending: HashMap<EndpointId, PendingDatagram> = HashMap::new();
    while let Some(event) = event_rx.recv().await {
        match event {
            PeripheralEvent::ReadRequest {
                request,
                offset,
                responder,
            } => {
                if request.characteristic != BLE_ID_CHAR_UUID {
                    let _ = responder.send(ReadRequestResponse {
                        value: Vec::new(),
                        response: RequestResponse::RequestNotSupported,
                    });
                    debug!("ble read rejected: unknown characteristic");
                    continue;
                }
                let bytes = local_id.as_bytes();
                if offset as usize > bytes.len() {
                    let _ = responder.send(ReadRequestResponse {
                        value: Vec::new(),
                        response: RequestResponse::InvalidOffset,
                    });
                    warn!("ble read rejected: invalid offset {}", offset);
                    continue;
                }
                let value = bytes[offset as usize..].to_vec();
                let _ = responder.send(ReadRequestResponse {
                    value,
                    response: RequestResponse::Success,
                });
                debug!("ble read served id");
            }
            PeripheralEvent::WriteRequest {
                request,
                value,
                offset,
                responder,
            } => {
                if offset != 0 {
                    let _ = responder.send(WriteRequestResponse {
                        response: RequestResponse::InvalidOffset,
                    });
                    warn!("ble write rejected: invalid offset {}", offset);
                    continue;
                }

                if request.characteristic == BLE_DATA_CHAR_UUID {
                    match decode_packet(&value) {
                        Ok(packet) => {
                            debug!(
                                "ble packet received: from={} len={} data={:?}",
                                packet.from.fmt_short(),
                                packet.data.len(),
                                data_encoding::HEXLOWER.encode(packet.data.as_ref())
                            );
                            let entry = pending.entry(packet.from).or_default();
                            if entry.segment_size.is_none() {
                                entry.segment_size = packet.segment_size;
                            }
                            entry.data.extend_from_slice(&packet.data);
                            let _ = responder.send(WriteRequestResponse {
                                response: RequestResponse::Success,
                            });
                        }
                        Err(err) => {
                            error!("failed to decode packet: {err}");
                            let _ = responder.send(WriteRequestResponse {
                                response: RequestResponse::UnlikelyError,
                            });
                        }
                    }
                    continue;
                }

                if request.characteristic == BLE_BOUNDARY_CHAR_UUID {
                    match decode_boundary(&value) {
                        Ok(boundary) => {
                            let assembled = pending.remove(&boundary.from).unwrap_or_default();
                            let total = assembled.data.len();
                            if let Some(expected) = boundary.total_len {
                                if expected as usize != total {
                                    warn!(
                                        "ble datagram length mismatch: expected={} got={}",
                                        expected, total
                                    );
                                }
                            }
                            let segment_size = boundary.segment_size.or(assembled.segment_size);
                            let packet = BlePacket {
                                from: boundary.from,
                                data: Bytes::from(assembled.data),
                                segment_size,
                            };
                            let _ = incoming_tx.send(packet).await;
                            let _ = responder.send(WriteRequestResponse {
                                response: RequestResponse::Success,
                            });
                        }
                        Err(err) => {
                            error!("failed to decode boundary: {err}");
                            let _ = responder.send(WriteRequestResponse {
                                response: RequestResponse::UnlikelyError,
                            });
                        }
                    }
                    continue;
                }

                let _ = responder.send(WriteRequestResponse {
                    response: RequestResponse::RequestNotSupported,
                });
                debug!("ble write rejected: unknown characteristic");
            }
            PeripheralEvent::CharacteristicSubscriptionUpdate { .. } => {}
            PeripheralEvent::StateUpdate { is_powered } => {
                if is_powered {
                    info!("ble state update: powered on");
                    let _ = peripheral
                        .start_advertising(&advertise_name, &[BLE_SERVICE_UUID])
                        .await;
                } else {
                    warn!("ble state update: powered off");
                }
            }
        }
    }
    Ok(())
}
