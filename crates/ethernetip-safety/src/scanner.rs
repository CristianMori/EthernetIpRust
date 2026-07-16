//! Safety scanner (originator) connection.
//!
//! Opens a safety `Forward_Open` server connection against an adapter, runs a
//! UDP producer that stamps each frame with the mode byte / timestamp /
//! rollover-seeded CRCs the safety protocol requires, and listens for the
//! target's TCOO (time-coordination) message to switch out of the initial
//! idle state into `run`. Consumer-side handling (T→O safety data flowing
//! back) is scaffolded but left as a follow-up — full "server + client" pair
//! parity with the C++/C# ports lands next.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time;

use ethernetip_connections::epio::{
    decode_frame_raw as decode_epio, encode_frame_raw as encode_epio, Frame,
};
use ethernetip_core::cip::{service, status, ReplyHeader};
use ethernetip_core::cpf::{item_type, Envelope, Item};
use ethernetip_core::encap::{encode_frame as encode_encap, Command, Header, HEADER_LEN};
use ethernetip_core::error::{EipError, Result};

use crate::crc;
use crate::forward_open::{
    build_safety_forward_open, SafetyAppReply, SafetyForwardOpenConfig, CM_PATH,
};
use crate::frame_codec;
use crate::types::{ModeByte, SafetyFormat};

/// Well-known safety I/O port.
pub const IO_UDP_PORT: u16 = 2222;

/// CPF item type ID for a Sockaddr Info O→T response item.
/// Public configuration for [`open_safety_scanner`].
#[derive(Debug, Clone)]
pub struct SafetyScannerConfig {
    pub adapter_tcp: SocketAddr,
    pub udp_bind: SocketAddr,
    /// Optional routing bytes (backplane / slot); empty for a device with a
    /// built-in safety validator.
    pub route_prefix: Vec<u8>,
    /// Server-direction FO — we produce O→T safety data.
    pub server: SafetyForwardOpenConfig,
    /// Optional client-direction FO — target produces T→O safety data.
    /// When set, the scanner opens a second connection right after the
    /// server one and stands up a consumer that decodes incoming safety
    /// frames (with target-timestamp rollover tracking) and sends a TCOO
    /// reply back on every fresh ping_count.
    pub client: Option<SafetyForwardOpenConfig>,
    pub orig_vendor: u16,
    pub orig_serial: u32,
    /// Peer UDP port for producer packets. Defaults to `IO_UDP_PORT`; local
    /// interop tests override so scanner and adapter don't clash on a single
    /// host.
    pub peer_udp_port: u16,
}

impl SafetyScannerConfig {
    pub fn new(adapter_tcp: SocketAddr, server: SafetyForwardOpenConfig) -> Self {
        Self {
            adapter_tcp,
            // Bind an ephemeral port by default so scanner and adapter can
            // coexist on the same host without port trickery. The chosen
            // endpoint is advertised to the target via Sockaddr Info T→O.
            udp_bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            route_prefix: Vec::new(),
            server,
            client: None,
            orig_vendor: 0x0001,
            orig_serial: 0x1234_5678,
            peer_udp_port: IO_UDP_PORT,
        }
    }

    /// Opt into the client direction — attach a second Forward_Open config
    /// so the scanner also consumes T→O safety data from the target.
    pub fn client(mut self, cfg: SafetyForwardOpenConfig) -> Self {
        self.client = Some(cfg);
        self
    }

    pub fn udp_bind(mut self, addr: SocketAddr) -> Self {
        self.udp_bind = addr;
        self
    }

    pub fn peer_udp_port(mut self, port: u16) -> Self {
        self.peer_udp_port = port;
        self
    }

    pub fn originator(mut self, vendor: u16, serial: u32) -> Self {
        self.orig_vendor = vendor;
        self.orig_serial = serial;
        self
    }

    pub fn route_prefix(mut self, bytes: Vec<u8>) -> Self {
        self.route_prefix = bytes;
        self
    }
}

/// Live handle to a running safety scanner connection.
pub struct SafetyScannerConnection {
    pub server_o_to_t_id: u32,
    pub server_t_to_o_id: u32,
    /// Client-direction (target-produced) O→T id, when client leg opened.
    pub client_o_to_t_id: Option<u32>,
    /// Client-direction (target-produced) T→O id, when client leg opened.
    pub client_t_to_o_id: Option<u32>,
    pub target_app_reply: SafetyAppReply,
    pub target_udp: SocketAddr,
    /// Number of O→T frames produced.
    pub tx_count: Arc<AtomicU64>,
    /// Number of T→O TCOO frames received from the target.
    pub tcoo_count: Arc<AtomicU64>,
    /// Number of valid T→O safety data frames received (client direction).
    pub rx_count: Arc<AtomicU64>,
    /// Number of T→O frames dropped because a CRC or complement check failed.
    pub rx_crc_fail: Arc<AtomicU64>,
    /// Number of TCOO replies we've sent to the target on the client leg.
    pub tcoo_tx: Arc<AtomicU64>,
    /// Output data buffer — writes here are picked up on the next producer tick.
    pub output_data: Arc<Mutex<Vec<u8>>>,
    /// Input buffer populated as valid T→O safety frames arrive (client leg).
    pub input_data: Arc<Mutex<Vec<u8>>>,
    /// True once at least one target TCOO has arrived (the C# scanner uses
    /// this to move from `idle` to `run`).
    pub consumer_active: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    tcp: Option<TcpStream>,
    session_handle: u32,
    server_conn_serial: u16,
    client_conn_serial: Option<u16>,
    orig_vendor: u16,
    orig_serial: u32,
    ctx: u64,
    route_prefix: Vec<u8>,
    closed: bool,
}

impl SafetyScannerConnection {
    pub async fn close(mut self) -> Result<()> {
        self.close_inner().await
    }

    async fn close_inner(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = self.shutdown_tx.send(true);
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
        let mut tcp = match self.tcp.take() {
            Some(s) => s,
            None => return Ok(()),
        };
        let _ = send_safety_forward_close(
            &mut tcp,
            self.session_handle,
            self.next_ctx(),
            self.server_conn_serial,
            self.orig_vendor,
            self.orig_serial,
            &self.route_prefix,
        )
        .await;
        if let Some(client_serial) = self.client_conn_serial {
            let _ = send_safety_forward_close(
                &mut tcp,
                self.session_handle,
                self.next_ctx(),
                client_serial,
                self.orig_vendor,
                self.orig_serial,
                &self.route_prefix,
            )
            .await;
        }
        let _ = send_unregister(&mut tcp, self.session_handle).await;
        let _ = tcp.shutdown().await;
        Ok(())
    }

    fn next_ctx(&mut self) -> [u8; 8] {
        self.ctx = self.ctx.wrapping_add(1);
        self.ctx.to_le_bytes()
    }
}

impl Drop for SafetyScannerConnection {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.shutdown_tx.send(true);
        }
    }
}

/// Open a safety scanner connection (server direction: originator produces
/// safety O→T data). Blocks until the target's Forward_Open reply is parsed.
pub async fn open_safety_scanner(cfg: SafetyScannerConfig) -> Result<SafetyScannerConnection> {
    let mut tcp = TcpStream::connect(cfg.adapter_tcp).await?;
    tcp.set_nodelay(true)?;

    let mut ctx: u64 = 0;
    let session_handle = register_session(&mut tcp, &mut ctx).await?;

    let ticks = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EipError::Protocol("system clock predates unix epoch".into()))?
        .as_micros() as u64;
    let server_conn_serial = ((ticks & 0xFFFF) as u16).max(1);

    // Bind UDP up front so we know the port to advertise in Sockaddr Info T→O.
    let udp = Arc::new(UdpSocket::bind(cfg.udp_bind).await?);
    let our_udp = udp.local_addr()?;

    let fo_wire = build_safety_forward_open(
        &cfg.server,
        server_conn_serial,
        cfg.orig_vendor,
        cfg.orig_serial,
        0xA0, // server direction
        &cfg.route_prefix,
        &[],
    )?;

    // Build the MR request (Forward_Open service) via the CM path.
    // Include a Sockaddr Info T→O CPF item so the target knows our UDP
    // endpoint for T→O safety data.
    let mr = build_mr_request(service::FORWARD_OPEN, &fo_wire.cm_path, &fo_wire.service_data);
    let sockaddr_bytes = ethernetip_core::cpf::encode_sockaddr_in_v4(our_udp)?;
    let items = [
        Item::null_address(),
        Item::new(item_type::UNCONNECTED_DATA, mr),
        Item::new(item_type::SOCKADDR_INFO_T_TO_O, sockaddr_bytes),
    ];
    let body = ethernetip_core::cpf::encode_envelope(0, 5, &items);
    let (fo_header, fo_reply_bytes) =
        exchange_with_header(&mut tcp, Command::SendRRData, session_handle, next_ctx(&mut ctx), &body).await?;
    let _ = fo_header;
    let envelope = Envelope::parse(&fo_reply_bytes)?;
    let mr_item = envelope
        .find(item_type::UNCONNECTED_DATA)
        .ok_or_else(|| EipError::Protocol("FO reply missing UnconnectedData".into()))?;
    let header = ReplyHeader::parse(&mr_item.data)?;
    if header.general_status != status::SUCCESS {
        return Err(EipError::Cip {
            status: header.general_status,
            ext: header.extended_status,
        });
    }
    let srd = &mr_item.data[header.body_offset..];
    if srd.len() < 26 {
        return Err(EipError::Short {
            expected: 26,
            actual: srd.len(),
        });
    }
    let server_oto_t_id = u32::from_le_bytes([srd[0], srd[1], srd[2], srd[3]]);
    let server_tto_o_id = u32::from_le_bytes([srd[4], srd[5], srd[6], srd[7]]);
    let app_reply_words = srd[24] as usize;
    let mut target_app_reply = SafetyAppReply::default();
    if app_reply_words > 0 && srd.len() >= 26 + app_reply_words * 2 {
        target_app_reply = SafetyAppReply::parse(&srd[26..26 + app_reply_words * 2]);
    }

    // Discover target UDP endpoint from Sockaddr Info O→T if present, else
    // fall back to (peer_ip, IO_UDP_PORT). The local-interop override lets
    // scanner and adapter share a host with different UDP ports.
    let mut target_udp = ethernetip_core::cpf::resolve_peer_udp(
        &envelope,
        item_type::SOCKADDR_INFO_O_TO_T,
        cfg.adapter_tcp.ip(),
        IO_UDP_PORT,
    );
    if cfg.peer_udp_port != IO_UDP_PORT {
        target_udp.set_port(cfg.peer_udp_port);
    }

    // Compute PID seeds for our O→T frames.
    let pid_seed_s1 = crc::pid_cid_seed_s1(cfg.orig_vendor, cfg.orig_serial, server_conn_serial);
    let pid_seed_s3 = crc::pid_cid_seed_s3(cfg.orig_vendor, cfg.orig_serial, server_conn_serial);
    let pid_seed_s5 = crc::pid_cid_seed_s5(cfg.orig_vendor, cfg.orig_serial, server_conn_serial);

    // If a client-direction config is provided, open a second Forward_Open
    // right after the server one and stand up a T→O consumer path.
    let (client_state, client_conn_serial) = if let Some(client_cfg) = &cfg.client {
        let client_conn_serial = server_conn_serial.wrapping_add(1).max(1);
        let client_fo_wire = build_safety_forward_open(
            client_cfg,
            client_conn_serial,
            cfg.orig_vendor,
            cfg.orig_serial,
            0x20, // client direction (target produces T→O)
            &cfg.route_prefix,
            &[],
        )?;
        let mr = build_mr_request(
            service::FORWARD_OPEN,
            &client_fo_wire.cm_path,
            &client_fo_wire.service_data,
        );
        let items = [
            Item::null_address(),
            Item::new(item_type::UNCONNECTED_DATA, mr),
        ];
        let body = ethernetip_core::cpf::encode_envelope(0, 5, &items);
        let (_hdr, reply_bytes) = exchange_with_header(
            &mut tcp,
            Command::SendRRData,
            session_handle,
            next_ctx(&mut ctx),
            &body,
        )
        .await?;
        let envelope2 = Envelope::parse(&reply_bytes)?;
        let mr_item2 = envelope2
            .find(item_type::UNCONNECTED_DATA)
            .ok_or_else(|| EipError::Protocol("client FO reply missing UnconnectedData".into()))?;
        let hdr2 = ReplyHeader::parse(&mr_item2.data)?;
        if hdr2.general_status != status::SUCCESS {
            // Best-effort: cancel the server connection we just opened.
            let _ = send_safety_forward_close(
                &mut tcp,
                session_handle,
                next_ctx(&mut ctx),
                server_conn_serial,
                cfg.orig_vendor,
                cfg.orig_serial,
                &cfg.route_prefix,
            )
            .await;
            return Err(EipError::Cip {
                status: hdr2.general_status,
                ext: hdr2.extended_status,
            });
        }
        let crd = &mr_item2.data[hdr2.body_offset..];
        if crd.len() < 26 {
            return Err(EipError::Short {
                expected: 26,
                actual: crd.len(),
            });
        }
        let client_oto_t = u32::from_le_bytes([crd[0], crd[1], crd[2], crd[3]]);
        let client_tto_o = u32::from_le_bytes([crd[4], crd[5], crd[6], crd[7]]);
        let app_reply_words = crd[24] as usize;
        let mut client_app_reply = SafetyAppReply::default();
        if app_reply_words > 0 && crd.len() >= 26 + app_reply_words * 2 {
            client_app_reply = SafetyAppReply::parse(&crd[26..26 + app_reply_words * 2]);
        }
        (
            Some(ClientLeg {
                oto_t_id: client_oto_t,
                tto_o_id: client_tto_o,
                app_reply: client_app_reply,
                format: client_cfg.format,
                data_size: client_cfg.produced_data_size as usize,
            }),
            Some(client_conn_serial),
        )
    } else {
        (None, None)
    };

    // UDP socket was bound earlier so we could advertise it in Sockaddr Info.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let output_data = Arc::new(Mutex::new(vec![0u8; cfg.server.consumed_data_size as usize]));
    let input_data = Arc::new(Mutex::new(vec![
        0u8;
        client_state
            .as_ref()
            .map(|c| c.data_size)
            .unwrap_or(0)
    ]));
    let consumer_active = Arc::new(AtomicBool::new(false));
    let tx_count = Arc::new(AtomicU64::new(0));
    let tcoo_count = Arc::new(AtomicU64::new(0));
    let rx_count = Arc::new(AtomicU64::new(0));
    let rx_crc_fail = Arc::new(AtomicU64::new(0));
    let tcoo_tx = Arc::new(AtomicU64::new(0));

    let producer = ProducerState {
        udp: udp.clone(),
        target: target_udp,
        connection_id: server_oto_t_id,
        rpi_us: cfg.server.o_to_t_rpi_us.max(cfg.server.rpi_us).max(1000),
        format: cfg.server.format,
        pid_seed_s1,
        pid_seed_s3,
        pid_seed_s5,
        output_data: output_data.clone(),
        consumer_active: consumer_active.clone(),
        tx_count: tx_count.clone(),
        seq: AtomicU32::new(0),
        ping_count: AtomicU16::new(0),
        // Seed timestamp / rollover from what we advertise in the safety
        // segment — a spec-compliant consumer reads the same values off the
        // segment and starts its counters there, so both ends must agree
        // from frame 1.
        timestamp: AtomicU16::new(cfg.server.initial_timestamp),
        rollover_count: AtomicU16::new(cfg.server.initial_rollover_value),
    };
    let producer_task = tokio::spawn(producer.run(shutdown_rx.clone()));

    // Client-side seeds (target-produced frames): use the target's identity
    // + the target's safety-validator instance id from the client-leg
    // SafetyAppReply.
    let target_vendor = target_app_reply.target_vendor_id;
    let target_serial = target_app_reply.target_device_serial;
    let client_leg = client_state.map(|c| {
        let sv_inst = c.app_reply.target_connection_serial;
        let target_pid_s1 = crc::pid_cid_seed_s1(target_vendor, target_serial, sv_inst);
        let target_pid_s3 = crc::pid_cid_seed_s3(target_vendor, target_serial, sv_inst);
        let target_pid_s5 = crc::pid_cid_seed_s5(target_vendor, target_serial, sv_inst);
        let cid_seed_s3 = crc::pid_cid_seed_s3(
            cfg.orig_vendor,
            cfg.orig_serial,
            client_conn_serial.unwrap(),
        );
        ClientLegState {
            oto_t_id: c.oto_t_id,
            tto_o_id: c.tto_o_id,
            format: c.format,
            data_size: c.data_size,
            target_pid_s1,
            target_pid_s3,
            target_pid_s5,
            cid_seed_s3,
            rollover: Arc::new(Mutex::new(RolloverState::default())),
            seq: Arc::new(AtomicU32::new(0)),
            production_start: std::time::Instant::now(),
        }
    });

    let consumer = ConsumerState {
        udp: udp.clone(),
        server_tto_o_id,
        consumer_active: consumer_active.clone(),
        tcoo_count: tcoo_count.clone(),
        rx_count: rx_count.clone(),
        rx_crc_fail: rx_crc_fail.clone(),
        tcoo_tx: tcoo_tx.clone(),
        input_data: input_data.clone(),
        client: client_leg.clone(),
        target_udp,
        orig_vendor: cfg.orig_vendor,
        orig_serial: cfg.orig_serial,
    };
    let consumer_task = tokio::spawn(consumer.run(shutdown_rx));

    Ok(SafetyScannerConnection {
        server_o_to_t_id: server_oto_t_id,
        server_t_to_o_id: server_tto_o_id,
        client_o_to_t_id: client_leg.as_ref().map(|c| c.oto_t_id),
        client_t_to_o_id: client_leg.as_ref().map(|c| c.tto_o_id),
        target_app_reply,
        target_udp,
        tx_count,
        tcoo_count,
        rx_count,
        rx_crc_fail,
        tcoo_tx,
        output_data,
        input_data,
        consumer_active,
        shutdown_tx,
        tasks: vec![producer_task, consumer_task],
        tcp: Some(tcp),
        session_handle,
        server_conn_serial,
        client_conn_serial,
        orig_vendor: cfg.orig_vendor,
        orig_serial: cfg.orig_serial,
        ctx,
        route_prefix: cfg.route_prefix,
        closed: false,
    })
}

/// Handoff between the open path and the consumer once the client-side FO
/// succeeds — carries just the IDs + format needed to spin up a decoder.
#[derive(Debug, Clone)]
struct ClientLeg {
    oto_t_id: u32,
    tto_o_id: u32,
    app_reply: SafetyAppReply,
    format: SafetyFormat,
    data_size: usize,
}

/// Full per-connection state the consumer thread holds for the client leg.
#[derive(Debug, Clone)]
struct ClientLegState {
    oto_t_id: u32,
    tto_o_id: u32,
    format: SafetyFormat,
    data_size: usize,
    target_pid_s1: u8,
    target_pid_s3: u16,
    target_pid_s5: u32,
    cid_seed_s3: u16,
    rollover: Arc<Mutex<RolloverState>>,
    seq: Arc<AtomicU32>,
    /// Monotonic reference the outgoing TCOO consumer_time is derived from
    /// (elapsed / 128 µs). Same convention as the C# SafetyDevice.
    production_start: std::time::Instant,
}

/// Target-timestamp rollover tracker. The 16-bit safety timestamp wraps
/// every ~8.4 s; the consumer has to advance a folded rollover count
/// BEFORE CRC verification because the CRC-S5 seed depends on it.
#[derive(Debug, Default)]
struct RolloverState {
    initialized: bool,
    last_ts: u16,
    rollover_count: u16,
    last_ping: u8,
}

fn next_ctx(ctx: &mut u64) -> [u8; 8] {
    *ctx = ctx.wrapping_add(1);
    ctx.to_le_bytes()
}

fn build_mr_request(service_code: u8, path: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + path.len() + body.len());
    out.push(service_code);
    out.push((path.len() / 2) as u8);
    out.extend_from_slice(path);
    out.extend_from_slice(body);
    out
}

async fn register_session(tcp: &mut TcpStream, ctx: &mut u64) -> Result<u32> {
    let payload = [0x01, 0x00, 0x00, 0x00];
    let (header, _body) = exchange_with_header(
        tcp,
        Command::RegisterSession,
        0,
        next_ctx(ctx),
        &payload,
    )
    .await?;
    Ok(header.session_handle)
}

async fn exchange_with_header(
    tcp: &mut TcpStream,
    command: Command,
    session_handle: u32,
    sender_context: [u8; 8],
    payload: &[u8],
) -> Result<(Header, Vec<u8>)> {
    let frame = encode_encap(command, session_handle, sender_context, payload);
    tcp.write_all(&frame).await?;
    let mut header_buf = [0u8; HEADER_LEN];
    tcp.read_exact(&mut header_buf).await?;
    let header = Header::parse(&header_buf)?;
    let mut body = vec![0u8; header.length as usize];
    if header.length > 0 {
        tcp.read_exact(&mut body).await?;
    }
    if header.status != 0 {
        return Err(EipError::Encap(header.status));
    }
    Ok((header, body))
}

async fn send_safety_forward_close(
    tcp: &mut TcpStream,
    session_handle: u32,
    sender_context: [u8; 8],
    conn_serial: u16,
    orig_vendor: u16,
    orig_serial: u32,
    route_prefix: &[u8],
) -> Result<()> {
    let mut close_data = Vec::with_capacity(12 + route_prefix.len());
    close_data.push(0x05);
    close_data.push(0x9C);
    close_data.extend_from_slice(&conn_serial.to_le_bytes());
    close_data.extend_from_slice(&orig_vendor.to_le_bytes());
    close_data.extend_from_slice(&orig_serial.to_le_bytes());
    close_data.push((route_prefix.len() / 2) as u8);
    close_data.push(0);
    close_data.extend_from_slice(route_prefix);
    let mr = build_mr_request(service::FORWARD_CLOSE, &CM_PATH, &close_data);
    let items = [
        Item::null_address(),
        Item::new(item_type::UNCONNECTED_DATA, mr),
    ];
    let body = ethernetip_core::cpf::encode_envelope(0, 5, &items);
    let mut ctx_local: u64 = u64::from_le_bytes(sender_context);
    let _ = exchange_with_header(
        tcp,
        Command::SendRRData,
        session_handle,
        next_ctx(&mut ctx_local),
        &body,
    )
    .await;
    Ok(())
}

async fn send_unregister(tcp: &mut TcpStream, session_handle: u32) -> Result<()> {
    let frame = encode_encap(Command::UnRegisterSession, session_handle, [0; 8], &[]);
    let _ = tcp.write_all(&frame).await;
    Ok(())
}

// -------------------- producer --------------------

struct ProducerState {
    udp: Arc<UdpSocket>,
    target: SocketAddr,
    connection_id: u32,
    rpi_us: u32,
    format: SafetyFormat,
    pid_seed_s1: u8,
    pid_seed_s3: u16,
    pid_seed_s5: u32,
    output_data: Arc<Mutex<Vec<u8>>>,
    consumer_active: Arc<AtomicBool>,
    tx_count: Arc<AtomicU64>,
    seq: AtomicU32,
    ping_count: AtomicU16,
    timestamp: AtomicU16,
    /// Producer rollover — folded into CRC-S5 seed for Extended format.
    /// Seeded from cfg.server.initial_rollover_value at open, bumped every
    /// time `timestamp` wraps 0xFFFF -> 0x0000. Base format ignores this
    /// (S1/S2/S3 don't fold rollover), but any Extended-format consumer
    /// would drift out of sync at the first wrap if it stayed at 0.
    rollover_count: AtomicU16,
}

impl ProducerState {
    async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        let period = Duration::from_micros(self.rpi_us as u64);
        let mut ticker = time::interval(period);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        // 128 µs per timestamp tick; ticks-per-frame = rpi_us / 128.
        let ts_delta = ((self.rpi_us as u32 / 128).max(1)) as u16;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    let active = self.consumer_active.load(Ordering::Relaxed);
                    let ping = (self.ping_count.load(Ordering::Relaxed) & 0x03) as u8;
                    let mode = ModeByte::build(active, ping);
                    // Snapshot both counters BEFORE advancing them. The frame
                    // we're about to encode carries the OLD timestamp with
                    // the OLD rollover; the consumer detects the wrap from
                    // the *next* frame's timestamp jump and bumps its own
                    // rollover to match. Reading rollover after the bump
                    // would emit (old_ts, new_rollover) on the wrap frame,
                    // which CRCs with the wrong seed and shows up as one
                    // failed frame per wrap boundary.
                    let (ts, rollover) = if active {
                        let ts_send = self.timestamp.load(Ordering::Relaxed);
                        let rollover_send = self.rollover_count.load(Ordering::Relaxed);
                        let next_ts = ts_send.wrapping_add(ts_delta);
                        self.timestamp.store(next_ts, Ordering::Relaxed);
                        if next_ts < ts_send {
                            self.rollover_count.fetch_add(1, Ordering::Relaxed);
                        }
                        (ts_send, rollover_send)
                    } else {
                        (0, self.rollover_count.load(Ordering::Relaxed))
                    };
                    let data = self.output_data.lock().await.clone();
                    let mut wire = vec![0u8; frame_codec::wire_size(data.len(), self.format)];
                    frame_codec::encode(
                        &mut wire,
                        &data,
                        self.format,
                        mode,
                        ts,
                        self.pid_seed_s1,
                        self.pid_seed_s3,
                        self.pid_seed_s5,
                        rollover,
                    );
                    let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
                    let epio = Frame {
                        connection_id: self.connection_id,
                        sequence: seq,
                        cip_sequence: seq as u16,
                        run_idle: None, // safety frames carry their own run/idle in mode byte
                        data: wire,
                    };
                    let bytes = encode_epio(&epio);
                    if self.udp.send_to(&bytes, self.target).await.is_ok() {
                        self.tx_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

// -------------------- consumer --------------------

struct ConsumerState {
    udp: Arc<UdpSocket>,
    server_tto_o_id: u32,
    consumer_active: Arc<AtomicBool>,
    tcoo_count: Arc<AtomicU64>,
    rx_count: Arc<AtomicU64>,
    rx_crc_fail: Arc<AtomicU64>,
    tcoo_tx: Arc<AtomicU64>,
    input_data: Arc<Mutex<Vec<u8>>>,
    client: Option<ClientLegState>,
    target_udp: SocketAddr,
    orig_vendor: u16,
    orig_serial: u32,
}

impl ConsumerState {
    async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        let mut buf = vec![0u8; 2048];
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                res = self.udp.recv_from(&mut buf) => {
                    let (n, _peer) = match res {
                        Ok(x) => x,
                        Err(err) => {
                            tracing::debug!("safety scanner udp recv: {err}");
                            continue;
                        }
                    };
                    let frame = match decode_epio(&buf[..n]) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    // Server T→O connection carries the target's TCOO (~5-6 B).
                    if frame.connection_id == self.server_tto_o_id {
                        self.tcoo_count.fetch_add(1, Ordering::Relaxed);
                        // First TCOO flips the consumer-active latch so the
                        // producer starts stamping run=1 on subsequent frames.
                        self.consumer_active.store(true, Ordering::Relaxed);
                        continue;
                    }
                    // Client T→O connection carries target-produced safety data.
                    if let Some(client) = self.client.as_ref() {
                        if frame.connection_id == client.tto_o_id {
                            self.handle_client_data(client, &frame.data).await;
                        }
                    }
                }
            }
        }
    }

    async fn handle_client_data(&self, client: &ClientLegState, payload: &[u8]) {
        // Derive data length from the wire size: short (≤2 B) is len+6,
        // long is 2*len+8. Anything under 5 B is a TCOO, not data.
        let wire_len = payload.len();
        if wire_len < 6 {
            return;
        }
        let data_len = if wire_len >= 7 && wire_len <= 8 {
            wire_len - 6
        } else if wire_len >= 14 && (wire_len - 8) % 2 == 0 {
            (wire_len - 8) / 2
        } else {
            return;
        };
        if data_len == 0 || data_len != client.data_size {
            return;
        }

        // Peek at the timestamp BEFORE the CRC-S5 seed depends on the
        // rollover count — a wrap detected here has to bump the counter
        // before verification.
        let ts = frame_codec::extract_timestamp(payload, data_len, client.format);
        let rollover_now = {
            let mut rs = client.rollover.lock().await;
            if rs.initialized {
                let delta = ts as i32 - rs.last_ts as i32;
                if delta < -0x4000 {
                    rs.rollover_count = rs.rollover_count.wrapping_add(1);
                }
            } else {
                rs.initialized = true;
            }
            rs.last_ts = ts;
            rs.rollover_count
        };

        let result = frame_codec::decode(
            payload,
            data_len,
            client.format,
            client.target_pid_s1,
            client.target_pid_s3,
            client.target_pid_s5,
            rollover_now,
        );

        // Mode byte lives right after the data bytes.
        let mode_byte = payload.get(data_len).copied().unwrap_or(0);
        let target_ping = mode_byte & 0x03;
        let should_reply = {
            let mut rs = client.rollover.lock().await;
            let first_time = !rs.initialized || rs.last_ping != target_ping;
            // Set below regardless so the reply gates on transitions only.
            rs.last_ping = target_ping;
            first_time
        };

        match result {
            Ok(frame) => {
                self.rx_count.fetch_add(1, Ordering::Relaxed);
                let mut w = self.input_data.lock().await;
                let n = frame.actual_data.len().min(w.len());
                w[..n].copy_from_slice(&frame.actual_data[..n]);
            }
            Err(err) => {
                self.rx_crc_fail.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("client-leg CRC fail: {:?}", err);
            }
        }

        if should_reply {
            self.send_client_tcoo(client, target_ping).await;
        }
    }

    async fn send_client_tcoo(&self, client: &ClientLegState, ping_reply: u8) {
        // Consumer time = 128 µs ticks since the connection came up. The
        // producer's time-correction math keys off this monotonic value —
        // C#, C++, and Python all use a per-connection Stopwatch reference
        // (see SafetyDevice.SendTimeCoordination in the C# port).
        let elapsed_us = client.production_start.elapsed().as_micros();
        let consumer_time_value = ((elapsed_us / 128) & 0xFFFF) as u16;

        let mut buf = [0u8; 8];
        let n = if client.format == SafetyFormat::Extended {
            frame_codec::encode_time_coordination_extended(
                &mut buf,
                ping_reply,
                consumer_time_value,
                client.target_pid_s5,
            )
        } else {
            // Base format uses the (originator identity + client connection
            // serial) CRC-S3 pre-computed at open time.
            frame_codec::encode_time_coordination(
                &mut buf,
                ping_reply,
                consumer_time_value,
                client.cid_seed_s3,
            )
        };
        let seq = client.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let epio = Frame {
            connection_id: client.oto_t_id,
            sequence: seq,
            cip_sequence: seq as u16,
            run_idle: None,
            data: buf[..n].to_vec(),
        };
        let bytes = encode_epio(&epio);
        if self.udp.send_to(&bytes, self.target_udp).await.is_ok() {
            self.tcoo_tx.fetch_add(1, Ordering::Relaxed);
        }
    }
}
