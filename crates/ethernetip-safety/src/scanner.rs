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

use ethernetip_connections::epio::{decode_frame as decode_epio, encode_frame as encode_epio, Frame};
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
    pub server: SafetyForwardOpenConfig,
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
            udp_bind: SocketAddr::from(([0, 0, 0, 0], IO_UDP_PORT)),
            route_prefix: Vec::new(),
            server,
            orig_vendor: 0x0001,
            orig_serial: 0x1234_5678,
            peer_udp_port: IO_UDP_PORT,
        }
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
    pub target_app_reply: SafetyAppReply,
    pub target_udp: SocketAddr,
    /// Number of O→T frames produced.
    pub tx_count: Arc<AtomicU64>,
    /// Number of T→O TCOO frames received from the target.
    pub tcoo_count: Arc<AtomicU64>,
    /// Output data buffer — writes here are picked up on the next producer tick.
    pub output_data: Arc<Mutex<Vec<u8>>>,
    /// True once at least one target TCOO has arrived (the C# scanner uses
    /// this to move from `idle` to `run`).
    pub consumer_active: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    tcp: Option<TcpStream>,
    session_handle: u32,
    server_conn_serial: u16,
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

    // UDP socket was bound earlier so we could advertise it in Sockaddr Info.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let output_data = Arc::new(Mutex::new(vec![0u8; cfg.server.consumed_data_size as usize]));
    let consumer_active = Arc::new(AtomicBool::new(false));
    let tx_count = Arc::new(AtomicU64::new(0));
    let tcoo_count = Arc::new(AtomicU64::new(0));

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
        timestamp: AtomicU16::new(0),
    };
    let producer_task = tokio::spawn(producer.run(shutdown_rx.clone()));

    let consumer = ConsumerState {
        udp: udp.clone(),
        server_tto_o_id,
        consumer_active: consumer_active.clone(),
        tcoo_count: tcoo_count.clone(),
    };
    let consumer_task = tokio::spawn(consumer.run(shutdown_rx));

    Ok(SafetyScannerConnection {
        server_o_to_t_id: server_oto_t_id,
        server_t_to_o_id: server_tto_o_id,
        target_app_reply,
        target_udp,
        tx_count,
        tcoo_count,
        output_data,
        consumer_active,
        shutdown_tx,
        tasks: vec![producer_task, consumer_task],
        tcp: Some(tcp),
        session_handle,
        server_conn_serial,
        orig_vendor: cfg.orig_vendor,
        orig_serial: cfg.orig_serial,
        ctx,
        route_prefix: cfg.route_prefix,
        closed: false,
    })
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
                    let ts = if active {
                        let cur = self.timestamp.fetch_add(ts_delta, Ordering::Relaxed);
                        cur.wrapping_add(ts_delta)
                    } else {
                        0
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
                        0, // producer rollover — we don't advance ours here
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
                    let frame = match decode_epio(&buf[..n], false) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    // Server T→O connection carries the target's TCOO (~5-6 B).
                    if frame.connection_id == self.server_tto_o_id {
                        self.tcoo_count.fetch_add(1, Ordering::Relaxed);
                        // First TCOO flips the consumer-active latch so the
                        // producer starts stamping run=1 on subsequent frames.
                        self.consumer_active.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}
