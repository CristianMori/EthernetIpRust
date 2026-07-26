//! Originator-side (scanner) Class 1 connection.
//!
//! Opens a `Forward_Open` against an adapter, keeps a T→O UDP receiver
//! running, and drives an O→T UDP producer at the negotiated RPI. Assembly
//! data flows through a caller-supplied [`AssemblyRegistry`], so multiple
//! scanners can share buffers with application code without any extra sync.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time;

use ethernetip_core::cip::{class_codes as class, service_codes as service, status, ReplyHeader};
use ethernetip_core::cpf::{item_type, Envelope, Item};
use ethernetip_core::encap::{encode_frame as encode_encap, Command, Header, HEADER_LEN};
use ethernetip_core::error::{EipError, Result};
use ethernetip_core::path::EpathWriter;

use crate::adapter::IO_UDP_PORT;
use crate::assembly::AssemblyRegistry;
use crate::epio::{self, Frame};
use crate::forward_open::{
    ForwardCloseRequest, ForwardOpenRequest, ForwardOpenResponse, NetworkConnectionParameters,
};

/// Assembly Object class id used in Class 1 connection paths.
const ASSEMBLY_CLASS: u16 = 0x04;

/// Default originator vendor id reported in Forward_Open.
const DEFAULT_ORIG_VENDOR: u16 = 0x0001;

/// Standard Class 1 transport type byte (server=0, class=1, trigger=cyclic).
const TRANSPORT_CLASS1_CYCLIC: u8 = 0x01;

/// One scanner-side Class 1 connection.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub adapter_tcp: SocketAddr,
    pub udp_bind: SocketAddr,
    /// Assembly instance carrying config bytes (may be 0 for none).
    pub config_assembly: u16,
    /// Assembly instance the scanner writes into on the originator side.
    pub o_to_t_assembly: u16,
    /// Assembly instance the scanner reads from on the target side.
    pub t_to_o_assembly: u16,
    /// Data-only size of the O→T assembly (run/idle header not counted).
    pub o_to_t_size: u16,
    /// Data-only size of the T→O assembly (run/idle header not counted).
    pub t_to_o_size: u16,
    pub o_to_t_rpi_us: u32,
    pub t_to_o_rpi_us: u32,
    pub run_idle_header: bool,
    /// Optional route bytes (from [`ethernetip_core::path::parse_route_path`]).
    pub route_path: Vec<u8>,
    pub assemblies: AssemblyRegistry,
    pub connection_timeout_mult: u8,
    pub orig_vendor: u16,
    /// Inline configuration data prepended into the connection path as a
    /// `Simple Data Segment (0x80)`. Empty vec means no config data segment.
    pub config_data: Vec<u8>,
}

impl ScannerConfig {
    pub fn new(
        adapter_tcp: SocketAddr,
        assemblies: AssemblyRegistry,
        config_assembly: u16,
        o_to_t_assembly: u16,
        t_to_o_assembly: u16,
        o_to_t_size: u16,
        t_to_o_size: u16,
    ) -> Self {
        Self {
            adapter_tcp,
            // Bind an ephemeral port by default — mirrors how the C# /
            // Python / C++ scanners behave in practice, and lets a scanner
            // coexist with an adapter (which owns 2222) on the same host
            // without any port trickery. The advertised endpoint gets
            // handed to the target via Sockaddr Info T→O.
            udp_bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            config_assembly,
            o_to_t_assembly,
            t_to_o_assembly,
            o_to_t_size,
            t_to_o_size,
            o_to_t_rpi_us: 10_000,
            t_to_o_rpi_us: 10_000,
            run_idle_header: true,
            route_path: Vec::new(),
            assemblies,
            connection_timeout_mult: 3,
            orig_vendor: DEFAULT_ORIG_VENDOR,
            config_data: Vec::new(),
        }
    }

    pub fn rpi(mut self, o_to_t_us: u32, t_to_o_us: u32) -> Self {
        self.o_to_t_rpi_us = o_to_t_us;
        self.t_to_o_rpi_us = t_to_o_us;
        self
    }

    pub fn udp_bind(mut self, addr: SocketAddr) -> Self {
        self.udp_bind = addr;
        self
    }

    pub fn route_path(mut self, bytes: Vec<u8>) -> Self {
        self.route_path = bytes;
        self
    }

    pub fn config_data(mut self, bytes: Vec<u8>) -> Self {
        self.config_data = bytes;
        self
    }

    pub fn run_idle_header(mut self, on: bool) -> Self {
        self.run_idle_header = on;
        self
    }
}

/// Live connection handle. Drop-safe (drops issue Forward_Close best-effort).
pub struct ScannerConnection {
    pub o_to_t_conn_id: u32,
    pub t_to_o_conn_id: u32,
    pub o_to_t_actual_rpi_us: u32,
    pub t_to_o_actual_rpi_us: u32,
    pub rx_count: Arc<AtomicU64>,
    pub tx_count: Arc<AtomicU64>,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    tcp_stream: Option<TcpStream>,
    session_handle: u32,
    orig_vendor: u16,
    orig_serial: u32,
    conn_serial: u16,
    ctx_counter: u64,
    close_path: Vec<u8>,
    closed: bool,
}

impl ScannerConnection {
    /// Attempt a clean Forward_Close + UnRegisterSession.
    pub async fn close(mut self) -> Result<()> {
        self.close_inner().await
    }

    async fn close_inner(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = self.shutdown_tx.send(true);
        let mut stream = match self.tcp_stream.take() {
            Some(s) => s,
            None => return Ok(()),
        };
        let _ = send_forward_close(
            &mut stream,
            self.session_handle,
            self.next_ctx(),
            self.conn_serial,
            self.orig_vendor,
            self.orig_serial,
            &self.close_path,
        )
        .await;
        // Unregister
        let _ = send_unregister(&mut stream, self.session_handle).await;
        let _ = stream.shutdown().await;
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
        Ok(())
    }

    fn next_ctx(&mut self) -> [u8; 8] {
        self.ctx_counter = self.ctx_counter.wrapping_add(1);
        self.ctx_counter.to_le_bytes()
    }
}

impl Drop for ScannerConnection {
    fn drop(&mut self) {
        // Fire-and-forget cleanup — we can't easily await in Drop, so we spawn
        // a best-effort task on the current runtime if the caller didn't call
        // close() explicitly.
        if !self.closed {
            let _ = self.shutdown_tx.send(true);
        }
    }
}

/// Open a Class 1 connection to an adapter and start the I/O tasks.
pub async fn open_connection(cfg: ScannerConfig) -> Result<ScannerConnection> {
    let mut stream = TcpStream::connect(cfg.adapter_tcp).await?;
    stream.set_nodelay(true)?;

    // Register session.
    let mut ctx_counter: u64 = 0;
    let session_handle = register_session(&mut stream, &mut ctx_counter).await?;

    // Build originator identifiers.
    let ticks = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EipError::Protocol("system clock predates unix epoch".into()))?
        .as_micros() as u64;
    let conn_serial = ((ticks & 0xFFFF) as u16).max(1);
    let orig_serial = ticks as u32;
    let t_to_o_conn_id = 0x8000_0000u32 | (conn_serial as u32);

    // Build connection path.
    let connection_path = build_connection_path(&cfg)?;

    let o_to_t_wire_size = cfg.o_to_t_size + if cfg.run_idle_header { 4 } else { 0 };
    let t_to_o_wire_size = cfg.t_to_o_size + if cfg.run_idle_header { 4 } else { 0 };

    let params_ot = NetworkConnectionParameters {
        redundant_owner: false,
        connection_type: 2, // Point-to-Point
        priority: 1,
        variable_size: false,
        size: o_to_t_wire_size,
    };
    let params_to = NetworkConnectionParameters {
        redundant_owner: false,
        connection_type: 2,
        priority: 1,
        variable_size: false,
        size: t_to_o_wire_size,
    };

    let fo_req = ForwardOpenRequest {
        priority_tick: 0x0A,
        timeout_ticks: 0x05,
        o_to_t_connection_id: 0,
        t_to_o_connection_id: t_to_o_conn_id,
        connection_serial: conn_serial,
        originator_vendor: cfg.orig_vendor,
        originator_serial: orig_serial,
        connection_timeout_mult: cfg.connection_timeout_mult,
        o_to_t_rpi_us: cfg.o_to_t_rpi_us,
        o_to_t_params: params_ot,
        t_to_o_rpi_us: cfg.t_to_o_rpi_us,
        t_to_o_params: params_to,
        transport_type: TRANSPORT_CLASS1_CYCLIC,
        connection_path: connection_path.clone(),
    };

    // Bind UDP up front so we know the port to advertise in Sockaddr Info T→O.
    let udp = Arc::new(UdpSocket::bind(cfg.udp_bind).await?);
    let our_udp = udp.local_addr()?;

    // Wrap FO request in Message Router format, send via SendRRData. We
    // include a Sockaddr Info T→O CPF item so the target knows exactly which
    // UDP endpoint to send T→O frames to — the CIP-standards-compliant way
    // to negotiate cyclic-I/O peer endpoints. Value is our bind address; a
    // wildcard `0.0.0.0` lets the target fall back to our TCP peer address.
    let mr = build_mr_request(service::FORWARD_OPEN, &cm_path_bytes(), &fo_req.encode());
    let sockaddr_bytes = ethernetip_core::cpf::encode_sockaddr_in_v4(our_udp)?;
    let items = [
        Item::null_address(),
        Item::new(item_type::UNCONNECTED_DATA, mr),
        Item::new(item_type::SOCKADDR_INFO_T_TO_O, sockaddr_bytes),
    ];
    let body = ethernetip_core::cpf::encode_envelope(0, 5, &items);
    ctx_counter = ctx_counter.wrapping_add(1);
    let reply_bytes = exchange(
        &mut stream,
        Command::SendRRData,
        session_handle,
        ctx_counter.to_le_bytes(),
        &body,
    )
    .await?;
    let reply_env = Envelope::parse(&reply_bytes)?;
    let data = reply_env
        .find(item_type::UNCONNECTED_DATA)
        .ok_or_else(|| EipError::Protocol("FO reply missing UnconnectedData".into()))?;
    let header = ReplyHeader::parse(&data.data)?;
    if header.general_status != status::SUCCESS {
        return Err(EipError::Cip {
            status: header.general_status,
            ext: header.extended_status,
        });
    }
    let fo_resp = ForwardOpenResponse::decode(&data.data[header.body_offset..])?;

    // Discover target UDP endpoint from Sockaddr Info O→T if the target
    // included one; else fall back to (adapter_tcp_ip, 2222). A zero address
    // in the CPF item means "use my TCP peer" — same convention C# follows.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let rx_count = Arc::new(AtomicU64::new(0));
    let tx_count = Arc::new(AtomicU64::new(0));

    let consumer_state = ConsumerState {
        udp: udp.clone(),
        assemblies: cfg.assemblies.clone(),
        t_to_o_assembly: cfg.t_to_o_assembly,
        expect_conn_id: t_to_o_conn_id,
        run_idle: cfg.run_idle_header,
        rx_count: rx_count.clone(),
    };
    let consumer_task = tokio::spawn(consumer_state.run(shutdown_rx.clone()));

    // Producer task: outgoing O→T frames.
    let peer_udp = ethernetip_core::cpf::resolve_peer_udp(
        &reply_env,
        item_type::SOCKADDR_INFO_O_TO_T,
        cfg.adapter_tcp.ip(),
        IO_UDP_PORT,
    );
    let producer_state = ProducerState {
        udp: udp.clone(),
        peer_udp,
        assemblies: cfg.assemblies.clone(),
        o_to_t_assembly: cfg.o_to_t_assembly,
        connection_id: fo_resp.o_to_t_connection_id,
        rpi_us: fo_resp.o_to_t_actual_rpi_us,
        run_idle: cfg.run_idle_header,
        seq: AtomicU32::new(0),
        tx_count: tx_count.clone(),
    };
    let producer_task = tokio::spawn(producer_state.run(shutdown_rx));

    Ok(ScannerConnection {
        o_to_t_conn_id: fo_resp.o_to_t_connection_id,
        t_to_o_conn_id: fo_resp.t_to_o_connection_id,
        o_to_t_actual_rpi_us: fo_resp.o_to_t_actual_rpi_us,
        t_to_o_actual_rpi_us: fo_resp.t_to_o_actual_rpi_us,
        rx_count,
        tx_count,
        shutdown_tx,
        tasks: vec![consumer_task, producer_task],
        tcp_stream: Some(stream),
        session_handle,
        orig_vendor: cfg.orig_vendor,
        orig_serial,
        conn_serial,
        ctx_counter,
        close_path: connection_path,
        closed: false,
    })
}

fn build_connection_path(cfg: &ScannerConfig) -> Result<Vec<u8>> {
    let mut w = EpathWriter::new();
    if !cfg.route_path.is_empty() {
        // Route bytes are already word-aligned pairs from parse_route_path.
        w.extend_from_slice(&cfg.route_path);
    }
    w.push_class(ASSEMBLY_CLASS);
    // Config assembly instance segment (Logical Instance).
    if cfg.config_assembly <= 0xFF {
        w.extend_from_slice(&[0x24, cfg.config_assembly as u8]);
    } else {
        w.extend_from_slice(&[0x25, 0x00]);
        w.extend_from_slice(&cfg.config_assembly.to_le_bytes());
    }
    // Optional Simple Data Segment for inline config bytes.
    if !cfg.config_data.is_empty() {
        let bytes = &cfg.config_data;
        let word_len = bytes.len().div_ceil(2);
        w.extend_from_slice(&[0x80, word_len as u8]);
        w.extend_from_slice(bytes);
        if bytes.len() % 2 == 1 {
            w.extend_from_slice(&[0x00]);
        }
    }
    // O→T (consumed by target) and T→O (produced by target) connection points.
    for asm in [cfg.o_to_t_assembly, cfg.t_to_o_assembly] {
        if asm <= 0xFF {
            w.extend_from_slice(&[0x2C, asm as u8]);
        } else {
            w.extend_from_slice(&[0x2D, 0x00]);
            w.extend_from_slice(&asm.to_le_bytes());
        }
    }
    Ok(w.into_bytes())
}

fn build_mr_request(service_code: u8, path: &[u8], body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + path.len() + body.len());
    buf.push(service_code);
    buf.push((path.len() / 2) as u8);
    buf.extend_from_slice(path);
    buf.extend_from_slice(body);
    buf
}

fn cm_path_bytes() -> Vec<u8> {
    let mut w = EpathWriter::new();
    w.push_class(class::CONNECTION_MANAGER);
    w.push_instance(1);
    w.into_bytes()
}

// resolve_peer_udp moved to ethernetip_core::cpf::resolve_peer_udp so the
// safety crate can share it without a cross-crate dependency.

async fn exchange(
    stream: &mut TcpStream,
    command: Command,
    session_handle: u32,
    sender_context: [u8; 8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let (_hdr, body) =
        exchange_with_header(stream, command, session_handle, sender_context, payload).await?;
    Ok(body)
}

async fn exchange_with_header(
    stream: &mut TcpStream,
    command: Command,
    session_handle: u32,
    sender_context: [u8; 8],
    payload: &[u8],
) -> Result<(Header, Vec<u8>)> {
    let frame = encode_encap(command, session_handle, sender_context, payload);
    stream.write_all(&frame).await?;
    let mut header_buf = [0u8; HEADER_LEN];
    stream.read_exact(&mut header_buf).await?;
    let header = Header::parse(&header_buf)?;
    let mut body = vec![0u8; header.length as usize];
    if header.length > 0 {
        stream.read_exact(&mut body).await?;
    }
    if header.status != 0 {
        return Err(EipError::Encap(header.status));
    }
    Ok((header, body))
}

async fn send_forward_close(
    stream: &mut TcpStream,
    session_handle: u32,
    sender_context: [u8; 8],
    connection_serial: u16,
    originator_vendor: u16,
    originator_serial: u32,
    connection_path: &[u8],
) -> Result<()> {
    let fc = ForwardCloseRequest {
        priority_tick: 0x0A,
        timeout_ticks: 0x05,
        connection_serial,
        originator_vendor,
        originator_serial,
        connection_path: connection_path.to_vec(),
    };
    let mr = build_mr_request(service::FORWARD_CLOSE, &cm_path_bytes(), &fc.encode());
    let items = [
        Item::null_address(),
        Item::new(item_type::UNCONNECTED_DATA, mr),
    ];
    let body = ethernetip_core::cpf::encode_envelope(0, 5, &items);
    let _ = exchange(
        stream,
        Command::SendRRData,
        session_handle,
        sender_context,
        &body,
    )
    .await;
    Ok(())
}

async fn send_unregister(stream: &mut TcpStream, session_handle: u32) -> Result<()> {
    let frame = encode_encap(
        Command::UnRegisterSession,
        session_handle,
        [0; 8],
        &[],
    );
    let _ = stream.write_all(&frame).await;
    Ok(())
}

struct ConsumerState {
    udp: Arc<UdpSocket>,
    assemblies: AssemblyRegistry,
    t_to_o_assembly: u16,
    expect_conn_id: u32,
    run_idle: bool,
    rx_count: Arc<AtomicU64>,
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
                            tracing::warn!("scanner udp recv error: {err}");
                            continue;
                        }
                    };
                    // T->O frames don't carry the run/idle header (that's O->T only).
                    let frame = match epio::decode_frame(&buf[..n], false) {
                        Ok(f) => f,
                        Err(err) => {
                            tracing::debug!("epio decode error: {err}");
                            continue;
                        }
                    };
                    if frame.connection_id != self.expect_conn_id {
                        continue;
                    }
                    self.rx_count.fetch_add(1, Ordering::Relaxed);
                    if let Some(asm) = self.assemblies.snapshot(self.t_to_o_assembly) {
                        let mut buf_to_write = vec![0u8; asm.size];
                        let m = frame.data.len().min(asm.size);
                        buf_to_write[..m].copy_from_slice(&frame.data[..m]);
                        let _ = self.assemblies.update(self.t_to_o_assembly, &buf_to_write);
                    }
                }
            }
        }
    }
}

struct ProducerState {
    udp: Arc<UdpSocket>,
    peer_udp: SocketAddr,
    assemblies: AssemblyRegistry,
    o_to_t_assembly: u16,
    connection_id: u32,
    rpi_us: u32,
    run_idle: bool,
    seq: AtomicU32,
    tx_count: Arc<AtomicU64>,
}

impl ProducerState {
    async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        let period = Duration::from_micros(self.rpi_us.max(1) as u64);
        let mut ticker = time::interval(period);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
                    let data = self.assemblies.read(self.o_to_t_assembly).unwrap_or_default();
                    let frame = Frame {
                        connection_id: self.connection_id,
                        sequence: seq,
                        cip_sequence: seq as u16,
                        run_idle: if self.run_idle { Some(true) } else { None },
                        data,
                    };
                    let bytes = epio::encode_frame(&frame);
                    if self.udp.send_to(&bytes, self.peer_udp).await.is_ok() {
                        self.tx_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

// Session-registration path used inside open_connection.
async fn register_session(stream: &mut TcpStream, ctx: &mut u64) -> Result<u32> {
    let payload = [0x01, 0x00, 0x00, 0x00];
    *ctx = ctx.wrapping_add(1);
    let (header, body) = exchange_with_header(
        stream,
        Command::RegisterSession,
        0,
        ctx.to_le_bytes(),
        &payload,
    )
    .await?;
    if body.len() < 4 {
        return Err(EipError::Short {
            expected: 4,
            actual: body.len(),
        });
    }
    Ok(header.session_handle)
}

