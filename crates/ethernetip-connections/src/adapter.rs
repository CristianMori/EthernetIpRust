//! Target-side (adapter) implementation of a Class 1 EtherNet/IP device.
//!
//! Binds TCP 44818 for encapsulated request/reply and UDP 2222 for cyclic
//! I/O, accepts `Forward_Open`s that reference registered [`Assembly`]s, and
//! runs a producer task per active connection that pushes T→O data at the
//! negotiated RPI. Incoming O→T frames are dispatched by connection id and
//! written into the referenced assembly.
//!
//! The adapter is intentionally single-connection-per-session on this first
//! pass: the tests we need it to pass — mostly cross-language interop with
//! the C#, Python, and C++ scanners — never open more than one Class 1
//! connection per TCP session. Extending it to multi-connection is a matter
//! of moving `active` from `Option` to `HashMap<connection_id, _>`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time;

use ethernetip_core::cip::{service_codes as service, status, CipDispatcher, CipPath};
use ethernetip_core::cpf::{item_type, Envelope, Item};
use ethernetip_core::encap::{encode_frame as encode_encap, Command, Header, HEADER_LEN};
use ethernetip_core::error::{EipError, Result};

use crate::assembly::AssemblyRegistry;
use crate::epio::{self, Frame};
use crate::forward_open::{
    ForwardCloseRequest, ForwardCloseResponse, ForwardOpenRequest, ForwardOpenResponse,
};

/// Default cyclic I/O UDP port (well-known EtherNet/IP value).
pub const IO_UDP_PORT: u16 = 2222;

/// Configuration for an [`Adapter`].
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    pub tcp_bind: SocketAddr,
    pub udp_bind: SocketAddr,
    pub assemblies: AssemblyRegistry,
    /// Whether to expect a 32-bit run/idle header at the start of every O→T
    /// data payload (and to emit one on every T→O payload). Logix scanners
    /// use this for the Generic Ethernet Module profile.
    pub run_idle_header: bool,
    /// UDP destination port for T→O producer packets. Defaults to the
    /// well-known [`IO_UDP_PORT`]. Overriding is useful for host-local
    /// interop tests where the scanner has to bind a different port.
    pub peer_udp_port: u16,
    /// Optional CIP object dispatcher for services that aren't FORWARD_OPEN
    /// / FORWARD_CLOSE. When populated, MR requests targeted at a
    /// registered class (Identity 0x01, Assembly 0x04, TCP/IP 0xF5, ...)
    /// are routed through [`CipDispatcher::dispatch`] instead of returning
    /// `SERVICE_NOT_SUPPORTED`. Shared `Arc` so the same dispatcher can
    /// serve multiple sessions.
    pub dispatcher: Option<Arc<CipDispatcher>>,
}

impl AdapterConfig {
    pub fn new(assemblies: AssemblyRegistry) -> Self {
        Self {
            tcp_bind: SocketAddr::from(([0, 0, 0, 0], 44818)),
            udp_bind: SocketAddr::from(([0, 0, 0, 0], IO_UDP_PORT)),
            assemblies,
            run_idle_header: true,
            peer_udp_port: IO_UDP_PORT,
            dispatcher: None,
        }
    }

    /// Install a [`CipDispatcher`] so MR requests for registered classes
    /// (Identity 0x01, Assembly 0x04, Connection Manager 0x06, TCP/IP
    /// 0xF5, Ethernet Link 0xF6, ...) are routed to their handlers
    /// instead of returning `SERVICE_NOT_SUPPORTED`.
    pub fn dispatcher(mut self, dispatcher: Arc<CipDispatcher>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    pub fn tcp_bind(mut self, addr: SocketAddr) -> Self {
        self.tcp_bind = addr;
        self
    }

    pub fn udp_bind(mut self, addr: SocketAddr) -> Self {
        self.udp_bind = addr;
        self
    }

    pub fn run_idle_header(mut self, on: bool) -> Self {
        self.run_idle_header = on;
        self
    }

    pub fn peer_udp_port(mut self, port: u16) -> Self {
        self.peer_udp_port = port;
        self
    }
}

/// Handle returned from [`start`] — dropping it does NOT stop the adapter;
/// call [`AdapterHandle::shutdown`] to bring it down cleanly.
pub struct AdapterHandle {
    pub tcp_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub connections: Arc<Mutex<ConnectionTable>>,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl AdapterHandle {
    /// Signal shutdown and wait for all background tasks to end.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
    }

    /// Snapshot the number of live Class 1 connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.rows.len()
    }
}

/// Publicly-visible summary of one live connection.
#[derive(Debug, Clone)]
pub struct ConnectionSummary {
    pub o_to_t_conn_id: u32,
    pub t_to_o_conn_id: u32,
    pub o_to_t_rpi_us: u32,
    pub t_to_o_rpi_us: u32,
    pub input_assembly: u16,
    pub output_assembly: u16,
    pub peer_udp: SocketAddr,
}

/// Shared connection registry for the adapter.
#[derive(Debug, Default)]
pub struct ConnectionTable {
    rows: HashMap<u32, ConnectionRow>,
}

#[derive(Debug)]
struct ConnectionRow {
    o_to_t_conn_id: u32,
    t_to_o_conn_id: u32,
    input_assembly: u16,
    output_assembly: u16,
    /// Live peer UDP endpoint — updated by the consumer to the actual source
    /// of received O→T frames so the producer sends T→O back to the port the
    /// scanner is actually receiving on (typically an ephemeral port, not the
    /// well-known 2222).
    peer_udp: Arc<std::sync::RwLock<SocketAddr>>,
    o_to_t_rpi_us: u32,
    t_to_o_rpi_us: u32,
    producer_shutdown: watch::Sender<bool>,
    producer_task: JoinHandle<()>,
}

impl ConnectionTable {
    fn summaries(&self) -> Vec<ConnectionSummary> {
        self.rows
            .values()
            .map(|r| ConnectionSummary {
                o_to_t_conn_id: r.o_to_t_conn_id,
                t_to_o_conn_id: r.t_to_o_conn_id,
                o_to_t_rpi_us: r.o_to_t_rpi_us,
                t_to_o_rpi_us: r.t_to_o_rpi_us,
                input_assembly: r.input_assembly,
                output_assembly: r.output_assembly,
                peer_udp: *r.peer_udp.read().unwrap(),
            })
            .collect()
    }
}

impl AdapterHandle {
    pub async fn snapshot_connections(&self) -> Vec<ConnectionSummary> {
        self.connections.lock().await.summaries()
    }
}

/// Start an adapter using the provided configuration.
pub async fn start(cfg: AdapterConfig) -> Result<AdapterHandle> {
    let tcp = TcpListener::bind(cfg.tcp_bind).await?;
    let tcp_addr = tcp.local_addr()?;
    let udp = Arc::new(UdpSocket::bind(cfg.udp_bind).await?);
    let udp_addr = udp.local_addr()?;

    let connections: Arc<Mutex<ConnectionTable>> = Arc::new(Mutex::new(ConnectionTable::default()));
    let next_conn_id = Arc::new(AtomicU32::new(0x8000_0000));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let assemblies = cfg.assemblies.clone();
    let run_idle = cfg.run_idle_header;

    // UDP consumer: decode incoming O→T frames and update the right assembly.
    let consumer_state = ConsumerState {
        connections: connections.clone(),
        assemblies: assemblies.clone(),
        run_idle,
        udp: udp.clone(),
    };
    let consumer_task = tokio::spawn(consumer_state.run(shutdown_rx.clone()));

    let accept_state = AcceptState {
        connections: connections.clone(),
        assemblies: assemblies.clone(),
        udp: udp.clone(),
        next_conn_id,
        run_idle,
        peer_udp_port: cfg.peer_udp_port,
        dispatcher: cfg.dispatcher.clone(),
    };
    let accept_task = tokio::spawn(accept_state.run(tcp, shutdown_rx));

    let combined = tokio::spawn(async move {
        let _ = tokio::join!(consumer_task, accept_task);
    });

    Ok(AdapterHandle {
        tcp_addr,
        udp_addr,
        connections,
        shutdown_tx,
        task: combined,
    })
}

struct AcceptState {
    connections: Arc<Mutex<ConnectionTable>>,
    assemblies: AssemblyRegistry,
    udp: Arc<UdpSocket>,
    next_conn_id: Arc<AtomicU32>,
    run_idle: bool,
    peer_udp_port: u16,
    dispatcher: Option<Arc<CipDispatcher>>,
}

impl AcceptState {
    async fn run(self, tcp: TcpListener, mut shutdown_rx: watch::Receiver<bool>) {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                accept = tcp.accept() => {
                    let (stream, peer) = match accept {
                        Ok(x) => x,
                        Err(err) => {
                            tracing::warn!("accept error: {err}");
                            continue;
                        }
                    };
                    let session = SessionState {
                        stream,
                        peer,
                        connections: self.connections.clone(),
                        assemblies: self.assemblies.clone(),
                        udp: self.udp.clone(),
                        next_conn_id: self.next_conn_id.clone(),
                        run_idle: self.run_idle,
                        peer_udp_port: self.peer_udp_port,
                        dispatcher: self.dispatcher.clone(),
                        session_handle: 0,
                        active_conn_id: None,
                    };
                    tokio::spawn(session.run());
                }
            }
        }
    }
}

struct SessionState {
    stream: TcpStream,
    peer: SocketAddr,
    connections: Arc<Mutex<ConnectionTable>>,
    assemblies: AssemblyRegistry,
    udp: Arc<UdpSocket>,
    next_conn_id: Arc<AtomicU32>,
    run_idle: bool,
    peer_udp_port: u16,
    dispatcher: Option<Arc<CipDispatcher>>,
    session_handle: u32,
    active_conn_id: Option<u32>,
}

impl SessionState {
    async fn run(mut self) {
        loop {
            let mut header_buf = [0u8; HEADER_LEN];
            if let Err(err) = self.stream.read_exact(&mut header_buf).await {
                tracing::debug!(peer=?self.peer, "session read ended: {err}");
                break;
            }
            let header = match Header::parse(&header_buf) {
                Ok(h) => h,
                Err(err) => {
                    tracing::warn!(peer=?self.peer, "bad header: {err}");
                    break;
                }
            };
            let mut payload = vec![0u8; header.length as usize];
            if header.length > 0 {
                if let Err(err) = self.stream.read_exact(&mut payload).await {
                    tracing::warn!(peer=?self.peer, "session body read ended: {err}");
                    break;
                }
            }
            if let Err(err) = self.dispatch(&header, &payload).await {
                tracing::warn!(peer=?self.peer, "dispatch failed: {err}");
                break;
            }
        }
        if let Some(id) = self.active_conn_id.take() {
            let mut table = self.connections.lock().await;
            if let Some(row) = table.rows.remove(&id) {
                let _ = row.producer_shutdown.send(true);
                drop(table);
                let _ = row.producer_task.await;
            }
        }
    }

    async fn dispatch(&mut self, header: &Header, payload: &[u8]) -> Result<()> {
        match header.command {
            x if x == Command::RegisterSession.as_u16() => {
                self.session_handle = 0x0000_0100 ^ (self.peer.port() as u32).wrapping_mul(0x9E37_79B9);
                // Echo protocol_version=1 back to the originator.
                let reply = [0x01, 0x00, 0x00, 0x00];
                self.write_reply(Command::RegisterSession, self.session_handle, header.sender_context, &reply)
                    .await
            }
            x if x == Command::UnRegisterSession.as_u16() => Err(EipError::Closed),
            x if x == Command::SendRRData.as_u16() => {
                self.handle_send_rr_data(header, payload).await
            }
            x if x == Command::SendUnitData.as_u16() => {
                // For now we do not accept Class 3 explicit into the adapter —
                // scanners issue their tag reads over UnconnectedData instead.
                Err(EipError::Protocol("SendUnitData not implemented".into()))
            }
            other => Err(EipError::Protocol(format!(
                "unsupported encap command 0x{:04X}",
                other
            ))),
        }
    }

    async fn write_reply(
        &mut self,
        command: Command,
        session_handle: u32,
        sender_context: [u8; 8],
        payload: &[u8],
    ) -> Result<()> {
        let frame = encode_encap(command, session_handle, sender_context, payload);
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    async fn handle_send_rr_data(&mut self, header: &Header, payload: &[u8]) -> Result<()> {
        let envelope = Envelope::parse(payload)?;
        let mr_item = envelope
            .find(item_type::UNCONNECTED_DATA)
            .ok_or_else(|| EipError::Protocol("SendRRData missing UnconnectedData item".into()))?;
        let (service_code, path, body) = split_mr_request(&mr_item.data)?;

        let mut include_sockaddr_reply = false;
        let mut reply_ext_status: Vec<u16> = Vec::new();
        let (reply_service, reply_status, reply_body) = match service_code {
            s if s == service::FORWARD_OPEN => {
                // Scanner may have advertised its UDP endpoint in a Sockaddr
                // Info T→O CPF item — use it (with 0.0.0.0 falling back to
                // the TCP peer IP) instead of the hard default peer:2222.
                let peer_udp = ethernetip_core::cpf::resolve_peer_udp(
                    &envelope,
                    item_type::SOCKADDR_INFO_T_TO_O,
                    self.peer.ip(),
                    self.peer_udp_port,
                );
                match self.handle_forward_open(&body, peer_udp).await {
                    Ok(resp) => {
                        include_sockaddr_reply = true;
                        (
                            service::FORWARD_OPEN | service::REPLY_FLAG,
                            status::SUCCESS,
                            resp.encode(),
                        )
                    }
                    Err(err) => {
                        tracing::warn!("Forward_Open rejected: {err}");
                        (
                            service::FORWARD_OPEN | service::REPLY_FLAG,
                            status::CONNECTION_FAILURE,
                            Vec::new(),
                        )
                    }
                }
            }
            s if s == service::FORWARD_CLOSE => {
                match self.handle_forward_close(&body).await {
                    Ok(resp) => (
                        service::FORWARD_CLOSE | service::REPLY_FLAG,
                        status::SUCCESS,
                        resp.encode(),
                    ),
                    Err(_) => (
                        service::FORWARD_CLOSE | service::REPLY_FLAG,
                        status::CONNECTION_FAILURE,
                        Vec::new(),
                    ),
                }
            }
            other => {
                if let Some(dispatcher) = self.dispatcher.as_ref() {
                    match CipPath::parse(&path) {
                        Ok(cip_path) => {
                            let response = dispatcher.dispatch(other, cip_path, body.to_vec());
                            reply_ext_status = response.extended_status.clone();
                            (response.service_code, response.general_status, response.data)
                        }
                        Err(err) => {
                            tracing::debug!("adapter path parse failed for service 0x{other:02X}: {err}");
                            (
                                other | service::REPLY_FLAG,
                                status::PATH_SEGMENT_ERROR,
                                Vec::new(),
                            )
                        }
                    }
                } else {
                    tracing::warn!("adapter: unsupported service 0x{:02X}", other);
                    (
                        other | service::REPLY_FLAG,
                        status::SERVICE_NOT_SUPPORTED,
                        Vec::new(),
                    )
                }
            }
        };

        // Path is echoed back untouched.
        let _ = path;

        let mut mr_reply =
            Vec::with_capacity(4 + reply_ext_status.len() * 2 + reply_body.len());
        mr_reply.push(reply_service);
        mr_reply.push(0); // reserved
        mr_reply.push(reply_status);
        mr_reply.push(reply_ext_status.len() as u8);
        for w in &reply_ext_status {
            mr_reply.extend_from_slice(&w.to_le_bytes());
        }
        mr_reply.extend_from_slice(&reply_body);

        // Build reply CPF items; on a successful Forward_Open reply, tack a
        // Sockaddr Info O→T item onto the response so the scanner knows the
        // adapter's UDP endpoint for cyclic frames.
        let mut items: Vec<Item> = vec![
            Item::null_address(),
            Item::new(item_type::UNCONNECTED_DATA, mr_reply),
        ];
        if include_sockaddr_reply {
            let local = self.udp.local_addr()?;
            let sockaddr_bytes = ethernetip_core::cpf::encode_sockaddr_in_v4(local)?;
            items.push(Item::new(item_type::SOCKADDR_INFO_O_TO_T, sockaddr_bytes));
        }
        let body = ethernetip_core::cpf::encode_envelope(0, envelope.timeout, &items);
        self.write_reply(
            Command::SendRRData,
            header.session_handle,
            header.sender_context,
            &body,
        )
        .await
    }

    async fn handle_forward_open(
        &mut self,
        body: &[u8],
        peer_udp: SocketAddr,
    ) -> Result<ForwardOpenResponse> {
        let req = ForwardOpenRequest::decode(body)?;
        let (input_asm, output_asm) = parse_connection_path(&req.connection_path)?;

        // Sanity check: both assemblies must exist.
        if self.assemblies.snapshot(input_asm).is_none() {
            return Err(EipError::Protocol(format!(
                "unknown T->O assembly {}",
                input_asm
            )));
        }
        if self.assemblies.snapshot(output_asm).is_none() {
            return Err(EipError::Protocol(format!(
                "unknown O->T assembly {}",
                output_asm
            )));
        }

        // Refuse if the originator asked for the same instance in both
        // directions — matches the guard the C++ port added after the
        // duplicate-assembly bug.
        if input_asm == output_asm {
            return Err(EipError::Protocol(format!(
                "Forward_Open uses assembly {} in both directions",
                input_asm
            )));
        }

        let assigned_oto_t = self.next_conn_id.fetch_add(1, Ordering::SeqCst);
        self.active_conn_id = Some(assigned_oto_t);

        // Producer task uses the SAME UDP socket for send — matches how
        // the C#/C++/Python ports organize their UDP transports, and lets
        // outgoing frames carry our advertised bind address as source so a
        // peer that filters on it sees a match. (Earlier we split into an
        // ephemeral send socket to dodge a suspected Windows loopback
        // quirk; the actual fix was Sockaddr Info hand-off, so we can
        // share the socket cleanly again.)
        let send_udp = self.udp.clone();
        let (producer_shutdown_tx, producer_shutdown_rx) = watch::channel(false);
        // Shared, mutable peer_udp — the consumer will update it to the
        // actual source of received O→T frames once the scanner starts
        // producing, so the producer sends T→O back to the port the peer
        // is actually listening on (typically ephemeral, not 2222).
        let peer_udp = Arc::new(std::sync::RwLock::new(peer_udp));
        let producer = ProducerState {
            connection_id: req.t_to_o_connection_id,
            udp: send_udp,
            peer_udp: peer_udp.clone(),
            rpi_us: req.t_to_o_rpi_us,
            assemblies: self.assemblies.clone(),
            input_assembly: input_asm,
            run_idle: self.run_idle,
            seq: AtomicU32::new(0),
        };
        let producer_task = tokio::spawn(producer.run(producer_shutdown_rx));

        {
            let mut table = self.connections.lock().await;
            table.rows.insert(
                assigned_oto_t,
                ConnectionRow {
                    o_to_t_conn_id: assigned_oto_t,
                    t_to_o_conn_id: req.t_to_o_connection_id,
                    input_assembly: input_asm,
                    output_assembly: output_asm,
                    peer_udp,
                    o_to_t_rpi_us: req.o_to_t_rpi_us,
                    t_to_o_rpi_us: req.t_to_o_rpi_us,
                    producer_shutdown: producer_shutdown_tx,
                    producer_task,
                },
            );
        }

        Ok(ForwardOpenResponse {
            o_to_t_connection_id: assigned_oto_t,
            t_to_o_connection_id: req.t_to_o_connection_id,
            connection_serial: req.connection_serial,
            originator_vendor: req.originator_vendor,
            originator_serial: req.originator_serial,
            o_to_t_actual_rpi_us: req.o_to_t_rpi_us,
            t_to_o_actual_rpi_us: req.t_to_o_rpi_us,
            app_reply: Vec::new(),
        })
    }

    async fn handle_forward_close(&mut self, body: &[u8]) -> Result<ForwardCloseResponse> {
        let req = ForwardCloseRequest::decode(body)?;
        if let Some(id) = self.active_conn_id.take() {
            let mut table = self.connections.lock().await;
            if let Some(row) = table.rows.remove(&id) {
                let _ = row.producer_shutdown.send(true);
                drop(table);
                let _ = row.producer_task.await;
            }
        }
        Ok(ForwardCloseResponse {
            connection_serial: req.connection_serial,
            originator_vendor: req.originator_vendor,
            originator_serial: req.originator_serial,
            app_reply: Vec::new(),
        })
    }
}

fn split_mr_request(bytes: &[u8]) -> Result<(u8, Vec<u8>, Vec<u8>)> {
    if bytes.len() < 2 {
        return Err(EipError::Short {
            expected: 2,
            actual: bytes.len(),
        });
    }
    let service_code = bytes[0];
    let path_words = bytes[1] as usize;
    let path_end = 2 + path_words * 2;
    if bytes.len() < path_end {
        return Err(EipError::Short {
            expected: path_end,
            actual: bytes.len(),
        });
    }
    Ok((
        service_code,
        bytes[2..path_end].to_vec(),
        bytes[path_end..].to_vec(),
    ))
}

/// Extract the O→T and T→O assembly instances from a Forward_Open
/// connection path. The Logix / Generic Ethernet Module convention is
/// `[route*] Class(4) Instance(config) Connection(consumed) Connection(produced)`,
/// with the class-and-instance segments identifying the config assembly and
/// two more logical-connection-point segments (0x2C) naming the O→T and T→O
/// assemblies.
fn parse_connection_path(path: &[u8]) -> Result<(u16, u16)> {
    let mut i = 0;
    let mut assemblies = Vec::new();
    while i < path.len() {
        let seg = path[i];
        match seg {
            // Port segment (route bytes) — skip.
            0x00..=0x0F => {
                if i + 1 >= path.len() {
                    break;
                }
                i += 2;
            }
            // Logical class segment (8-bit).
            0x20 => i += 2,
            0x21 => i += 4,
            // Logical instance segment (8-bit / 16-bit).
            0x24 => i += 2,
            0x25 => i += 4,
            // Logical connection point (assembly instance) — this is what we want.
            0x2C => {
                if i + 1 >= path.len() {
                    return Err(EipError::Short {
                        expected: i + 2,
                        actual: path.len(),
                    });
                }
                assemblies.push(path[i + 1] as u16);
                i += 2;
            }
            0x2D => {
                if i + 3 >= path.len() {
                    return Err(EipError::Short {
                        expected: i + 4,
                        actual: path.len(),
                    });
                }
                assemblies.push(u16::from_le_bytes([path[i + 2], path[i + 3]]));
                i += 4;
            }
            // Data segments — skip inline config bytes.
            0x80 => {
                if i + 1 >= path.len() {
                    break;
                }
                let word_size = path[i + 1] as usize;
                i += 2 + word_size * 2;
            }
            _ => {
                // Unknown segment — bail out with what we've got.
                break;
            }
        }
    }
    if assemblies.len() < 2 {
        return Err(EipError::Protocol(format!(
            "Forward_Open connection path did not yield 2 assembly instances (got {})",
            assemblies.len()
        )));
    }
    // Convention: first connection-point segment = O→T (consumed by adapter),
    // second = T→O (produced by adapter).
    let output_asm = assemblies[assemblies.len() - 2]; // O→T
    let input_asm = assemblies[assemblies.len() - 1]; // T→O
    Ok((input_asm, output_asm))
}

struct ProducerState {
    connection_id: u32,
    udp: Arc<UdpSocket>,
    peer_udp: Arc<std::sync::RwLock<SocketAddr>>,
    rpi_us: u32,
    assemblies: AssemblyRegistry,
    input_assembly: u16,
    run_idle: bool,
    seq: AtomicU32,
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
                    let data = self.assemblies.read(self.input_assembly).unwrap_or_default();
                    let frame = Frame {
                        connection_id: self.connection_id,
                        sequence: seq,
                        cip_sequence: seq as u16,
                        // Run/idle header is O->T only per the Generic Ethernet
                        // Module profile — adapters don't emit it on T->O.
                        run_idle: None,
                        data,
                    };
                    let bytes = epio::encode_frame(&frame);
                    let peer = *self.peer_udp.read().unwrap();
                    if let Err(err) = self.udp.send_to(&bytes, peer).await {
                        tracing::warn!("producer send failed: {err}");
                    }
                }
            }
        }
    }
}

struct ConsumerState {
    connections: Arc<Mutex<ConnectionTable>>,
    assemblies: AssemblyRegistry,
    run_idle: bool,
    udp: Arc<UdpSocket>,
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
                    let (n, sender) = match res {
                        Ok(x) => x,
                        Err(err) => {
                            tracing::warn!("adapter udp recv error: {err}");
                            continue;
                        }
                    };
                    let frame = match epio::decode_frame(&buf[..n], self.run_idle) {
                        Ok(f) => f,
                        Err(err) => {
                            tracing::debug!("epio decode error: {err}");
                            continue;
                        }
                    };
                    let target = {
                        let table = self.connections.lock().await;
                        table.rows
                            .values()
                            .find(|row| row.o_to_t_conn_id == frame.connection_id)
                            .map(|row| (row.output_assembly, row.o_to_t_conn_id, row.peer_udp.clone()))
                    };
                    if let Some((asm, _, peer_udp_shared)) = target {
                        // Track the scanner's actual UDP source — its port is
                        // typically ephemeral, not the well-known 2222. The
                        // producer reads this on every tick so T→O lands where
                        // the scanner is actually listening.
                        let cur = *peer_udp_shared.read().unwrap();
                        if cur != sender {
                            *peer_udp_shared.write().unwrap() = sender;
                        }
                        // Truncate/pad the incoming data to the assembly size, in
                        // case the scanner sends a larger payload than we host.
                        let asm_snapshot = self.assemblies.snapshot(asm);
                        if let Some(a) = asm_snapshot {
                            let mut buf_to_write = vec![0u8; a.size];
                            let n = frame.data.len().min(a.size);
                            buf_to_write[..n].copy_from_slice(&frame.data[..n]);
                            let _ = self.assemblies.update(asm, &buf_to_write);
                        }
                    }
                }
            }
        }
    }
}
