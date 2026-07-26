//! Safety adapter (target).
//!
//! Symmetric with [`crate::scanner::open_safety_scanner`]: accepts a safety
//! `Forward_Open`, parses out the safety network segment to learn the
//! originator's identifiers, and runs:
//!
//! * a UDP consumer that decodes each incoming O→T safety frame, tracking the
//!   originator's timestamp so the rollover-seeded CRC-S5 keeps verifying
//!   past the 8.4-second wrap, and
//! * a UDP producer that periodically emits a base-format TCOO reply so the
//!   scanner flips its `consumer_active` latch and transitions to run.
//!
//! The full CIP-Safety Supervisor / Validator object model (Configure /
//! Apply / Reset services, state attributes, `Get_Attribute_Single`
//! endpoints) is scaffolded in `supervisor` for a later commit — the wire
//! path here is enough for scanner ↔ adapter interop.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time;

use ethernetip_connections::epio::{
    decode_frame_raw as decode_epio, encode_frame_raw as encode_epio, Frame,
};
use ethernetip_core::cip::{service_codes as service, status, CipDispatcher, CipPath};
use ethernetip_core::cpf::{item_type, Envelope, Item};
use ethernetip_core::encap::{encode_frame as encode_encap, Command, Header, HEADER_LEN};
use ethernetip_core::error::{EipError, Result};

use crate::crc;
use crate::forward_open::SafetyAppReply;
use crate::frame_codec::{self, DecodedFrame, SafetyDecodeError};
use crate::scanner::IO_UDP_PORT;
use crate::segment::{SafetyNetworkSegment, SEGMENT_TYPE};
use crate::types::{ModeByte, SafetyFormat, UniqueNetworkId};
use crate::validator::{SafetyValidatorInstanceState, SafetyValidatorObject, SafetyValidatorState};

/// Configuration for [`start_safety_adapter`].
#[derive(Debug, Clone)]
pub struct SafetyAdapterConfig {
    pub tcp_bind: SocketAddr,
    pub udp_bind: SocketAddr,
    /// Adapter (target) vendor id and device serial — advertised through the
    /// safety application reply so the originator can compute matching PID
    /// seeds for our T→O side.
    pub target_vendor: u16,
    pub target_serial: u32,
    pub target_tunid: UniqueNetworkId,
    /// Expected O→T safety data length (safety validator refuses connections
    /// whose consumed size doesn't match).
    pub input_data_size: usize,
    /// Wire format the adapter will accept.
    pub format: SafetyFormat,
    /// UDP destination port for TCOO producer packets. Defaults to
    /// [`IO_UDP_PORT`]; local-interop tests override.
    pub peer_udp_port: u16,
    /// TCOO cadence in microseconds — how often we emit a target TCOO to keep
    /// the scanner's consumer_active latch alive.
    pub tcoo_period_us: u32,
    /// Optional CIP object dispatcher for services that aren't
    /// FORWARD_OPEN / FORWARD_CLOSE. When populated, MR requests targeted
    /// at a registered class (e.g. Safety Supervisor 0x39) are routed
    /// through [`CipDispatcher::dispatch`] instead of returning
    /// `SERVICE_NOT_SUPPORTED`. Shared `Arc` so a single dispatcher can be
    /// used across multiple sessions.
    pub dispatcher: Option<Arc<CipDispatcher>>,
    /// Optional Safety Validator (class 0x3A) that allocates a fresh
    /// instance for every accepted safety Forward_Open. The instance id
    /// feeds the target-side PID / CID seed calculation (matches C#
    /// `SafetyDevice.cs:184-215`) — without a validator, the adapter
    /// hard-codes `sv_inst = 1`. The validator's `CipClass` must already
    /// be registered on `dispatcher`; both are typically wired together
    /// at startup.
    pub validator: Option<Arc<SafetyValidatorObject>>,
    /// Optional Safety Supervisor (class 0x39). When configured, the
    /// adapter drives its state machine from connection lifecycle events:
    /// the first accepted safety Forward_Open transitions the supervisor
    /// Idle → Executing (mode Idle → Run); the last Forward_Close (or
    /// end-of-session cleanup that removes the last connection) reverses
    /// it. Mirrors the C# `SafetyDevice` pattern where the supervisor
    /// state tracks whether *any* safety connection is live.
    pub supervisor: Option<Arc<crate::supervisor::SafetySupervisorObject>>,
}

impl SafetyAdapterConfig {
    pub fn new(target_vendor: u16, target_serial: u32, input_data_size: usize) -> Self {
        Self {
            tcp_bind: SocketAddr::from(([0, 0, 0, 0], 44818)),
            udp_bind: SocketAddr::from(([0, 0, 0, 0], IO_UDP_PORT)),
            target_vendor,
            target_serial,
            target_tunid: UniqueNetworkId::default(),
            input_data_size,
            format: SafetyFormat::Base,
            peer_udp_port: IO_UDP_PORT,
            tcoo_period_us: 100_000,
            dispatcher: None,
            validator: None,
            supervisor: None,
        }
    }

    /// Install a [`CipDispatcher`] so MR requests for registered classes
    /// (e.g. Safety Supervisor 0x39) are routed to their handlers instead
    /// of returning `SERVICE_NOT_SUPPORTED`.
    pub fn dispatcher(mut self, dispatcher: Arc<CipDispatcher>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Install a [`SafetyValidatorObject`] so every accepted safety
    /// Forward_Open gets its own instance and the instance id becomes the
    /// `sv_inst` component of the target-side PID / CID seeds.
    pub fn validator(mut self, validator: Arc<SafetyValidatorObject>) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Install a [`crate::supervisor::SafetySupervisorObject`]. The
    /// adapter will call `.start()` on the first accepted FO and
    /// `.reset()` when the last connection closes, keeping the
    /// supervisor's State (attr 1) / Mode (attr 2) in sync with whether
    /// any safety connection is currently live.
    pub fn supervisor(
        mut self,
        supervisor: Arc<crate::supervisor::SafetySupervisorObject>,
    ) -> Self {
        self.supervisor = Some(supervisor);
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

    pub fn peer_udp_port(mut self, port: u16) -> Self {
        self.peer_udp_port = port;
        self
    }

    pub fn tunid(mut self, tunid: UniqueNetworkId) -> Self {
        self.target_tunid = tunid;
        self
    }
}

/// Handle to a running safety adapter.
pub struct SafetyAdapterHandle {
    pub tcp_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    /// Latest decoded O→T safety data (last valid frame from the PLC producer
    /// on our server-direction connection). Writer: internal consumer loop.
    /// Reader: application.
    pub input_data: Arc<Mutex<Vec<u8>>>,
    /// Bytes the adapter sends as producer on its client-direction
    /// connection (PLC consumes). Writer: application. Reader: internal
    /// producer loop. Sized to `input_data_size` — same buffer shape
    /// today; can split later if the two directions need different sizes.
    pub produced_data: Arc<Mutex<Vec<u8>>>,
    pub rx_valid: Arc<AtomicU64>,
    pub rx_crc_fail: Arc<AtomicU64>,
    pub tx_tcoo: Arc<AtomicU64>,
    pub tx_producer: Arc<AtomicU64>,
    pub connection_open: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl SafetyAdapterHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
    }
}

/// Bind and start serving safety connections.
pub async fn start_safety_adapter(cfg: SafetyAdapterConfig) -> Result<SafetyAdapterHandle> {
    let tcp = TcpListener::bind(cfg.tcp_bind).await?;
    let tcp_addr = tcp.local_addr()?;
    let udp = Arc::new(UdpSocket::bind(cfg.udp_bind).await?);
    let udp_addr = udp.local_addr()?;

    let input_data = Arc::new(Mutex::new(vec![0u8; cfg.input_data_size]));
    let produced_data = Arc::new(Mutex::new(vec![0u8; cfg.input_data_size]));
    let rx_valid = Arc::new(AtomicU64::new(0));
    let rx_crc_fail = Arc::new(AtomicU64::new(0));
    let tx_tcoo = Arc::new(AtomicU64::new(0));
    let tx_producer = Arc::new(AtomicU64::new(0));
    let connection_open = Arc::new(AtomicBool::new(false));
    let next_conn_id = Arc::new(AtomicU32::new(0x8000_0000));
    let shared: Arc<Mutex<std::collections::HashMap<u32, ActiveConnection>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // UDP consumer task: decode incoming O→T safety frames.
    let consumer = ConsumerLoop {
        udp: udp.clone(),
        input_data: input_data.clone(),
        rx_valid: rx_valid.clone(),
        rx_crc_fail: rx_crc_fail.clone(),
        shared: shared.clone(),
        format: cfg.format,
        validator: cfg.validator.clone(),
    };
    let consumer_task = tokio::spawn(consumer.run(shutdown_rx.clone()));

    // TCOO producer task: keep the scanner's consumer_active latch alive.
    // Only drives connections where t_to_o_size == 6 (server-role, target
    // acting as consumer). Producer-role conns are driven by ProducerLoop
    // below and would be double-transmitted if TcooLoop touched them.
    let producer = TcooLoop {
        udp: udp.clone(),
        peer_udp_port: cfg.peer_udp_port,
        tcoo_period_us: cfg.tcoo_period_us,
        tx_tcoo: tx_tcoo.clone(),
        shared: shared.clone(),
        validator: cfg.validator.clone(),
    };
    let producer_task = tokio::spawn(producer.run(shutdown_rx.clone()));

    // T→O data producer task: for connections opened as client-role
    // (t_to_o_size > 6), emit safety data frames at the T→O RPI cadence
    // sourced from `produced_data`. Without this the paired client
    // connection sits silent, PLC's consumer times out, and the safety
    // supervisor faults the module. See memory `safety-producer-role-detection`.
    let data_producer = ProducerLoop {
        udp: udp.clone(),
        produced_data: produced_data.clone(),
        tx_producer: tx_producer.clone(),
        shared: shared.clone(),
        validator: cfg.validator.clone(),
    };
    let data_producer_task = tokio::spawn(data_producer.run(shutdown_rx.clone()));

    // TCP accept loop: one FO per session for now.
    let cfg_clone = cfg.clone();
    let shared_accept = shared.clone();
    let connection_open_task = connection_open.clone();
    let next_conn_id_task = next_conn_id.clone();
    let udp_accept = udp.clone();
    let accept_task = tokio::spawn(async move {
        let mut shutdown_rx = shutdown_rx;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                accept = tcp.accept() => {
                    let (stream, peer) = match accept {
                        Ok(x) => x,
                        Err(err) => {
                            tracing::warn!("safety adapter accept: {err}");
                            continue;
                        }
                    };
                    let cfg = cfg_clone.clone();
                    let shared = shared_accept.clone();
                    let open = connection_open_task.clone();
                    let next_conn_id = next_conn_id_task.clone();
                    let udp_task = udp_accept.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_session(stream, peer, udp_task, cfg, shared, open, next_conn_id).await {
                            tracing::debug!("safety session ended: {err}");
                        }
                    });
                }
            }
        }
    });

    let combined = tokio::spawn(async move {
        let _ = tokio::join!(consumer_task, producer_task, data_producer_task, accept_task);
    });

    Ok(SafetyAdapterHandle {
        tcp_addr,
        udp_addr,
        input_data,
        produced_data,
        rx_valid,
        rx_crc_fail,
        tx_tcoo,
        tx_producer,
        connection_open,
        shutdown_tx,
        task: combined,
    })
}

#[derive(Debug, Clone)]
struct ActiveConnection {
    o_to_t_conn_id: u32,
    t_to_o_conn_id: u32,
    peer_udp: SocketAddr,
    /// Wire format the scanner picked in its Forward_Open — Base or Extended.
    /// Locked in per-connection so the consumer decodes with the right seeds.
    format: SafetyFormat,
    /// Originator-side PID seeds (scanner produces O→T with these). Used
    /// by ConsumerLoop to verify incoming safety data.
    pid_seed_s1: u8,
    pid_seed_s3: u16,
    pid_seed_s5: u32,
    /// Target-side CID seeds (we're consumer of the O→T data; the TCOO
    /// we send back is CRC-seeded by our own identity via these fields).
    cid_seed_s3: u16,
    cid_seed_s5: u32,
    /// Target-side PID seeds — used by ProducerLoop when this connection's
    /// T→O direction carries data (client-role open). Same derivation as
    /// cid_seed_s3/s5 but the S1 variant we don't already store.
    target_pid_seed_s1: u8,
    target_pid_seed_s3: u16,
    target_pid_seed_s5: u32,
    input_data_len: usize,
    /// T→O wire size in bytes from the FO net params. 6 = TCOO-only
    /// (server role, we consume PLC's O→T data). >6 = producer data
    /// (client role, we produce T→O for PLC to consume). Determines
    /// which loop drives this connection (heuristic — see memory
    /// `safety-producer-role-detection`; move to transport_class_trigger
    /// bit 7 later).
    t_to_o_size: u16,
    /// T→O RPI in microseconds from the FO. ProducerLoop uses this as
    /// the cadence for outgoing safety data frames.
    t_to_o_rpi_us: u32,
    /// Ping interval in microseconds — how often WE (as producer) bump
    /// our outgoing ping_count so PLC's consumer responds with a TCOO.
    /// Derived from safety_seg.ping_interval_multiplier * t_to_o_rpi_us.
    ping_interval_us: u64,
    /// Safety Validator instance id allocated for this connection at FO
    /// accept — needed so Forward_Close can drop the same instance and
    /// avoid leaking one Validator per connect / disconnect cycle.
    sv_inst: u32,
    /// Monotonic reference point for the outgoing consumer_time value in
    /// every TCOO reply, AND for the producer's own timestamp on data
    /// frames we emit. Set when the FO is accepted.
    production_start: Instant,
    // Rollover tracking for the ORIGINATOR's producer (scanner's O→T).
    rollover_count: u16,
    last_ts: u16,
    rollover_initialized: bool,
    /// Initial rollover value for OUR outgoing timestamps — taken from
    /// FO safety segment for client-role, 0 for server. The current
    /// rollover count is computed on demand as
    /// `producer_initial_rollover + wraps_since_open` (see ProducerLoop),
    /// no need to cache it separately.
    producer_initial_rollover: u16,
    /// Base value for OUR outgoing timestamps. Client-role: taken from
    /// safety_seg.initial_time_stamp so PLC's CRC-S5 seed (which folds
    /// in initial_ts + rollover) matches what we produce.
    producer_initial_ts: u16,
    /// Application data length for T→O producer frames — computed once
    /// at FO time via `frame_codec::data_len_for_wire(format, t_to_o_size)`
    /// so ProducerLoop doesn't recompute framing math per tick.
    producer_data_bytes: usize,
    // Target-side ping-response counter (advances every time we hear a new
    // ping_count on an incoming frame — the scanner's mode byte carries it).
    last_ping: u16,
    /// Outgoing ping-count for T→O producer data (advances at ping_interval).
    outgoing_ping: u8,
    /// Elapsed-microseconds-since-production_start at which
    /// `outgoing_ping` was last bumped. `None` before the first
    /// producer send; ProducerLoop treats that as "bump on this tick".
    outgoing_ping_last_change_us: Option<u128>,
}

async fn handle_session(
    mut stream: TcpStream,
    peer: SocketAddr,
    udp: Arc<UdpSocket>,
    cfg: SafetyAdapterConfig,
    shared: Arc<Mutex<std::collections::HashMap<u32, ActiveConnection>>>,
    connection_open: Arc<AtomicBool>,
    next_conn_id: Arc<AtomicU32>,
) -> Result<()> {
    let session_handle = 0x0100_0000 ^ (peer.port() as u32).wrapping_mul(0x9E37_79B9);
    let mut header_buf = [0u8; HEADER_LEN];
    loop {
        if stream.read_exact(&mut header_buf).await.is_err() {
            break;
        }
        let header = Header::parse(&header_buf)?;
        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 {
            stream.read_exact(&mut payload).await?;
        }
        match header.command {
            x if x == Command::RegisterSession.as_u16() => {
                let reply = [0x01, 0x00, 0x00, 0x00];
                let frame =
                    encode_encap(Command::RegisterSession, session_handle, header.sender_context, &reply);
                stream.write_all(&frame).await?;
            }
            x if x == Command::UnRegisterSession.as_u16() => return Ok(()),
            x if x == Command::SendRRData.as_u16() => {
                let reply_body = handle_send_rr_data(
                    &payload,
                    peer,
                    &udp,
                    &cfg,
                    &shared,
                    &connection_open,
                    &next_conn_id,
                )
                .await?;
                let frame = encode_encap(
                    Command::SendRRData,
                    header.session_handle,
                    header.sender_context,
                    &reply_body,
                );
                stream.write_all(&frame).await?;
            }
            other => {
                tracing::debug!("safety adapter unhandled encap 0x{:04X}", other);
                return Ok(());
            }
        }
    }
    connection_open.store(false, Ordering::Relaxed);
    // TCP session ended without an explicit Forward_Close (peer closed the
    // socket or crashed). Drop the same Validator instances the FC path
    // would have removed so those leaks don't accumulate either.
    let mut guard = shared.lock().await;
    let had_connections = !guard.is_empty();
    if let (Some(dispatcher), Some(validator)) = (cfg.dispatcher.as_ref(), cfg.validator.as_ref()) {
        for row in guard.values() {
            validator.remove_instance_via_dispatcher(dispatcher, row.sv_inst);
        }
    }
    guard.clear();
    drop(guard);
    // Supervisor: if we had live connections and the session's death
    // took them all with it, transition back to Idle.
    if had_connections {
        if let (Some(sup), Some(disp)) = (cfg.supervisor.as_ref(), cfg.dispatcher.as_ref()) {
            sup.transition_idle_via(disp);
        }
    }
    Ok(())
}

async fn handle_send_rr_data(
    payload: &[u8],
    peer: SocketAddr,
    udp: &UdpSocket,
    cfg: &SafetyAdapterConfig,
    shared: &Mutex<std::collections::HashMap<u32, ActiveConnection>>,
    connection_open: &AtomicBool,
    next_conn_id: &AtomicU32,
) -> Result<Vec<u8>> {
    let envelope = Envelope::parse(payload)?;
    let mr_item = envelope
        .find(item_type::UNCONNECTED_DATA)
        .ok_or_else(|| EipError::Protocol("SendRRData missing UnconnectedData".into()))?;
    let mr = mr_item.data.clone();
    if mr.len() < 2 {
        return Ok(build_reply_envelope(
            0x00,
            status::PATH_SEGMENT_ERROR,
            &[],
            &[],
            envelope.timeout,
            None,
        ));
    }
    let service_code = mr[0];
    let path_words = mr[1] as usize;
    let path_end = 2 + path_words * 2;
    if mr.len() < path_end {
        return Ok(build_reply_envelope(
            service_code | service::REPLY_FLAG,
            status::PATH_SEGMENT_ERROR,
            &[],
            &[],
            envelope.timeout,
            None,
        ));
    }
    let path_bytes = &mr[2..path_end];
    let body = &mr[path_end..];

    let mut sockaddr_reply_bytes: Option<Vec<u8>> = None;
    // Extended-status words the reply carries — populated by the dispatcher
    // path, empty for the FO / FC handlers which never emit ext status.
    let mut reply_ext_status: Vec<u16> = Vec::new();
    let (reply_service, reply_status, reply_body) = match service_code {
        s if s == service::FORWARD_OPEN => {
            // Prefer the originator's advertised T→O endpoint from Sockaddr
            // Info; fall back to (peer_tcp_ip, cfg.peer_udp_port).
            let peer_udp = ethernetip_core::cpf::resolve_peer_udp(
                &envelope,
                item_type::SOCKADDR_INFO_T_TO_O,
                peer.ip(),
                cfg.peer_udp_port,
            );
            match handle_safety_forward_open(
                body,
                peer_udp,
                cfg,
                shared,
                connection_open,
                next_conn_id,
            )
            .await
            {
                Ok(reply) => {
                    // Include our UDP endpoint in the reply so the scanner
                    // knows where to place O→T frames.
                    if let Ok(local) = udp.local_addr() {
                        if let Ok(sa) = ethernetip_core::cpf::encode_sockaddr_in_v4(local) {
                            sockaddr_reply_bytes = Some(sa);
                        }
                    }
                    // Supervisor state transition: Idle → Executing on
                    // the FIRST accepted safety connection. Subsequent
                    // FOs don't re-transition (state stays Executing
                    // as long as any connection is live).
                    if let (Some(sup), Some(disp)) =
                        (cfg.supervisor.as_ref(), cfg.dispatcher.as_ref())
                    {
                        let is_first = shared.lock().await.len() == 1;
                        if is_first {
                            sup.transition_executing_via(disp);
                        }
                    }
                    (s | service::REPLY_FLAG, status::SUCCESS, reply)
                }
                Err(err) => {
                    tracing::warn!("safety Forward_Open rejected: {err}");
                    (s | service::REPLY_FLAG, status::CONNECTION_FAILURE, Vec::new())
                }
            }
        }
        s if s == service::FORWARD_CLOSE => {
            // Removing all rows keeps the semantics simple for now — the
            // C++/C#/Python ports parse the FC body's connection serial to
            // remove one specific row; do that next if multi-close per
            // session is ever needed on both legs independently.
            //
            // Also drop the Safety Validator instance we allocated for
            // each connection during FO — otherwise a scanner that
            // repeatedly connects and disconnects leaks a Validator
            // instance per cycle.
            connection_open.store(false, Ordering::Relaxed);
            let mut guard = shared.lock().await;
            if let (Some(dispatcher), Some(validator)) =
                (cfg.dispatcher.as_ref(), cfg.validator.as_ref())
            {
                for row in guard.values() {
                    validator.remove_instance_via_dispatcher(dispatcher, row.sv_inst);
                }
            }
            guard.clear();
            drop(guard);
            // Supervisor state transition: no connections left → back to
            // Idle. The FC service always clears the entire connection
            // table (the "close all rows" simplification kept from
            // before), so we know we're going Executing → Idle.
            if let (Some(sup), Some(disp)) =
                (cfg.supervisor.as_ref(), cfg.dispatcher.as_ref())
            {
                sup.transition_idle_via(disp);
            }
            // Minimal Forward_Close reply body: echo conn_serial + orig_vendor + orig_serial + zero pad.
            let mut r = Vec::with_capacity(10);
            if body.len() >= 8 {
                r.extend_from_slice(&body[2..10]);
            } else {
                r.resize(8, 0);
            }
            r.push(0); // reply size words
            r.push(0);
            (s | service::REPLY_FLAG, status::SUCCESS, r)
        }
        other => {
            // Route through the CIP object dispatcher if one is registered.
            // The dispatcher's response gives us all four MR-reply fields
            // (service, general_status, extended_status words, body) —
            // build_reply_envelope carries them through verbatim.
            if let Some(dispatcher) = cfg.dispatcher.as_ref() {
                match CipPath::parse(path_bytes) {
                    Ok(path) => {
                        let response = dispatcher.dispatch(other, path, body.to_vec());
                        reply_ext_status = response.extended_status.clone();
                        (response.service_code, response.general_status, response.data)
                    }
                    Err(err) => {
                        tracing::debug!("safety adapter path parse failed for service 0x{other:02X}: {err}");
                        (other | service::REPLY_FLAG, status::PATH_SEGMENT_ERROR, Vec::new())
                    }
                }
            } else {
                (other | service::REPLY_FLAG, status::SERVICE_NOT_SUPPORTED, Vec::new())
            }
        }
    };

    Ok(build_reply_envelope(
        reply_service,
        reply_status,
        &reply_ext_status,
        &reply_body,
        envelope.timeout,
        sockaddr_reply_bytes,
    ))
}

fn build_reply_envelope(
    service: u8,
    status: u8,
    extended_status: &[u16],
    body: &[u8],
    timeout: u16,
    sockaddr_o_to_t: Option<Vec<u8>>,
) -> Vec<u8> {
    // MR reply layout: service, reserved(0), general_status,
    // extended_status_count (words), extended_status words (LE), body.
    let mut mr_reply = Vec::with_capacity(4 + extended_status.len() * 2 + body.len());
    mr_reply.push(service);
    mr_reply.push(0);
    mr_reply.push(status);
    mr_reply.push(extended_status.len() as u8);
    for w in extended_status {
        mr_reply.extend_from_slice(&w.to_le_bytes());
    }
    mr_reply.extend_from_slice(body);
    let mut items: Vec<Item> = vec![
        Item::null_address(),
        Item::new(item_type::UNCONNECTED_DATA, mr_reply),
    ];
    if let Some(sa) = sockaddr_o_to_t {
        items.push(Item::new(item_type::SOCKADDR_INFO_O_TO_T, sa));
    }
    ethernetip_core::cpf::encode_envelope(0, timeout, &items)
}

async fn handle_safety_forward_open(
    body: &[u8],
    peer_udp: SocketAddr,
    cfg: &SafetyAdapterConfig,
    shared: &Mutex<std::collections::HashMap<u32, ActiveConnection>>,
    connection_open: &AtomicBool,
    next_conn_id: &AtomicU32,
) -> Result<Vec<u8>> {
    if body.len() < 36 {
        return Err(EipError::Short {
            expected: 36,
            actual: body.len(),
        });
    }
    let t_to_o_conn_id = u32::from_le_bytes([body[6], body[7], body[8], body[9]]);
    let connection_serial = u16::from_le_bytes([body[10], body[11]]);
    let orig_vendor = u16::from_le_bytes([body[12], body[13]]);
    let orig_serial = u32::from_le_bytes([body[14], body[15], body[16], body[17]]);
    // T→O RPI (microseconds) and T→O net params — needed for the producer
    // path so we can drive outgoing safety data at the same RPI the PLC
    // consumer expects, and know the wire size (bits 8-0 of net params)
    // that decides producer-role vs TCOO-only.
    let t_to_o_rpi_us = u32::from_le_bytes([body[28], body[29], body[30], body[31]]);
    let t_to_o_net_params = u16::from_le_bytes([body[32], body[33]]);
    let t_to_o_size = t_to_o_net_params & 0x01FF;
    let path_size_words = body[35] as usize;
    let path_start = 36;
    let path_end = path_start + path_size_words * 2;
    if body.len() < path_end {
        return Err(EipError::Short {
            expected: path_end,
            actual: body.len(),
        });
    }
    let conn_path = &body[path_start..path_end];

    // Find the safety network segment (leader 0x50) inside the connection path.
    let mut safety_off = None;
    let mut i = 0;
    while i < conn_path.len() {
        if conn_path[i] == SEGMENT_TYPE {
            safety_off = Some(i);
            break;
        }
        // Segment length depends on segment type. Handle the segments the
        // C++/C#/Python scanners actually put in a safety FO path:
        //   * Port segments (0x00..0x0F) — 2 bytes
        //   * Logical 8-bit (Class/Instance/Member/CP/Attribute/Service) — 2
        //   * Logical 16-bit — 4
        //   * Logical 32-bit — 6
        //   * Electronic Key (0x34 special, length in next byte, in words)
        //   * Data segments (0x80 Simple, 0x91 ANSI symbolic)
        let step = match conn_path[i] {
            0x00..=0x0F => 2,
            0x20 | 0x24 | 0x28 | 0x2C | 0x30 | 0x38 => 2,
            0x21 | 0x25 | 0x29 | 0x2D | 0x31 => 4,
            0x22 | 0x26 | 0x2A | 0x2E | 0x32 => 6,
            0x34 => {
                // Special: length byte at i+1 is number of 16-bit words.
                if i + 1 >= conn_path.len() {
                    break;
                }
                2 + conn_path[i + 1] as usize * 2
            }
            0x80 | 0x91 => {
                if i + 1 >= conn_path.len() {
                    break;
                }
                let word_len = conn_path[i + 1] as usize;
                // ANSI symbolic length is in BYTES, not words; Simple Data
                // Segment length is in words. Padding takes ANSI symbolic
                // up to even byte count.
                if conn_path[i] == 0x91 {
                    let raw = 2 + word_len;
                    raw + (raw & 1)
                } else {
                    2 + word_len * 2
                }
            }
            _ => 2,
        };
        i += step;
    }
    let safety_off =
        safety_off.ok_or_else(|| EipError::Protocol("no safety segment in Forward_Open".into()))?;
    let (safety_seg, _) = SafetyNetworkSegment::parse(&conn_path[safety_off..])?;
    // Accept whichever format the scanner picked; per-connection state
    // records it so the consumer decodes each frame with the right CRC
    // family (Base = S1/S3, Extended = S5 with rollover-folded seeds).
    let format = if safety_seg.format == 0x02 {
        SafetyFormat::Extended
    } else {
        SafetyFormat::Base
    };
    let _ = cfg.format; // format on cfg becomes the receive buffer's expected shape only.

    // Target connection serial = safety validator instance id, echoed in
    // the SafetyAppReply. Matches C# `SafetyDevice.cs:184-215`: if a
    // validator is configured we allocate a fresh instance per accepted
    // FO and use its id; otherwise fall back to a hard-coded 1 (older
    // Rust adapter behavior — kept so callers without a validator still
    // interop against clients that always talk to instance 1).
    let target_connection_serial: u16 = match (cfg.validator.as_ref(), cfg.dispatcher.as_ref())
    {
        (Some(v), Some(d)) => v
            .create_instance_via_dispatcher(
                d,
                SafetyValidatorInstanceState {
                    state: SafetyValidatorState::Executing,
                    ..Default::default()
                },
            )
            .map(|id| id as u16)
            .unwrap_or(1),
        _ => 1,
    };

    // PID seeds for the O→T direction (scanner produces): originator identity +
    // scanner's connection serial. These verify incoming safety data.
    let pid_seed_s1 = crc::pid_cid_seed_s1(orig_vendor, orig_serial, connection_serial);
    let pid_seed_s3 = crc::pid_cid_seed_s3(orig_vendor, orig_serial, connection_serial);
    let pid_seed_s5 = crc::pid_cid_seed_s5(orig_vendor, orig_serial, connection_serial);
    // CID seeds for the TCOO reply we emit on the T→O side. In CIP Safety
    // the CID belongs to the CONSUMER of the corresponding data direction;
    // for a target-side server connection that's the target itself
    // (target_vendor + target_serial + our safety validator instance id).
    let cid_seed_s3 = crc::pid_cid_seed_s3(cfg.target_vendor, cfg.target_serial, target_connection_serial);
    let cid_seed_s5 = crc::pid_cid_seed_s5(cfg.target_vendor, cfg.target_serial, target_connection_serial);
    // Target PID seeds — used by ProducerLoop to CRC OUR outgoing safety
    // data on a client-role connection (we produce T→O, PLC consumes).
    // Derivation is identical to CID (target identity + validator instance)
    // — the S1 variant we don't cache in cid_seed_* so add it explicitly.
    let target_pid_seed_s1 = crc::pid_cid_seed_s1(cfg.target_vendor, cfg.target_serial, target_connection_serial);
    // Ping-interval budget for OUR outgoing producer ping bumps. Derived
    // from the safety segment's ping_interval_multiplier field times the
    // T→O RPI. If PLC advertises 0 (unusual), fall back to 5 * RPI so we
    // still ping periodically and the consumer stays responsive.
    let ping_interval_us: u64 = if safety_seg.ping_interval_multiplier > 0 {
        (safety_seg.ping_interval_multiplier as u64) * (t_to_o_rpi_us as u64)
    } else {
        5u64 * (t_to_o_rpi_us as u64)
    };

    let assigned_oto_t = next_conn_id.fetch_add(1, Ordering::SeqCst);

    // Build the FO reply.
    let mut reply = Vec::with_capacity(30);
    reply.extend_from_slice(&assigned_oto_t.to_le_bytes());
    reply.extend_from_slice(&t_to_o_conn_id.to_le_bytes());
    reply.extend_from_slice(&connection_serial.to_le_bytes());
    reply.extend_from_slice(&orig_vendor.to_le_bytes());
    reply.extend_from_slice(&orig_serial.to_le_bytes());
    // Actual RPIs — echo requested (they live at body[22..26] and body[28..32]).
    reply.extend_from_slice(&body[22..26]);
    reply.extend_from_slice(&body[28..32]);
    // App reply — 5 words (10 bytes) for Base format, 7 words (14 bytes)
    // for Extended (adds InitialTimestamp + InitialRolloverValue that the
    // scanner needs to seed its rollover-folded CRC-S5 producer). Without
    // the extra two words an Extended-format scanner accepts the FO (first
    // 5 words parse fine) but never starts producing — silent failure
    // mode caught 2026-07-24 against a live ControlLogix. Matches
    // C++ / C# / Python target implementations.
    let is_extended = format == SafetyFormat::Extended;
    let app_reply_words: u8 = if is_extended { 7 } else { 5 };
    reply.push(app_reply_words);
    reply.push(0);
    // SafetyAppReply role-dependent per C++ SafetyDevice:
    //   * Server direction (we consume, t_to_o_size == 6): InitialTS = 0,
    //     InitialRV = 0 — deterministic reference across reconnects.
    //   * Client direction (we produce, t_to_o_size > 6): ECHO the
    //     originator's initial_time_stamp / initial_rollover_value from
    //     the safety segment so PLC's consumer can seed its rollover-
    //     folded CRC-S5 to match ours. Using 0 for a client-role reply
    //     causes PLC's consumer to reject (silent close ~30ms after FO).
    let is_client_role = t_to_o_size > 6;
    let (reply_initial_ts, reply_initial_rv) = if is_client_role {
        (safety_seg.initial_time_stamp, safety_seg.initial_rollover_value)
    } else {
        (0, 0)
    };
    let app_reply = SafetyAppReply {
        consumer_number: 1,
        target_vendor_id: cfg.target_vendor,
        target_device_serial: cfg.target_serial,
        target_connection_serial,
        initial_timestamp: reply_initial_ts,
        initial_rollover_value: reply_initial_rv,
    };
    reply.extend_from_slice(&app_reply.consumer_number.to_le_bytes());
    reply.extend_from_slice(&app_reply.target_vendor_id.to_le_bytes());
    reply.extend_from_slice(&app_reply.target_device_serial.to_le_bytes());
    reply.extend_from_slice(&app_reply.target_connection_serial.to_le_bytes());
    if is_extended {
        reply.extend_from_slice(&app_reply.initial_timestamp.to_le_bytes());
        reply.extend_from_slice(&app_reply.initial_rollover_value.to_le_bytes());
    }

    // Seed the ORIGINATOR-side rollover count (used to verify PLC's
    // outgoing producer data). Role-dependent per C++ reference:
    //
    //   * Server-role (we consumer, PLC producer): PLC's producer
    //     starts its rollover at 0 regardless of what the safety
    //     segment carries. Using the safety_seg value here causes
    //     every RUN-mode frame from PLC to fail CRC-S5 because the
    //     seed folds in rollover, and our rollover != PLC's.
    //   * Client-role (we producer, PLC consumer): echoes safety_seg
    //     so both sides start with the same seed. Doesn't matter in
    //     practice because on the client conn PLC only sends TCOOs,
    //     not producer data — but keep the branch aligned with C++.
    //
    // Base format doesn't fold rollover into any CRC so the choice
    // is irrelevant there.
    let initial_rollover = if format == SafetyFormat::Extended && is_client_role {
        safety_seg.initial_rollover_value
    } else {
        0
    };

    // Register the active connection so consumer / TCOO tasks pick it up.
    // peer_udp came from the caller (Sockaddr Info T→O or fallback default).
    shared.lock().await.insert(assigned_oto_t, ActiveConnection {
        o_to_t_conn_id: assigned_oto_t,
        t_to_o_conn_id,
        peer_udp,
        format,
        pid_seed_s1,
        pid_seed_s3,
        pid_seed_s5,
        cid_seed_s3,
        cid_seed_s5,
        target_pid_seed_s1,
        target_pid_seed_s3: cid_seed_s3,
        target_pid_seed_s5: cid_seed_s5,
        input_data_len: cfg.input_data_size,
        t_to_o_size,
        t_to_o_rpi_us,
        ping_interval_us,
        sv_inst: target_connection_serial as u32,
        production_start: Instant::now(),
        rollover_count: initial_rollover,
        last_ts: 0,
        rollover_initialized: false,
        producer_initial_rollover: if is_client_role {
            safety_seg.initial_rollover_value
        } else { 0 },
        producer_initial_ts: if is_client_role {
            safety_seg.initial_time_stamp
        } else { 0 },
        producer_data_bytes: frame_codec::data_len_for_wire(format, t_to_o_size as usize),
        last_ping: 0xFF,
        outgoing_ping: 0,
        outgoing_ping_last_change_us: None,
    });
    connection_open.store(true, Ordering::Relaxed);
    Ok(reply)
}

// -------------------- UDP consumer --------------------

struct ConsumerLoop {
    udp: Arc<UdpSocket>,
    input_data: Arc<Mutex<Vec<u8>>>,
    rx_valid: Arc<AtomicU64>,
    rx_crc_fail: Arc<AtomicU64>,
    shared: Arc<Mutex<std::collections::HashMap<u32, ActiveConnection>>>,
    format: SafetyFormat,
    /// Optional Validator handle — when present, per-connection counters
    /// (`packets_consumed`, `crc_errors`, `rollover_count`, `timestamp`)
    /// on the corresponding `SafetyValidatorInstanceState` get ticked as
    /// frames arrive. This is what makes `Get_Attribute_Single` on a
    /// Validator instance return live numbers instead of the zero
    /// defaults the instance was created with.
    validator: Option<Arc<SafetyValidatorObject>>,
}

impl ConsumerLoop {
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
                        Err(_) => continue,
                    };
                    self.handle_datagram(&buf[..n], sender).await;
                }
            }
        }
    }

    async fn handle_datagram(&self, bytes: &[u8], sender: SocketAddr) {
        let frame = match decode_epio(bytes) {
            Ok(f) => f,
            Err(_) => return,
        };
        // Derive the safety data length from the wire size so we don't have
        // to match a preconfigured cfg.input_data_size — real scanners
        // negotiate the payload size in the FO's network parameters and
        // the wire is self-describing. Short frames encode data_len 1-2
        // as wire_len - 6; long frames encode data_len 3+ as
        // (wire_len - 8) / 2.
        let wire_len = frame.data.len();
        let data_len = if wire_len == 7 || wire_len == 8 {
            wire_len - 6
        } else if wire_len >= 14 && (wire_len - 8) % 2 == 0 {
            (wire_len - 8) / 2
        } else {
            // Unrecognized size — could be TCOO on the wrong id or garbage.
            return;
        };

        let (seeds, conn_format, sv_inst) = {
            let mut guard = self.shared.lock().await;
            let Some(conn) = guard.get_mut(&frame.connection_id) else { return };
            // Track the scanner's actual UDP source — its port is typically
            // ephemeral, not the well-known 2222. Producer / TCOO tasks read
            // peer_udp on every tick so they send back where the scanner is
            // actually listening.
            if conn.peer_udp != sender {
                conn.peer_udp = sender;
            }
            (
                (conn.pid_seed_s1, conn.pid_seed_s3, conn.pid_seed_s5),
                conn.format,
                conn.sv_inst,
            )
        };

        // Peek at the timestamp before verifying the CRC so the rollover
        // counter can be advanced first if the target wrapped.
        let this_ts = frame_codec::extract_timestamp(&frame.data, data_len, conn_format);

        let rollover_now = {
            let mut guard = self.shared.lock().await;
            let Some(conn) = guard.get_mut(&frame.connection_id) else { return };
            if conn.rollover_initialized {
                let delta = this_ts as i32 - conn.last_ts as i32;
                if delta < -0x4000 {
                    conn.rollover_count = conn.rollover_count.wrapping_add(1);
                }
            } else {
                conn.rollover_initialized = true;
            }
            conn.last_ts = this_ts;
            conn.rollover_count
        };

        let mut result = frame_codec::decode(
            &frame.data,
            data_len,
            conn_format,
            seeds.0,
            seeds.1,
            seeds.2,
            rollover_now,
        );

        // Idle-frame fallback: the C# scanner emits a few idle frames with
        // rollover_count=0 (its struct default) before its consumer flips to
        // run and adopts initial_rollover_value. Retry with 0 when the first
        // attempt failed AND the mode byte says idle AND we're not already at 0.
        if result.is_err() && rollover_now != 0 && wire_len > data_len {
            let mode_byte = frame.data[data_len];
            if mode_byte & 0x80 == 0 {
                result = frame_codec::decode(
                    &frame.data,
                    data_len,
                    conn_format,
                    seeds.0,
                    seeds.1,
                    seeds.2,
                    0,
                );
            }
        }

        match result {
            Ok(DecodedFrame { actual_data, mode, timestamp, .. }) => {
                let ping = (mode.0 & 0x03) as u16;
                {
                    let mut guard = self.shared.lock().await;
                    if let Some(conn) = guard.get_mut(&frame.connection_id) {
                        conn.last_ping = ping;
                    }
                }
                self.rx_valid.fetch_add(1, Ordering::Relaxed);
                // Tick the per-connection Validator runtime counters so
                // a scanner's Get_Attribute_Single(0x3A/n/...) can read
                // live values.
                if let Some(v) = self.validator.as_ref() {
                    v.with_runtime_state(sv_inst, |s| {
                        s.packets_consumed = s.packets_consumed.wrapping_add(1);
                        s.rollover_count = rollover_now;
                        s.timestamp = timestamp;
                        s.ping_count = (mode.0 & 0x03) as u8;
                    });
                }
                let mut w = self.input_data.lock().await;
                let n = actual_data.len().min(w.len());
                w[..n].copy_from_slice(&actual_data[..n]);
            }
            Err(err) => {
                if !matches!(err, SafetyDecodeError::TooShort { .. }) {
                    self.rx_crc_fail.fetch_add(1, Ordering::Relaxed);
                    if let Some(v) = self.validator.as_ref() {
                        v.with_runtime_state(sv_inst, |s| {
                            s.crc_errors = s.crc_errors.wrapping_add(1);
                        });
                    }
                }
            }
        }
    }
}

// -------------------- TCOO producer --------------------

struct TcooLoop {
    udp: Arc<UdpSocket>,
    peer_udp_port: u16,
    tcoo_period_us: u32,
    tx_tcoo: Arc<AtomicU64>,
    shared: Arc<Mutex<std::collections::HashMap<u32, ActiveConnection>>>,
    /// Optional Validator — per-connection `packets_produced` on the
    /// `SafetyValidatorInstanceState` gets ticked on each TCOO send.
    validator: Option<Arc<SafetyValidatorObject>>,
}

impl TcooLoop {
    async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        let period = Duration::from_micros(self.tcoo_period_us.max(1000) as u64);
        let mut ticker = time::interval(period);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let seq = AtomicU32::new(0);
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    // Snapshot every TCOO-only connection under one lock,
                    // then send TCOOs outside the critical section.
                    // Producer-role connections (t_to_o_size > 6) are
                    // driven by ProducerLoop instead — TcooLoop stays out
                    // of their way so we don't double-transmit on the
                    // same T→O connection id.
                    let rows: Vec<(u32, SocketAddr, u16, u32, SafetyFormat, u8, u16, u32)> = {
                        let guard = self.shared.lock().await;
                        guard.values().filter(|c| c.t_to_o_size == 6).map(|conn| {
                            // consumer_time = monotonic elapsed since FO
                            // accept, in 128 µs ticks, u16-wrapped. Same
                            // formula the C# / C++ / Python targets use so
                            // the producer's time-correction math sees our
                            // clock advance at the CIP Safety cadence.
                            let elapsed_us = conn.production_start.elapsed().as_micros();
                            let consumer_time = ((elapsed_us / 128) & 0xFFFF) as u16;
                            (
                                conn.t_to_o_conn_id,
                                conn.peer_udp,
                                conn.cid_seed_s3,
                                conn.cid_seed_s5,
                                conn.format,
                                (conn.last_ping & 0x03) as u8,
                                consumer_time,
                                conn.sv_inst,
                            )
                        }).collect()
                    };
                    for (conn_id, peer, cid_seed_s3, cid_seed_s5, format, ping, consumer_time_value, sv_inst) in rows {
                        let mut buf = [0u8; 8];
                        // TCOO CRC family must match the connection's safety
                        // format: Base = CRC-S3, Extended = CRC-S5. Both seed
                        // off the CID (target's identity + SV instance for the
                        // server direction, which is where this adapter lives).
                        let n = if format == SafetyFormat::Extended {
                            frame_codec::encode_time_coordination_extended(
                                &mut buf,
                                ping,
                                consumer_time_value,
                                cid_seed_s5,
                            )
                        } else {
                            frame_codec::encode_time_coordination(
                                &mut buf,
                                ping,
                                consumer_time_value,
                                cid_seed_s3,
                            )
                        };
                        let seq_next = seq.fetch_add(1, Ordering::Relaxed) + 1;
                        let epio = Frame {
                            connection_id: conn_id,
                            sequence: seq_next,
                            cip_sequence: seq_next as u16,
                            run_idle: None,
                            data: buf[..n].to_vec(),
                        };
                        let bytes = encode_epio(&epio);
                        if self.udp.send_to(&bytes, peer).await.is_ok() {
                            self.tx_tcoo.fetch_add(1, Ordering::Relaxed);
                            if let Some(v) = self.validator.as_ref() {
                                v.with_runtime_state(sv_inst, |s| {
                                    s.packets_produced = s.packets_produced.wrapping_add(1);
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

// -------------------- Producer (T→O data) --------------------

/// Drives the client-role T→O producer direction: for every active
/// connection whose `t_to_o_size > 6` (i.e. carries actual safety data,
/// not just TCOO), emit an Extended-format safety data frame at the
/// connection's own RPI cadence. Data comes from the shared
/// `produced_data` buffer the application writes to. Mode byte carries
/// our own ping-count which advances at `ping_interval_us` so PLC's
/// consumer keeps responding with TCOOs.
struct ProducerLoop {
    udp: Arc<UdpSocket>,
    produced_data: Arc<Mutex<Vec<u8>>>,
    tx_producer: Arc<AtomicU64>,
    shared: Arc<Mutex<std::collections::HashMap<u32, ActiveConnection>>>,
    validator: Option<Arc<SafetyValidatorObject>>,
}

impl ProducerLoop {
    async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        // Wake every 1 ms and check each producer-role conn's own RPI
        // budget. Simpler than spawning a task per conn; the tokio timer
        // handles up to a few hundred pending connections easily.
        let mut ticker = time::interval(Duration::from_millis(1));
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        // Per-conn last-send tracking. Keyed by `o_to_t_conn_id` since
        // ActiveConnection is keyed that way in the shared map.
        let mut last_send_us: std::collections::HashMap<u32, u128> =
            std::collections::HashMap::new();
        let seq = AtomicU32::new(0);
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    // Snapshot per-conn producer state under one lock.
                    let rows: Vec<ProducerRow> = {
                        let mut guard = self.shared.lock().await;
                        let mut out = Vec::new();
                        for (&key, conn) in guard.iter_mut() {
                            if conn.t_to_o_size <= 6 { continue; }
                            let elapsed_us = conn.production_start.elapsed().as_micros();
                            let last = *last_send_us.get(&key).unwrap_or(&0);
                            if elapsed_us - last < conn.t_to_o_rpi_us as u128 { continue; }
                            last_send_us.insert(key, elapsed_us);

                            // Advance our outgoing ping at the ping
                            // interval so PLC's consumer responds with
                            // TCOOs. `None` = first tick; either way,
                            // bump the ping and record the moment.
                            let should_bump = match conn.outgoing_ping_last_change_us {
                                None => true,
                                Some(last) => elapsed_us - last >= conn.ping_interval_us as u128,
                            };
                            if should_bump {
                                conn.outgoing_ping = (conn.outgoing_ping + 1) & 0x03;
                                conn.outgoing_ping_last_change_us = Some(elapsed_us);
                            }

                            // Timestamp anchored at producer_initial_ts +
                            // elapsed. Rollover count = initial_rollover +
                            // wraps since production start (no cached
                            // field needed — pure derivation from the two
                            // base values).
                            let elapsed_ticks = (elapsed_us / 128) as u64;
                            let raw = (conn.producer_initial_ts as u64) + elapsed_ticks;
                            let ts = (raw & 0xFFFF) as u16;
                            let wraps_since_open = (raw >> 16) as u16;
                            let rollover_now = conn
                                .producer_initial_rollover
                                .wrapping_add(wraps_since_open);

                            out.push(ProducerRow {
                                conn_id: conn.t_to_o_conn_id,
                                peer: conn.peer_udp,
                                format: conn.format,
                                pid_seed_s1: conn.target_pid_seed_s1,
                                pid_seed_s3: conn.target_pid_seed_s3,
                                pid_seed_s5: conn.target_pid_seed_s5,
                                rollover_count: rollover_now,
                                ping: conn.outgoing_ping,
                                timestamp: ts,
                                data_len: conn.producer_data_bytes,
                                sv_inst: conn.sv_inst,
                            });
                        }
                        out
                    };
                    if rows.is_empty() { continue; }
                    // Read the produced_data snapshot once for this tick.
                    let snapshot = { self.produced_data.lock().await.clone() };

                    for row in rows {
                        // Slice / pad the snapshot to the exact data_len
                        // this connection expects. Padding with zeros
                        // matches how a real safety input module reports
                        // an inactive channel — no surprises for PLC.
                        let mut data = vec![0u8; row.data_len];
                        let copy_n = row.data_len.min(snapshot.len());
                        data[..copy_n].copy_from_slice(&snapshot[..copy_n]);

                        // Mode byte: Run=1, plus current ping count.
                        // ModeByte::build fills in the complement bits.
                        let mode = ModeByte::build(true, row.ping);

                        let mut wire = vec![0u8; row.data_len + 24];
                        let n = frame_codec::encode(
                            &mut wire,
                            &data,
                            row.format,
                            mode,
                            row.timestamp,
                            row.pid_seed_s1,
                            row.pid_seed_s3,
                            row.pid_seed_s5,
                            row.rollover_count,
                        );

                        let seq_next = seq.fetch_add(1, Ordering::Relaxed) + 1;
                        let epio = Frame {
                            connection_id: row.conn_id,
                            sequence: seq_next,
                            cip_sequence: seq_next as u16,
                            run_idle: None,
                            data: wire[..n].to_vec(),
                        };
                        let bytes = encode_epio(&epio);
                        if self.udp.send_to(&bytes, row.peer).await.is_ok() {
                            self.tx_producer.fetch_add(1, Ordering::Relaxed);
                            if let Some(v) = self.validator.as_ref() {
                                v.with_runtime_state(row.sv_inst, |s| {
                                    s.packets_produced = s.packets_produced.wrapping_add(1);
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

/// One producer-role frame's worth of state, captured while holding the
/// shared lock so the actual UDP send can happen outside the critical
/// section. Keeps the lock scope tight and lets many producers share
/// the ticker without serializing on the send.
struct ProducerRow {
    conn_id: u32,
    peer: SocketAddr,
    format: SafetyFormat,
    pid_seed_s1: u8,
    pid_seed_s3: u16,
    pid_seed_s5: u32,
    rollover_count: u16,
    ping: u8,
    timestamp: u16,
    data_len: usize,
    sv_inst: u32,
}

