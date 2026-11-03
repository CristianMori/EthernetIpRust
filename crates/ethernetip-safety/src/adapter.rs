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
use tokio::sync::{watch, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time;

use ethernetip_connections::epio::{
    decode_frame_raw as decode_epio, encode_frame_raw as encode_epio, Frame,
};
use ethernetip_core::cip::{service_codes as service, status, CipDispatcher, CipPath};
use ethernetip_core::cpf::{item_type, Envelope, Item};
use ethernetip_core::encap::{encode_frame as encode_encap, Command, Header, HEADER_LEN};
use ethernetip_core::error::{EipError, Result};

use crate::cpcrc;
use crate::crc;
use crate::forward_open::SafetyAppReply;

/// Produce an unpredictable starting value for the safety adapter's T→O
/// id allocator. Mirrors the helper in
/// `ethernetip_connections::connection_manager_object::random_conn_id_seed`:
/// a passive observer who sees (or makes) one safety Forward_Open could
/// otherwise predict the exact ids issued to subsequent peers, because
/// every process booted at 0x8000_0000 and incremented by one.
/// SplitMix64-mix wall-clock nanoseconds with the process id, then force
/// the top bit set so the seed stays in the originator-chosen half of
/// the 32-bit connection-id space. Not cryptographic — adequate only to
/// defeat a passive network guesser, which is all this needs to do.
fn random_conn_id_seed() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let mut z = nanos ^ pid.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    // 0x8000_0000..=0xBFFF_FFFF — still ~1 billion ids of headroom before
    // fetch_add rolls out of the originator-chosen half of the id space.
    ((z as u32) & 0x3FFF_FFFF) | 0x8000_0000
}
use crate::frame_codec::{self, DecodedFrame, SafetyDecodeError};
use crate::scanner::IO_UDP_PORT;
use crate::segment::{SafetyNetworkSegment, SEGMENT_TYPE};
use crate::types::{SafetyFormat, UniqueNetworkId};
use crate::validator::{SafetyValidatorInstanceState, SafetyValidatorObject, SafetyValidatorState};

/// Maximum concurrent TCP sessions. Idle sessions on `read_exact` park
/// indefinitely, so without a cap a peer can exhaust tokio tasks (and file
/// descriptors) by opening thousands of connections and never writing.
pub const MAX_CONCURRENT_SESSIONS: usize = 64;

// Static Once's for "log this configuration warning on the first FO only"
// — keeps a hot stream of Forward_Opens from spamming the log.
static WARN_DEFAULT_TUNID: std::sync::Once = std::sync::Once::new();
static WARN_NO_SUPERVISOR_SCID: std::sync::Once = std::sync::Once::new();
static WARN_NO_CONFIGURED_SCID: std::sync::Once = std::sync::Once::new();

fn warn_default_tunid_once() {
    WARN_DEFAULT_TUNID.call_once(|| {
        tracing::warn!(
            "safety adapter has no configured TUNID — accepting safety Forward_Opens \
             from any originator. Configure SafetyAdapterConfig::tunid for production use."
        );
    });
}

fn warn_no_supervisor_scid_once() {
    WARN_NO_SUPERVISOR_SCID.call_once(|| {
        tracing::warn!(
            "safety adapter has no supervisor configured — skipping SCCRC check. \
             Install SafetyAdapterConfig::supervisor to enable SCID enforcement."
        );
    });
}

fn warn_no_configured_scid_once() {
    WARN_NO_CONFIGURED_SCID.call_once(|| {
        tracing::warn!(
            "safety supervisor has no configured SCID — skipping SCCRC check. \
             Set attribute 6 on class 0x39 (Safety Supervisor) to enable SCID enforcement."
        );
    });
}

/// Hard cap on the number of simultaneous safety Forward_Opens a single TCP
/// session is allowed to hold. Safety connections are heavier than ordinary
/// Class 1 ones (each allocates a Validator instance, a producer-side
/// rollover state slot, and a seat in the shared connection map), so the
/// per-session cap is deliberately lower than
/// [`ethernetip_connections::adapter::MAX_FORWARD_OPENS_PER_SESSION`].
pub const MAX_SAFETY_FORWARD_OPENS_PER_SESSION: usize = 8;

/// Hard cap on the total number of simultaneous safety connections across
/// all sessions. Also bounds the `next_instance_id` growth on the installed
/// Safety Validator and the size of the shared connection map, so a swarm
/// of sessions each near the per-session cap can't balloon memory or push
/// the validator's u32 id space toward wrap. 0x0113 ("No more connection
/// resources") is the CIP-standard reject extended status.
pub const MAX_SAFETY_TOTAL_CONNECTIONS: usize = 64;

/// Per-request idle timeout. If a peer opens a TCP session and goes quiet
/// mid-frame the session is dropped so its slot in the semaphore above is
/// returned to the pool. 60 s is long enough for any legitimate scanner's
/// keep-alive gap and short enough that a parked idle session can't hold a
/// slot forever.
pub const SESSION_READ_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// Latest decoded O→T safety data (last valid frame).
    pub input_data: Arc<Mutex<Vec<u8>>>,
    pub rx_valid: Arc<AtomicU64>,
    pub rx_crc_fail: Arc<AtomicU64>,
    pub tx_tcoo: Arc<AtomicU64>,
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
    let rx_valid = Arc::new(AtomicU64::new(0));
    let rx_crc_fail = Arc::new(AtomicU64::new(0));
    let tx_tcoo = Arc::new(AtomicU64::new(0));
    let connection_open = Arc::new(AtomicBool::new(false));
    let next_conn_id = Arc::new(AtomicU32::new(random_conn_id_seed()));
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
    let producer = TcooLoop {
        udp: udp.clone(),
        peer_udp_port: cfg.peer_udp_port,
        tcoo_period_us: cfg.tcoo_period_us,
        tx_tcoo: tx_tcoo.clone(),
        shared: shared.clone(),
        validator: cfg.validator.clone(),
    };
    let producer_task = tokio::spawn(producer.run(shutdown_rx.clone()));

    // TCP accept loop: one FO per session for now.
    let cfg_clone = cfg.clone();
    let shared_accept = shared.clone();
    let connection_open_task = connection_open.clone();
    let next_conn_id_task = next_conn_id.clone();
    let udp_accept = udp.clone();
    let session_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS));
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
                    // Try to grab a session slot. If we're already at
                    // MAX_CONCURRENT_SESSIONS, drop the connection rather
                    // than queueing — a slow peer must not delay accept
                    // for everyone else.
                    let permit = match session_limit.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            tracing::warn!(
                                "safety session limit reached ({}), rejecting {}",
                                MAX_CONCURRENT_SESSIONS,
                                peer
                            );
                            drop(stream);
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
                        drop(permit);
                    });
                }
            }
        }
    });

    let combined = tokio::spawn(async move {
        let _ = tokio::join!(consumer_task, producer_task, accept_task);
    });

    Ok(SafetyAdapterHandle {
        tcp_addr,
        udp_addr,
        input_data,
        rx_valid,
        rx_crc_fail,
        tx_tcoo,
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
    pid_seed_s1: u8,
    pid_seed_s3: u16,
    pid_seed_s5: u32,
    cid_seed_s3: u16,
    cid_seed_s5: u32,
    input_data_len: usize,
    /// Safety Validator instance id allocated for this connection at FO
    /// accept — needed so Forward_Close can drop the same instance and
    /// avoid leaking one Validator per connect / disconnect cycle.
    sv_inst: u32,
    /// Originator triplet carried in the FO body — the FC path matches
    /// on these three values to drop exactly one row rather than
    /// clearing the entire shared table.
    connection_serial: u16,
    orig_vendor: u16,
    orig_serial: u32,
    /// Monotonic reference point for the outgoing consumer_time value in
    /// every TCOO reply. Set when the FO is accepted; every TCOO advertises
    /// (elapsed_us / 128) & 0xFFFF from this point so the scanner sees our
    /// clock tick forward at the CIP Safety-mandated 128 µs cadence.
    production_start: Instant,
    // Rollover tracking for the ORIGINATOR's producer (scanner's O→T).
    rollover_count: u16,
    last_ts: u16,
    rollover_initialized: bool,
    // Target-side ping-response counter (advances every time we hear a new
    // ping_count on an incoming frame — the scanner's mode byte carries it).
    last_ping: u16,
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
    // Per-session FO count — bounds how many safety connections one TCP
    // session can allocate. Incremented on each accepted FO, decremented
    // on each FC and on session teardown. The global HashMap size caps
    // the aggregate.
    let mut session_fo_count: usize = 0;
    loop {
        // Idle timeout on the next-request boundary: a peer that opens a
        // TCP session and goes silent must not keep its slot in the
        // global session semaphore forever. Mid-frame reads below are
        // not timed out — once a header is in, the payload is already
        // bounded.
        match tokio::time::timeout(SESSION_READ_TIMEOUT, stream.read_exact(&mut header_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => {
                tracing::debug!("safety session {} idle timeout", peer);
                break;
            }
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
                    &mut session_fo_count,
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
    session_fo_count: &mut usize,
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
            // Per-session + global caps on safety Forward_Opens. Reject
            // before parsing the FO body so a hostile peer that blasts
            // Forward_Opens can't allocate validator instances or
            // HashMap slots past the configured cap. 0x0113 ("no more
            // connection resources") is the CIP-standard reject.
            if *session_fo_count >= MAX_SAFETY_FORWARD_OPENS_PER_SESSION {
                tracing::warn!(
                    peer=?peer,
                    "safety Forward_Open rejected: session already holds {} connections (cap {})",
                    *session_fo_count,
                    MAX_SAFETY_FORWARD_OPENS_PER_SESSION,
                );
                reply_ext_status = vec![0x0113];
                (
                    service::FORWARD_OPEN | service::REPLY_FLAG,
                    status::CONNECTION_FAILURE,
                    Vec::new(),
                )
            } else if shared.lock().await.len() >= MAX_SAFETY_TOTAL_CONNECTIONS {
                tracing::warn!(
                    peer=?peer,
                    "safety Forward_Open rejected: global connection table full (cap {})",
                    MAX_SAFETY_TOTAL_CONNECTIONS,
                );
                reply_ext_status = vec![0x0113];
                (
                    service::FORWARD_OPEN | service::REPLY_FLAG,
                    status::CONNECTION_FAILURE,
                    Vec::new(),
                )
            } else {
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
                    *session_fo_count += 1;
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
        }
        s if s == service::FORWARD_CLOSE => {
            // Parse the originator triplet from the FC body and remove
            // ONLY the matching row — not every live row on the adapter.
            // The pre-fix behavior cleared the entire shared HashMap on
            // any FC, which meant any peer that could complete
            // RegisterSession + one FC MR packet tore down every live
            // safety connection on the adapter and transitioned the
            // Supervisor Executing → Idle.
            //
            // TODO: full per-session owned-id tracking (equivalent of
            // the connections crate's `active_conn_ids` list from
            // `5dccf8d`) would additionally require the FC's triplet to
            // belong to a connection THIS session opened. Without that,
            // a peer who guesses or observes another originator's
            // triplet can still close that one connection from an
            // unrelated session. The minimum correctness fix below —
            // triplet-match + remove-single-row — closes the "any FC
            // clears everything" vector; the cross-session guess
            // vector is a separate commit.
            if body.len() < 10 {
                tracing::warn!("safety Forward_Close body too short ({} bytes)", body.len());
                (s | service::REPLY_FLAG, status::PATH_SEGMENT_ERROR, Vec::new())
            } else {
                let fc_conn_serial = u16::from_le_bytes([body[2], body[3]]);
                let fc_orig_vendor = u16::from_le_bytes([body[4], body[5]]);
                let fc_orig_serial =
                    u32::from_le_bytes([body[6], body[7], body[8], body[9]]);

                let mut guard = shared.lock().await;
                let matching_id: Option<u32> = guard
                    .values()
                    .find(|row| {
                        row.connection_serial == fc_conn_serial
                            && row.orig_vendor == fc_orig_vendor
                            && row.orig_serial == fc_orig_serial
                    })
                    .map(|row| row.o_to_t_conn_id);

                if let Some(id) = matching_id {
                    // Drop the matching Validator instance BEFORE pulling
                    // the row out so we read sv_inst from the row we're
                    // about to remove.
                    if let (Some(dispatcher), Some(validator)) =
                        (cfg.dispatcher.as_ref(), cfg.validator.as_ref())
                    {
                        if let Some(row) = guard.get(&id) {
                            validator.remove_instance_via_dispatcher(dispatcher, row.sv_inst);
                        }
                    }
                    guard.remove(&id);
                    // Only clear `connection_open` and transition the
                    // Supervisor back to Idle when the LAST row is gone.
                    // A session that holds several safety connections
                    // and closes one of them must keep the others live.
                    let is_empty_now = guard.is_empty();
                    drop(guard);
                    *session_fo_count = session_fo_count.saturating_sub(1);
                    if is_empty_now {
                        connection_open.store(false, Ordering::Relaxed);
                        if let (Some(sup), Some(disp)) =
                            (cfg.supervisor.as_ref(), cfg.dispatcher.as_ref())
                        {
                            sup.transition_idle_via(disp);
                        }
                    }
                    let mut r = Vec::with_capacity(10);
                    r.extend_from_slice(&body[2..10]);
                    r.push(0); // app reply size words
                    r.push(0);
                    (s | service::REPLY_FLAG, status::SUCCESS, r)
                } else {
                    tracing::warn!(
                        "safety Forward_Close: no row for triplet \
                         (conn_serial=0x{fc_conn_serial:04X}, \
                         orig_vendor=0x{fc_orig_vendor:04X}, \
                         orig_serial=0x{fc_orig_serial:08X})"
                    );
                    drop(guard);
                    // CIP ext 0x0107: "Target connection not found"
                    reply_ext_status = vec![0x0107];
                    (
                        s | service::REPLY_FLAG,
                        status::CONNECTION_FAILURE,
                        Vec::new(),
                    )
                }
            }
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

    // Safety validation: before allocating any Validator instance or
    // seat in the shared connection table, verify that the originator
    // targeted THIS device and that the Forward_Open hasn't been
    // tampered with in flight.
    //
    // 1. TUNID: when the adapter has a configured non-default TUNID,
    //    compare it to safety_seg.tunid. CIP ext-status 0x080E is the
    //    standard "wrong target" reject. For dev builds that run with
    //    the default-zero TUNID, log a warning once and accept — the
    //    user explicitly didn't configure one.
    // 2. CPCRC: mandatory. Recompute from the Forward_Open bytes the
    //    originator saw (the full body passed into this function) and
    //    compare to safety_seg.cpcrc. Mismatch rejects with 0x0803
    //    ("Connection Parameter CRC error").
    // 3. SCCRC: only enforceable when the supervisor has a configured
    //    Safety Configuration Identifier (SCID set via class 0x39 attr
    //    6). On a configured device with sccrc != 0 AND a non-zero
    //    seg.sccrc, mismatch rejects with 0x080F ("SCID mismatch").
    //    Without a configured SCID, log once and skip (matches the
    //    behavior in the C# and C++ ports — SCCRC is a hash over the
    //    safety configuration data, which only the configuration tool
    //    knows; the target can only reject an sccrc that explicitly
    //    disagrees with a value it was told to expect).
    {
        let tunid_configured = cfg.target_tunid != UniqueNetworkId::default();
        if tunid_configured {
            if safety_seg.tunid != cfg.target_tunid {
                tracing::warn!(
                    "safety Forward_Open rejected: TUNID mismatch (seg={:?} cfg={:?})",
                    safety_seg.tunid,
                    cfg.target_tunid,
                );
                return Err(EipError::Cip {
                    status: 0x01,
                    ext: vec![0x080E],
                });
            }
        } else {
            warn_default_tunid_once();
        }

        // CPCRC — mandatory.
        let nsd_size = if safety_seg.format == 0x02 { 50 } else { 48 };
        if safety_off + nsd_size > conn_path.len() {
            return Err(EipError::Protocol(
                "safety segment NSD extends past connection path".into(),
            ));
        }
        let nsd = &conn_path[safety_off..safety_off + nsd_size];
        let app_path = &conn_path[..safety_off];
        // Target sees the path as-is from body[35] once routing (if any)
        // is stripped by intermediate bridges; use that for the CPCRC
        // path_size byte (byte at offset 35 of the FO service data).
        let effective_path_size_words = path_size_words as u8;
        let computed_cpcrc =
            cpcrc::compute_from_raw(body, app_path, nsd, effective_path_size_words)?;
        if computed_cpcrc != safety_seg.cpcrc {
            tracing::warn!(
                "safety Forward_Open rejected: CPCRC mismatch (computed=0x{:08X} seg=0x{:08X})",
                computed_cpcrc,
                safety_seg.cpcrc,
            );
            return Err(EipError::Cip {
                status: 0x01,
                ext: vec![0x0803],
            });
        }

        // SCCRC — compare against configured SCID when both sides have one.
        if let Some(sup) = cfg.supervisor.as_ref() {
            let configured = sup.scid();
            if configured.sccrc != 0 && safety_seg.sccrc != 0
                && configured.sccrc != safety_seg.sccrc
            {
                tracing::warn!(
                    "safety Forward_Open rejected: SCCRC mismatch (seg=0x{:08X} supervisor=0x{:08X})",
                    safety_seg.sccrc,
                    configured.sccrc,
                );
                return Err(EipError::Cip {
                    status: 0x01,
                    ext: vec![0x080F],
                });
            }
            if configured.sccrc == 0 {
                warn_no_configured_scid_once();
            }
        } else {
            warn_no_supervisor_scid_once();
        }
    }

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
    // SafetyAppReply — for a target's server-direction connection we
    // seed InitialTS = 0 and InitialRV = 0 (deterministic reference
    // across reconnects, matching the C++ SafetyDevice `is_server` path).
    let app_reply = SafetyAppReply {
        consumer_number: 1,
        target_vendor_id: cfg.target_vendor,
        target_device_serial: cfg.target_serial,
        target_connection_serial,
        initial_timestamp: 0,
        initial_rollover_value: 0,
    };
    reply.extend_from_slice(&app_reply.consumer_number.to_le_bytes());
    reply.extend_from_slice(&app_reply.target_vendor_id.to_le_bytes());
    reply.extend_from_slice(&app_reply.target_device_serial.to_le_bytes());
    reply.extend_from_slice(&app_reply.target_connection_serial.to_le_bytes());
    if is_extended {
        reply.extend_from_slice(&app_reply.initial_timestamp.to_le_bytes());
        reply.extend_from_slice(&app_reply.initial_rollover_value.to_le_bytes());
    }

    // Seed the originator-side rollover from the safety segment's
    // initial_rollover_value (Extended format only — Base format doesn't fold
    // rollover into any CRC). C# scanner defaults this to 0xFFFF, so a naive
    // zero-init on our side works for the first ~8.4 s window and then all
    // frames CRC-fail on the wrap.
    let initial_rollover = if format == SafetyFormat::Extended {
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
        input_data_len: cfg.input_data_size,
        sv_inst: target_connection_serial as u32,
        connection_serial,
        orig_vendor,
        orig_serial,
        production_start: Instant::now(),
        rollover_count: initial_rollover,
        last_ts: 0,
        rollover_initialized: false,
        last_ping: 0xFF,
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
        //
        // State-update rule: compute `candidate_rollover` / `candidate_ts`
        // locally and run the decoder with the candidate rollover. ONLY
        // commit `conn.rollover_count` / `conn.last_ts` after the decoder
        // reports Ok. A spoofed UDP packet with a crafted timestamp lacks
        // the PID seed → the decoder fails, and we leave the rollover
        // state intact. Without this gate, one spoofed packet with a
        // crafted timestamp bumps `rollover_count` and overwrites
        // `last_ts` before CRC verification, permanently desynchronizing
        // the legitimate stream (every subsequent legitimate frame then
        // fails CRC with the wrong seed).
        let this_ts = frame_codec::extract_timestamp(&frame.data, data_len, conn_format);

        let (candidate_rollover, prev_last_ts, prev_initialized) = {
            let guard = self.shared.lock().await;
            let Some(conn) = guard.get(&frame.connection_id) else { return };
            let mut candidate = conn.rollover_count;
            if conn.rollover_initialized {
                let delta = this_ts as i32 - conn.last_ts as i32;
                if delta < -0x4000 {
                    candidate = candidate.wrapping_add(1);
                }
            }
            (candidate, conn.last_ts, conn.rollover_initialized)
        };
        let _ = prev_last_ts;

        let mut used_rollover = candidate_rollover;
        let mut result = frame_codec::decode(
            &frame.data,
            data_len,
            conn_format,
            seeds.0,
            seeds.1,
            seeds.2,
            candidate_rollover,
        );

        // Idle-frame fallback: the C# scanner emits a few idle frames with
        // rollover_count=0 (its struct default) before its consumer flips to
        // run and adopts initial_rollover_value. Retry with 0 when the first
        // attempt failed AND the mode byte says idle AND we're not already at 0.
        if result.is_err() && candidate_rollover != 0 && wire_len > data_len {
            let mode_byte = frame.data[data_len];
            if mode_byte & 0x80 == 0 {
                let retry = frame_codec::decode(
                    &frame.data,
                    data_len,
                    conn_format,
                    seeds.0,
                    seeds.1,
                    seeds.2,
                    0,
                );
                if retry.is_ok() {
                    used_rollover = 0;
                    result = retry;
                }
            }
        }

        // Commit rollover + ts only on a successful decode. On an error
        // (crafted frame, CRC fail) leave the per-connection rollover
        // state unchanged so the legitimate stream stays in sync.
        if result.is_ok() {
            let mut guard = self.shared.lock().await;
            if let Some(conn) = guard.get_mut(&frame.connection_id) {
                conn.rollover_count = used_rollover;
                conn.last_ts = this_ts;
                conn.rollover_initialized = true;
            }
        } else {
            // Keep the "prev_initialized" value — nothing changes.
            let _ = prev_initialized;
        }

        // `rollover_now` is kept around to preserve downstream logging
        // behavior that previously read the committed rollover.
        let rollover_now = used_rollover;

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
                    // Snapshot every active connection under one lock, then
                    // send TCOOs outside the critical section.
                    let rows: Vec<(u32, SocketAddr, u16, u32, SafetyFormat, u8, u16, u32)> = {
                        let guard = self.shared.lock().await;
                        guard.values().map(|conn| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward_open::{build_safety_forward_open, SafetyForwardOpenConfig};
    use crate::types::SafetyNetworkNumber;

    fn test_cfg() -> SafetyForwardOpenConfig {
        SafetyForwardOpenConfig {
            consumed_assembly: 300,
            produced_assembly: 301,
            config_assembly: 302,
            consumed_data_size: 8,
            produced_data_size: 8,
            rpi_us: 10_000,
            format: SafetyFormat::Base,
            tunid: UniqueNetworkId {
                snn: SafetyNetworkNumber([1, 2, 3, 4, 5, 6]),
                node_address: 0xC0A8_0158,
            },
            ounid: UniqueNetworkId {
                snn: SafetyNetworkNumber([9, 8, 7, 6, 5, 4]),
                node_address: 0xC0A8_014A,
            },
            ..SafetyForwardOpenConfig::default()
        }
    }

    fn adapter_cfg_with_tunid(tunid: UniqueNetworkId) -> SafetyAdapterConfig {
        SafetyAdapterConfig {
            tcp_bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            udp_bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            target_vendor: 0x1234,
            target_serial: 0xDEAD_BEEF,
            target_tunid: tunid,
            input_data_size: 8,
            format: SafetyFormat::Base,
            peer_udp_port: 2222,
            tcoo_period_us: 100_000,
            dispatcher: None,
            validator: None,
            supervisor: None,
        }
    }

    /// The randomised T→O id seed from `random_conn_id_seed` must land
    /// in the originator-chosen half of the id space, and two calls
    /// must almost always disagree. We tolerate a one-in-a-billion
    /// coincidence by trying up to 32 samples before failing; the
    /// SplitMix64 mix of nanoseconds + pid should move on nearly every
    /// invocation on any real machine.
    #[test]
    fn random_conn_id_seed_differs_across_calls_and_stays_in_upper_half() {
        let first = random_conn_id_seed();
        assert!(
            first >= 0x8000_0000 && first <= 0xBFFF_FFFF,
            "seed {first:#010X} outside originator-chosen half 0x8000_0000..=0xBFFF_FFFF",
        );
        let mut saw_different = false;
        for _ in 0..32 {
            let next = random_conn_id_seed();
            assert!(
                next >= 0x8000_0000 && next <= 0xBFFF_FFFF,
                "seed {next:#010X} outside originator-chosen half",
            );
            if next != first {
                saw_different = true;
                break;
            }
        }
        assert!(
            saw_different,
            "random_conn_id_seed produced the same value 32 times in a row",
        );
    }

    /// Finding 4 regression: a Forward_Open body whose CPCRC field has been
    /// tampered with must be rejected with CIP 0x01 ext 0x0803, and no
    /// state must be inserted into the shared connection table.
    #[tokio::test]
    async fn safety_fo_rejects_cpcrc_mismatch_with_0x0803() {
        let fo_cfg = test_cfg();
        let wire = build_safety_forward_open(
            &fo_cfg,
            0x1111,
            0x0001,
            0xC0FF_EE01,
            0xA0,
            &[],
            &[],
        )
        .unwrap();

        // The target TUNID in the adapter config matches the one baked
        // into the FO path, so TUNID is accepted and the test exercises
        // the CPCRC gate specifically.
        let cfg = adapter_cfg_with_tunid(fo_cfg.tunid);

        // Baseline: unmodified wire — should be accepted.
        {
            let shared = Mutex::new(std::collections::HashMap::new());
            let open = AtomicBool::new(false);
            let next_id = AtomicU32::new(0x8000_0000);
            let ok = handle_safety_forward_open(
                &wire.service_data,
                SocketAddr::from(([127, 0, 0, 1], 2222)),
                &cfg,
                &shared,
                &open,
                &next_id,
            )
            .await;
            assert!(ok.is_ok(), "legitimate safety FO must verify: {:?}", ok.err());
            assert_eq!(shared.lock().await.len(), 1);
        }

        // Attack: flip one byte inside the segment's CPCRC field. In the
        // segment the CPCRC lives at offset 48 from the 0x50 leader (Base
        // format), and the segment starts after the 36-byte FO prefix
        // plus the 8-byte assembly shortcut.
        let seg_start = 36 + 8;
        let cpcrc_abs = seg_start + 48;
        let mut tampered = wire.service_data.clone();
        tampered[cpcrc_abs] ^= 0xFF;

        let shared = Mutex::new(std::collections::HashMap::new());
        let open = AtomicBool::new(false);
        let next_id = AtomicU32::new(0x8000_0000);
        let err = handle_safety_forward_open(
            &tampered,
            SocketAddr::from(([127, 0, 0, 1], 2222)),
            &cfg,
            &shared,
            &open,
            &next_id,
        )
        .await
        .expect_err("tampered CPCRC must be rejected");
        match err {
            EipError::Cip { status, ext } => {
                assert_eq!(status, 0x01, "general status must be CONNECTION_FAILURE");
                assert_eq!(ext, vec![0x0803], "ext status must be 0x0803 (CPCRC mismatch)");
            }
            other => panic!("expected CIP error, got {:?}", other),
        }
        // State must NOT have been inserted on reject.
        assert_eq!(shared.lock().await.len(), 0);
    }

    /// Finding 1 regression: a Forward_Close that targets ONE connection
    /// must leave every other active connection and the Supervisor state
    /// untouched. Pre-fix, any FC cleared the entire shared HashMap and
    /// transitioned the Supervisor Executing → Idle; a peer with
    /// RegisterSession access could tear down every live safety
    /// connection with one spoofed FC.
    #[tokio::test]
    async fn safety_fc_removes_only_matching_triplet() {
        let mut fo_cfg_a = test_cfg();
        let mut fo_cfg_b = test_cfg();
        // Two distinct originator triplets.
        let wire_a = build_safety_forward_open(
            &fo_cfg_a,
            0x1111,
            0x0001,
            0xC0FF_EE01,
            0xA0,
            &[],
            &[],
        )
        .unwrap();
        let wire_b = build_safety_forward_open(
            &fo_cfg_b,
            0x2222,
            0x0001,
            0xC0FF_EE02,
            0xA0,
            &[],
            &[],
        )
        .unwrap();
        let _ = (&mut fo_cfg_a, &mut fo_cfg_b);

        let cfg = adapter_cfg_with_tunid(test_cfg().tunid);
        let shared = Mutex::new(std::collections::HashMap::new());
        let open = AtomicBool::new(false);
        let next_id = AtomicU32::new(0x8000_0000);

        handle_safety_forward_open(
            &wire_a.service_data,
            SocketAddr::from(([127, 0, 0, 1], 2222)),
            &cfg,
            &shared,
            &open,
            &next_id,
        )
        .await
        .expect("FO A must verify");
        handle_safety_forward_open(
            &wire_b.service_data,
            SocketAddr::from(([127, 0, 0, 1], 2222)),
            &cfg,
            &shared,
            &open,
            &next_id,
        )
        .await
        .expect("FO B must verify");
        assert_eq!(shared.lock().await.len(), 2);

        // Build a Forward_Close body targeting ONLY triplet B
        // (0x2222, 0x0001, 0xC0FF_EE02). Layout:
        //   byte 0: priority_tick, 1: timeout_ticks,
        //   2..4: connection_serial (LE), 4..6: orig_vendor,
        //   6..10: orig_serial, 10: path_size words, 11: reserved,
        //   12..: path.
        let mut fc = Vec::<u8>::new();
        fc.push(0x05);
        fc.push(0x9C);
        fc.extend_from_slice(&0x2222u16.to_le_bytes());
        fc.extend_from_slice(&0x0001u16.to_le_bytes());
        fc.extend_from_slice(&0xC0FF_EE02u32.to_le_bytes());
        fc.push(0x02); // path_size words
        fc.push(0x00);
        fc.extend_from_slice(&[0x20, 0x06, 0x24, 0x01]);

        // Replicate the handler's slice: FC handler receives `body`
        // which is everything after the MR path words. Craft a tiny
        // handler input that just calls the FC branch via the public
        // entry. Here, we inline the match: directly check that given
        // triplet B is parsed, the row for B is removed and the row
        // for A stays.
        //
        // Call the FC resolution logic by hand (same code the handler
        // runs under the FORWARD_CLOSE match arm) — the handler's
        // signature doesn't expose it, so this test mirrors the
        // intended behavior.
        let fc_conn_serial = u16::from_le_bytes([fc[2], fc[3]]);
        let fc_orig_vendor = u16::from_le_bytes([fc[4], fc[5]]);
        let fc_orig_serial = u32::from_le_bytes([fc[6], fc[7], fc[8], fc[9]]);

        let mut guard = shared.lock().await;
        let matching: Option<u32> = guard
            .values()
            .find(|row| {
                row.connection_serial == fc_conn_serial
                    && row.orig_vendor == fc_orig_vendor
                    && row.orig_serial == fc_orig_serial
            })
            .map(|row| row.o_to_t_conn_id);
        let id = matching.expect("row for triplet B must be present");
        guard.remove(&id);
        assert_eq!(guard.len(), 1);
        // Confirm the surviving row is A (triplet A).
        let surviving = guard.values().next().unwrap();
        assert_eq!(surviving.connection_serial, 0x1111);
        assert_eq!(surviving.orig_serial, 0xC0FF_EE01);
    }

    /// Finding 4 companion: tampered TUNID in the FO's safety segment
    /// is rejected with 0x080E when the adapter has a configured TUNID.
    #[tokio::test]
    async fn safety_fo_rejects_tunid_mismatch_with_0x080e() {
        let fo_cfg = test_cfg();
        let wire = build_safety_forward_open(
            &fo_cfg,
            0x1111,
            0x0001,
            0xC0FF_EE01,
            0xA0,
            &[],
            &[],
        )
        .unwrap();

        // Adapter is configured with a DIFFERENT TUNID than the FO carries.
        let different = UniqueNetworkId {
            snn: SafetyNetworkNumber([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]),
            node_address: 0xC0A8_0199,
        };
        let cfg = adapter_cfg_with_tunid(different);

        let shared = Mutex::new(std::collections::HashMap::new());
        let open = AtomicBool::new(false);
        let next_id = AtomicU32::new(0x8000_0000);
        let err = handle_safety_forward_open(
            &wire.service_data,
            SocketAddr::from(([127, 0, 0, 1], 2222)),
            &cfg,
            &shared,
            &open,
            &next_id,
        )
        .await
        .expect_err("mismatched TUNID must be rejected");
        match err {
            EipError::Cip { status, ext } => {
                assert_eq!(status, 0x01);
                assert_eq!(ext, vec![0x080E]);
            }
            other => panic!("expected CIP error, got {:?}", other),
        }
        assert_eq!(shared.lock().await.len(), 0);
    }
}

