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
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time;

use ethernetip_connections::epio::{
    decode_frame_raw as decode_epio, encode_frame_raw as encode_epio, Frame,
};
use ethernetip_core::cip::{service, status};
use ethernetip_core::cpf::{item_type, Envelope, Item};
use ethernetip_core::encap::{encode_frame as encode_encap, Command, Header, HEADER_LEN};
use ethernetip_core::error::{EipError, Result};

use crate::crc;
use crate::forward_open::SafetyAppReply;
use crate::frame_codec::{self, DecodedFrame, SafetyDecodeError};
use crate::scanner::IO_UDP_PORT;
use crate::segment::{SafetyNetworkSegment, SEGMENT_TYPE};
use crate::types::{SafetyFormat, UniqueNetworkId};

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
        }
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
    };
    let consumer_task = tokio::spawn(consumer.run(shutdown_rx.clone()));

    // TCOO producer task: keep the scanner's consumer_active latch alive.
    let producer = TcooLoop {
        udp: udp.clone(),
        peer_udp_port: cfg.peer_udp_port,
        tcoo_period_us: cfg.tcoo_period_us,
        tx_tcoo: tx_tcoo.clone(),
        shared: shared.clone(),
    };
    let producer_task = tokio::spawn(producer.run(shutdown_rx.clone()));

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
    shared.lock().await.clear();
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
            envelope.timeout,
            None,
        ));
    }
    let body = &mr[path_end..];

    let mut sockaddr_reply_bytes: Option<Vec<u8>> = None;
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
            connection_open.store(false, Ordering::Relaxed);
            shared.lock().await.clear();
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
        other => (other | service::REPLY_FLAG, status::SERVICE_NOT_SUPPORTED, Vec::new()),
    };

    Ok(build_reply_envelope(
        reply_service,
        reply_status,
        &reply_body,
        envelope.timeout,
        sockaddr_reply_bytes,
    ))
}

fn build_reply_envelope(
    service: u8,
    status: u8,
    body: &[u8],
    timeout: u16,
    sockaddr_o_to_t: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut mr_reply = Vec::with_capacity(4 + body.len());
    mr_reply.push(service);
    mr_reply.push(0);
    mr_reply.push(status);
    mr_reply.push(0);
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
    // Accept whichever format the scanner picked; per-connection state
    // records it so the consumer decodes each frame with the right CRC
    // family (Base = S1/S3, Extended = S5 with rollover-folded seeds).
    let format = if safety_seg.format == 0x02 {
        SafetyFormat::Extended
    } else {
        SafetyFormat::Base
    };
    let _ = cfg.format; // format on cfg becomes the receive buffer's expected shape only.

    // We advertise a made-up target connection serial (safety validator
    // instance id) and echo it back in the SafetyAppReply. The scanner uses
    // this to seed CRCs for the T→O direction (which we don't produce beyond
    // TCOO right now, so the scanner's client-side seeds are unused).
    let target_connection_serial: u16 = 1;

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
    // App reply — 5 words (10 bytes) for base format.
    reply.push(5);
    reply.push(0);
    // SafetyAppReply:
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
        rollover_count: 0,
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

        let (seeds, conn_format) = {
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

        let result = frame_codec::decode(
            &frame.data,
            data_len,
            conn_format,
            seeds.0,
            seeds.1,
            seeds.2,
            rollover_now,
        );

        match result {
            Ok(DecodedFrame { actual_data, mode, .. }) => {
                let ping = (mode.0 & 0x03) as u16;
                {
                    let mut guard = self.shared.lock().await;
                    if let Some(conn) = guard.get_mut(&frame.connection_id) {
                        conn.last_ping = ping;
                    }
                }
                self.rx_valid.fetch_add(1, Ordering::Relaxed);
                let mut w = self.input_data.lock().await;
                let n = actual_data.len().min(w.len());
                w[..n].copy_from_slice(&actual_data[..n]);
            }
            Err(err) => {
                if !matches!(err, SafetyDecodeError::TooShort { .. }) {
                    self.rx_crc_fail.fetch_add(1, Ordering::Relaxed);
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
                    let rows: Vec<(u32, SocketAddr, u16, u32, SafetyFormat, u8)> = {
                        let guard = self.shared.lock().await;
                        guard.values().map(|conn| (
                            conn.t_to_o_conn_id,
                            conn.peer_udp,
                            conn.cid_seed_s3,
                            conn.cid_seed_s5,
                            conn.format,
                            (conn.last_ping & 0x03) as u8,
                        )).collect()
                    };
                    for (conn_id, peer, cid_seed_s3, cid_seed_s5, format, ping) in rows {
                        let mut buf = [0u8; 8];
                        let consumer_time_value = 0u16; // TODO: derive from monotonic clock
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
                        }
                    }
                }
            }
        }
    }
}

