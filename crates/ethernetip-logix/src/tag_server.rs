//! Server side of the Logix tag protocol.
//!
//! Binds a TCP port, accepts encapsulated request/reply, and answers
//! `Read_Tag`, `Write_Tag`, `Read_Tag_Fragmented`,
//! `Get_Instance_Attribute_List`, `Forward_Open` / `Large_Forward_Open`,
//! `Forward_Close`, `ListIdentity`, `ListServices`, and connected explicit
//! messaging (`SendUnitData`) against a shared [`TagRegistry`]. Requests
//! wrapped in `Unconnected_Send` are unwrapped so scanners that always
//! prepend a routing envelope still work.
//!
//! The encap-level `ListIdentity` (0x0063) handler is what unblocks
//! pycomm3's `LogixDriver.__enter__`: pycomm3 sends it immediately after
//! `RegisterSession` to classify the target as Micro800 vs. ControlLogix,
//! and refuses to proceed without a reply. `Forward_Open` + `SendUnitData`
//! are what let pycomm3 route tag reads over an explicit Class 3 CIP
//! connection the way it does against a real Logix controller.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use ethernetip_core::cip::{class_codes as class, service_codes as service, status};
use ethernetip_core::cpf::{item_type, Envelope, Item};
use ethernetip_core::device::IdentityInfo;
use ethernetip_core::encap::{encode_frame as encode_encap, Command, Header, HEADER_LEN};
use ethernetip_core::error::{EipError, Result};
use ethernetip_core::path_parse::{parse_epath, PathSegment};

use crate::tag_registry::{TagEntry, TagRegistry};
use crate::types::{CipType, SHORT_STRING_STORAGE_SIZE};
use crate::walker::{walk, WalkResult};

/// Configuration for [`start`].
#[derive(Debug, Clone)]
pub struct TagServerConfig {
    pub tcp_bind: SocketAddr,
    pub registry: TagRegistry,
    /// Identity returned on `ListIdentity` (encap 0x63) and on
    /// `Get_Attributes_All` to the Identity object. pycomm3 inspects the
    /// product name to pick its Logix vs. Micro800 code path.
    pub identity: IdentityInfo,
}

impl TagServerConfig {
    pub fn new(registry: TagRegistry) -> Self {
        Self {
            tcp_bind: SocketAddr::from(([0, 0, 0, 0], 44818)),
            registry,
            identity: default_identity(),
        }
    }

    pub fn tcp_bind(mut self, addr: SocketAddr) -> Self {
        self.tcp_bind = addr;
        self
    }

    pub fn identity(mut self, identity: IdentityInfo) -> Self {
        self.identity = identity;
        self
    }
}

/// Default identity used when the host didn't set one. Serial / product
/// name match no real device on purpose — keeps the server identifiable
/// in wireshark but doesn't impersonate a specific Rockwell SKU.
fn default_identity() -> IdentityInfo {
    IdentityInfo {
        vendor_id: 0x0001,
        device_type: 0x000E, // Programmable Logic Controller
        product_code: 65,
        major_revision: 20,
        minor_revision: 11,
        status: 0x0030,
        serial_number: 0x1234_5678,
        product_name: "EthernetIPRust-TagServer".into(),
    }
}

/// Handle to a running tag server.
pub struct TagServerHandle {
    pub tcp_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl TagServerHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
    }
}

/// Bind and start serving.
pub async fn start(cfg: TagServerConfig) -> Result<TagServerHandle> {
    let tcp = TcpListener::bind(cfg.tcp_bind).await?;
    let tcp_addr = tcp.local_addr()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let registry = cfg.registry;
    let identity = Arc::new(cfg.identity);
    let task = tokio::spawn(async move {
        let mut shutdown_rx = shutdown_rx;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                accept = tcp.accept() => {
                    match accept {
                        Ok((stream, peer)) => {
                            let registry = registry.clone();
                            let identity = identity.clone();
                            let local = tcp_addr;
                            tokio::spawn(async move {
                                if let Err(err) = handle_session(stream, peer, local, registry, identity).await {
                                    tracing::debug!("session ended: {err}");
                                }
                            });
                        }
                        Err(err) => tracing::warn!("accept error: {err}"),
                    }
                }
            }
        }
    });
    Ok(TagServerHandle {
        tcp_addr,
        shutdown_tx,
        task,
    })
}

/// Per-TCP-session state. One Class 3 explicit-messaging connection at a
/// time is enough for pycomm3, libplctag, and our own client — if a second
/// `Forward_Open` arrives we overwrite the slot (and emit a trace), which
/// mirrors what the Python port does.
#[derive(Debug, Default)]
struct SessionConn {
    /// Target-assigned Originator→Target connection ID. The originator uses
    /// this value in the Connected Address CPF item on every subsequent
    /// `SendUnitData` request. Kept for future validation (reject frames
    /// whose address item doesn't match this id).
    #[allow(dead_code)]
    ot_id: u32,
    /// Originator-assigned Target→Originator connection ID. We stamp this
    /// into the Connected Address CPF item on every reply so the originator
    /// can route it to the right handler.
    to_id: u32,
}

async fn handle_session(
    mut stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    registry: TagRegistry,
    identity: Arc<IdentityInfo>,
) -> Result<()> {
    let session_handle = derive_session_handle(peer);
    let mut header_buf = [0u8; HEADER_LEN];
    let mut conn: Option<SessionConn> = None;
    loop {
        stream.read_exact(&mut header_buf).await?;
        let header = Header::parse(&header_buf)?;
        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 {
            stream.read_exact(&mut payload).await?;
        }
        match header.command {
            x if x == Command::ListIdentity.as_u16() => {
                // ListIdentity (0x63) carries no request payload. Reply has
                // session_handle=0 per CIP Vol. 2 Table 2-4.4. pycomm3's
                // LogixDriver.__enter__ sends this on every TCP connect to
                // decide between Logix and Micro800 code paths.
                let body = build_list_identity_body(local, &identity);
                let frame = encode_encap(Command::ListIdentity, 0, header.sender_context, &body);
                stream.write_all(&frame).await?;
            }
            x if x == Command::ListServices.as_u16() => {
                let body = build_list_services_body();
                let frame = encode_encap(Command::ListServices, 0, header.sender_context, &body);
                stream.write_all(&frame).await?;
            }
            x if x == Command::RegisterSession.as_u16() => {
                let reply = [0x01, 0x00, 0x00, 0x00];
                write_reply(
                    &mut stream,
                    Command::RegisterSession,
                    session_handle,
                    header.sender_context,
                    &reply,
                )
                .await?;
            }
            x if x == Command::UnRegisterSession.as_u16() => return Ok(()),
            x if x == Command::SendRRData.as_u16() => {
                handle_send_rr_data(
                    &mut stream,
                    &header,
                    &payload,
                    &registry,
                    &identity,
                    &mut conn,
                )
                .await?;
            }
            x if x == Command::SendUnitData.as_u16() => {
                handle_send_unit_data(
                    &mut stream,
                    &header,
                    &payload,
                    &registry,
                    &identity,
                    &conn,
                )
                .await?;
            }
            other => {
                tracing::debug!("unhandled command 0x{:04X}", other);
                return Ok(());
            }
        }
    }
}

/// Build the CPF-wrapped ListIdentity (0x63) reply body.
///
/// Wire shape per CIP Vol. 2 §2-4.3:
///   `[item_count=1][type=0x000C][len:UINT][payload]`
///
/// Payload:
///   `encap_protocol_version:UINT`
/// + `sin_family:INT_BE` + `sin_port:UINT_BE` + `sin_addr:4 BE` + `sin_zero:8`
/// + `vendor:UINT` + `device_type:UINT` + `product_code:UINT`
/// + `major_rev:USINT` + `minor_rev:USINT`
/// + `status:WORD` + `serial:UDINT`
/// + `product_name:SHORT_STRING`
/// + `state:USINT` (0xFF = "unknown but running" — matches the sibling ports)
fn build_list_identity_body(local: SocketAddr, identity: &IdentityInfo) -> Vec<u8> {
    let mut item = Vec::with_capacity(64);
    // Encapsulation protocol version
    item.extend_from_slice(&1u16.to_le_bytes());
    // Socket address (big-endian: sin_family + sin_port + sin_addr + 8-byte zero)
    item.extend_from_slice(&2i16.to_be_bytes());
    item.extend_from_slice(&local.port().to_be_bytes());
    let ip_bytes: [u8; 4] = match local {
        SocketAddr::V4(v4) => v4.ip().octets(),
        SocketAddr::V6(_) => [0; 4],
    };
    item.extend_from_slice(&ip_bytes);
    item.extend_from_slice(&[0u8; 8]);
    // Identity attributes
    item.extend_from_slice(&identity.vendor_id.to_le_bytes());
    item.extend_from_slice(&identity.device_type.to_le_bytes());
    item.extend_from_slice(&identity.product_code.to_le_bytes());
    item.push(identity.major_revision);
    item.push(identity.minor_revision);
    item.extend_from_slice(&identity.status.to_le_bytes());
    item.extend_from_slice(&identity.serial_number.to_le_bytes());
    let name_bytes = identity.product_name.as_bytes();
    let name_len = name_bytes.len().min(0xFF) as u8;
    item.push(name_len);
    item.extend_from_slice(&name_bytes[..name_len as usize]);
    item.push(0xFF); // state

    let mut body = Vec::with_capacity(4 + item.len());
    body.extend_from_slice(&1u16.to_le_bytes()); // item count
    body.extend_from_slice(&0x000Cu16.to_le_bytes()); // CPF item type: CIP Identity
    body.extend_from_slice(&(item.len() as u16).to_le_bytes());
    body.extend_from_slice(&item);
    body
}

/// Build the CPF-wrapped ListServices (0x04) reply body. One service entry
/// advertising "Communications" with the Class 0+1 + Class 3 capability
/// bits set (0x0120 == supports both CIP-over-UDP I/O and encapsulation
/// over TCP), which is the shape every Rockwell device returns.
fn build_list_services_body() -> Vec<u8> {
    let mut item = Vec::with_capacity(20);
    item.extend_from_slice(&1u16.to_le_bytes()); // version
    item.extend_from_slice(&0x0120u16.to_le_bytes()); // capability bitfield
    let mut name = [0u8; 16];
    let src = b"Communications";
    name[..src.len()].copy_from_slice(src);
    item.extend_from_slice(&name);

    let mut body = Vec::with_capacity(4 + item.len());
    body.extend_from_slice(&1u16.to_le_bytes()); // item count
    body.extend_from_slice(&0x0100u16.to_le_bytes()); // CPF item type: ListServices response
    body.extend_from_slice(&(item.len() as u16).to_le_bytes());
    body.extend_from_slice(&item);
    body
}

fn derive_session_handle(peer: SocketAddr) -> u32 {
    // Any non-zero value works; deriving it from the peer port keeps handles
    // distinguishable in wireshark.
    let mut h = 0x0100_0000u32 ^ (peer.port() as u32).wrapping_mul(0x9E37_79B9);
    if h == 0 {
        h = 1;
    }
    h
}

async fn write_reply(
    stream: &mut TcpStream,
    command: Command,
    session_handle: u32,
    sender_context: [u8; 8],
    payload: &[u8],
) -> Result<()> {
    let frame = encode_encap(command, session_handle, sender_context, payload);
    stream.write_all(&frame).await?;
    Ok(())
}

async fn handle_send_rr_data(
    stream: &mut TcpStream,
    header: &Header,
    payload: &[u8],
    registry: &TagRegistry,
    identity: &IdentityInfo,
    conn: &mut Option<SessionConn>,
) -> Result<()> {
    let envelope = Envelope::parse(payload)?;
    let mr_item = envelope
        .find(item_type::UNCONNECTED_DATA)
        .ok_or_else(|| EipError::Protocol("SendRRData missing UnconnectedData item".into()))?;
    // Unwrap Unconnected_Send if present (service 0x52 to Connection Manager).
    let inner = maybe_unwrap_unconnected_send(&mr_item.data).unwrap_or_else(|| mr_item.data.clone());
    let mr_reply = dispatch_mr(&inner, registry, identity, conn, header.session_handle);

    let items = [
        Item::null_address(),
        Item::new(item_type::UNCONNECTED_DATA, mr_reply),
    ];
    let body = ethernetip_core::cpf::encode_envelope(0, envelope.timeout, &items);
    write_reply(
        stream,
        Command::SendRRData,
        header.session_handle,
        header.sender_context,
        &body,
    )
    .await
}

/// `SendUnitData` (encap 0x70) — the Class 3 connected-explicit frame
/// pycomm3 uses for every tag read/write after `Forward_Open` succeeds.
///
/// Wire shape: CPF with `Connected Address` item (type 0xA1, 4-byte O→T
/// connection id) + `Connected Data` item (type 0xB1, 2-byte sequence +
/// MR request). The reply replaces the connection id with the T→O id the
/// originator chose in `Forward_Open` so it can route the response.
///
/// If no `Forward_Open` has been seen yet, drop the frame — the sibling
/// ports reply with `INVALID_SESSION_HANDLE`, but pycomm3 only pulls this
/// code path after a successful `Forward_Open` so it never trips.
async fn handle_send_unit_data(
    stream: &mut TcpStream,
    header: &Header,
    payload: &[u8],
    registry: &TagRegistry,
    identity: &IdentityInfo,
    conn: &Option<SessionConn>,
) -> Result<()> {
    let envelope = Envelope::parse(payload)?;
    let data_item = envelope
        .find(item_type::CONNECTED_DATA)
        .ok_or_else(|| EipError::Protocol("SendUnitData missing ConnectedData item".into()))?;
    if data_item.data.len() < 2 {
        return Err(EipError::Protocol("SendUnitData ConnectedData < 2 bytes".into()));
    }
    let seq = u16::from_le_bytes([data_item.data[0], data_item.data[1]]);
    let mr = &data_item.data[2..];
    // Connected MR dispatch — same path as unconnected except FwdOpen/Close
    // are not valid here (pycomm3 never sends them on a connected channel).
    // We still accept the whole dispatch_mr surface so Multiple_Service_Packet
    // and other inline services keep working.
    let mut local_conn: Option<SessionConn> = None;
    let mr_reply = dispatch_mr(mr, registry, identity, &mut local_conn, header.session_handle);

    let reply_cid = conn.as_ref().map(|c| c.to_id).unwrap_or(0);
    let mut data = Vec::with_capacity(2 + mr_reply.len());
    data.extend_from_slice(&seq.to_le_bytes());
    data.extend_from_slice(&mr_reply);

    let items = [
        Item::new(
            item_type::CONNECTED_ADDRESS,
            reply_cid.to_le_bytes().to_vec(),
        ),
        Item::new(item_type::CONNECTED_DATA, data),
    ];
    let body = ethernetip_core::cpf::encode_envelope(0, envelope.timeout, &items);
    write_reply(
        stream,
        Command::SendUnitData,
        header.session_handle,
        header.sender_context,
        &body,
    )
    .await
}

/// If the outer MR is an `Unconnected_Send` addressed to the Connection
/// Manager, return the embedded message; otherwise `None`.
///
/// Note: service code 0x52 is shared between `Unconnected_Send` and
/// `Read_Tag_Fragmented`.  Disambiguation requires the Connection-Manager
/// path check: a UCMM request always addresses `Class 0x06, Instance 1`,
/// while `Read_Tag_Fragmented` addresses a Logix tag by symbolic name or
/// Symbol Object instance (`Class 0x6B`). Without this check, a
/// fragmented read with a well-formed path looked like a malformed UCMM
/// and the heuristic unwrap returned a bogus "inner message", which the
/// dispatcher then rejected with `PATH_SEGMENT_ERROR`.
fn maybe_unwrap_unconnected_send(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 4 {
        return None;
    }
    if bytes[0] != service::UNCONNECTED_SEND {
        return None;
    }
    // The UCMM path addresses the Connection Manager: Class 0x06 Instance 1.
    // Encoded as [0x20 0x06 0x24 0x01]. If the first logical class segment is
    // anything else (e.g. Class 0x6B Symbol Object for Read_Tag_Fragmented),
    // this is a different 0x52 service and must not be unwrapped.
    if bytes[2] != 0x20 || bytes[3] != class::CONNECTION_MANAGER as u8 {
        return None;
    }
    let path_words = bytes[1] as usize;
    let path_end = 2 + path_words * 2;
    if bytes.len() < path_end + 4 {
        return None;
    }
    // Skip priority/tick + timeout + embedded_size(u16).
    let msg_size = u16::from_le_bytes([bytes[path_end + 2], bytes[path_end + 3]]) as usize;
    let msg_start = path_end + 4;
    let msg_end = msg_start + msg_size;
    if bytes.len() < msg_end {
        return None;
    }
    Some(bytes[msg_start..msg_end].to_vec())
}

/// Dispatch a fully-unwrapped MR request against the registry and return the
/// serialized MR reply bytes.
fn dispatch_mr(
    mr: &[u8],
    registry: &TagRegistry,
    identity: &IdentityInfo,
    conn: &mut Option<SessionConn>,
    session_handle: u32,
) -> Vec<u8> {
    let (service_code, path, body) = match split_mr(mr) {
        Some(x) => x,
        None => return build_mr_reply(0x00 | service::REPLY_FLAG, status::PATH_SEGMENT_ERROR, &[]),
    };
    match service_code {
        s if s == service::READ_TAG => handle_read_tag(&path, &body, registry),
        s if s == service::READ_TAG_FRAGMENTED => {
            handle_read_tag_fragmented(&path, &body, registry)
        }
        s if s == service::WRITE_TAG => handle_write_tag(&path, &body, registry),
        s if s == service::WRITE_TAG_FRAGMENTED => {
            handle_write_tag_fragmented(&path, &body, registry)
        }
        s if s == service::GET_INSTANCE_ATTRIBUTE_LIST => {
            handle_get_instance_attribute_list(&path, &body, registry)
        }
        s if s == service::FORWARD_OPEN => {
            handle_forward_open(&path, &body, conn, session_handle, false)
        }
        s if s == service::LARGE_FORWARD_OPEN => {
            handle_forward_open(&path, &body, conn, session_handle, true)
        }
        s if s == service::FORWARD_CLOSE => handle_forward_close(&path, &body, conn),
        s if s == GET_ATTRIBUTES_ALL => handle_get_attributes_all(&path, identity),
        s if s == GET_ATTRIBUTE_SINGLE => handle_get_attribute_single(&path, identity),
        s if s == MULTIPLE_SERVICE_PACKET => {
            handle_multiple_service_packet(&path, &body, registry, identity, conn, session_handle)
        }
        other => build_mr_reply(other | service::REPLY_FLAG, status::SERVICE_NOT_SUPPORTED, &[]),
    }
}

const GET_ATTRIBUTES_ALL: u8 = 0x01;
const GET_ATTRIBUTE_SINGLE: u8 = 0x0E;

/// `Get_Attributes_All` on class 0x01 Identity returns the standard
/// `ModuleIdentityObject` block pycomm3 decodes in `get_plc_info`. On
/// class 0x64 Program Name it returns a CIP STRING with the program name,
/// which pycomm3 reads in `get_plc_name` whenever the target isn't a
/// Micro800 (Rockwell KB 23341).
fn handle_get_attributes_all(path: &[u8], identity: &IdentityInfo) -> Vec<u8> {
    let reply_svc = GET_ATTRIBUTES_ALL | service::REPLY_FLAG;
    let Some(class_id) = read_class_id(path) else {
        return build_mr_reply(reply_svc, status::PATH_SEGMENT_ERROR, &[]);
    };
    match class_id {
        class::IDENTITY => {
            let body = identity_get_attrs_all_body(identity);
            build_mr_reply(reply_svc, status::SUCCESS, &body)
        }
        0x64 => {
            // Program Name: single attribute, CIP STRING (UINT length + ASCII).
            let name = identity.product_name.as_bytes();
            let mut body = Vec::with_capacity(2 + name.len());
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(name);
            build_mr_reply(reply_svc, status::SUCCESS, &body)
        }
        _ => build_mr_reply(reply_svc, status::OBJECT_DOES_NOT_EXIST, &[]),
    }
}

/// `Get_Attribute_Single` on class 0x01. Only the few attributes pycomm3
/// reads directly are implemented; the rest fall through to
/// `ATTRIBUTE_NOT_SUPPORTED` so a browser that probes the whole table
/// doesn't take down the session.
fn handle_get_attribute_single(path: &[u8], identity: &IdentityInfo) -> Vec<u8> {
    let reply_svc = GET_ATTRIBUTE_SINGLE | service::REPLY_FLAG;
    let Some(class_id) = read_class_id(path) else {
        return build_mr_reply(reply_svc, status::PATH_SEGMENT_ERROR, &[]);
    };
    let attr_id = read_attribute_id(path);
    match (class_id, attr_id) {
        (class::IDENTITY, Some(1)) => build_mr_reply(
            reply_svc,
            status::SUCCESS,
            &identity.vendor_id.to_le_bytes(),
        ),
        (class::IDENTITY, Some(2)) => build_mr_reply(
            reply_svc,
            status::SUCCESS,
            &identity.device_type.to_le_bytes(),
        ),
        (class::IDENTITY, Some(3)) => build_mr_reply(
            reply_svc,
            status::SUCCESS,
            &identity.product_code.to_le_bytes(),
        ),
        (class::IDENTITY, Some(4)) => build_mr_reply(
            reply_svc,
            status::SUCCESS,
            &[identity.major_revision, identity.minor_revision],
        ),
        (class::IDENTITY, Some(5)) => build_mr_reply(
            reply_svc,
            status::SUCCESS,
            &identity.status.to_le_bytes(),
        ),
        (class::IDENTITY, Some(6)) => build_mr_reply(
            reply_svc,
            status::SUCCESS,
            &identity.serial_number.to_le_bytes(),
        ),
        (class::IDENTITY, Some(7)) => {
            let name = identity.product_name.as_bytes();
            let mut body = Vec::with_capacity(1 + name.len());
            body.push(name.len().min(0xFF) as u8);
            body.extend_from_slice(&name[..name.len().min(0xFF)]);
            build_mr_reply(reply_svc, status::SUCCESS, &body)
        }
        _ => build_mr_reply(reply_svc, status::ATTRIBUTE_NOT_SUPPORTED, &[]),
    }
}

fn identity_get_attrs_all_body(identity: &IdentityInfo) -> Vec<u8> {
    let name = identity.product_name.as_bytes();
    let name_len = name.len().min(0xFF);
    let mut out = Vec::with_capacity(15 + name_len);
    out.extend_from_slice(&identity.vendor_id.to_le_bytes());
    out.extend_from_slice(&identity.device_type.to_le_bytes());
    out.extend_from_slice(&identity.product_code.to_le_bytes());
    out.push(identity.major_revision);
    out.push(identity.minor_revision);
    out.extend_from_slice(&identity.status.to_le_bytes());
    out.extend_from_slice(&identity.serial_number.to_le_bytes());
    out.push(name_len as u8);
    out.extend_from_slice(&name[..name_len]);
    out
}

/// Read the class id from the leading 8-bit (0x20) or 16-bit (0x21) class
/// segment. Attribute path probes come through with the exact same prefix
/// so this is enough for both.
fn read_class_id(path: &[u8]) -> Option<u16> {
    if path.len() < 2 {
        return None;
    }
    match path[0] {
        0x20 => Some(path[1] as u16),
        0x21 if path.len() >= 4 => Some(u16::from_le_bytes([path[2], path[3]])),
        _ => None,
    }
}

/// Read the attribute id from a path, if a `30 <id>` or `31 <0> <id:u16>`
/// attribute segment is present. The attribute segment is always last on
/// `Get_Attribute_Single` paths.
fn read_attribute_id(path: &[u8]) -> Option<u16> {
    // Find the final `30`/`31` segment.
    let mut i = 0;
    let mut last: Option<u16> = None;
    while i < path.len() {
        match path[i] {
            0x20 | 0x24 | 0x28 | 0x2C | 0x30 => {
                if i + 2 > path.len() {
                    return last;
                }
                if path[i] == 0x30 {
                    last = Some(path[i + 1] as u16);
                }
                i += 2;
            }
            0x21 | 0x25 | 0x29 | 0x2D | 0x31 => {
                if i + 4 > path.len() {
                    return last;
                }
                if path[i] == 0x31 {
                    last = Some(u16::from_le_bytes([path[i + 2], path[i + 3]]));
                }
                i += 4;
            }
            _ => return last,
        }
    }
    last
}

/// CIP Multiple_Service_Packet (0x0A). Each sub-service is dispatched
/// through `dispatch_mr` recursively so Logix tag reads, FwdOpen replies,
/// and the Symbol Object browse all compose naturally.
const MULTIPLE_SERVICE_PACKET: u8 = 0x0A;

fn handle_multiple_service_packet(
    path: &[u8],
    body: &[u8],
    registry: &TagRegistry,
    identity: &IdentityInfo,
    conn: &mut Option<SessionConn>,
    session_handle: u32,
) -> Vec<u8> {
    let reply_svc = MULTIPLE_SERVICE_PACKET | service::REPLY_FLAG;
    // Must address Message Router (class 2 instance 1). Any other target is
    // a client bug — Logix rejects with PATH_SEGMENT_ERROR.
    if path.len() < 4 || path[0] != 0x20 || path[1] != class::MESSAGE_ROUTER as u8 {
        return build_mr_reply(reply_svc, status::PATH_SEGMENT_ERROR, &[]);
    }
    if body.len() < 2 {
        return build_mr_reply(reply_svc, status::NOT_ENOUGH_DATA, &[]);
    }
    let n = u16::from_le_bytes([body[0], body[1]]) as usize;
    let needed = 2 + 2 * n;
    if body.len() < needed {
        return build_mr_reply(reply_svc, status::NOT_ENOUGH_DATA, &[]);
    }
    let mut offsets = Vec::with_capacity(n);
    for i in 0..n {
        let off = u16::from_le_bytes([body[2 + 2 * i], body[2 + 2 * i + 1]]) as usize;
        offsets.push(off);
    }
    let mut sub_replies = Vec::with_capacity(n);
    for i in 0..n {
        let start = offsets[i];
        let end = if i + 1 < n { offsets[i + 1] } else { body.len() };
        if start > body.len() || end > body.len() || start > end {
            return build_mr_reply(reply_svc, status::NOT_ENOUGH_DATA, &[]);
        }
        let sub = &body[start..end];
        let r = dispatch_mr(sub, registry, identity, conn, session_handle);
        sub_replies.push(r);
    }
    // Encode: [n:UINT][offset_i*n:UINT][sub_replies concatenated]. Offsets
    // are relative to the start of this body.
    let header_len = 2 + 2 * n;
    let mut out = Vec::new();
    out.extend_from_slice(&(n as u16).to_le_bytes());
    let mut running = header_len;
    for r in &sub_replies {
        out.extend_from_slice(&(running as u16).to_le_bytes());
        running += r.len();
    }
    for r in &sub_replies {
        out.extend_from_slice(r);
    }
    build_mr_reply(reply_svc, status::SUCCESS, &out)
}

/// Shared handler for `Forward_Open` (0x54) and `Large_Forward_Open` (0x5B).
///
/// Request bodies (connection path lives at the end, preceded by a size
/// byte):
///
///   Standard: `[priority:USINT][tick:USINT][OT_id:UDINT][TO_id:UDINT]`
///             `[conn_serial:UINT][orig_vendor:UINT][orig_serial:UDINT]`
///             `[timeout_mult:USINT][reserved:3][OT_rpi:UDINT]`
///             `[OT_params:UINT][TO_rpi:UDINT][TO_params:UINT]`
///             `[xport_class:USINT][path_size:USINT][padded_epath]`
///
///   Large  : identical but `OT_params`/`TO_params` are UDINT.
///
/// Reply body: `[OT_id:UDINT][TO_id:UDINT][conn_serial:UINT]`
///             `[orig_vendor:UINT][orig_serial:UDINT]`
///             `[OT_api:UDINT][TO_api:UDINT][app_reply_size:USINT][0:USINT]`
///
/// The `OT_id` the target returns is the one pycomm3 pins into every
/// subsequent `SendUnitData` request as the Connected Address.
fn handle_forward_open(
    _path: &[u8],
    body: &[u8],
    conn: &mut Option<SessionConn>,
    session_handle: u32,
    is_large: bool,
) -> Vec<u8> {
    let reply_svc = if is_large {
        service::LARGE_FORWARD_OPEN | service::REPLY_FLAG
    } else {
        service::FORWARD_OPEN | service::REPLY_FLAG
    };
    // 36 bytes of fixed header before the connection path, 40 for large.
    // The actual path bytes aren't needed — any reachable path is accepted
    // for a Class 3 explicit connection; pycomm3 always sends `[20 02 24 01]`
    // (Message Router), real Logix accepts more.
    let min = if is_large { 40 } else { 36 };
    if body.len() < min {
        return build_mr_reply(reply_svc, status::NOT_ENOUGH_DATA, &[]);
    }
    let _priority = body[0];
    let _ticks = body[1];
    let _ot_in = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
    let to_id = u32::from_le_bytes([body[6], body[7], body[8], body[9]]);
    let conn_serial = u16::from_le_bytes([body[10], body[11]]);
    let orig_vendor = u16::from_le_bytes([body[12], body[13]]);
    let orig_serial = u32::from_le_bytes([body[14], body[15], body[16], body[17]]);
    let _timeout_mult = body[18];
    // body[19..22] reserved
    let ot_rpi = u32::from_le_bytes([body[22], body[23], body[24], body[25]]);
    // Skip ot_params (2 or 4 bytes), then read to_rpi.
    let to_rpi_off = if is_large { 30 } else { 28 };
    let to_rpi = u32::from_le_bytes([
        body[to_rpi_off],
        body[to_rpi_off + 1],
        body[to_rpi_off + 2],
        body[to_rpi_off + 3],
    ]);

    // Target-assigned OT. Derive deterministically from the session handle
    // so wireshark can match connections to sessions by inspection — but
    // keep it distinct from the session so pycomm3's post-FwdOpen checks
    // (which compare the CPF address id to _target_cid) actually test the
    // field.
    let ot_id = 0x8000_0000 | session_handle.wrapping_add(1);
    *conn = Some(SessionConn { ot_id, to_id });

    let mut out = Vec::with_capacity(26);
    out.extend_from_slice(&ot_id.to_le_bytes());
    out.extend_from_slice(&to_id.to_le_bytes());
    out.extend_from_slice(&conn_serial.to_le_bytes());
    out.extend_from_slice(&orig_vendor.to_le_bytes());
    out.extend_from_slice(&orig_serial.to_le_bytes());
    out.extend_from_slice(&ot_rpi.to_le_bytes());
    out.extend_from_slice(&to_rpi.to_le_bytes());
    out.push(0); // app_reply_size (16-bit words of trailing app data)
    out.push(0); // reserved
    build_mr_reply(reply_svc, status::SUCCESS, &out)
}

/// `Forward_Close` (0x4E). Body: `[priority:USINT][tick:USINT]`
/// `[conn_serial:UINT][orig_vendor:UINT][orig_serial:UDINT][path_size]`
/// `[reserved][padded_epath]`.
///
/// We tear down the session's connection slot unconditionally — the Rust
/// server only tracks one Class 3 connection per TCP session anyway — and
/// mirror the request's triad back so the originator can match the reply.
fn handle_forward_close(
    _path: &[u8],
    body: &[u8],
    conn: &mut Option<SessionConn>,
) -> Vec<u8> {
    let reply_svc = service::FORWARD_CLOSE | service::REPLY_FLAG;
    if body.len() < 10 {
        return build_mr_reply(reply_svc, status::NOT_ENOUGH_DATA, &[]);
    }
    let conn_serial = u16::from_le_bytes([body[2], body[3]]);
    let orig_vendor = u16::from_le_bytes([body[4], body[5]]);
    let orig_serial = u32::from_le_bytes([body[6], body[7], body[8], body[9]]);
    *conn = None;
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(&conn_serial.to_le_bytes());
    out.extend_from_slice(&orig_vendor.to_le_bytes());
    out.extend_from_slice(&orig_serial.to_le_bytes());
    out.push(0); // app_reply_size
    out.push(0); // reserved
    build_mr_reply(reply_svc, status::SUCCESS, &out)
}

fn split_mr(bytes: &[u8]) -> Option<(u8, Vec<u8>, Vec<u8>)> {
    if bytes.len() < 2 {
        return None;
    }
    let service_code = bytes[0];
    let path_words = bytes[1] as usize;
    let path_end = 2 + path_words * 2;
    if bytes.len() < path_end {
        return None;
    }
    Some((
        service_code,
        bytes[2..path_end].to_vec(),
        bytes[path_end..].to_vec(),
    ))
}

/// Build an MR reply carrying an extended-status word (two bytes after the
/// one-byte general status). Used for the Logix-specific `0xFF / 0x2107`
/// family where the general status says "general error" and the extended
/// status disambiguates. Mirrors the shape C#, C++, and Python emit for
/// tag_type mismatches so cross-port tests can assert the exact bytes.
fn build_mr_reply_ext(service_code: u8, status: u8, ext_status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + body.len());
    out.push(service_code);
    out.push(0);
    out.push(status);
    out.push(1); // additional_size = 1 word (the ext_status that follows)
    out.extend_from_slice(&ext_status.to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn build_mr_reply(service_code: u8, status: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(service_code);
    out.push(0);
    out.push(status);
    out.push(0);
    out.extend_from_slice(body);
    out
}

/// Segment-based path resolution.  Returns the root tag plus a walker result
/// covering any post-root member/element/BOOL-bit segments.  Also handles
/// the Program:<name> prefix by looking up the program scope and resolving
/// the next symbolic segment against its tag table.
enum ResolvedPath {
    /// Controller-scope tag with optional walker result (None → whole tag).
    Controller(TagEntry, Option<WalkResult>),
    /// Program-scope tag: (program_name, tag_entry, optional walker result).
    Program(String, TagEntry, Option<WalkResult>),
}

fn resolve_tag_path(path: &[u8], registry: &TagRegistry) -> Option<ResolvedPath> {
    let (segments, _) = parse_epath(path).ok()?;
    // Try instance-form shortcut when the path leads with Class(0x6B) +
    // Instance(N). Any trailing segments (Element + Symbolic chains for
    // member drilling) are then handed to the walker so paths like
    // `MotorArr[1].Speed` and `MotorA.Fault` resolve the same way they do
    // off a symbolic root. pycomm3 always sends the instance form once
    // init_tags populates its tag cache.
    if segments.len() >= 2 {
        if let (
            PathSegment::Logical { kind: k1, value: v1 },
            PathSegment::Logical { kind: k2, value: v2 },
        ) = (&segments[0], &segments[1])
        {
            use ethernetip_core::path_parse::LogicalKind;
            if matches!(k1, LogicalKind::ClassId)
                && *v1 == class::SYMBOL_OBJECT as u32
                && matches!(k2, LogicalKind::InstanceId)
            {
                let entry = registry.get_by_instance(*v2)?;
                let post: Vec<PathSegment> =
                    segments.iter().skip(2).cloned().collect();
                if post.is_empty() {
                    return Some(ResolvedPath::Controller(entry, None));
                }
                let w = walk(&entry, &post, registry).ok()?;
                return Some(ResolvedPath::Controller(entry, Some(w)));
            }
        }
    }
    let first_sym_idx = segments.iter().position(|s| matches!(s, PathSegment::Symbolic(_)))?;
    let PathSegment::Symbolic(first_name) = &segments[first_sym_idx] else {
        return None;
    };

    if let Some(program_tail) = first_name.strip_prefix("Program:") {
        // Program-scope: next symbolic segment is the tag root inside the program.
        let root_sym_idx = segments
            .iter()
            .enumerate()
            .skip(first_sym_idx + 1)
            .find_map(|(i, s)| matches!(s, PathSegment::Symbolic(_)).then_some(i))?;
        let PathSegment::Symbolic(root_name) = &segments[root_sym_idx] else {
            return None;
        };
        let entry = registry.get_program_tag(program_tail, root_name)?;
        let post: Vec<PathSegment> = segments
            .iter()
            .skip(root_sym_idx + 1)
            .filter(|s| !matches!(s, PathSegment::Logical { .. }))
            .cloned()
            .collect();
        if post.is_empty() {
            return Some(ResolvedPath::Program(program_tail.to_string(), entry, None));
        }
        let w = walk(&entry, &post, registry).ok()?;
        return Some(ResolvedPath::Program(program_tail.to_string(), entry, Some(w)));
    }

    let entry = registry.get_by_name(first_name)?;
    let post: Vec<PathSegment> = segments
        .iter()
        .skip(first_sym_idx + 1)
        .filter(|s| !matches!(s, PathSegment::Logical { .. }))
        .cloned()
        .collect();
    if post.is_empty() {
        Some(ResolvedPath::Controller(entry, None))
    } else {
        let w = walk(&entry, &post, registry).ok()?;
        Some(ResolvedPath::Controller(entry, Some(w)))
    }
}

fn handle_read_tag(path: &[u8], body: &[u8], registry: &TagRegistry) -> Vec<u8> {
    if body.len() < 2 {
        return build_mr_reply(
            service::READ_TAG | service::REPLY_FLAG,
            status::NOT_ENOUGH_DATA,
            &[],
        );
    }
    let count = u16::from_le_bytes([body[0], body[1]]) as usize;
    let resolved = match resolve_tag_path(path, registry) {
        Some(r) => r,
        None => {
            return build_mr_reply(
                service::READ_TAG | service::REPLY_FLAG,
                status::PATH_DESTINATION_UNKNOWN,
                &[],
            );
        }
    };
    let (entry, walked) = match resolved {
        ResolvedPath::Controller(e, w) => (e, w),
        ResolvedPath::Program(_, e, w) => (e, w),
    };

    // Walker path: member drilling, element indexing, BOOL bit access.
    if let Some(w) = walked {
        return build_walker_read_reply(&entry, w, count, registry);
    }

    // Whole-tag / root-level read.
    let mut out = Vec::with_capacity(2 + entry.data.len());
    out.extend_from_slice(&(entry.cip_type as u16).to_le_bytes());
    if entry.cip_type == CipType::Struct {
        // The authoritative structure handle lives on the template; derive
        // from sym_type only as a fallback. Default-registered templates
        // keep structure_handle == 0x8000 | instance_id so the low 12 bits
        // of sym_type and of structure_handle match, but a caller using
        // add_template_prebuilt may install a custom handle (CRC-16, Logix
        // Studio export) and the stored value is what belongs on the wire.
        let handle = entry
            .template_id
            .and_then(|tid| registry.get_template(tid))
            .map(|t| t.structure_handle)
            .unwrap_or(entry.sym_type & 0x0FFF);
        out.extend_from_slice(&handle.to_le_bytes());
        out.extend_from_slice(&entry.data);
    } else {
        let per = entry.atomic_size().unwrap_or(0);
        let take = per * count;
        let want = take.min(entry.data.len());
        out.extend_from_slice(&entry.data[..want]);
    }
    build_mr_reply(service::READ_TAG | service::REPLY_FLAG, status::SUCCESS, &out)
}

fn build_walker_read_reply(
    entry: &TagEntry,
    w: WalkResult,
    count: usize,
    registry: &TagRegistry,
) -> Vec<u8> {
    // BOOL bit read: single-byte 0x01/0x00 reply.
    if let Some(bit) = w.bit_pos {
        let host = entry.data.get(w.offset).copied().unwrap_or(0);
        let value = (host >> bit) & 0x01;
        let mut out = Vec::with_capacity(3);
        out.extend_from_slice(&(CipType::Bool as u16).to_le_bytes());
        out.push(value);
        return build_mr_reply(service::READ_TAG | service::REPLY_FLAG, status::SUCCESS, &out);
    }
    let bytes_to_read = count * w.element_size;
    if w.offset + bytes_to_read > entry.data.len() {
        return build_mr_reply(
            service::READ_TAG | service::REPLY_FLAG,
            status::PATH_DESTINATION_UNKNOWN,
            &[],
        );
    }
    // Struct members land on the wire with the 4-byte prefix
    // [0x02A0][structure_handle]; atomic members keep the 2-byte [type_code].
    // Older code emitted [member.data_type][template_id] which is neither
    // shape libplctag or pycomm3 accept — tracked against C# issue #2.
    let is_struct_member = w.type_code & 0x8000 != 0;
    if is_struct_member {
        // Look the handle up from the walker's recorded template id; falling
        // back to CipType::Struct keeps us Lucifer-safe if the template was
        // garbage-collected between walk and reply, though in practice the
        // registry holds Arc<ServerTemplate> for the lifetime of a request.
        let handle = w
            .template
            .and_then(|tid| registry.get_template(tid))
            .map(|t| t.structure_handle)
            .unwrap_or(w.type_code & 0x0FFF);
        let mut out = Vec::with_capacity(4 + bytes_to_read);
        out.extend_from_slice(&(CipType::Struct as u16).to_le_bytes());
        out.extend_from_slice(&handle.to_le_bytes());
        out.extend_from_slice(&entry.data[w.offset..w.offset + bytes_to_read]);
        return build_mr_reply(service::READ_TAG | service::REPLY_FLAG, status::SUCCESS, &out);
    }
    let mut out = Vec::with_capacity(2 + bytes_to_read);
    out.extend_from_slice(&w.type_code.to_le_bytes());
    out.extend_from_slice(&entry.data[w.offset..w.offset + bytes_to_read]);
    build_mr_reply(service::READ_TAG | service::REPLY_FLAG, status::SUCCESS, &out)
}

fn handle_read_tag_fragmented(path: &[u8], body: &[u8], registry: &TagRegistry) -> Vec<u8> {
    if body.len() < 6 {
        return build_mr_reply(
            service::READ_TAG_FRAGMENTED | service::REPLY_FLAG,
            status::NOT_ENOUGH_DATA,
            &[],
        );
    }
    let _count = u16::from_le_bytes([body[0], body[1]]) as usize;
    let fragment_offset = u32::from_le_bytes([body[2], body[3], body[4], body[5]]) as usize;
    let resolved = match resolve_tag_path(path, registry) {
        Some(r) => r,
        None => {
            return build_mr_reply(
                service::READ_TAG_FRAGMENTED | service::REPLY_FLAG,
                status::PATH_DESTINATION_UNKNOWN,
                &[],
            );
        }
    };

    // The walker (symbolic + Element segments, or the instance-form shortcut
    // for Class 0x6B + Instance + Element) carries the absolute byte offset
    // of the target element. The fragment offset in the request body is
    // relative to that; the atomic Read_Tag path already honors this. Before
    // this fix, Read_Tag_Fragmented was ignoring the walker and reading from
    // byte 0 of the tag.
    let (entry, walked) = match resolved {
        ResolvedPath::Controller(e, w) | ResolvedPath::Program(_, e, w) => (e, w),
    };
    let (base, type_code, is_struct) = match &walked {
        Some(w) => {
            let is_struct = (w.type_code & 0x8000) != 0 || w.type_code == 0x02A0;
            (w.offset, w.type_code, is_struct)
        }
        None => (
            0usize,
            entry.cip_type as u16,
            entry.cip_type == CipType::Struct,
        ),
    };

    let start = base + fragment_offset;
    if start >= entry.data.len() {
        return build_mr_reply(
            service::READ_TAG_FRAGMENTED | service::REPLY_FLAG,
            status::PATH_DESTINATION_UNKNOWN,
            &[],
        );
    }
    // Cap each chunk so a very large struct is naturally paged.
    const CHUNK: usize = 500;
    let end = (start + CHUNK).min(entry.data.len());
    let more = end < entry.data.len();
    let mut out = Vec::with_capacity(4 + (end - start));
    out.extend_from_slice(&type_code.to_le_bytes());
    if is_struct {
        // Prefer the walker's handle (nested struct member) over the tag's
        // own sym_type when both are available.
        let handle = match walked {
            Some(w) => w.type_code & 0x0FFF,
            None => entry.sym_type & 0x0FFF,
        };
        out.extend_from_slice(&handle.to_le_bytes());
    }
    out.extend_from_slice(&entry.data[start..end]);
    let st = if more {
        status::PARTIAL_TRANSFER
    } else {
        status::SUCCESS
    };
    build_mr_reply(service::READ_TAG_FRAGMENTED | service::REPLY_FLAG, st, &out)
}

fn handle_write_tag(path: &[u8], body: &[u8], registry: &TagRegistry) -> Vec<u8> {
    if body.len() < 4 {
        return build_mr_reply(
            service::WRITE_TAG | service::REPLY_FLAG,
            status::NOT_ENOUGH_DATA,
            &[],
        );
    }
    let type_code = u16::from_le_bytes([body[0], body[1]]);

    // Two write shapes land here:
    //   atomic:  [type (UINT)][count (UINT)][data...]
    //   struct:  [type=0x02A0][struct_handle (UINT)][count (UINT)][data...]
    // The struct shape carries an extra UINT between the type marker and the
    // element count. Reading `count` out of the wrong byte offset was the
    // bug the earlier atomic-only path hid.
    const CIP_TYPE_STRUCT_MARKER: u16 = 0x02A0;
    let (client_struct_handle, count, value): (Option<u16>, usize, &[u8]) =
        if type_code == CIP_TYPE_STRUCT_MARKER {
            if body.len() < 6 {
                return build_mr_reply(
                    service::WRITE_TAG | service::REPLY_FLAG,
                    status::NOT_ENOUGH_DATA,
                    &[],
                );
            }
            (
                Some(u16::from_le_bytes([body[2], body[3]])),
                u16::from_le_bytes([body[4], body[5]]) as usize,
                &body[6..],
            )
        } else {
            (
                None,
                u16::from_le_bytes([body[2], body[3]]) as usize,
                &body[4..],
            )
        };

    // pycomm3 writes SHORT_STRING as `[length_byte][chars]` and does NOT pad
    // the fixed 81-byte slot — a write of "hello" is 6 payload bytes, not 81.
    // Our atomic size for SHORT_STRING is 81, so the normal length check
    // would reject the shorter payload with 0x13 (NOT_ENOUGH_DATA).
    // Accept the short form here and pad with zeros so Read_Tag returns the
    // same value back.  Studio 5000 uses this shape on Identity attribute 7
    // (the only place real Logix exposes SHORT_STRING).
    let padded_short_string: Option<Vec<u8>> = if type_code == CipType::ShortString as u16
        && client_struct_handle.is_none()
        && !value.is_empty()
        && value.len() >= 1 + value[0] as usize
    {
        let elem = CipType::ShortString.atomic_size().unwrap_or(SHORT_STRING_STORAGE_SIZE);
        let want = count.max(1) * elem;
        if value.len() < want {
            let mut v = Vec::with_capacity(want);
            v.extend_from_slice(value);
            v.resize(want, 0);
            Some(v)
        } else {
            None
        }
    } else {
        None
    };
    let value: &[u8] = padded_short_string.as_deref().unwrap_or(value);

    let resolved = match resolve_tag_path(path, registry) {
        Some(r) => r,
        None => {
            return build_mr_reply(
                service::WRITE_TAG | service::REPLY_FLAG,
                status::PATH_DESTINATION_UNKNOWN,
                &[],
            );
        }
    };

    // Validate the client-supplied type against the resolved target. Four
    // cases, because the walker-aware path and the whole-tag path both have
    // atomic and struct variants:
    //
    //   walker + atomic member:   type_code must equal w.type_code
    //   walker + struct member:   struct_handle must equal the nested
    //                             template's structure_handle (looked up
    //                             via w.template)
    //   whole-tag + atomic:       type_code must equal entry.cip_type as u16
    //   whole-tag + struct:       struct_handle must equal the root
    //                             template's structure_handle
    //
    // Mismatch returns 0xFF / 0x2107 — the Logix-standard "wrong type for
    // attribute" reply, bytes-identical to the other three ports' servers.
    let lookup_handle = |tid: u16| registry.get_template(tid).map(|t| t.structure_handle);
    let type_check_failed = match &resolved {
        ResolvedPath::Controller(_, Some(w)) | ResolvedPath::Program(_, _, Some(w)) => {
            let member_is_struct = (w.type_code & 0x8000) != 0;
            match (client_struct_handle, member_is_struct) {
                (None, false)  => type_code != w.type_code,
                (Some(h), true) => {
                    let expected = w.template.and_then(lookup_handle)
                        .unwrap_or(w.type_code & 0x0FFF);
                    h != expected
                }
                // Struct marker against an atomic member, or atomic code
                // against a struct member — categorically wrong.
                _ => true,
            }
        }
        ResolvedPath::Controller(e, None) | ResolvedPath::Program(_, e, None) => {
            let tag_is_struct = e.cip_type == CipType::Struct;
            match (client_struct_handle, tag_is_struct) {
                (None, false)  => type_code != e.cip_type as u16,
                (Some(h), true) => {
                    let expected = e.template_id.and_then(lookup_handle)
                        .unwrap_or(e.sym_type & 0x0FFF);
                    h != expected
                }
                _ => true,
            }
        }
    };
    if type_check_failed {
        return build_mr_reply_ext(
            service::WRITE_TAG | service::REPLY_FLAG,
            0xFF,
            0x2107,
            &[],
        );
    }

    // Walker path — write into a specific member/element offset (with BOOL bit
    // handling).  Program-scoped writes also flow through here since both
    // resolutions produce the same walker result.
    match resolved {
        ResolvedPath::Controller(entry, Some(w))
        | ResolvedPath::Program(_, entry, Some(w)) => {
            if let Some(bit) = w.bit_pos {
                if value.is_empty() {
                    return build_mr_reply(
                        service::WRITE_TAG | service::REPLY_FLAG,
                        status::NOT_ENOUGH_DATA,
                        &[],
                    );
                }
                let new = value[0] & 0x01 != 0;
                if registry
                    .atomic_set_bit(entry.instance, w.offset, bit, new)
                    .is_err()
                {
                    return build_mr_reply(
                        service::WRITE_TAG | service::REPLY_FLAG,
                        status::INVALID_ATTRIBUTE_VALUE,
                        &[],
                    );
                }
                return build_mr_reply(service::WRITE_TAG | service::REPLY_FLAG, status::SUCCESS, &[]);
            }
            let bytes_to_write = count.max(1) * w.element_size;
            if value.len() < bytes_to_write {
                return build_mr_reply(
                    service::WRITE_TAG | service::REPLY_FLAG,
                    status::NOT_ENOUGH_DATA,
                    &[],
                );
            }
            if registry
                .set_bytes_at(entry.instance, w.offset, &value[..bytes_to_write])
                .is_err()
            {
                return build_mr_reply(
                    service::WRITE_TAG | service::REPLY_FLAG,
                    status::INVALID_ATTRIBUTE_VALUE,
                    &[],
                );
            }
            build_mr_reply(service::WRITE_TAG | service::REPLY_FLAG, status::SUCCESS, &[])
        }
        ResolvedPath::Controller(entry, None) => {
            write_whole_tag(&entry, value, count, registry)
        }
        ResolvedPath::Program(program, entry, None) => {
            let per = entry.atomic_size().unwrap_or(entry.data.len());
            let take = per * count.max(1);
            if value.len() < take {
                return build_mr_reply(
                    service::WRITE_TAG | service::REPLY_FLAG,
                    status::NOT_ENOUGH_DATA,
                    &[],
                );
            }
            if registry
                .set_program_tag_bytes(&program, &entry.name, 0, &value[..take])
                .is_err()
            {
                return build_mr_reply(
                    service::WRITE_TAG | service::REPLY_FLAG,
                    status::INVALID_ATTRIBUTE_VALUE,
                    &[],
                );
            }
            build_mr_reply(service::WRITE_TAG | service::REPLY_FLAG, status::SUCCESS, &[])
        }
    }
}

/// Write_Tag_Fragmented service (0x53).
///
/// Mirrors the C# port's `TagServices.HandleWriteTagFragmented` byte-for-byte
/// so cross-port tests see identical status codes.  Request body:
///
///   atomic: `[type:UINT][count:UINT][offset:UDINT][payload...]`      (8+N bytes)
///   struct: `[0x02A0][handle:UINT][count:UINT][offset:UDINT][payload]` (10+N bytes)
///
/// The absolute write offset is `walker.offset + offset_in_elements`.  For a
/// walker-aware path (symbolic + Element, or the Class 0x6B + Instance +
/// Element shortcut) `walker.offset` already includes the element-segment
/// contribution — the same shape the fragmented read path uses after the
/// earlier element-segment fix.  Fragmented writes to BOOL members are
/// rejected with 0x08 (service not supported), matching the C# port.
fn handle_write_tag_fragmented(path: &[u8], body: &[u8], registry: &TagRegistry) -> Vec<u8> {
    let reply_svc = service::WRITE_TAG_FRAGMENTED | service::REPLY_FLAG;
    if body.len() < 8 {
        return build_mr_reply(reply_svc, status::NOT_ENOUGH_DATA, &[]);
    }
    let type_code = u16::from_le_bytes([body[0], body[1]]);
    const CIP_TYPE_STRUCT_MARKER: u16 = 0x02A0;

    let (client_struct_handle, count, byte_offset_in_elements, value): (Option<u16>, u16, u32, &[u8]) =
        if type_code == CIP_TYPE_STRUCT_MARKER {
            if body.len() < 10 {
                return build_mr_reply(reply_svc, status::NOT_ENOUGH_DATA, &[]);
            }
            (
                Some(u16::from_le_bytes([body[2], body[3]])),
                u16::from_le_bytes([body[4], body[5]]),
                u32::from_le_bytes([body[6], body[7], body[8], body[9]]),
                &body[10..],
            )
        } else {
            (
                None,
                u16::from_le_bytes([body[2], body[3]]),
                u32::from_le_bytes([body[4], body[5], body[6], body[7]]),
                &body[8..],
            )
        };

    // pycomm3-compat: fragmented SHORT_STRING write at offset 0 arrives as
    // `[length_byte][chars]` with no fixed-slot padding.  Pad to the full
    // 81-byte slot (per count) so the slot ends up zero-tailed.  We only
    // pad for offset 0 — a non-zero offset is an explicit partial write.
    let padded_short_string: Option<Vec<u8>> = if type_code == CipType::ShortString as u16
        && client_struct_handle.is_none()
        && byte_offset_in_elements == 0
        && !value.is_empty()
        && value.len() >= 1 + value[0] as usize
    {
        let elem = CipType::ShortString.atomic_size().unwrap_or(SHORT_STRING_STORAGE_SIZE);
        let want = (count as usize).max(1) * elem;
        if value.len() < want {
            let mut v = Vec::with_capacity(want);
            v.extend_from_slice(value);
            v.resize(want, 0);
            Some(v)
        } else {
            None
        }
    } else {
        None
    };
    let value: &[u8] = padded_short_string.as_deref().unwrap_or(value);

    let resolved = match resolve_tag_path(path, registry) {
        Some(r) => r,
        None => return build_mr_reply(reply_svc, status::PATH_DESTINATION_UNKNOWN, &[]),
    };

    // Type validation — same four-way check as `handle_write_tag`.
    let type_check_failed = match &resolved {
        ResolvedPath::Controller(_, Some(w)) | ResolvedPath::Program(_, _, Some(w)) => {
            let member_is_struct = (w.type_code & 0x8000) != 0;
            match (client_struct_handle, member_is_struct) {
                (None, false) => type_code != w.type_code,
                (Some(h), true) => h != (w.type_code & 0x0FFF),
                _ => true,
            }
        }
        ResolvedPath::Controller(e, None) | ResolvedPath::Program(_, e, None) => {
            let tag_is_struct = e.cip_type == CipType::Struct;
            match (client_struct_handle, tag_is_struct) {
                (None, false) => type_code != e.cip_type as u16,
                (Some(h), true) => h != (e.sym_type & 0x0FFF),
                _ => true,
            }
        }
    };
    if type_check_failed {
        return build_mr_reply_ext(reply_svc, 0xFF, 0x2107, &[]);
    }

    // Resolve base offset and element size for the window check.
    let (base, element_size) = match &resolved {
        ResolvedPath::Controller(_, Some(w)) | ResolvedPath::Program(_, _, Some(w)) => {
            if w.bit_pos.is_some() {
                // Bit writes don't support fragmented transfers (parity with C#).
                return build_mr_reply(reply_svc, status::SERVICE_NOT_SUPPORTED, &[]);
            }
            (w.offset, w.element_size)
        }
        ResolvedPath::Controller(e, None) | ResolvedPath::Program(_, e, None) => {
            (0usize, e.atomic_size().unwrap_or(e.data.len()))
        }
    };

    // 0x2104: payload exceeds the declared element-count window.
    let total_bytes = (count as usize).saturating_mul(element_size);
    let write_len = value.len();
    if (byte_offset_in_elements as usize).saturating_add(write_len) > total_bytes {
        return build_mr_reply_ext(reply_svc, 0xFF, 0x2104, &[]);
    }

    let abs = base.saturating_add(byte_offset_in_elements as usize);

    // 0x2105: absolute offset + payload runs past the tag buffer.
    let buffer_len = match &resolved {
        ResolvedPath::Controller(e, _) | ResolvedPath::Program(_, e, _) => e.data.len(),
    };
    if abs.saturating_add(write_len) > buffer_len {
        return build_mr_reply_ext(reply_svc, 0xFF, 0x2105, &[]);
    }

    // Perform the write.
    let write_result = match &resolved {
        ResolvedPath::Controller(entry, _) => registry.set_bytes_at(entry.instance, abs, value),
        ResolvedPath::Program(program, entry, _) => {
            registry.set_program_tag_bytes(program, &entry.name, abs, value)
        }
    };
    if write_result.is_err() {
        return build_mr_reply(reply_svc, status::INVALID_ATTRIBUTE_VALUE, &[]);
    }
    build_mr_reply(reply_svc, status::SUCCESS, &[])
}

fn write_whole_tag(entry: &TagEntry, value: &[u8], count: usize, registry: &TagRegistry) -> Vec<u8> {
    let per = entry.atomic_size().unwrap_or(entry.data.len());
    let take = per * count.max(1);
    if value.len() < take {
        return build_mr_reply(
            service::WRITE_TAG | service::REPLY_FLAG,
            status::NOT_ENOUGH_DATA,
            &[],
        );
    }
    let mut new_data = entry.data.clone();
    let n = take.min(new_data.len());
    new_data[..n].copy_from_slice(&value[..n]);
    if registry.set_by_name(&entry.name, &new_data).is_err() {
        return build_mr_reply(
            service::WRITE_TAG | service::REPLY_FLAG,
            status::INVALID_ATTRIBUTE_VALUE,
            &[],
        );
    }
    build_mr_reply(service::WRITE_TAG | service::REPLY_FLAG, status::SUCCESS, &[])
}

fn handle_get_instance_attribute_list(
    path: &[u8],
    body_in: &[u8],
    registry: &TagRegistry,
) -> Vec<u8> {
    let reply_svc = service::GET_INSTANCE_ATTRIBUTE_LIST | service::REPLY_FLAG;
    // Path must at least contain the class segment.
    if path.len() < 4 || path[0] != 0x20 || path[1] != class::SYMBOL_OBJECT as u8 {
        return build_mr_reply(reply_svc, status::PATH_SEGMENT_ERROR, &[]);
    }
    let start_instance = match path[2] {
        0x24 => path[3] as u32,
        0x25 if path.len() >= 6 => u16::from_le_bytes([path[4], path[5]]) as u32,
        _ => 0,
    };
    // Parse the attribute-id list from the request body. Logix clients send
    // `[count:UINT][attr_id:UINT * count]`. pycomm3's canonical set is
    // {1, 2, 3, 5, 6, 8, 10}, our own TagClient sends {1, 2}. The response
    // emits each entry's fields in the exact order the client asked for.
    let attr_ids: Vec<u16> = if body_in.len() >= 2 {
        let count = u16::from_le_bytes([body_in[0], body_in[1]]) as usize;
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let off = 2 + 2 * i;
            if off + 2 > body_in.len() {
                break;
            }
            ids.push(u16::from_le_bytes([body_in[off], body_in[off + 1]]));
        }
        ids
    } else {
        // Fall back to the historical pair (name + sym_type) so legacy
        // callers that omit the attribute list keep working.
        vec![1, 2]
    };

    let entries = registry.browse_entries();
    let mut cursor = entries
        .into_iter()
        .filter(|(inst, _, _)| *inst >= start_instance)
        .peekable();

    // Pack as many entries as we can into a bounded response. Each entry
    // starts with the UDINT instance id, then one field per requested
    // attribute. Unknown attribute ids are written as a 4-byte zero so a
    // careless browser doesn't desync the stream.
    const RESPONSE_CAP: usize = 480;
    let mut body = Vec::new();
    let mut wrote_all = true;
    while let Some(&(inst, ref name, sym_type)) = cursor.peek() {
        let entry_len = 4 + attr_ids
            .iter()
            .map(|a| attribute_field_len(*a, name))
            .sum::<usize>();
        if body.len() + entry_len > RESPONSE_CAP {
            wrote_all = false;
            break;
        }
        body.extend_from_slice(&inst.to_le_bytes());
        for &a in &attr_ids {
            append_attribute_field(&mut body, a, name, sym_type);
        }
        cursor.next();
    }
    let st = if wrote_all {
        status::SUCCESS
    } else {
        status::PARTIAL_TRANSFER
    };
    build_mr_reply(reply_svc, st, &body)
}

/// Byte length of one attribute's value in a `Get_Instance_Attribute_List`
/// response. All of pycomm3's canonical attributes are fixed-size except
/// the Symbol Name (attribute 1), which carries a UINT length header.
fn attribute_field_len(attr_id: u16, name: &str) -> usize {
    match attr_id {
        1 => 2 + name.len(), // STRING (UINT len + ASCII)
        2 => 2,              // UINT symbol_type
        3 => 4,              // UDINT symbol_address
        4 => 4,              // UDINT (reserved)
        5 => 4,              // UDINT symbol_object_address
        6 => 4,              // UDINT software_control
        7 => 4,              // UDINT (reserved)
        8 => 12,             // [3]UDINT array dimensions
        10 => 1,             // USINT external_access
        _ => 4,              // unknown — reserve a slot so the stream stays aligned
    }
}

fn append_attribute_field(out: &mut Vec<u8>, attr_id: u16, name: &str, sym_type: u16) {
    match attr_id {
        1 => {
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        2 => out.extend_from_slice(&sym_type.to_le_bytes()),
        3 | 5 | 6 | 4 | 7 => out.extend_from_slice(&0u32.to_le_bytes()),
        8 => {
            // Dimensions. Atomic scalars report [0, 0, 0]; this is what a
            // real controller returns for a non-array tag.
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        10 => {
            // External Access: 1=ReadOnly, 2=None, 3=ReadWrite. pycomm3
            // decodes this through its EXTERNAL_ACCESS map; "Read/Write" is
            // the sane default for a simulator target.
            out.push(0x03);
        }
        _ => out.extend_from_slice(&0u32.to_le_bytes()),
    }
}

// Silence the unused Arc import if this file ever loses its last direct use.
const _KEEP_ARC: fn() = || {
    let _ = std::marker::PhantomData::<Arc<()>>;
};
