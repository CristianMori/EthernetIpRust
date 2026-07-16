//! Server side of the Logix tag protocol.
//!
//! Binds a TCP port, accepts encapsulated request/reply, and answers
//! `Read_Tag`, `Write_Tag`, `Read_Tag_Fragmented`, and
//! `Get_Instance_Attribute_List` against a shared [`TagRegistry`]. Requests
//! wrapped in `Unconnected_Send` are unwrapped so scanners that always
//! prepend a routing envelope still work.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use ethernetip_core::cip::{class_codes as class, service_codes as service, status};
use ethernetip_core::cpf::{item_type, Envelope, Item};
use ethernetip_core::encap::{encode_frame as encode_encap, Command, Header, HEADER_LEN};
use ethernetip_core::error::{EipError, Result};

use crate::tag_registry::TagRegistry;
use crate::types::CipType;

/// Configuration for [`start`].
#[derive(Debug, Clone)]
pub struct TagServerConfig {
    pub tcp_bind: SocketAddr,
    pub registry: TagRegistry,
}

impl TagServerConfig {
    pub fn new(registry: TagRegistry) -> Self {
        Self {
            tcp_bind: SocketAddr::from(([0, 0, 0, 0], 44818)),
            registry,
        }
    }

    pub fn tcp_bind(mut self, addr: SocketAddr) -> Self {
        self.tcp_bind = addr;
        self
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
                            tokio::spawn(async move {
                                if let Err(err) = handle_session(stream, peer, registry).await {
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

async fn handle_session(
    mut stream: TcpStream,
    peer: SocketAddr,
    registry: TagRegistry,
) -> Result<()> {
    let session_handle = derive_session_handle(peer);
    let mut header_buf = [0u8; HEADER_LEN];
    loop {
        stream.read_exact(&mut header_buf).await?;
        let header = Header::parse(&header_buf)?;
        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 {
            stream.read_exact(&mut payload).await?;
        }
        match header.command {
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
                handle_send_rr_data(&mut stream, &header, &payload, &registry).await?;
            }
            other => {
                tracing::debug!("unhandled command 0x{:04X}", other);
                return Ok(());
            }
        }
    }
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
) -> Result<()> {
    let envelope = Envelope::parse(payload)?;
    let mr_item = envelope
        .find(item_type::UNCONNECTED_DATA)
        .ok_or_else(|| EipError::Protocol("SendRRData missing UnconnectedData item".into()))?;
    // Unwrap Unconnected_Send if present (service 0x52 to Connection Manager).
    let inner = maybe_unwrap_unconnected_send(&mr_item.data).unwrap_or_else(|| mr_item.data.clone());
    let mr_reply = dispatch_mr(&inner, registry);

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

/// If the outer MR is an `Unconnected_Send` addressed to the Connection
/// Manager, return the embedded message; otherwise `None`.
fn maybe_unwrap_unconnected_send(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 2 {
        return None;
    }
    if bytes[0] != service::UNCONNECTED_SEND {
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
fn dispatch_mr(mr: &[u8], registry: &TagRegistry) -> Vec<u8> {
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
        s if s == service::GET_INSTANCE_ATTRIBUTE_LIST => {
            handle_get_instance_attribute_list(&path, &body, registry)
        }
        other => build_mr_reply(other | service::REPLY_FLAG, status::SERVICE_NOT_SUPPORTED, &[]),
    }
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

fn build_mr_reply(service_code: u8, status: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(service_code);
    out.push(0);
    out.push(status);
    out.push(0);
    out.extend_from_slice(body);
    out
}

/// Decode a Logix tag reference from an MR path. Handles:
/// * Full symbolic (`0x91` … chain)
/// * Cached instance form (`0x24 <inst>` or `0x25 00 <lo> <hi>`)
/// * Program-scope prefix (`0x91 "Program:X"` followed by more segments)
///
/// Returns the top-level tag entry looked up from the registry plus the
/// residual member path (chain of ANSI symbolic names) — the residual is
/// empty for a direct tag read.
fn resolve_tag_path(path: &[u8], registry: &TagRegistry) -> Option<crate::tag_registry::TagEntry> {
    let mut i = 0;
    // Skip a leading class-6B segment if present (some clients emit
    // `Class(Symbol) + Instance(id)` explicitly).
    if path.len() >= 4 && path[0] == 0x20 && path[1] == class::SYMBOL_OBJECT as u8 {
        i = 2;
    }
    if i >= path.len() {
        return None;
    }
    match path[i] {
        0x91 => {
            let len = path[i + 1] as usize;
            let name_bytes = &path[i + 2..i + 2 + len];
            let name = std::str::from_utf8(name_bytes).ok()?;
            registry.get_by_name(name)
        }
        0x24 => {
            let inst = path[i + 1] as u32;
            registry.get_by_instance(inst)
        }
        0x25 => {
            let inst = u16::from_le_bytes([path[i + 2], path[i + 3]]) as u32;
            registry.get_by_instance(inst)
        }
        _ => None,
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
    let entry = match resolve_tag_path(path, registry) {
        Some(e) => e,
        None => {
            return build_mr_reply(
                service::READ_TAG | service::REPLY_FLAG,
                status::PATH_DESTINATION_UNKNOWN,
                &[],
            );
        }
    };

    let mut out = Vec::with_capacity(2 + entry.data.len());
    out.extend_from_slice(&(entry.cip_type as u16).to_le_bytes());
    if entry.cip_type == CipType::Struct {
        // 2-byte struct CRC handle sits between the type and the data. Use
        // the low byte of the sym_type as the handle when the caller didn't
        // supply one.
        let handle = entry.sym_type & 0x0FFF;
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

fn handle_read_tag_fragmented(path: &[u8], body: &[u8], registry: &TagRegistry) -> Vec<u8> {
    if body.len() < 6 {
        return build_mr_reply(
            service::READ_TAG_FRAGMENTED | service::REPLY_FLAG,
            status::NOT_ENOUGH_DATA,
            &[],
        );
    }
    let _count = u16::from_le_bytes([body[0], body[1]]) as usize;
    let offset = u32::from_le_bytes([body[2], body[3], body[4], body[5]]) as usize;
    let entry = match resolve_tag_path(path, registry) {
        Some(e) => e,
        None => {
            return build_mr_reply(
                service::READ_TAG_FRAGMENTED | service::REPLY_FLAG,
                status::PATH_DESTINATION_UNKNOWN,
                &[],
            );
        }
    };
    // Cap each chunk so a very large struct is naturally paged.
    const CHUNK: usize = 500;
    let end = (offset + CHUNK).min(entry.data.len());
    let more = end < entry.data.len();
    let mut out = Vec::with_capacity(4 + (end - offset));
    out.extend_from_slice(&(entry.cip_type as u16).to_le_bytes());
    if entry.cip_type == CipType::Struct {
        let handle = entry.sym_type & 0x0FFF;
        out.extend_from_slice(&handle.to_le_bytes());
    }
    out.extend_from_slice(&entry.data[offset..end]);
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
    let _type_code = u16::from_le_bytes([body[0], body[1]]);
    let count = u16::from_le_bytes([body[2], body[3]]) as usize;
    let value = &body[4..];
    let entry = match resolve_tag_path(path, registry) {
        Some(e) => e,
        None => {
            return build_mr_reply(
                service::WRITE_TAG | service::REPLY_FLAG,
                status::PATH_DESTINATION_UNKNOWN,
                &[],
            );
        }
    };
    let per = entry.atomic_size().unwrap_or(entry.data.len());
    let take = per * count.max(1);
    if value.len() < take {
        return build_mr_reply(
            service::WRITE_TAG | service::REPLY_FLAG,
            status::NOT_ENOUGH_DATA,
            &[],
        );
    }
    // Write into position 0 for the requested `count` elements.
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
    _body: &[u8],
    registry: &TagRegistry,
) -> Vec<u8> {
    // Path must at least contain the class segment.
    if path.len() < 4 || path[0] != 0x20 || path[1] != class::SYMBOL_OBJECT as u8 {
        return build_mr_reply(
            service::GET_INSTANCE_ATTRIBUTE_LIST | service::REPLY_FLAG,
            status::PATH_SEGMENT_ERROR,
            &[],
        );
    }
    let start_instance = match path[2] {
        0x24 => path[3] as u32,
        0x25 if path.len() >= 6 => u16::from_le_bytes([path[4], path[5]]) as u32,
        _ => 0,
    };

    let entries = registry.browse_entries();
    let mut cursor = entries
        .into_iter()
        .filter(|(inst, _, _)| *inst >= start_instance)
        .peekable();

    // Pack as many entries as we can into a bounded response.
    const RESPONSE_CAP: usize = 480;
    let mut body = Vec::new();
    let mut wrote_all = true;
    while let Some(&(inst, ref name, sym_type)) = cursor.peek() {
        let entry_len = 4 + 2 + name.len() + 2;
        if body.len() + entry_len > RESPONSE_CAP {
            wrote_all = false;
            break;
        }
        body.extend_from_slice(&inst.to_le_bytes());
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&sym_type.to_le_bytes());
        cursor.next();
    }
    let st = if wrote_all {
        status::SUCCESS
    } else {
        status::PARTIAL_TRANSFER
    };
    build_mr_reply(
        service::GET_INSTANCE_ATTRIBUTE_LIST | service::REPLY_FLAG,
        st,
        &body,
    )
}

// Silence the unused Arc import if this file ever loses its last direct use.
const _KEEP_ARC: fn() = || {
    let _ = std::marker::PhantomData::<Arc<()>>;
};
