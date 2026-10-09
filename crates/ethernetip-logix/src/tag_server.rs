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
use ethernetip_core::path_parse::{parse_epath, PathSegment};

use crate::tag_registry::{TagEntry, TagRegistry};
use crate::types::CipType;
use crate::walker::{walk, WalkResult};

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
    // Try instance-only shortcut when the path is Class(0x6B) + Instance(N).
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
                // No post-root symbolic drilling supported for instance-form paths
                // (rare and typically used only for whole-tag reads).
                return Some(ResolvedPath::Controller(entry, None));
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
        return build_walker_read_reply(&entry, w, count);
    }

    // Whole-tag / root-level read.
    let mut out = Vec::with_capacity(2 + entry.data.len());
    out.extend_from_slice(&(entry.cip_type as u16).to_le_bytes());
    if entry.cip_type == CipType::Struct {
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

fn build_walker_read_reply(entry: &TagEntry, w: WalkResult, count: usize) -> Vec<u8> {
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
    let mut out = Vec::with_capacity(2 + bytes_to_read);
    out.extend_from_slice(&w.type_code.to_le_bytes());
    if w.type_code & 0x8000 != 0 {
        // Nested struct member — emit struct handle in the same slot.
        out.extend_from_slice(&(w.type_code & 0x0FFF).to_le_bytes());
    }
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
    let offset = u32::from_le_bytes([body[2], body[3], body[4], body[5]]) as usize;
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
    let entry = match resolved {
        ResolvedPath::Controller(e, _) | ResolvedPath::Program(_, e, _) => e,
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
    let type_code = u16::from_le_bytes([body[0], body[1]]);
    let count = u16::from_le_bytes([body[2], body[3]]) as usize;
    let value = &body[4..];
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

    // Reject client-side `tag_type` that doesn't match the target.  Logix
    // controllers return `0xFF / 0x2107` (general error + extended "wrong
    // type") for this; matching that bytes-for-bytes keeps the Rust
    // server interchangeable with C#/C++/Python under the same test
    // assertions. Struct writes (tag_type == 0x02A0) carry the struct
    // handle in the next two bytes rather than matching the atomic code
    // directly, so skip the atomic check for them — the struct-write
    // path has its own handle check elsewhere (TODO: wire the struct
    // handle validation here once Rust gains the two-u16 struct write
    // header parse).
    const CIP_TYPE_STRUCT_MARKER: u16 = 0x02A0;
    let expected_type: u16 = match &resolved {
        ResolvedPath::Controller(_, Some(w)) | ResolvedPath::Program(_, _, Some(w)) => w.type_code,
        ResolvedPath::Controller(e, None) | ResolvedPath::Program(_, e, None) => e.cip_type as u16,
    };
    if type_code != CIP_TYPE_STRUCT_MARKER && type_code != expected_type {
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
