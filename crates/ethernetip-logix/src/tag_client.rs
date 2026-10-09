//! High-level Logix tag client.
//!
//! Wraps an [`EipSession`] with tag-oriented helpers: [`TagClient::read_tag`],
//! [`TagClient::write_tag`], and [`TagClient::browse_tags`]. Requests go
//! through the target's Message Router; when a routing path is configured
//! (typical on a ControlLogix rack where the Ethernet card and CPU sit in
//! different slots) they get wrapped in `Unconnected_Send` addressed to the
//! local Connection Manager, which handles the actual bridging. When
//! `use_connected` is set on the builder, the client opens a Class 3
//! connection at register time and rides `SendUnitData` for every subsequent
//! request.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ethernetip_core::cip::{class_codes as class, service_codes as service, status, ReplyHeader};
use ethernetip_core::cpf::{item_type, Item};
use ethernetip_core::error::{EipError, Result};
use ethernetip_core::path::{parse_route_path, EpathWriter};
use ethernetip_core::{EipSession, EIP_PORT};

use crate::browse::{
    build_symbol_list_request, parse_symbol_chunk, TagCategory, TagInfo,
};
use crate::request::{
    build_mr_request, build_multiple_service_packet, parse_multiple_service_packet,
    wrap_unconnected_send,
};
use crate::tag_path::{encode_with_cache, AtomCache};
use crate::template::{
    build_read_template_request, build_template_header_request, decode_struct,
    expected_definition_bytes, parse_read_template_reply, parse_template_definition,
    parse_template_header_reply, SymType, TemplateDefinition, TypedValue, READ_TEMPLATE_CHUNK,
};
use crate::types::{decode_read_tag, CipType, TagValue};

/// Timeout advertised to the target on each unconnected request.
const REQUEST_TIMEOUT_SECS: u16 = 5;

/// Default originator vendor ID reported in `Forward_Open`.
const DEFAULT_ORIG_VENDOR: u16 = 0x0001;

/// Class 3 connection parameters, matched to what pycomm3 / Studio 5000 send:
/// P2P, priority high, fixed 504 bytes.
const CLASS3_NET_PARAMS: u16 = 0x43F8;

/// Class 3 explicit transport class + trigger byte.
const CLASS3_TRANSPORT: u8 = 0xA3;

/// Requested Packet Interval for Class 3 (microseconds — this is really the
/// inactivity/watchdog timeout for explicit connections).
const CLASS3_RPI_US: u32 = 2_500_000;

/// Builder for [`TagClient`].
#[derive(Debug, Clone)]
pub struct TagClientBuilder {
    host: String,
    port: u16,
    route_path: Option<String>,
    use_connected: bool,
    reopen_on_drop: bool,
}

impl TagClientBuilder {
    fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: EIP_PORT,
            route_path: None,
            use_connected: false,
            reopen_on_drop: false,
        }
    }

    /// When a Class 3 request fails with a "connection dead" CIP status
    /// (`CONNECTION_FAILURE` 0x01 or `DEVICE_STATE_CONFLICT` 0x10) or the
    /// underlying I/O returns an error, transparently close the Class 3
    /// connection, re-Forward_Open it, and retry the request once.
    /// Off by default so long-running processes that expect an
    /// idle-timeout can decide themselves whether silent retry is safe.
    pub fn reopen_on_drop(mut self, on: bool) -> Self {
        self.reopen_on_drop = on;
        self
    }

    /// Override the TCP port (default `44818`).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set a libplctag-style routing path such as `"1,0"` (backplane, slot 0).
    ///
    /// Leaving this unset targets the controller directly — correct for
    /// CompactLogix or when connecting straight to a device with a built-in
    /// controller.
    pub fn path(mut self, spec: impl Into<String>) -> Self {
        self.route_path = Some(spec.into());
        self
    }

    /// Open a Class 3 explicit connection at register time and use
    /// `SendUnitData` for every subsequent request. Slightly cheaper per
    /// round-trip once the connection is up, and required by some peers.
    pub fn use_connected(mut self, on: bool) -> Self {
        self.use_connected = on;
        self
    }

    /// Open the TCP session, register, and (optionally) open Class 3.
    pub async fn connect(self) -> Result<TagClient> {
        let route = match &self.route_path {
            Some(spec) => parse_route_path(spec).ok_or_else(|| {
                EipError::Protocol(format!("invalid routing path `{}`", spec))
            })?,
            None => Vec::new(),
        };
        let addr = format!("{}:{}", self.host, self.port);
        let session = EipSession::connect_and_register(addr).await?;
        let mut client = TagClient {
            session,
            route_path: route,
            atoms: AtomCache::new(),
            use_connected: self.use_connected,
            reopen_on_drop: self.reopen_on_drop,
            class3_open: false,
            oto_t_conn_id: 0,
            tto_o_conn_id: 0,
            conn_serial: 0,
            orig_vendor: DEFAULT_ORIG_VENDOR,
            orig_serial: 0,
            seq_count: 0,
            template_cache: Arc::new(Mutex::new(HashMap::new())),
            sym_types: HashMap::new(),
        };
        if client.use_connected {
            client.open_class3().await?;
        }
        Ok(client)
    }
}

/// Async Logix tag client bound to a single controller.
pub struct TagClient {
    session: EipSession,
    route_path: Vec<u8>,
    atoms: AtomCache,
    use_connected: bool,
    reopen_on_drop: bool,
    class3_open: bool,
    oto_t_conn_id: u32,
    tto_o_conn_id: u32,
    conn_serial: u16,
    orig_vendor: u16,
    orig_serial: u32,
    seq_count: u16,
    // Template Object cache: instance id → parsed definition. Shared via Arc
    // so callers who clone the cache handle for offline decoding still see
    // fresh entries the client fetches later.
    template_cache: Arc<Mutex<HashMap<u16, TemplateDefinition>>>,
    // sym_type map keyed by tag name — populated by browse_tags so
    // read_tag_typed can resolve template ids without a second round trip.
    sym_types: HashMap<String, SymType>,
}

impl TagClient {
    /// Start a new client builder for the given host.
    pub fn builder(host: impl Into<String>) -> TagClientBuilder {
        TagClientBuilder::new(host)
    }

    /// Connect straight to `host:44818` with no routing path.
    pub async fn connect(host: impl Into<String>) -> Result<Self> {
        Self::builder(host).connect().await
    }

    /// Peer session handle (0 before register succeeds).
    pub fn session_handle(&self) -> u32 {
        self.session.session_handle()
    }

    /// True while a Class 3 explicit connection is open.
    pub fn is_class3_open(&self) -> bool {
        self.class3_open
    }

    /// Read a single element from a tag, decoded as [`TagValue`].
    pub async fn read_tag(&mut self, name: &str) -> Result<TagValue> {
        let raw = self.read_tag_raw(name, 1).await?;
        decode_read_tag(&raw)
    }

    /// Read `count` elements as the raw wire bytes (type header + payload).
    ///
    /// When the target answers `PARTIAL_TRANSFER` or `REPLY_TOO_LARGE` — the
    /// typical case for structures and long strings — the read transparently
    /// switches to `Read_Tag_Fragmented` and reassembles the chunks. The
    /// returned buffer always starts with the CIP type header (and struct CRC
    /// when applicable) so the caller can inspect it uniformly.
    pub async fn read_tag_raw(&mut self, name: &str, count: u16) -> Result<Vec<u8>> {
        let path = encode_with_cache(name, &self.atoms)?;
        let body = count.to_le_bytes();
        let mr = build_mr_request(service::READ_TAG, &path, &body);
        let bytes = self.dispatch(mr).await?;
        let header = ReplyHeader::parse(&bytes)?;
        match header.general_status {
            status::SUCCESS => Ok(bytes[header.body_offset..].to_vec()),
            status::PARTIAL_TRANSFER | status::REPLY_TOO_LARGE => {
                self.read_tag_fragmented(name, count).await
            }
            _ => Err(EipError::Cip {
                status: header.general_status,
                ext: header.extended_status,
            }),
        }
    }

    /// Force a fragmented read regardless of size.
    ///
    /// Callers that already know the reply won't fit can skip the initial
    /// `Read_Tag` round-trip by calling this directly.
    pub async fn read_tag_fragmented(&mut self, name: &str, count: u16) -> Result<Vec<u8>> {
        let path = encode_with_cache(name, &self.atoms)?;
        let mut assembled: Vec<u8> = Vec::new();
        let mut offset: u32 = 0;

        loop {
            let mut body = Vec::with_capacity(6);
            body.extend_from_slice(&count.to_le_bytes());
            body.extend_from_slice(&offset.to_le_bytes());
            let mr = build_mr_request(service::READ_TAG_FRAGMENTED, &path, &body);
            let bytes = self.dispatch(mr).await?;
            let header = ReplyHeader::parse(&bytes)?;
            let done = match header.general_status {
                status::SUCCESS => true,
                status::PARTIAL_TRANSFER => false,
                _ => {
                    return Err(EipError::Cip {
                        status: header.general_status,
                        ext: header.extended_status,
                    });
                }
            };
            let chunk = &bytes[header.body_offset..];
            if chunk.len() < 2 {
                return Err(EipError::Short {
                    expected: 2,
                    actual: chunk.len(),
                });
            }
            let type_code = u16::from_le_bytes([chunk[0], chunk[1]]);
            // Struct replies carry a 2-byte type marker plus a 2-byte CRC handle
            // in every fragment; atomic replies just carry the 2-byte type code.
            let prefix = if type_code == CipType::Struct as u16 {
                4
            } else {
                2
            };
            if chunk.len() < prefix {
                return Err(EipError::Short {
                    expected: prefix,
                    actual: chunk.len(),
                });
            }
            if assembled.is_empty() {
                assembled.extend_from_slice(&chunk[..prefix]);
            }
            let payload = &chunk[prefix..];
            assembled.extend_from_slice(payload);
            offset = offset.saturating_add(payload.len() as u32);
            if done {
                break;
            }
            if payload.is_empty() {
                return Err(EipError::Protocol(
                    "fragmented read stalled: partial transfer with empty chunk".into(),
                ));
            }
        }
        Ok(assembled)
    }

    /// Write a single-element atomic tag. Structures are not yet supported
    /// through this method — use [`Self::write_tag_raw`] once you have the
    /// exact wire bytes.
    pub async fn write_tag(&mut self, name: &str, value: &TagValue) -> Result<()> {
        let ty = value.ty();
        if ty == CipType::Struct {
            return Err(EipError::Protocol(
                "write_tag does not yet cover structures — use write_tag_raw".into(),
            ));
        }
        let mut body = Vec::new();
        body.extend_from_slice(&(ty as u16).to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // one element
        body.extend_from_slice(&value.encode_body());
        self.write_tag_raw(name, &body).await
    }

    /// Read many tags in one round-trip via Multiple Service Packet
    /// (0x0A). Returns one `Result<TagValue>` per input name in order.
    /// The whole request is a single MR service to the target's Message
    /// Router; each embedded `Read_Tag` returns its own per-sub-service
    /// status so a single bad tag name doesn't fail the batch.
    ///
    /// The batch is limited by the target's max MR request size — a
    /// ControlLogix typically handles 500 bytes of embedded services
    /// before responding `REPLY_TOO_LARGE`, which comes back as `Err`
    /// on the batch as a whole. Split large batches yourself if you
    /// hit that.
    pub async fn read_tags_batch(&mut self, names: &[&str]) -> Result<Vec<Result<TagValue>>> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let mut embedded = Vec::with_capacity(names.len());
        for name in names {
            let path = encode_with_cache(name, &self.atoms)?;
            let body = 1u16.to_le_bytes();
            embedded.push(build_mr_request(service::READ_TAG, &path, &body));
        }
        let mr = build_multiple_service_packet(&embedded);
        let bytes = self.dispatch(mr).await?;
        let header = ReplyHeader::parse(&bytes)?;
        if header.general_status != status::SUCCESS {
            return Err(EipError::Cip {
                status: header.general_status,
                ext: header.extended_status,
            });
        }
        let msp_body = &bytes[header.body_offset..];
        let replies = parse_multiple_service_packet(msp_body)?;
        let mut out = Vec::with_capacity(replies.len());
        for reply in replies {
            out.push(decode_read_tag_reply(&reply));
        }
        Ok(out)
    }

    /// Write many tags in one round-trip via Multiple Service Packet.
    /// Each entry is `(name, value_body)` where `value_body` is the raw
    /// `type + count + data` slice a normal `write_tag_raw` would send.
    /// Returns one `Result<()>` per entry in order.
    pub async fn write_tags_batch(
        &mut self,
        writes: &[(&str, &[u8])],
    ) -> Result<Vec<Result<()>>> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        let mut embedded = Vec::with_capacity(writes.len());
        for (name, body) in writes {
            let path = encode_with_cache(name, &self.atoms)?;
            embedded.push(build_mr_request(service::WRITE_TAG, &path, body));
        }
        let mr = build_multiple_service_packet(&embedded);
        let bytes = self.dispatch(mr).await?;
        let header = ReplyHeader::parse(&bytes)?;
        if header.general_status != status::SUCCESS {
            return Err(EipError::Cip {
                status: header.general_status,
                ext: header.extended_status,
            });
        }
        let msp_body = &bytes[header.body_offset..];
        let replies = parse_multiple_service_packet(msp_body)?;
        let mut out = Vec::with_capacity(replies.len());
        for reply in replies {
            let hdr = match ReplyHeader::parse(&reply) {
                Ok(h) => h,
                Err(e) => {
                    out.push(Err(e));
                    continue;
                }
            };
            if hdr.general_status == status::SUCCESS {
                out.push(Ok(()));
            } else {
                out.push(Err(EipError::Cip {
                    status: hdr.general_status,
                    ext: hdr.extended_status,
                }));
            }
        }
        Ok(out)
    }

    /// Send a `Write_Tag` with an already-built body (`type + count + data`).
    pub async fn write_tag_raw(&mut self, name: &str, body: &[u8]) -> Result<()> {
        let path = encode_with_cache(name, &self.atoms)?;
        let mr = build_mr_request(service::WRITE_TAG, &path, body);
        let bytes = self.dispatch(mr).await?;
        let header = ReplyHeader::parse(&bytes)?;
        if header.general_status != status::SUCCESS {
            return Err(EipError::Cip {
                status: header.general_status,
                ext: header.extended_status,
            });
        }
        Ok(())
    }

    /// Enumerate every controller-scope tag and cache their instance IDs.
    ///
    /// After this returns, subsequent reads and writes of any discovered tag
    /// use a Symbol Object logical instance segment instead of the full ANSI
    /// symbolic segment, which is shorter on the wire.
    ///
    /// Program-scope tags surface as `Program:<name>` entries so the caller
    /// knows they exist; recursing into a specific program is done via
    /// [`Self::browse_program_tags`].
    pub async fn browse_tags(&mut self) -> Result<Vec<TagInfo>> {
        let all = self.enumerate_symbols(None).await?;
        for entry in &all {
            self.atoms.insert_controller(&entry.name, entry.instance_id);
            self.sym_types
                .insert(entry.name.clone(), SymType(entry.sym_type));
        }
        Ok(all)
    }

    /// Enumerate tags in the given program scope (without the `Program:`
    /// prefix) and cache their instance IDs in the program-atom map.
    pub async fn browse_program_tags(&mut self, program: &str) -> Result<Vec<TagInfo>> {
        let mut all = self.enumerate_symbols(Some(program)).await?;
        for entry in &mut all {
            entry.category = TagCategory::Program;
            self.atoms
                .insert_program(program, &entry.name, entry.instance_id);
            self.sym_types.insert(
                format!("Program:{}.{}", program, entry.name),
                SymType(entry.sym_type),
            );
        }
        Ok(all)
    }

    /// Shared handle to the parsed-template cache. Cloning the returned
    /// `Arc` is cheap; the client and the caller see the same entries.
    /// Useful when decoding raw `TagValue::Struct` payloads offline (e.g.
    /// replaying a capture through [`decode_struct`]).
    pub fn template_cache(&self) -> Arc<Mutex<HashMap<u16, TemplateDefinition>>> {
        Arc::clone(&self.template_cache)
    }

    /// Fetch the Template Object metadata + definition for `template_id`
    /// and cache it. Idempotent — subsequent calls return the cached copy.
    pub async fn fetch_template(&mut self, template_id: u16) -> Result<TemplateDefinition> {
        if let Some(cached) = self
            .template_cache
            .lock()
            .expect("template cache poisoned")
            .get(&template_id)
            .cloned()
        {
            return Ok(cached);
        }
        // Metadata: attrs 1/2/4/5.
        let (svc, path, body) = build_template_header_request(template_id);
        let mr = build_mr_request(svc, &path, &body);
        let reply = self.dispatch(mr).await?;
        let header = parse_template_header_reply(&reply)?;

        // Chunked Read_Template loop until we have the whole definition.
        let expected = expected_definition_bytes(&header);
        let mut acc = Vec::with_capacity(expected);
        let mut offset: u32 = 0;
        while acc.len() < expected {
            let want = READ_TEMPLATE_CHUNK.min((expected - acc.len()) as u16);
            let (svc, path, body) = build_read_template_request(template_id, offset, want);
            let mr = build_mr_request(svc, &path, &body);
            let reply = self.dispatch(mr).await?;
            let (chunk, done) = parse_read_template_reply(&reply)?;
            if chunk.is_empty() {
                return Err(EipError::Protocol(
                    "Read_Template stalled: empty chunk".into(),
                ));
            }
            offset = offset.saturating_add(chunk.len() as u32);
            acc.extend_from_slice(&chunk);
            if done && acc.len() >= expected {
                break;
            }
        }
        acc.truncate(expected);
        let def = parse_template_definition(&header, &acc)?;
        self.template_cache
            .lock()
            .expect("template cache poisoned")
            .insert(template_id, def.clone());
        Ok(def)
    }

    /// Read a tag and decode it against its Template Object definition when
    /// it's a structure. Atomic tags come back as the matching
    /// `TypedValue::*` scalar. Structures require a preceding [`Self::browse_tags`]
    /// (or `browse_program_tags`) call so the tag's `sym_type` is known —
    /// otherwise the caller has to supply a template id directly via
    /// [`Self::read_tag_typed_with_template`].
    pub async fn read_tag_typed(&mut self, name: &str) -> Result<TypedValue> {
        let sym = self.sym_types.get(name).copied();
        let raw = self.read_tag(name).await?;
        match raw {
            TagValue::Struct { .. } => {
                let sym = sym.ok_or_else(|| {
                    EipError::Protocol(format!(
                        "read_tag_typed({name}): structure decode needs sym_type — call browse_tags first"
                    ))
                })?;
                let template_id = sym.template_id().ok_or_else(|| {
                    EipError::Protocol(format!(
                        "read_tag_typed({name}): sym_type reports struct-bit clear"
                    ))
                })?;
                self.read_tag_typed_with_template(name, template_id).await
            }
            _ => Ok(atomic_to_typed(raw)),
        }
    }

    /// Read a tag and decode it as a structure of the given template id.
    /// Bypasses the sym_type cache — useful when you already know the
    /// template (e.g. from a saved layout).
    pub async fn read_tag_typed_with_template(
        &mut self,
        name: &str,
        template_id: u16,
    ) -> Result<TypedValue> {
        let def = self.fetch_template(template_id).await?;
        let raw = self.read_tag_raw(name, 1).await?;
        // read_tag_raw prepends the 4-byte struct header (type + crc); skip it.
        if raw.len() < 4 {
            return Err(EipError::Short {
                expected: 4,
                actual: raw.len(),
            });
        }
        let type_code = u16::from_le_bytes([raw[0], raw[1]]);
        if type_code != CipType::Struct as u16 {
            return Err(EipError::Protocol(format!(
                "read_tag_typed_with_template({name}): reply type 0x{type_code:04X} is not a struct"
            )));
        }
        let payload = &raw[4..];
        let cache = Arc::clone(&self.template_cache);
        let resolve = move |id: u16| cache.lock().ok().and_then(|c| c.get(&id).cloned());
        decode_struct(&def, payload, &resolve)
    }

    /// Read-only view of the instance-ID cache.
    pub fn atom_cache(&self) -> &AtomCache {
        &self.atoms
    }

    async fn enumerate_symbols(&mut self, program: Option<&str>) -> Result<Vec<TagInfo>> {
        let mut all = Vec::new();
        let mut cursor = 0u32;
        loop {
            let (service_code, path, body) = build_symbol_list_request(cursor);
            let mr = if let Some(program) = program {
                // Program-scope enumeration: prefix the Symbol Object path with
                // a symbolic segment naming the program so the controller
                // resolves the right scope.
                let mut anchored = EpathWriter::new();
                anchored.push_symbolic(&format!("Program:{}", program));
                anchored.extend_from_slice(&path);
                build_mr_request(service_code, anchored.as_bytes(), &body)
            } else {
                build_mr_request(service_code, &path, &body)
            };
            let bytes = self.dispatch(mr).await?;
            let (chunk, last, done) = parse_symbol_chunk(&bytes)?;
            let empty = chunk.is_empty();
            all.extend(chunk);
            if done {
                break;
            }
            if empty {
                return Err(EipError::Protocol(
                    "browse stalled: partial transfer with no entries".into(),
                ));
            }
            cursor = last + 1;
        }
        for entry in &mut all {
            if entry.name.starts_with("Program:") {
                entry.category = TagCategory::Program;
            }
        }
        Ok(all)
    }

    /// Cleanly close the Class 3 connection (if any), unregister, and close
    /// the socket.
    pub async fn close(mut self) -> Result<()> {
        if self.class3_open {
            let _ = self.close_class3().await;
        }
        self.session.close().await
    }

    async fn dispatch(&mut self, mr: Vec<u8>) -> Result<Vec<u8>> {
        if self.class3_open {
            // First try. If it fails with a symptom of a dead Class 3
            // connection AND reopen_on_drop is on, close + re-Forward_Open
            // + retry once. Non-connection failures (SERVICE_NOT_SUPPORTED,
            // ATTRIBUTE_NOT_SUPPORTED, ...) bubble up as-is.
            let first = self.send_connected(mr.clone()).await;
            if !self.reopen_on_drop {
                return first;
            }
            match first {
                Ok(bytes) => Ok(bytes),
                Err(err) if is_class3_dead(&err) => {
                    tracing::debug!("Class 3 connection appears dead ({err}); reopening");
                    // Best-effort teardown; ignore errors (peer may already
                    // have dropped both sides).
                    let _ = self.close_class3().await;
                    self.class3_open = false;
                    self.open_class3().await?;
                    self.send_connected(mr).await
                }
                Err(err) => Err(err),
            }
        } else {
            let route = self.route_path.clone();
            self.dispatch_unconnected(&mr, &route).await
        }
    }

    async fn dispatch_unconnected(&mut self, mr: &[u8], route: &[u8]) -> Result<Vec<u8>> {
        let payload = if route.is_empty() {
            mr.to_vec()
        } else {
            wrap_unconnected_send(mr, route)
        };
        let items = [
            Item::null_address(),
            Item::new(item_type::UNCONNECTED_DATA, payload),
        ];
        let envelope = self.session.send_rr_data(&items, REQUEST_TIMEOUT_SECS).await?;
        let data = envelope
            .find(item_type::UNCONNECTED_DATA)
            .ok_or_else(|| EipError::Protocol("reply missing UnconnectedData item".into()))?;
        Ok(data.data.clone())
    }

    async fn send_connected(&mut self, mr: Vec<u8>) -> Result<Vec<u8>> {
        self.seq_count = self.seq_count.wrapping_add(1);
        let mut cd = Vec::with_capacity(2 + mr.len());
        cd.extend_from_slice(&self.seq_count.to_le_bytes());
        cd.extend_from_slice(&mr);
        let items = [
            Item::new(
                item_type::CONNECTED_ADDRESS,
                self.oto_t_conn_id.to_le_bytes().to_vec(),
            ),
            Item::new(item_type::CONNECTED_DATA, cd),
        ];
        let envelope = self.session.send_unit_data(&items).await?;
        let item = envelope
            .find(item_type::CONNECTED_DATA)
            .ok_or_else(|| EipError::Protocol("connected reply missing data item".into()))?;
        if item.data.len() < 2 {
            return Err(EipError::Short {
                expected: 2,
                actual: item.data.len(),
            });
        }
        // Skip the 2-byte reply sequence count so the caller sees only the MR.
        Ok(item.data[2..].to_vec())
    }

    async fn open_class3(&mut self) -> Result<()> {
        let ticks = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EipError::Protocol("system clock predates unix epoch".into()))?
            .as_micros() as u64;
        self.conn_serial = ((ticks & 0xFFFF) as u16).max(1);
        self.orig_serial = ticks as u32;
        self.tto_o_conn_id = 0x8000_0000u32 | (self.conn_serial as u32);
        self.seq_count = 0;

        // Application path = route bytes + Message Router (class 2 instance 1).
        // The route is baked into the connection here so that per-request
        // dispatch doesn't need to wrap in Unconnected_Send once the
        // connection is up.
        let mut app_path = self.route_path.clone();
        app_path.extend_from_slice(&[0x20, 0x02, 0x24, 0x01]);

        let mut fo = Vec::with_capacity(36 + app_path.len());
        fo.push(0x07); // priority/tick
        fo.push(0x09); // timeout ticks
        fo.extend_from_slice(&0u32.to_le_bytes()); // O→T id = 0 (target picks)
        fo.extend_from_slice(&self.tto_o_conn_id.to_le_bytes());
        fo.extend_from_slice(&self.conn_serial.to_le_bytes());
        fo.extend_from_slice(&self.orig_vendor.to_le_bytes());
        fo.extend_from_slice(&self.orig_serial.to_le_bytes());
        fo.push(0x03); // connection timeout multiplier (×32)
        fo.extend_from_slice(&[0, 0, 0]); // reserved
        fo.extend_from_slice(&CLASS3_RPI_US.to_le_bytes());
        fo.extend_from_slice(&CLASS3_NET_PARAMS.to_le_bytes());
        fo.extend_from_slice(&CLASS3_RPI_US.to_le_bytes());
        fo.extend_from_slice(&CLASS3_NET_PARAMS.to_le_bytes());
        fo.push(CLASS3_TRANSPORT);
        fo.push((app_path.len() / 2) as u8);
        fo.extend_from_slice(&app_path);

        let cm_path = {
            let mut w = EpathWriter::new();
            w.push_class(class::CONNECTION_MANAGER);
            w.push_instance(1);
            w.into_bytes()
        };
        let mr = build_mr_request(service::FORWARD_OPEN, &cm_path, &fo);

        // Forward_Open targets the LOCAL Connection Manager and must go as a
        // bare MR request — the route lives inside the FO's connection_path,
        // not wrapped around it. Send with an empty route to skip the UCS
        // wrap in dispatch_unconnected.
        let bytes = self.dispatch_unconnected(&mr, &[]).await?;
        let header = ReplyHeader::parse(&bytes)?;
        if header.general_status != status::SUCCESS {
            return Err(EipError::Cip {
                status: header.general_status,
                ext: header.extended_status,
            });
        }
        let body = &bytes[header.body_offset..];
        if body.len() < 4 {
            return Err(EipError::Short {
                expected: 4,
                actual: body.len(),
            });
        }
        self.oto_t_conn_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        self.class3_open = true;
        Ok(())
    }

    async fn close_class3(&mut self) -> Result<()> {
        if !self.class3_open {
            return Ok(());
        }
        self.class3_open = false;

        let mut app_path = self.route_path.clone();
        app_path.extend_from_slice(&[0x20, 0x02, 0x24, 0x01]);

        let mut close_data = Vec::with_capacity(12 + app_path.len());
        close_data.push(0x07);
        close_data.push(0x09);
        close_data.extend_from_slice(&self.conn_serial.to_le_bytes());
        close_data.extend_from_slice(&self.orig_vendor.to_le_bytes());
        close_data.extend_from_slice(&self.orig_serial.to_le_bytes());
        close_data.push((app_path.len() / 2) as u8);
        close_data.push(0); // reserved
        close_data.extend_from_slice(&app_path);

        let cm_path = {
            let mut w = EpathWriter::new();
            w.push_class(class::CONNECTION_MANAGER);
            w.push_instance(1);
            w.into_bytes()
        };
        let mr = build_mr_request(service::FORWARD_CLOSE, &cm_path, &close_data);
        let _ = self.dispatch_unconnected(&mr, &[]).await;
        Ok(())
    }
}

/// True when an error from `send_connected` looks like the Class 3
/// connection died on the peer's side and a reopen might recover it.
/// Covers the common flavors:
///
///  * `EipError::Io` — socket-level failure (peer closed, timeout).
///  * `EipError::Encap` with a status other than 0 — session got
///    invalidated on the peer.
///  * CIP `CONNECTION_FAILURE` (0x01) — the classic "your connection
///    id doesn't match anything I know about".
///  * CIP `DEVICE_STATE_CONFLICT` (0x10) — some Logix firmware
///    variants return this after an idle timeout.
///  * `EipError::Protocol` — usually the connected reply parser
///    couldn't find CONNECTED_DATA, which happens when the peer
///    responded with UNCONNECTED_DATA because it forgot the connection.
///
/// Kept intentionally narrow — protocol-level errors that indicate a
/// bad request (SERVICE_NOT_SUPPORTED, ATTRIBUTE_NOT_SUPPORTED, ...)
/// aren't included so those bubble up rather than causing a pointless
/// reopen loop.
fn is_class3_dead(err: &EipError) -> bool {
    match err {
        EipError::Io(_) => true,
        EipError::Encap(status) if *status != 0 => true,
        EipError::Protocol(_) => true,
        EipError::Cip { status: s, .. } => matches!(
            *s,
            status::CONNECTION_FAILURE | status::DEVICE_STATE_CONFLICT
        ),
        _ => false,
    }
}

/// Convert a scalar [`TagValue`] into the matching [`TypedValue`].
/// Structs are handled separately in [`TagClient::read_tag_typed`] — this
/// function panics if called with a struct.
fn atomic_to_typed(v: TagValue) -> TypedValue {
    match v {
        TagValue::Bool(x) => TypedValue::Bool(x),
        TagValue::Sint(x) => TypedValue::Sint(x),
        TagValue::Int(x) => TypedValue::Int(x),
        TagValue::Dint(x) => TypedValue::Dint(x),
        TagValue::Lint(x) => TypedValue::Lint(x),
        TagValue::Usint(x) => TypedValue::Usint(x),
        TagValue::Uint(x) => TypedValue::Uint(x),
        TagValue::Udint(x) => TypedValue::Udint(x),
        TagValue::Ulint(x) => TypedValue::Ulint(x),
        TagValue::Real(x) => TypedValue::Real(x),
        TagValue::Lreal(x) => TypedValue::Lreal(x),
        TagValue::Byte(x) => TypedValue::Byte(x),
        TagValue::Word(x) => TypedValue::Word(x),
        TagValue::Dword(x) => TypedValue::Dword(x),
        TagValue::Lword(x) => TypedValue::Lword(x),
        TagValue::Struct { .. } => {
            unreachable!("atomic_to_typed called with a struct — caller bug")
        }
    }
}

/// Peel a Multiple Service Packet sub-reply — an embedded Read_Tag
/// response — into a decoded `TagValue`. Returns the CIP error for
/// non-success sub-replies so a batch can carry per-tag results.
fn decode_read_tag_reply(reply: &[u8]) -> Result<TagValue> {
    let header = ReplyHeader::parse(reply)?;
    if header.general_status != status::SUCCESS {
        return Err(EipError::Cip {
            status: header.general_status,
            ext: header.extended_status,
        });
    }
    decode_read_tag(&reply[header.body_offset..])
}
