//! High-level Logix tag client.
//!
//! Wraps an [`EipSession`] with tag-oriented helpers: [`TagClient::read_tag`],
//! [`TagClient::write_tag`], and [`TagClient::browse_tags`]. Requests go
//! through the target's Message Router; when a routing path is configured
//! (typical on a ControlLogix rack where the Ethernet card and CPU sit in
//! different slots) they get wrapped in `Unconnected_Send` addressed to the
//! local Connection Manager, which handles the actual bridging.

use ethernetip_core::cip::{service, status, ReplyHeader};
use ethernetip_core::cpf::{item_type, Item};
use ethernetip_core::error::{EipError, Result};
use ethernetip_core::path::parse_route_path;
use ethernetip_core::{EipSession, EIP_PORT};

use crate::browse::{
    build_symbol_list_request, parse_symbol_chunk, TagCategory, TagInfo,
};
use crate::request::{build_mr_request, wrap_unconnected_send};
use crate::tag_path::{encode_with_cache, AtomCache};
use crate::types::{decode_read_tag, CipType, TagValue};

/// Timeout advertised to the target on each unconnected request.
const REQUEST_TIMEOUT_SECS: u16 = 5;

/// Builder for [`TagClient`].
#[derive(Debug, Clone)]
pub struct TagClientBuilder {
    host: String,
    port: u16,
    route_path: Option<String>,
}

impl TagClientBuilder {
    fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: EIP_PORT,
            route_path: None,
        }
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

    /// Open the TCP session and register.
    pub async fn connect(self) -> Result<TagClient> {
        let route = match &self.route_path {
            Some(spec) => parse_route_path(spec).ok_or_else(|| {
                EipError::Protocol(format!("invalid routing path `{}`", spec))
            })?,
            None => Vec::new(),
        };
        let addr = format!("{}:{}", self.host, self.port);
        let session = EipSession::connect_and_register(addr).await?;
        Ok(TagClient {
            session,
            route_path: route,
            atoms: AtomCache::new(),
        })
    }
}

/// Async Logix tag client bound to a single controller.
pub struct TagClient {
    session: EipSession,
    route_path: Vec<u8>,
    atoms: AtomCache,
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
        }
        Ok(all)
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
                let mut anchored = ethernetip_core::path::EpathWriter::new();
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

    /// Cleanly unregister and close the socket.
    pub async fn close(self) -> Result<()> {
        self.session.close().await
    }

    /// Wrap the MR request per routing configuration and exchange one round.
    async fn dispatch(&mut self, mr: Vec<u8>) -> Result<Vec<u8>> {
        let payload = if self.route_path.is_empty() {
            mr
        } else {
            wrap_unconnected_send(&mr, &self.route_path)
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
}

