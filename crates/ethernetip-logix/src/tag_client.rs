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
use crate::tag_path::encode_symbolic;
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
        })
    }
}

/// Async Logix tag client bound to a single controller.
pub struct TagClient {
    session: EipSession,
    route_path: Vec<u8>,
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
    /// Structures come back with the `0x02A0` type header intact so the caller
    /// can inspect the CRC handle.
    pub async fn read_tag_raw(&mut self, name: &str, count: u16) -> Result<Vec<u8>> {
        let path = encode_symbolic(name)?;
        let body = count.to_le_bytes();
        let mr = build_mr_request(service::READ_TAG, &path, &body);
        let bytes = self.dispatch(mr).await?;
        let header = ReplyHeader::parse(&bytes)?;
        if header.general_status != status::SUCCESS {
            return Err(EipError::Cip {
                status: header.general_status,
                ext: header.extended_status,
            });
        }
        Ok(bytes[header.body_offset..].to_vec())
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
        let path = encode_symbolic(name)?;
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

    /// Enumerate every controller-scope tag.
    ///
    /// This does not yet recurse into program scopes; program-scope tags will
    /// come back as `Program:<name>` entries so the caller can spot them.
    pub async fn browse_tags(&mut self) -> Result<Vec<TagInfo>> {
        let mut all = Vec::new();
        let mut cursor = 0u32;
        loop {
            let (service_code, path, body) = build_symbol_list_request(cursor);
            let mr = build_mr_request(service_code, &path, &body);
            let bytes = self.dispatch(mr).await?;
            let (chunk, last, done) = parse_symbol_chunk(&bytes)?;
            let empty = chunk.is_empty();
            all.extend(chunk);
            if done {
                break;
            }
            if empty {
                // Guard against a target that returns partial_transfer but no
                // new instances — otherwise we'd spin forever.
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

