//! Common Packet Format envelope.
//!
//! `SendRRData` / `SendUnitData` wrap a CPF item array inside an interface
//! handle + timeout prefix. This module builds and parses that envelope.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::{EipError, Result};

/// CPF item type IDs.
pub mod item_type {
    pub const NULL_ADDRESS: u16 = 0x0000;
    pub const CONNECTED_ADDRESS: u16 = 0x00A1;
    pub const CONNECTED_DATA: u16 = 0x00B1;
    pub const UNCONNECTED_DATA: u16 = 0x00B2;
    /// Sockaddr Info for the T→O direction — carries the ORIGINATOR's
    /// UDP endpoint. Scanner adds it to the FO request so the target knows
    /// where to send T→O; adapter reads it and uses the address as the
    /// producer's destination.
    pub const SOCKADDR_INFO_T_TO_O: u16 = 0x8000;
    /// Sockaddr Info for the O→T direction — carries the TARGET's UDP
    /// endpoint. Adapter adds it to the FO reply so the originator knows
    /// where to send O→T; scanner reads it and uses the address as the
    /// producer's destination.
    pub const SOCKADDR_INFO_O_TO_T: u16 = 0x8001;
}

/// Encode a 16-byte sockaddr_in for a Sockaddr Info CPF item. Family is
/// AF_INET (2) in big-endian, port and IPv4 address are also big-endian
/// (network byte order); the trailing 8 bytes of sin_zero stay 0. IPv6
/// addresses are rejected — CIP Sockaddr Info is v4-only.
pub fn encode_sockaddr_in_v4(endpoint: std::net::SocketAddr) -> Result<Vec<u8>> {
    let v4 = match endpoint {
        std::net::SocketAddr::V4(a) => a,
        std::net::SocketAddr::V6(_) => {
            return Err(EipError::Protocol(
                "Sockaddr Info CPF items require IPv4".into(),
            ));
        }
    };
    let mut buf = vec![0u8; 16];
    buf[0..2].copy_from_slice(&2u16.to_be_bytes()); // sin_family = AF_INET
    buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
    buf[4..8].copy_from_slice(&v4.ip().octets());
    Ok(buf)
}

/// Decode a 16-byte sockaddr_in from a Sockaddr Info CPF item. Only the port
/// and address are returned; family + sin_zero are ignored. A `0.0.0.0`
/// address means "let the receiver use the TCP peer address as fallback" —
/// the caller checks for it explicitly.
pub fn decode_sockaddr_in_v4(bytes: &[u8]) -> Result<std::net::SocketAddrV4> {
    if bytes.len() < 8 {
        return Err(EipError::Short {
            expected: 8,
            actual: bytes.len(),
        });
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let addr = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    Ok(std::net::SocketAddrV4::new(addr, port))
}

/// Resolve a peer UDP endpoint using a Sockaddr Info CPF item found in the
/// given envelope. Convention: if the item is missing or its address is
/// unspecified (`0.0.0.0`), fall back to `default_ip` with either the item's
/// port (if non-zero) or `default_port`. Matches how the C# / C++ / Python
/// ports resolve peer endpoints when a peer advertises a wildcard.
pub fn resolve_peer_udp(
    envelope: &Envelope,
    sockaddr_type_id: u16,
    default_ip: std::net::IpAddr,
    default_port: u16,
) -> std::net::SocketAddr {
    use std::net::{IpAddr, SocketAddr};
    if let Some(item) = envelope.find(sockaddr_type_id) {
        if let Ok(v4) = decode_sockaddr_in_v4(&item.data) {
            let port = if v4.port() != 0 { v4.port() } else { default_port };
            let ip = if v4.ip().is_unspecified() {
                default_ip
            } else {
                IpAddr::V4(*v4.ip())
            };
            return SocketAddr::new(ip, port);
        }
    }
    SocketAddr::new(default_ip, default_port)
}

/// A single CPF item: type id + inline payload.
#[derive(Debug, Clone)]
pub struct Item {
    pub type_id: u16,
    pub data: Vec<u8>,
}

impl Item {
    pub fn new(type_id: u16, data: Vec<u8>) -> Self {
        Self { type_id, data }
    }

    pub fn null_address() -> Self {
        Self::new(item_type::NULL_ADDRESS, Vec::new())
    }

    pub fn connected_address(conn_id: u32) -> Self {
        let mut d = Vec::with_capacity(4);
        d.extend_from_slice(&conn_id.to_le_bytes());
        Self::new(item_type::CONNECTED_ADDRESS, d)
    }
}

/// Build the CPF envelope used inside `SendRRData` / `SendUnitData`.
///
/// * `interface_handle` — usually 0.
/// * `timeout` — request timeout in seconds (only meaningful for `SendRRData`,
///   ignored on Unit Data — pass 0 there).
pub fn encode_envelope(interface_handle: u32, timeout: u16, items: &[Item]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(8 + items.iter().map(|i| 4 + i.data.len()).sum::<usize>());
    buf.put_u32_le(interface_handle);
    buf.put_u16_le(timeout);
    buf.put_u16_le(items.len() as u16);
    for item in items {
        buf.put_u16_le(item.type_id);
        buf.put_u16_le(item.data.len() as u16);
        buf.put_slice(&item.data);
    }
    buf.to_vec()
}

/// Parsed CPF envelope from a reply.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub interface_handle: u32,
    pub timeout: u16,
    pub items: Vec<Item>,
}

impl Envelope {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(EipError::Short {
                expected: 8,
                actual: bytes.len(),
            });
        }
        let mut c = bytes;
        let interface_handle = c.get_u32_le();
        let timeout = c.get_u16_le();
        let item_count = c.get_u16_le() as usize;
        let mut items = Vec::with_capacity(item_count);
        for _ in 0..item_count {
            if c.remaining() < 4 {
                return Err(EipError::Short {
                    expected: 4,
                    actual: c.remaining(),
                });
            }
            let type_id = c.get_u16_le();
            let len = c.get_u16_le() as usize;
            if c.remaining() < len {
                return Err(EipError::Short {
                    expected: len,
                    actual: c.remaining(),
                });
            }
            let mut data = vec![0u8; len];
            c.copy_to_slice(&mut data);
            items.push(Item { type_id, data });
        }
        Ok(Self {
            interface_handle,
            timeout,
            items,
        })
    }

    /// Find first item of a given type.
    pub fn find(&self, type_id: u16) -> Option<&Item> {
        self.items.iter().find(|i| i.type_id == type_id)
    }
}
