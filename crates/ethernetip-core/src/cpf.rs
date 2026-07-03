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
