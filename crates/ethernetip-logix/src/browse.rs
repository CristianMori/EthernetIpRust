//! Enumerate the Logix Symbol Object (class 0x6B).
//!
//! Each iteration of `Get_Instance_Attribute_List` returns a chunk of entries;
//! we chase the "partial transfer" status (0x06) with the last seen instance
//! id until the target answers `SUCCESS`. Program-scope tags live under
//! `Program:<name>` symbols and expose their own Symbol Object instances via
//! a per-program class hierarchy that we recurse into.

use bytes::Buf;
use ethernetip_core::cip::{class, service, status, ReplyHeader};
use ethernetip_core::error::{EipError, Result};
use ethernetip_core::path::EpathWriter;

/// One discovered tag entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagInfo {
    /// Fully qualified tag name (`Program:Foo.Bar` for program-scope tags).
    pub name: String,
    /// Symbol Object instance id — usable as the atom in an indexed path.
    pub instance_id: u32,
    /// Symbol type code from attribute 2 (the raw CIP type descriptor bits).
    pub sym_type: u16,
    /// True for program-scope tags (`Program:X` prefix or discovered under a program).
    pub category: TagCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagCategory {
    Controller,
    Program,
}

/// Parse one `Get_Instance_Attribute_List` reply body into tag entries.
///
/// Returns `(entries, last_instance_id, done)` where `done` is true when the
/// reply carried CIP status `SUCCESS` (no further chunks). The caller uses
/// `last_instance_id + 1` as the starting instance for the next chunk if not
/// done.
pub fn parse_symbol_chunk(reply: &[u8]) -> Result<(Vec<TagInfo>, u32, bool)> {
    let header = ReplyHeader::parse(reply)?;
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
    let mut cursor = &reply[header.body_offset..];
    let mut out = Vec::new();
    let mut last_id = 0u32;
    while cursor.remaining() >= 6 {
        let instance_id = cursor.get_u32_le();
        let name_len = cursor.get_u16_le() as usize;
        if cursor.remaining() < name_len + 2 {
            return Err(EipError::Short {
                expected: name_len + 2,
                actual: cursor.remaining(),
            });
        }
        let name_bytes = &cursor[..name_len];
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        cursor.advance(name_len);
        let sym_type = cursor.get_u16_le();
        last_id = instance_id;
        out.push(TagInfo {
            name,
            instance_id,
            sym_type,
            category: TagCategory::Controller,
        });
    }
    Ok((out, last_id, done))
}

/// Build the request body for `Get_Instance_Attribute_List` starting from
/// `start_instance`. Attributes requested: 1 (name) and 2 (sym_type).
///
/// The returned tuple is `(service_code, path_bytes, body_bytes)` ready to be
/// fed to [`crate::request::build_mr_request`].
pub fn build_symbol_list_request(start_instance: u32) -> (u8, Vec<u8>, Vec<u8>) {
    let mut path = EpathWriter::new();
    path.push_class(class::SYMBOL_OBJECT);
    path.push_instance(start_instance);
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&2u16.to_le_bytes()); // attribute count
    body.extend_from_slice(&1u16.to_le_bytes()); // attr 1 = name
    body.extend_from_slice(&2u16.to_le_bytes()); // attr 2 = type
    (
        service::GET_INSTANCE_ATTRIBUTE_LIST,
        path.into_bytes(),
        body,
    )
}
