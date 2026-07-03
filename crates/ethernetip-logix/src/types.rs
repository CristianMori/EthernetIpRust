//! CIP atomic data-type codes and a tagged value enum.

use ethernetip_core::error::{EipError, Result};

/// Well-known CIP atomic type codes as they appear on the wire.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipType {
    Bool = 0x00C1,
    Sint = 0x00C2,
    Int = 0x00C3,
    Dint = 0x00C4,
    Lint = 0x00C5,
    Usint = 0x00C6,
    Uint = 0x00C7,
    Udint = 0x00C8,
    Ulint = 0x00C9,
    Real = 0x00CA,
    Lreal = 0x00CB,
    /// Structure marker; the two bytes following the marker are the CRC handle.
    Struct = 0x02A0,
}

impl CipType {
    pub fn from_u16(code: u16) -> Option<Self> {
        Some(match code {
            0x00C1 => Self::Bool,
            0x00C2 => Self::Sint,
            0x00C3 => Self::Int,
            0x00C4 => Self::Dint,
            0x00C5 => Self::Lint,
            0x00C6 => Self::Usint,
            0x00C7 => Self::Uint,
            0x00C8 => Self::Udint,
            0x00C9 => Self::Ulint,
            0x00CA => Self::Real,
            0x00CB => Self::Lreal,
            0x02A0 => Self::Struct,
            _ => return None,
        })
    }

    /// Byte size for atomic types; structures have no fixed size.
    pub fn atomic_size(self) -> Option<usize> {
        Some(match self {
            Self::Bool | Self::Sint | Self::Usint => 1,
            Self::Int | Self::Uint => 2,
            Self::Dint | Self::Udint | Self::Real => 4,
            Self::Lint | Self::Ulint | Self::Lreal => 8,
            Self::Struct => return None,
        })
    }
}

/// A read tag result, decoded from the on-wire representation.
#[derive(Debug, Clone, PartialEq)]
pub enum TagValue {
    Bool(bool),
    Sint(i8),
    Int(i16),
    Dint(i32),
    Lint(i64),
    Usint(u8),
    Uint(u16),
    Udint(u32),
    Ulint(u64),
    Real(f32),
    Lreal(f64),
    /// Undecoded structure: caller must know the UDT layout to interpret it.
    Struct { crc: u16, bytes: Vec<u8> },
}

impl TagValue {
    pub fn ty(&self) -> CipType {
        match self {
            Self::Bool(_) => CipType::Bool,
            Self::Sint(_) => CipType::Sint,
            Self::Int(_) => CipType::Int,
            Self::Dint(_) => CipType::Dint,
            Self::Lint(_) => CipType::Lint,
            Self::Usint(_) => CipType::Usint,
            Self::Uint(_) => CipType::Uint,
            Self::Udint(_) => CipType::Udint,
            Self::Ulint(_) => CipType::Ulint,
            Self::Real(_) => CipType::Real,
            Self::Lreal(_) => CipType::Lreal,
            Self::Struct { .. } => CipType::Struct,
        }
    }

    /// Encode as the raw on-wire payload of a `Write_Tag` request (without the
    /// leading type header — that is added by the request builder).
    pub fn encode_body(&self) -> Vec<u8> {
        match self {
            Self::Bool(b) => vec![if *b { 0xFF } else { 0x00 }],
            Self::Sint(v) => v.to_le_bytes().to_vec(),
            Self::Int(v) => v.to_le_bytes().to_vec(),
            Self::Dint(v) => v.to_le_bytes().to_vec(),
            Self::Lint(v) => v.to_le_bytes().to_vec(),
            Self::Usint(v) => v.to_le_bytes().to_vec(),
            Self::Uint(v) => v.to_le_bytes().to_vec(),
            Self::Udint(v) => v.to_le_bytes().to_vec(),
            Self::Ulint(v) => v.to_le_bytes().to_vec(),
            Self::Real(v) => v.to_le_bytes().to_vec(),
            Self::Lreal(v) => v.to_le_bytes().to_vec(),
            Self::Struct { bytes, .. } => bytes.clone(),
        }
    }
}

/// Decode a `Read_Tag` reply body (starting at the type header).
///
/// The wire layout is: `type_code (u16)` then either the atomic value bytes
/// or `struct_crc (u16) + struct_bytes` for structures.
pub fn decode_read_tag(bytes: &[u8]) -> Result<TagValue> {
    if bytes.len() < 2 {
        return Err(EipError::Short {
            expected: 2,
            actual: bytes.len(),
        });
    }
    let type_code = u16::from_le_bytes([bytes[0], bytes[1]]);
    let payload = &bytes[2..];
    let ty = CipType::from_u16(type_code)
        .ok_or_else(|| EipError::Protocol(format!("unknown CIP type 0x{:04X}", type_code)))?;
    if ty == CipType::Struct {
        if payload.len() < 2 {
            return Err(EipError::Short {
                expected: 2,
                actual: payload.len(),
            });
        }
        let crc = u16::from_le_bytes([payload[0], payload[1]]);
        return Ok(TagValue::Struct {
            crc,
            bytes: payload[2..].to_vec(),
        });
    }
    let needed = ty.atomic_size().unwrap();
    if payload.len() < needed {
        return Err(EipError::Short {
            expected: needed,
            actual: payload.len(),
        });
    }
    Ok(match ty {
        CipType::Bool => TagValue::Bool(payload[0] != 0),
        CipType::Sint => TagValue::Sint(i8::from_le_bytes([payload[0]])),
        CipType::Usint => TagValue::Usint(payload[0]),
        CipType::Int => TagValue::Int(i16::from_le_bytes([payload[0], payload[1]])),
        CipType::Uint => TagValue::Uint(u16::from_le_bytes([payload[0], payload[1]])),
        CipType::Dint => TagValue::Dint(i32::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ])),
        CipType::Udint => TagValue::Udint(u32::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ])),
        CipType::Real => TagValue::Real(f32::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ])),
        CipType::Lint => TagValue::Lint(i64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ])),
        CipType::Ulint => TagValue::Ulint(u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ])),
        CipType::Lreal => TagValue::Lreal(f64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ])),
        CipType::Struct => unreachable!(),
    })
}
