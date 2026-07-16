//! A single CIP attribute — a typed, access-controlled value identified by a
//! numeric ID within its owning [`CipInstance`]. Data is stored as raw bytes
//! in wire (little-endian) format; typed convenience constructors write the
//! bytes for the common scalar types.
//!
//! An attribute's backing storage is one of:
//!
//!  * `Owned(Vec<u8>)` — the attribute owns its bytes. Zero-overhead beyond
//!    the vector itself. Use for identity / config values that don't move.
//!  * `Shared(Arc<RwLock<Vec<u8>>>)` — the attribute shares its bytes with
//!    an external actor. Use to back the Assembly Object's data attribute
//!    with the same buffer an I/O loop is reading from, so a CIP write and
//!    an incoming UDP frame race for the same bytes instead of two
//!    disjoint copies.

use std::borrow::Cow;
use std::sync::{Arc, RwLock};

use crate::cip::data_type::CipDataType;

/// Which standard services are allowed against this attribute. A plain
/// bit-set on a `u8` — no `bitflags` crate dependency for a three-flag enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeAccess(pub u8);

impl AttributeAccess {
    /// Readable via `Get_Attribute_Single` (0x0E).
    pub const GET_SINGLE: Self = Self(0b0001);
    /// Writable via `Set_Attribute_Single` (0x10).
    pub const SET_SINGLE: Self = Self(0b0010);
    /// Included in `Get_Attributes_All` (0x01) response.
    pub const GET_ALL: Self = Self(0b0100);
    /// Full access: readable, writable, included in Get_Attributes_All.
    pub const ALL: Self = Self(0b0111);
    /// Read-only: readable + included in Get_Attributes_All.
    pub const READ: Self = Self(0b0101);
    /// No permitted access — attribute exists but returns errors.
    pub const NONE: Self = Self(0);

    /// True when every flag in `other` is set on `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for AttributeAccess {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone)]
enum Backing {
    Owned(Vec<u8>),
    Shared(Arc<RwLock<Vec<u8>>>),
}

/// A CIP attribute — id + data type + access + raw wire bytes.
#[derive(Debug, Clone)]
pub struct CipAttribute {
    pub id: u16,
    pub data_type: CipDataType,
    pub access: AttributeAccess,
    backing: Backing,
}

impl CipAttribute {
    /// Create an owned attribute wrapping the given raw bytes.
    pub fn new(
        id: u16,
        data_type: CipDataType,
        access: AttributeAccess,
        initial: Vec<u8>,
    ) -> Self {
        Self {
            id,
            data_type,
            access,
            backing: Backing::Owned(initial),
        }
    }

    /// Create an attribute whose bytes are backed by a caller-owned
    /// `Arc<RwLock<Vec<u8>>>`. Writes to the attribute mutate the shared
    /// buffer; reads see whatever's currently there. Used to bridge
    /// Assembly Object attribute 3 to the live I/O buffer.
    pub fn new_shared(
        id: u16,
        data_type: CipDataType,
        access: AttributeAccess,
        shared: Arc<RwLock<Vec<u8>>>,
    ) -> Self {
        Self {
            id,
            data_type,
            access,
            backing: Backing::Shared(shared),
        }
    }

    /// One-byte scalar (BOOL / SINT / USINT / BYTE).
    pub fn from_u8(id: u16, data_type: CipDataType, access: AttributeAccess, value: u8) -> Self {
        Self::new(id, data_type, access, vec![value])
    }

    /// Two-byte scalar (INT / UINT / WORD) in little-endian.
    pub fn from_u16(id: u16, data_type: CipDataType, access: AttributeAccess, value: u16) -> Self {
        Self::new(id, data_type, access, value.to_le_bytes().to_vec())
    }

    /// Four-byte scalar (DINT / UDINT / DWORD) in little-endian.
    pub fn from_u32(id: u16, data_type: CipDataType, access: AttributeAccess, value: u32) -> Self {
        Self::new(id, data_type, access, value.to_le_bytes().to_vec())
    }

    /// SHORT_STRING: 1-byte length + ASCII payload.
    pub fn from_short_string(id: u16, access: AttributeAccess, value: &str) -> Self {
        let mut buf = Vec::with_capacity(1 + value.len());
        buf.push(value.len() as u8);
        buf.extend_from_slice(value.as_bytes());
        Self::new(id, CipDataType::ShortString, access, buf)
    }

    /// Read the raw wire bytes. Borrowed for the owned case (zero-copy);
    /// owned for the shared case (snapshot under the read lock).
    pub fn data(&self) -> Cow<'_, [u8]> {
        match &self.backing {
            Backing::Owned(v) => Cow::Borrowed(v.as_slice()),
            Backing::Shared(arc) => Cow::Owned(arc.read().unwrap().clone()),
        }
    }

    /// Byte length of the current data.
    pub fn len(&self) -> usize {
        match &self.backing {
            Backing::Owned(v) => v.len(),
            Backing::Shared(arc) => arc.read().unwrap().len(),
        }
    }

    /// True when the current data is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Overwrite the raw data. For owned bytes, reallocates when the new
    /// payload has a different length. For shared bytes, the existing
    /// buffer is length-adjusted in place — callers that expect a fixed
    /// wire size (Assembly attr 3) will normally pass a slice matching
    /// the existing length.
    pub fn set_data(&mut self, value: &[u8]) {
        match &mut self.backing {
            Backing::Owned(v) => {
                if value.len() != v.len() {
                    *v = value.to_vec();
                } else {
                    v.copy_from_slice(value);
                }
            }
            Backing::Shared(arc) => {
                let mut g = arc.write().unwrap();
                if value.len() != g.len() {
                    *g = value.to_vec();
                } else {
                    g.copy_from_slice(value);
                }
            }
        }
    }

    /// If this attribute shares its bytes, return a clone of the shared
    /// handle so a second owner can read / write the same buffer. `None`
    /// for owned attributes.
    pub fn shared_handle(&self) -> Option<Arc<RwLock<Vec<u8>>>> {
        match &self.backing {
            Backing::Owned(_) => None,
            Backing::Shared(arc) => Some(arc.clone()),
        }
    }
}
