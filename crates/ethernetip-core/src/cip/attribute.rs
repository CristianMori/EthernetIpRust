//! A single CIP attribute — a typed, access-controlled value identified by a
//! numeric ID within its owning [`CipInstance`]. Data is stored as raw bytes
//! in wire (little-endian) format; typed convenience constructors write the
//! bytes for the common scalar types.

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

/// A CIP attribute — id + data type + access + raw wire bytes.
#[derive(Debug, Clone)]
pub struct CipAttribute {
    pub id: u16,
    pub data_type: CipDataType,
    pub access: AttributeAccess,
    data: Vec<u8>,
}

impl CipAttribute {
    /// Create an attribute wrapping the given raw bytes.
    pub fn new(
        id: u16,
        data_type: CipDataType,
        access: AttributeAccess,
        initial: Vec<u8>,
    ) -> Self {
        Self { id, data_type, access, data: initial }
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

    /// Read the raw wire bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Byte length of the current data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True when the current data is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Overwrite the raw data. Reallocates when the new payload has a
    /// different length; small on the hot path but callers that mutate every
    /// tick (assemblies) should use a fixed-size buffer.
    pub fn set_data(&mut self, value: &[u8]) {
        if value.len() != self.data.len() {
            self.data = value.to_vec();
        } else {
            self.data.copy_from_slice(value);
        }
    }
}
