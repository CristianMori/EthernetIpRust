//! CIP constants: service codes, well-known classes, and status codes.

/// CIP service codes.
pub mod service {
    pub const GET_ATTRIBUTES_ALL: u8 = 0x01;
    pub const SET_ATTRIBUTES_ALL: u8 = 0x02;
    pub const RESET: u8 = 0x05;
    pub const START: u8 = 0x06;
    pub const STOP: u8 = 0x07;
    pub const CREATE: u8 = 0x08;
    pub const DELETE: u8 = 0x09;
    pub const MULTIPLE_SERVICE_PACKET: u8 = 0x0A;
    pub const APPLY_ATTRIBUTES: u8 = 0x0D;
    pub const GET_ATTRIBUTE_SINGLE: u8 = 0x0E;
    pub const SET_ATTRIBUTE_SINGLE: u8 = 0x10;
    pub const FIND_NEXT_OBJECT_INSTANCE: u8 = 0x11;
    pub const GET_INSTANCE_ATTRIBUTE_LIST: u8 = 0x55;

    // Vendor extensions used by Logix.
    pub const READ_TAG: u8 = 0x4C;
    pub const WRITE_TAG: u8 = 0x4D;
    pub const READ_TAG_FRAGMENTED: u8 = 0x52;
    pub const WRITE_TAG_FRAGMENTED: u8 = 0x53;

    // Connection Manager services.
    pub const FORWARD_CLOSE: u8 = 0x4E;
    pub const UNCONNECTED_SEND: u8 = 0x52;
    pub const FORWARD_OPEN: u8 = 0x54;
    pub const LARGE_FORWARD_OPEN: u8 = 0x5B;

    /// Bit OR'd into the service code in a reply.
    pub const REPLY_FLAG: u8 = 0x80;
}

/// Well-known CIP class IDs.
pub mod class {
    pub const MESSAGE_ROUTER: u16 = 0x02;
    pub const CONNECTION_MANAGER: u16 = 0x06;
    pub const SYMBOL_OBJECT: u16 = 0x6B;
    pub const TEMPLATE_OBJECT: u16 = 0x6C;
}

/// Selected CIP general status codes.
pub mod status {
    pub const SUCCESS: u8 = 0x00;
    pub const CONNECTION_FAILURE: u8 = 0x01;
    pub const RESOURCE_UNAVAILABLE: u8 = 0x02;
    pub const PATH_SEGMENT_ERROR: u8 = 0x04;
    pub const PATH_DESTINATION_UNKNOWN: u8 = 0x05;
    pub const PARTIAL_TRANSFER: u8 = 0x06;
    pub const SERVICE_NOT_SUPPORTED: u8 = 0x08;
    pub const INVALID_ATTRIBUTE_VALUE: u8 = 0x09;
    pub const OBJECT_STATE_CONFLICT: u8 = 0x0C;
    pub const ATTRIBUTE_NOT_SETTABLE: u8 = 0x0E;
    pub const PRIVILEGE_VIOLATION: u8 = 0x0F;
    pub const DEVICE_STATE_CONFLICT: u8 = 0x10;
    pub const REPLY_TOO_LARGE: u8 = 0x11;
    pub const NOT_ENOUGH_DATA: u8 = 0x13;
    pub const ATTRIBUTE_NOT_SUPPORTED: u8 = 0x14;
    pub const TOO_MUCH_DATA: u8 = 0x15;
    pub const OBJECT_DOES_NOT_EXIST: u8 = 0x16;
    pub const INVALID_PARAMETER: u8 = 0x20;
}

/// Decoded CIP reply header (service + status + optional extended status).
#[derive(Debug, Clone)]
pub struct ReplyHeader {
    /// Reply service code with the `REPLY_FLAG` bit cleared.
    pub service: u8,
    /// CIP general status (`status::SUCCESS` on success).
    pub general_status: u8,
    /// Extended status words, if any (0 or more `u16` LE values).
    pub extended_status: Vec<u16>,
    /// Offset into the original buffer where the service-specific data starts.
    pub body_offset: usize,
}

impl ReplyHeader {
    /// Parse the leading bytes of a Message Router response.
    ///
    /// Wire format: `service | reply_flag`, `reserved (0)`, `general_status`,
    /// `ext_size (words)`, `ext_size * u16 LE`, then service-specific body.
    pub fn parse(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.len() < 4 {
            return Err(crate::error::EipError::Short {
                expected: 4,
                actual: bytes.len(),
            });
        }
        let service_reply = bytes[0];
        let general_status = bytes[2];
        let ext_words = bytes[3] as usize;
        let ext_bytes_start = 4;
        let ext_bytes_end = ext_bytes_start + ext_words * 2;
        if bytes.len() < ext_bytes_end {
            return Err(crate::error::EipError::Short {
                expected: ext_bytes_end,
                actual: bytes.len(),
            });
        }
        let mut extended_status = Vec::with_capacity(ext_words);
        for i in 0..ext_words {
            let off = ext_bytes_start + i * 2;
            extended_status.push(u16::from_le_bytes([bytes[off], bytes[off + 1]]));
        }
        Ok(Self {
            service: service_reply & !service::REPLY_FLAG,
            general_status,
            extended_status,
            body_offset: ext_bytes_end,
        })
    }
}
