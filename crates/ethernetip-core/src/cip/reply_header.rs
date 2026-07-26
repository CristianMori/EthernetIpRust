//! Decode the four-byte Message Router reply prefix (plus any extended-status
//! words) so a client can pull the general status out before parsing the
//! service-specific body.

use crate::cip::service_codes;
use crate::error::{EipError, Result};

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
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(EipError::Short {
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
            return Err(EipError::Short {
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
            service: service_reply & !service_codes::REPLY_FLAG,
            general_status,
            extended_status,
            body_offset: ext_bytes_end,
        })
    }
}
