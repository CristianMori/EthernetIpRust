//! EtherNet/IP encapsulation header.
//!
//! Every encapsulated request/reply on the TCP session starts with a fixed
//! 24-byte header followed by a command-specific payload.

use bytes::{Buf, BufMut, BytesMut};

use crate::error::{EipError, Result};

/// Length of the encapsulation header in bytes.
pub const HEADER_LEN: usize = 24;

/// Encapsulation command codes we care about.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    RegisterSession = 0x0065,
    UnRegisterSession = 0x0066,
    SendRRData = 0x006F,
    SendUnitData = 0x0070,
}

impl Command {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Parsed encapsulation header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub command: u16,
    pub length: u16,
    pub session_handle: u32,
    pub status: u32,
    pub sender_context: [u8; 8],
    pub options: u32,
}

impl Header {
    /// Serialize into `dst`.
    pub fn write_to(&self, dst: &mut BytesMut) {
        dst.put_u16_le(self.command);
        dst.put_u16_le(self.length);
        dst.put_u32_le(self.session_handle);
        dst.put_u32_le(self.status);
        dst.put_slice(&self.sender_context);
        dst.put_u32_le(self.options);
    }

    /// Parse from a 24-byte slice.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(EipError::Short {
                expected: HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let mut c = bytes;
        let command = c.get_u16_le();
        let length = c.get_u16_le();
        let session_handle = c.get_u32_le();
        let status = c.get_u32_le();
        let mut sender_context = [0u8; 8];
        c.copy_to_slice(&mut sender_context);
        let options = c.get_u32_le();
        Ok(Header {
            command,
            length,
            session_handle,
            status,
            sender_context,
            options,
        })
    }
}

/// Encode a full encapsulation frame (header + payload).
pub fn encode_frame(
    command: Command,
    session_handle: u32,
    sender_context: [u8; 8],
    payload: &[u8],
) -> BytesMut {
    let mut buf = BytesMut::with_capacity(HEADER_LEN + payload.len());
    Header {
        command: command.as_u16(),
        length: payload.len() as u16,
        session_handle,
        status: 0,
        sender_context,
        options: 0,
    }
    .write_to(&mut buf);
    buf.put_slice(payload);
    buf
}
