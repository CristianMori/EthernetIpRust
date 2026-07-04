//! Cyclic I/O (EPIO) framing over UDP.
//!
//! Each frame is the same CPF envelope as TCP `SendUnitData`, but carrying a
//! Sequenced Address item (0x8002) that names the connection id and I/O
//! sequence number, followed by a Connected Data item (0x00B1) holding the
//! assembly bytes (optionally preceded by a 32-bit run/idle header when the
//! connection was opened with that transport option).

use bytes::{Buf, BufMut, BytesMut};

use ethernetip_core::cpf::item_type;
use ethernetip_core::error::{EipError, Result};

/// Sequenced Address item type id.
pub const SEQUENCED_ADDRESS: u16 = 0x8002;

/// One decoded EPIO frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub connection_id: u32,
    /// Encapsulation (CPF Sequenced Address) sequence number — a monotonically
    /// increasing counter carried alongside the connection id so a receiver
    /// can detect UDP reordering / loss.
    pub sequence: u32,
    /// CIP Class 1 sequence count — a per-connection u16 that lives inside
    /// the ConnectedData payload and increments once per produced frame.
    /// Distinct from the CPF sequence above.
    pub cip_sequence: u16,
    /// Optional run/idle header — `Some(true)` for run, `Some(false)` for idle,
    /// `None` when the connection format has no run/idle header.
    pub run_idle: Option<bool>,
    pub data: Vec<u8>,
}

/// Encode an EPIO frame. When `run_idle` is `Some`, the four run/idle header
/// bytes are prepended to the connected-data payload so the receiver knows
/// how to distinguish idle heartbeats from actual data updates.
///
/// Unlike the CPF envelope used inside TCP `SendRRData` / `SendUnitData`,
/// UDP EPIO frames start directly at the item count — no leading
/// `interface_handle` / `timeout` prefix.
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let run_idle_bytes = if frame.run_idle.is_some() { 4 } else { 0 };
    // Payload = CIP seq (2) + [run/idle (4)] + app data
    let payload_len = 2 + run_idle_bytes + frame.data.len();
    let total = 2 + 4 + 8 + 4 + payload_len;
    let mut buf = BytesMut::with_capacity(total);
    buf.put_u16_le(2); // item count
    buf.put_u16_le(SEQUENCED_ADDRESS);
    buf.put_u16_le(8);
    buf.put_u32_le(frame.connection_id);
    buf.put_u32_le(frame.sequence);
    buf.put_u16_le(item_type::CONNECTED_DATA);
    buf.put_u16_le(payload_len as u16);
    buf.put_u16_le(frame.cip_sequence);
    if let Some(run) = frame.run_idle {
        buf.put_u32_le(if run { 1 } else { 0 });
    }
    buf.put_slice(&frame.data);
    buf.to_vec()
}

/// Decode an EPIO frame. `expect_run_idle` tells the decoder whether the
/// connection was opened with a 32-bit run/idle header — the receiver has to
/// know this because it's not self-describing on the wire.
///
/// UDP EPIO frames start with the item count directly (no envelope prefix),
/// which is why this decoder walks the byte stream by hand instead of going
/// through the shared TCP CPF envelope parser.
pub fn decode_frame(bytes: &[u8], expect_run_idle: bool) -> Result<Frame> {
    if bytes.len() < 18 {
        return Err(EipError::Short {
            expected: 18,
            actual: bytes.len(),
        });
    }
    let mut cur = bytes;
    let item_count = cur.get_u16_le();
    if item_count < 2 {
        return Err(EipError::Protocol(format!(
            "EPIO frame item count {} < 2",
            item_count
        )));
    }
    let addr_type = cur.get_u16_le();
    let addr_len = cur.get_u16_le();
    if addr_type != SEQUENCED_ADDRESS || addr_len != 8 {
        return Err(EipError::Protocol(format!(
            "EPIO frame not SequencedAddress: type=0x{:04X} len={}",
            addr_type, addr_len
        )));
    }
    let connection_id = cur.get_u32_le();
    let sequence = cur.get_u32_le();

    if cur.remaining() < 4 {
        return Err(EipError::Short {
            expected: 4,
            actual: cur.remaining(),
        });
    }
    let data_type = cur.get_u16_le();
    let data_len = cur.get_u16_le() as usize;
    if data_type != item_type::CONNECTED_DATA {
        return Err(EipError::Protocol(format!(
            "EPIO frame data item type 0x{:04X} != 0x00B1",
            data_type
        )));
    }
    if cur.remaining() < data_len {
        return Err(EipError::Short {
            expected: data_len,
            actual: cur.remaining(),
        });
    }
    let payload = &cur[..data_len];
    if payload.len() < 2 {
        return Err(EipError::Short {
            expected: 2,
            actual: payload.len(),
        });
    }
    let cip_sequence = u16::from_le_bytes([payload[0], payload[1]]);
    let after_seq = &payload[2..];
    let (run_idle, data) = if expect_run_idle {
        if after_seq.len() < 4 {
            return Err(EipError::Short {
                expected: 4,
                actual: after_seq.len(),
            });
        }
        let hdr = u32::from_le_bytes([after_seq[0], after_seq[1], after_seq[2], after_seq[3]]);
        (Some((hdr & 1) != 0), after_seq[4..].to_vec())
    } else {
        (None, after_seq.to_vec())
    };
    Ok(Frame {
        connection_id,
        sequence,
        cip_sequence,
        run_idle,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_run_idle() {
        let frame = Frame {
            connection_id: 0xDEAD_BEEF,
            sequence: 42,
            cip_sequence: 7,
            run_idle: Some(true),
            data: vec![0x11, 0x22, 0x33, 0x44],
        };
        let bytes = encode_frame(&frame);
        let back = decode_frame(&bytes, true).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn roundtrip_without_run_idle() {
        let frame = Frame {
            connection_id: 0x1234,
            sequence: 1,
            cip_sequence: 99,
            run_idle: None,
            data: b"payload".to_vec(),
        };
        let bytes = encode_frame(&frame);
        let back = decode_frame(&bytes, false).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn idle_bit_survives_encode() {
        let frame = Frame {
            connection_id: 1,
            sequence: 0,
            cip_sequence: 0,
            run_idle: Some(false),
            data: vec![],
        };
        let bytes = encode_frame(&frame);
        let back = decode_frame(&bytes, true).unwrap();
        assert_eq!(back.run_idle, Some(false));
    }
}
