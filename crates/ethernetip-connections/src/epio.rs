//! Cyclic I/O (EPIO) framing over UDP.
//!
//! Each frame is the same CPF envelope as TCP `SendUnitData`, but carrying a
//! Sequenced Address item (0x8002) that names the connection id and I/O
//! sequence number, followed by a Connected Data item (0x00B1) holding the
//! assembly bytes (optionally preceded by a 32-bit run/idle header when the
//! connection was opened with that transport option).

use bytes::{Buf, BufMut, BytesMut};

use ethernetip_core::cpf::{item_type, Envelope, Item};
use ethernetip_core::error::{EipError, Result};

/// Sequenced Address item type id.
pub const SEQUENCED_ADDRESS: u16 = 0x8002;

/// One decoded EPIO frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub connection_id: u32,
    pub sequence: u32,
    /// Optional run/idle header — `Some(true)` for run, `Some(false)` for idle,
    /// `None` when the connection format has no run/idle header.
    pub run_idle: Option<bool>,
    pub data: Vec<u8>,
}

/// Encode an EPIO frame. When `run_idle` is `Some`, the four run/idle header
/// bytes are prepended to the connected-data item so the receiver knows how
/// to distinguish idle heartbeats from actual data updates.
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut sa = BytesMut::with_capacity(8);
    sa.put_u32_le(frame.connection_id);
    sa.put_u32_le(frame.sequence);
    let mut cd = Vec::with_capacity(4 + frame.data.len());
    if let Some(run) = frame.run_idle {
        cd.extend_from_slice(&(if run { 1u32 } else { 0u32 }).to_le_bytes());
    }
    cd.extend_from_slice(&frame.data);
    let items = [
        Item::new(SEQUENCED_ADDRESS, sa.to_vec()),
        Item::new(item_type::CONNECTED_DATA, cd),
    ];
    ethernetip_core::cpf::encode_envelope(0, 0, &items)
}

/// Decode an EPIO frame. `expect_run_idle` tells the decoder whether the
/// connection was opened with a 32-bit run/idle header — the receiver has to
/// know this because it's not self-describing on the wire.
pub fn decode_frame(bytes: &[u8], expect_run_idle: bool) -> Result<Frame> {
    let envelope = Envelope::parse(bytes)?;
    let sa = envelope
        .find(SEQUENCED_ADDRESS)
        .ok_or_else(|| EipError::Protocol("EPIO frame missing SequencedAddress item".into()))?;
    let cd = envelope
        .find(item_type::CONNECTED_DATA)
        .ok_or_else(|| EipError::Protocol("EPIO frame missing ConnectedData item".into()))?;
    if sa.data.len() < 8 {
        return Err(EipError::Short {
            expected: 8,
            actual: sa.data.len(),
        });
    }
    let mut cur = sa.data.as_slice();
    let connection_id = cur.get_u32_le();
    let sequence = cur.get_u32_le();
    let (run_idle, data) = if expect_run_idle {
        if cd.data.len() < 4 {
            return Err(EipError::Short {
                expected: 4,
                actual: cd.data.len(),
            });
        }
        let hdr = u32::from_le_bytes([cd.data[0], cd.data[1], cd.data[2], cd.data[3]]);
        (Some((hdr & 1) != 0), cd.data[4..].to_vec())
    } else {
        (None, cd.data.clone())
    };
    Ok(Frame {
        connection_id,
        sequence,
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
            run_idle: Some(false),
            data: vec![],
        };
        let bytes = encode_frame(&frame);
        let back = decode_frame(&bytes, true).unwrap();
        assert_eq!(back.run_idle, Some(false));
    }
}
