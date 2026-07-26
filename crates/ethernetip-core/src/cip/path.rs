//! Parse a Message Router request path — the leading EPATH bytes that
//! identify a class / instance / attribute / member for object dispatch.
//!
//! Encoding is a subset of Vol 1 App C.1:
//!
//! * Logical / Class:     `0x20 8b` or `0x21 pad 16bLE`
//! * Logical / Instance:  `0x24 8b` or `0x25 pad 16bLE` or `0x26 pad 32bLE`
//! * Logical / Attribute: `0x30 8b` or `0x31 pad 16bLE`
//! * Logical / Member:    `0x28 8b` or `0x29 pad 16bLE`
//!
//! Any other segment (port, symbolic, data) is skipped over — those show up
//! in routed and Logix requests and aren't part of object dispatch.

use crate::error::{EipError, Result};

/// Parsed object-dispatch fields from an MR request path.
#[derive(Debug, Clone, Default)]
pub struct CipPath {
    pub class_id: Option<u32>,
    pub instance_id: Option<u32>,
    pub attribute_id: Option<u32>,
    pub member_id: Option<u32>,
}

impl CipPath {
    /// Parse an EPATH from a raw byte slice.
    ///
    /// Unknown segments (port, symbolic) don't fail — they're skipped so a
    /// routed request path can still resolve its class/instance/attribute
    /// components. Truncated segments or reserved logical formats (32-bit
    /// class, 32-bit attribute) do fail with `PathSegmentError`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut out = CipPath::default();
        let mut i = 0;
        while i < bytes.len() {
            let seg = bytes[i];
            let (advance, class, instance, attribute, member) = decode_segment(&bytes[i..], seg)?;
            if let Some(v) = class { out.class_id = Some(v); }
            if let Some(v) = instance { out.instance_id = Some(v); }
            if let Some(v) = attribute { out.attribute_id = Some(v); }
            if let Some(v) = member { out.member_id = Some(v); }
            i += advance;
        }
        Ok(out)
    }
}

fn decode_segment(
    bytes: &[u8],
    seg: u8,
) -> Result<(usize, Option<u32>, Option<u32>, Option<u32>, Option<u32>)> {
    // Return tuple: (bytes_consumed, class, instance, attribute, member)
    match seg {
        // Class — 8-bit
        0x20 => need(bytes, 2).map(|_| (2, Some(bytes[1] as u32), None, None, None)),
        // Class — 16-bit (pad byte after seg)
        0x21 => need(bytes, 4).map(|_| {
            let v = u16::from_le_bytes([bytes[2], bytes[3]]) as u32;
            (4, Some(v), None, None, None)
        }),
        // Instance — 8-bit
        0x24 => need(bytes, 2).map(|_| (2, None, Some(bytes[1] as u32), None, None)),
        // Instance — 16-bit
        0x25 => need(bytes, 4).map(|_| {
            let v = u16::from_le_bytes([bytes[2], bytes[3]]) as u32;
            (4, None, Some(v), None, None)
        }),
        // Instance — 32-bit
        0x26 => need(bytes, 6).map(|_| {
            let v = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
            (6, None, Some(v), None, None)
        }),
        // Attribute — 8-bit
        0x30 => need(bytes, 2).map(|_| (2, None, None, Some(bytes[1] as u32), None)),
        // Attribute — 16-bit
        0x31 => need(bytes, 4).map(|_| {
            let v = u16::from_le_bytes([bytes[2], bytes[3]]) as u32;
            (4, None, None, Some(v), None)
        }),
        // Member — 8-bit
        0x28 => need(bytes, 2).map(|_| (2, None, None, None, Some(bytes[1] as u32))),
        // Member — 16-bit
        0x29 => need(bytes, 4).map(|_| {
            let v = u16::from_le_bytes([bytes[2], bytes[3]]) as u32;
            (4, None, None, None, Some(v))
        }),
        // Port segment (0x00..=0x0F, plus optional extended link address) — skip.
        p if p <= 0x0F => {
            let extended = (p & 0x10) != 0; // extended link address flag isn't set here
            let _ = extended;
            Ok((2, None, None, None, None))
        }
        // Simple data segment (0x80) — length in bytes at [1], data follows.
        0x80 => need(bytes, 2).and_then(|_| {
            let len_words = bytes[1] as usize;
            let total = 2 + len_words * 2;
            need(bytes, total).map(|_| (total, None, None, None, None))
        }),
        // ANSI symbolic segment (0x91) — length in BYTES at [1], padded to
        // an even total length.
        0x91 => need(bytes, 2).and_then(|_| {
            let raw = 2 + bytes[1] as usize;
            let total = raw + (raw & 1);
            need(bytes, total).map(|_| (total, None, None, None, None))
        }),
        // Electronic key (0x34) — length in words at [1] (typically 4 → 10 bytes total).
        0x34 => need(bytes, 2).and_then(|_| {
            let total = 2 + (bytes[1] as usize) * 2;
            need(bytes, total).map(|_| (total, None, None, None, None))
        }),
        // Any other segment — refuse rather than silently drop, so untested
        // formats surface as an obvious error instead of a mis-routed request.
        other => Err(EipError::Protocol(format!(
            "unsupported EPATH segment 0x{other:02X} at object-dispatch parse"
        ))),
    }
}

fn need(bytes: &[u8], min: usize) -> Result<()> {
    if bytes.len() < min {
        Err(EipError::Short { expected: min, actual: bytes.len() })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_instance_8bit() {
        // Class 0x39, Instance 1 — the safety-supervisor path.
        let p = CipPath::parse(&[0x20, 0x39, 0x24, 0x01]).unwrap();
        assert_eq!(p.class_id, Some(0x39));
        assert_eq!(p.instance_id, Some(1));
        assert_eq!(p.attribute_id, None);
    }

    #[test]
    fn class_instance_attribute() {
        let p = CipPath::parse(&[0x20, 0x01, 0x24, 0x01, 0x30, 0x07]).unwrap();
        assert_eq!(p.class_id, Some(1));
        assert_eq!(p.instance_id, Some(1));
        assert_eq!(p.attribute_id, Some(7));
    }

    #[test]
    fn class_16bit() {
        // Extended class 0x0100 encoded with the pad byte.
        let p = CipPath::parse(&[0x21, 0x00, 0x00, 0x01, 0x24, 0x01]).unwrap();
        assert_eq!(p.class_id, Some(0x0100));
        assert_eq!(p.instance_id, Some(1));
    }

    #[test]
    fn skips_port_and_electronic_key() {
        // Port 1, link=0 (2 bytes), key (10 bytes), class 0x39, inst 1.
        let bytes = [
            0x01, 0x00, // port
            0x34, 0x04, 0x01, 0x00, 0x23, 0x00, 0x10, 0x00, 0x82, 0x02, // ekey
            0x20, 0x39, 0x24, 0x01,
        ];
        let p = CipPath::parse(&bytes).unwrap();
        assert_eq!(p.class_id, Some(0x39));
        assert_eq!(p.instance_id, Some(1));
    }
}
