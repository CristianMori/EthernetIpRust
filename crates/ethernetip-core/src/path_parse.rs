//! Parse an EPATH byte stream into an ordered list of segments.
//!
//! The encoder in [`crate::path::EpathWriter`] emits bytes one segment at a
//! time. This module goes the other way: given a raw EPATH, it returns the
//! segments in the order they appeared on the wire. Server-side dispatchers
//! use the ordered list to distinguish `Program:X.Tag` (two symbolics),
//! `Motor.Timer.PRE` (three symbolics), `Matrix[1,2]` (two element indices
//! after a symbolic), and so on — collapsing them into a single flat name
//! loses the structure needed for member drilling and multi-dim indexing.

use crate::error::{EipError, Result};

/// One segment inside a CIP EPATH, in on-wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    /// ANSI Extended Symbolic (0x91) — a tag name or member name.
    Symbolic(String),
    /// Logical Element ID (0x28 / 0x29 / 0x2A) — one array index.
    Element(u32),
    /// Any other logical segment (Class, Instance, Attribute, ConnectionPoint).
    Logical { kind: LogicalKind, value: u32 },
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalKind {
    ClassId = 0x00,
    InstanceId = 0x04,
    ConnectionPoint = 0x0C,
    AttributeId = 0x10,
}

const SEGMENT_TYPE_MASK: u8 = 0xE0;
const LOGICAL_SEGMENT: u8 = 0x20;
const SYMBOLIC_SEGMENT: u8 = 0x91;
const LOGICAL_TYPE_MASK: u8 = 0x1C;
const LOGICAL_TYPE_ELEMENT: u8 = 0x08;
const LOGICAL_FORMAT_MASK: u8 = 0x03;

/// Parse an EPATH byte stream into ordered segments. Returns the segments
/// plus the number of bytes consumed. Unknown segment types stop the parse
/// (a subsequent segment is not attempted) rather than silently discarding
/// bytes, matching the C# reference parser.
pub fn parse_epath(bytes: &[u8]) -> Result<(Vec<PathSegment>, usize)> {
    let mut segments = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let seg = bytes[i];
        if seg == SYMBOLIC_SEGMENT {
            if i + 2 > bytes.len() {
                return Err(EipError::Protocol("truncated ANSI symbolic segment".into()));
            }
            let len = bytes[i + 1] as usize;
            let start = i + 2;
            let end = start + len;
            if end > bytes.len() {
                return Err(EipError::Protocol("truncated ANSI symbolic name".into()));
            }
            let name = std::str::from_utf8(&bytes[start..end])
                .map_err(|_| EipError::Protocol("non-ASCII in symbolic segment".into()))?
                .to_string();
            i = end;
            if len % 2 == 1 {
                i += 1; // pad to word boundary
            }
            segments.push(PathSegment::Symbolic(name));
            continue;
        }
        let seg_type = seg & SEGMENT_TYPE_MASK;
        if seg_type != LOGICAL_SEGMENT {
            break; // unknown / unhandled type
        }
        let logical_type = seg & LOGICAL_TYPE_MASK;
        let format = seg & LOGICAL_FORMAT_MASK;
        i += 1;
        let value = match format {
            0 => {
                let v = bytes[i] as u32;
                i += 1;
                v
            }
            1 => {
                if i % 2 == 1 {
                    i += 1;
                }
                if i + 2 > bytes.len() {
                    break;
                }
                let v = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as u32;
                i += 2;
                v
            }
            2 => {
                if i % 2 == 1 {
                    i += 1;
                }
                if i + 4 > bytes.len() {
                    break;
                }
                let v = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
                i += 4;
                v
            }
            _ => break,
        };
        if logical_type == LOGICAL_TYPE_ELEMENT {
            segments.push(PathSegment::Element(value));
        } else {
            let kind = match logical_type {
                0x00 => LogicalKind::ClassId,
                0x04 => LogicalKind::InstanceId,
                0x0C => LogicalKind::ConnectionPoint,
                0x10 => LogicalKind::AttributeId,
                _ => break,
            };
            segments.push(PathSegment::Logical { kind, value });
        }
    }
    Ok((segments, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_program_scoped_tag() {
        // 0x91 "Program:Main" + 0x91 "MyTag"
        let bytes = [
            0x91, 12, b'P', b'r', b'o', b'g', b'r', b'a', b'm', b':', b'M', b'a', b'i', b'n',
            0x91, 5, b'M', b'y', b'T', b'a', b'g', 0x00,
        ];
        let (segs, consumed) = parse_epath(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(
            segs,
            vec![
                PathSegment::Symbolic("Program:Main".into()),
                PathSegment::Symbolic("MyTag".into()),
            ]
        );
    }

    #[test]
    fn parses_member_chain() {
        let bytes = [
            0x91, 5, b'M', b'o', b't', b'o', b'r', 0x00,
            0x91, 5, b'T', b'i', b'm', b'e', b'r', 0x00,
            0x91, 3, b'P', b'R', b'E', 0x00,
        ];
        let (segs, _) = parse_epath(&bytes).unwrap();
        assert_eq!(
            segs,
            vec![
                PathSegment::Symbolic("Motor".into()),
                PathSegment::Symbolic("Timer".into()),
                PathSegment::Symbolic("PRE".into()),
            ]
        );
    }

    #[test]
    fn parses_element_between_members() {
        // Line[2].Motor.Fault
        let bytes = [
            0x91, 4, b'L', b'i', b'n', b'e',
            0x28, 0x02,
            0x91, 5, b'M', b'o', b't', b'o', b'r', 0x00,
            0x91, 5, b'F', b'a', b'u', b'l', b't', 0x00,
        ];
        let (segs, _) = parse_epath(&bytes).unwrap();
        assert_eq!(
            segs,
            vec![
                PathSegment::Symbolic("Line".into()),
                PathSegment::Element(2),
                PathSegment::Symbolic("Motor".into()),
                PathSegment::Symbolic("Fault".into()),
            ]
        );
    }

    #[test]
    fn parses_multi_dim_indices() {
        // Matrix[1,2]
        let bytes = [
            0x91, 6, b'M', b'a', b't', b'r', b'i', b'x',
            0x28, 0x01,
            0x28, 0x02,
        ];
        let (segs, _) = parse_epath(&bytes).unwrap();
        assert_eq!(
            segs,
            vec![
                PathSegment::Symbolic("Matrix".into()),
                PathSegment::Element(1),
                PathSegment::Element(2),
            ]
        );
    }

    #[test]
    fn parses_class_instance_logical() {
        let bytes = [0x20, 0x06, 0x24, 0x01];
        let (segs, _) = parse_epath(&bytes).unwrap();
        assert_eq!(
            segs,
            vec![
                PathSegment::Logical { kind: LogicalKind::ClassId, value: 6 },
                PathSegment::Logical { kind: LogicalKind::InstanceId, value: 1 },
            ]
        );
    }

    #[test]
    fn parses_16_bit_instance() {
        // 0x25 pad 0x34 0x12 → instance 0x1234
        let bytes = [0x25, 0x00, 0x34, 0x12];
        let (segs, _) = parse_epath(&bytes).unwrap();
        assert_eq!(
            segs,
            vec![PathSegment::Logical { kind: LogicalKind::InstanceId, value: 0x1234 }]
        );
    }
}
