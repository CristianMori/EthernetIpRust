//! Logix Template Object (class `0x6C`) reader and typed struct decoder.
//!
//! A tag whose Symbol Object reports `sym_type` with the structure bit set
//! carries a `template_instance_id` in its low 12 bits. That id resolves to
//! a Template Object instance whose four metadata attributes and definition
//! stream describe the struct layout: field names, types, and byte offsets.
//! With that in hand we can turn the opaque `TagValue::Struct { bytes }`
//! returned by `read_tag` into a named-field [`TypedValue::Struct`].

use std::collections::BTreeMap;

use bytes::Buf;

use ethernetip_core::cip::{class_codes as class, service_codes as service, status, ReplyHeader};
use ethernetip_core::error::{EipError, Result};
use ethernetip_core::path::EpathWriter;

use crate::types::CipType;

/// Symbol Object type descriptor bits, common to tag and template members.
///
/// Layout (little-endian u16):
///
/// ```text
///  bit 15    : 1 = structure, 0 = atomic
///  bit 14-13 : array dimension count (0..3)
///  bit 12    : reserved
///  bits 11-0 : template instance id (struct) OR atomic type code
/// ```
///
/// Held as a plain `u16` — the accessors interpret the bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymType(pub u16);

impl SymType {
    pub fn is_struct(self) -> bool {
        self.0 & 0x8000 != 0
    }

    /// 0 = scalar, 1..3 = number of array dimensions.
    pub fn array_dims(self) -> u8 {
        ((self.0 >> 13) & 0x03) as u8
    }

    /// Template instance id when [`Self::is_struct`] is true.
    pub fn template_id(self) -> Option<u16> {
        if self.is_struct() {
            Some(self.0 & 0x0FFF)
        } else {
            None
        }
    }

    /// Atomic CIP type code when [`Self::is_struct`] is false.
    /// The low 8 bits are the type; the CIP atomic codes live in that range
    /// (BOOL 0xC1 .. LREAL 0xCB).
    pub fn atomic_type_code(self) -> Option<u16> {
        if self.is_struct() {
            None
        } else {
            Some(0x00C0 | (self.0 & 0x00FF))
        }
    }
}

/// Fixed-size Template Object attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateHeader {
    /// Attribute 1: structure handle (a CRC computed over the layout).
    /// A [`crate::types::TagValue::Struct`] whose `crc` matches this handle
    /// is definitely of this template's shape; a mismatch means the PLC's
    /// UDT was edited since the template was last cached.
    pub crc: u16,
    /// Attribute 2: number of members in the struct.
    pub member_count: u16,
    /// Attribute 4: template object definition size, in 32-bit words.
    /// The definition byte stream returned by `Read_Template` totals
    /// `definition_size_dwords * 4 - 23` bytes (Logix quirk — the 23-byte
    /// trailer covers a padding + structure-name null-terminator area
    /// that never comes back over the wire).
    pub definition_size_dwords: u32,
    /// Attribute 5: total byte size of the actual struct payload.
    /// Matches `TagValue::Struct.bytes.len()` for a single-element read.
    pub structure_size_bytes: u32,
}

impl TemplateHeader {
    fn definition_body_size(&self) -> usize {
        (self.definition_size_dwords as usize)
            .saturating_mul(4)
            .saturating_sub(23)
    }
}

/// One member of a UDT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateMember {
    /// Field name (Logix identifier, ASCII).
    pub name: String,
    /// Type descriptor bits — same encoding as `SymType`.
    pub sym_type: SymType,
    /// For BOOL members, the low 3 bits are the bit position within the
    /// containing byte at `offset`. For array members, this carries the
    /// element count on some firmware versions; leave interpretation to
    /// [`decode_struct`] which is the only consumer.
    pub info: u16,
    /// Byte offset from the start of the struct payload.
    pub offset: u32,
}

/// A parsed Template Object definition — every field needed to decode a
/// struct payload of this shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateDefinition {
    /// Template name, with the Logix `;n=…` trailer stripped.
    pub name: String,
    /// Structure CRC handle from [`TemplateHeader::crc`].
    pub crc: u16,
    /// Total struct byte size from [`TemplateHeader::structure_size_bytes`].
    pub structure_size_bytes: u32,
    /// Members in declaration order.
    pub members: Vec<TemplateMember>,
}

/// Named, typed value — the result of decoding a raw `TagValue` against
/// its template. Structs carry a name-keyed map of members so callers can
/// walk them without touching wire bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
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
    /// Any type code not covered above — carried as raw bytes with the
    /// wire type. Common cases: SHORT_STRING, opaque vendor types.
    Raw {
        type_code: u16,
        bytes: Vec<u8>,
    },
    /// A UDT / nested structure. Keys are member names in declaration order
    /// (BTreeMap preserves lexicographic order — see [`Struct::members`] on
    /// the wrapper for insertion-order iteration if you need it).
    Struct {
        name: String,
        crc: u16,
        fields: BTreeMap<String, TypedValue>,
    },
}

/// Build a `Get_Attribute_List` request body for template attributes 1, 2,
/// 4, 5. Path targets Template Object class `0x6C`, instance `template_id`.
pub fn build_template_header_request(template_id: u16) -> (u8, Vec<u8>, Vec<u8>) {
    let mut path = EpathWriter::new();
    path.push_class(class::TEMPLATE_OBJECT);
    path.push_instance(template_id as u32);
    let attrs: [u16; 4] = [1, 2, 4, 5];
    let mut body = Vec::with_capacity(2 + attrs.len() * 2);
    body.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
    for a in attrs {
        body.extend_from_slice(&a.to_le_bytes());
    }
    (service::GET_ATTRIBUTE_LIST, path.into_bytes(), body)
}

/// Parse a `Get_Attribute_List` reply for template attributes 1, 2, 4, 5.
///
/// Reply body shape (Vol 1 §5-3.2):
///
/// ```text
///   UINT LE  attribute_count
///   for each returned attribute:
///     UINT LE  attribute_id
///     UINT LE  general_status
///     bytes    attribute_value  (size depends on attribute type)
/// ```
///
/// We tolerate the target returning the attributes in any order and require
/// success status on every one we requested.
pub fn parse_template_header_reply(reply: &[u8]) -> Result<TemplateHeader> {
    let header = ReplyHeader::parse(reply)?;
    if header.general_status != status::SUCCESS {
        return Err(EipError::Cip {
            status: header.general_status,
            ext: header.extended_status,
        });
    }
    let mut c = &reply[header.body_offset..];
    if c.remaining() < 2 {
        return Err(EipError::Short {
            expected: 2,
            actual: c.remaining(),
        });
    }
    let count = c.get_u16_le() as usize;
    let mut crc = None;
    let mut member_count = None;
    let mut definition_size_dwords = None;
    let mut structure_size_bytes = None;
    for _ in 0..count {
        if c.remaining() < 4 {
            return Err(EipError::Short {
                expected: 4,
                actual: c.remaining(),
            });
        }
        let attr_id = c.get_u16_le();
        let gs = c.get_u16_le();
        if gs != 0 {
            return Err(EipError::Cip {
                status: gs as u8,
                ext: Vec::new(),
            });
        }
        match attr_id {
            1 => {
                if c.remaining() < 2 {
                    return Err(EipError::Short {
                        expected: 2,
                        actual: c.remaining(),
                    });
                }
                crc = Some(c.get_u16_le());
            }
            2 => {
                if c.remaining() < 2 {
                    return Err(EipError::Short {
                        expected: 2,
                        actual: c.remaining(),
                    });
                }
                member_count = Some(c.get_u16_le());
            }
            4 => {
                if c.remaining() < 4 {
                    return Err(EipError::Short {
                        expected: 4,
                        actual: c.remaining(),
                    });
                }
                definition_size_dwords = Some(c.get_u32_le());
            }
            5 => {
                if c.remaining() < 4 {
                    return Err(EipError::Short {
                        expected: 4,
                        actual: c.remaining(),
                    });
                }
                structure_size_bytes = Some(c.get_u32_le());
            }
            other => {
                return Err(EipError::Protocol(format!(
                    "unexpected template attribute id {other} in reply"
                )));
            }
        }
    }
    Ok(TemplateHeader {
        crc: crc.ok_or_else(|| EipError::Protocol("template reply missing attr 1".into()))?,
        member_count: member_count
            .ok_or_else(|| EipError::Protocol("template reply missing attr 2".into()))?,
        definition_size_dwords: definition_size_dwords
            .ok_or_else(|| EipError::Protocol("template reply missing attr 4".into()))?,
        structure_size_bytes: structure_size_bytes
            .ok_or_else(|| EipError::Protocol("template reply missing attr 5".into()))?,
    })
}

/// Build one `Read_Template` request (service `0x4C`, same code as
/// `Read_Tag` but routed to the Template Object). Wire body is
/// `offset u32 + num_bytes u16`.
pub fn build_read_template_request(
    template_id: u16,
    offset: u32,
    num_bytes: u16,
) -> (u8, Vec<u8>, Vec<u8>) {
    let mut path = EpathWriter::new();
    path.push_class(class::TEMPLATE_OBJECT);
    path.push_instance(template_id as u32);
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&offset.to_le_bytes());
    body.extend_from_slice(&num_bytes.to_le_bytes());
    (service::READ_TAG, path.into_bytes(), body)
}

/// Parse a `Read_Template` chunk reply — returns just the raw definition
/// bytes at this chunk's offset, along with `done` (true when the CIP
/// status was `SUCCESS` rather than `PARTIAL_TRANSFER`).
pub fn parse_read_template_reply(reply: &[u8]) -> Result<(Vec<u8>, bool)> {
    let header = ReplyHeader::parse(reply)?;
    let done = match header.general_status {
        status::SUCCESS => true,
        status::PARTIAL_TRANSFER => false,
        _ => {
            return Err(EipError::Cip {
                status: header.general_status,
                ext: header.extended_status,
            });
        }
    };
    Ok((reply[header.body_offset..].to_vec(), done))
}

/// Parse the full concatenated Template Object definition body into a
/// [`TemplateDefinition`]. Requires the accompanying [`TemplateHeader`]
/// so member count and CRC can be attached without re-fetching.
///
/// Body layout, verified against Logix on-wire captures:
///
/// ```text
///   for i in 0..member_count:
///     UINT LE  info        (BOOL bit position in low 3 bits, else array_size)
///     UINT LE  sym_type    (same bit layout as SymType)
///     UDINT LE offset      (byte offset within the struct payload)
///
///   CString  template_name (null-terminated; may carry ";n=..." trailer
///                            that we strip)
///   for i in 0..member_count:
///     CString member_name  (null-terminated)
/// ```
pub fn parse_template_definition(
    header: &TemplateHeader,
    body: &[u8],
) -> Result<TemplateDefinition> {
    let n = header.member_count as usize;
    let entries_end = n * 8;
    if body.len() < entries_end {
        return Err(EipError::Short {
            expected: entries_end,
            actual: body.len(),
        });
    }
    let mut members = Vec::with_capacity(n);
    for i in 0..n {
        let off = i * 8;
        let info = u16::from_le_bytes([body[off], body[off + 1]]);
        let sym = u16::from_le_bytes([body[off + 2], body[off + 3]]);
        let member_offset = u32::from_le_bytes([
            body[off + 4],
            body[off + 5],
            body[off + 6],
            body[off + 7],
        ]);
        members.push(TemplateMember {
            name: String::new(),
            sym_type: SymType(sym),
            info,
            offset: member_offset,
        });
    }
    // Consume the template name (up to and including the null terminator).
    let mut cursor = entries_end;
    let name = read_cstring(body, &mut cursor)?;
    // The template name often has a trailer like ";n=8" indicating the
    // structure has 8 hidden bytes for its header (LEN+DATA for STRING,
    // etc). Strip everything from the first ';'.
    let name = name.split(';').next().unwrap_or(&name).to_string();
    // Then member names, in order.
    for m in &mut members {
        m.name = read_cstring(body, &mut cursor)?;
    }
    Ok(TemplateDefinition {
        name,
        crc: header.crc,
        structure_size_bytes: header.structure_size_bytes,
        members,
    })
}

fn read_cstring(body: &[u8], cursor: &mut usize) -> Result<String> {
    let start = *cursor;
    while *cursor < body.len() && body[*cursor] != 0 {
        *cursor += 1;
    }
    if *cursor >= body.len() {
        return Err(EipError::Protocol(
            "template definition ended mid-string".into(),
        ));
    }
    let s = String::from_utf8_lossy(&body[start..*cursor]).into_owned();
    *cursor += 1; // skip the null
    Ok(s)
}

/// Decode raw struct payload bytes into a named-field [`TypedValue`].
/// `resolve` is called for each nested struct member — return
/// `Some(child_template)` to recurse, or `None` to leave it as a `Raw`
/// blob (useful when the caller hasn't fetched the child template yet).
pub fn decode_struct<F>(
    def: &TemplateDefinition,
    bytes: &[u8],
    resolve: &F,
) -> Result<TypedValue>
where
    F: Fn(u16) -> Option<TemplateDefinition>,
{
    if bytes.len() < def.structure_size_bytes as usize {
        return Err(EipError::Short {
            expected: def.structure_size_bytes as usize,
            actual: bytes.len(),
        });
    }
    let mut fields = BTreeMap::new();
    for m in &def.members {
        let value = decode_member(m, bytes, resolve)?;
        fields.insert(m.name.clone(), value);
    }
    Ok(TypedValue::Struct {
        name: def.name.clone(),
        crc: def.crc,
        fields,
    })
}

fn decode_member<F>(
    m: &TemplateMember,
    bytes: &[u8],
    resolve: &F,
) -> Result<TypedValue>
where
    F: Fn(u16) -> Option<TemplateDefinition>,
{
    let off = m.offset as usize;
    if m.sym_type.is_struct() {
        // Nested struct — try to resolve, otherwise fall back to raw bytes.
        // We don't know the nested struct's size without its template, so
        // when the caller hasn't provided one we return the tail from the
        // offset onward and let them decode later.
        let child_id = m.sym_type.template_id().unwrap();
        if let Some(child) = resolve(child_id) {
            let size = child.structure_size_bytes as usize;
            if off + size > bytes.len() {
                return Err(EipError::Short {
                    expected: off + size,
                    actual: bytes.len(),
                });
            }
            return decode_struct(&child, &bytes[off..off + size], resolve);
        }
        return Ok(TypedValue::Raw {
            type_code: m.sym_type.0,
            bytes: bytes[off..].to_vec(),
        });
    }
    let code = m.sym_type.atomic_type_code().unwrap();
    match CipType::from_u16(code) {
        Some(CipType::Bool) => {
            // Info low 3 bits carry the bit position when BOOLs are packed.
            if off >= bytes.len() {
                return Err(EipError::Short {
                    expected: off + 1,
                    actual: bytes.len(),
                });
            }
            let bit = (m.info & 0x07) as u8;
            let value = (bytes[off] >> bit) & 0x01 != 0;
            Ok(TypedValue::Bool(value))
        }
        Some(ty) => {
            let size = ty.atomic_size().unwrap();
            if off + size > bytes.len() {
                return Err(EipError::Short {
                    expected: off + size,
                    actual: bytes.len(),
                });
            }
            let slice = &bytes[off..off + size];
            Ok(match ty {
                CipType::Sint => TypedValue::Sint(i8::from_le_bytes([slice[0]])),
                CipType::Usint => TypedValue::Usint(slice[0]),
                CipType::Int => TypedValue::Int(i16::from_le_bytes([slice[0], slice[1]])),
                CipType::Uint => TypedValue::Uint(u16::from_le_bytes([slice[0], slice[1]])),
                CipType::Dint => TypedValue::Dint(i32::from_le_bytes([
                    slice[0], slice[1], slice[2], slice[3],
                ])),
                CipType::Udint => TypedValue::Udint(u32::from_le_bytes([
                    slice[0], slice[1], slice[2], slice[3],
                ])),
                CipType::Real => TypedValue::Real(f32::from_le_bytes([
                    slice[0], slice[1], slice[2], slice[3],
                ])),
                CipType::Lint => TypedValue::Lint(i64::from_le_bytes([
                    slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6],
                    slice[7],
                ])),
                CipType::Ulint => TypedValue::Ulint(u64::from_le_bytes([
                    slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6],
                    slice[7],
                ])),
                CipType::Lreal => TypedValue::Lreal(f64::from_le_bytes([
                    slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6],
                    slice[7],
                ])),
                CipType::Bool | CipType::Struct => unreachable!(),
            })
        }
        None => {
            // Unknown atomic — expose as Raw at the member's offset. Length
            // is unknowable without a spec, so we grab the tail; harmless
            // because callers who care about size are the ones parsing the
            // spec anyway.
            Ok(TypedValue::Raw {
                type_code: code,
                bytes: bytes[off..].to_vec(),
            })
        }
    }
}

/// Recommended per-chunk byte count for `Read_Template`. Keeps the reply
/// well under a Logix `REPLY_TOO_LARGE` limit while minimising round trips.
pub const READ_TEMPLATE_CHUNK: u16 = 500;

/// Total bytes to fetch for the definition body — the caller drives the
/// loop and stops when it has accumulated this many bytes.
pub fn expected_definition_bytes(header: &TemplateHeader) -> usize {
    header.definition_body_size()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_atomic(type_code: u16) -> SymType {
        SymType(type_code & 0x00FF)
    }

    #[test]
    fn sym_type_atomic() {
        let s = make_atomic(0x00C4); // DINT
        assert!(!s.is_struct());
        assert_eq!(s.array_dims(), 0);
        assert_eq!(s.atomic_type_code(), Some(0x00C4));
        assert_eq!(s.template_id(), None);
    }

    #[test]
    fn sym_type_struct() {
        // structure bit set, template id 0x123
        let s = SymType(0x8000 | 0x0123);
        assert!(s.is_struct());
        assert_eq!(s.template_id(), Some(0x0123));
        assert_eq!(s.atomic_type_code(), None);
    }

    #[test]
    fn sym_type_array_dims() {
        // structure + 2 dims + template id
        let s = SymType(0x8000 | (2 << 13) | 0x0055);
        assert!(s.is_struct());
        assert_eq!(s.array_dims(), 2);
    }

    #[test]
    fn parse_header_reply_all_four_attrs() {
        // Build a synthetic reply: service | reserved | status=0 | ext_size=0
        //                          UINT count=4
        //                          attr1: id=1, gs=0, u16 crc = 0xABCD
        //                          attr2: id=2, gs=0, u16 count = 3
        //                          attr4: id=4, gs=0, u32 defsize = 10
        //                          attr5: id=5, gs=0, u32 structsize = 24
        let mut r = Vec::new();
        r.push(0x03 | 0x80); // reply service
        r.push(0x00); // reserved
        r.push(0x00); // general status
        r.push(0x00); // ext size
        r.extend_from_slice(&4u16.to_le_bytes());
        for (id, val) in [(1u16, 0xABCDu32), (2, 3)] {
            r.extend_from_slice(&id.to_le_bytes());
            r.extend_from_slice(&0u16.to_le_bytes());
            r.extend_from_slice(&(val as u16).to_le_bytes());
        }
        for (id, val) in [(4u16, 10u32), (5, 24)] {
            r.extend_from_slice(&id.to_le_bytes());
            r.extend_from_slice(&0u16.to_le_bytes());
            r.extend_from_slice(&val.to_le_bytes());
        }
        let h = parse_template_header_reply(&r).unwrap();
        assert_eq!(h.crc, 0xABCD);
        assert_eq!(h.member_count, 3);
        assert_eq!(h.definition_size_dwords, 10);
        assert_eq!(h.structure_size_bytes, 24);
        assert_eq!(h.definition_body_size(), 10 * 4 - 23);
    }

    fn dint_member() -> u16 {
        // atomic, dims=0, type=DINT (0xC4 → low byte 0xC4)
        CipType::Dint as u16 & 0x00FF
    }

    #[test]
    fn parse_definition_two_dints() {
        // Layout: two DINT members named "Alpha" and "Beta", struct size 8.
        let header = TemplateHeader {
            crc: 0x1234,
            member_count: 2,
            // definition_size chosen only to satisfy the sanity path; parse
            // doesn't consult it directly, only the body slice we pass in.
            definition_size_dwords: 0,
            structure_size_bytes: 8,
        };
        let mut body = Vec::new();
        // member 0: info=0, sym=DINT, offset=0
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&dint_member().to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        // member 1: info=0, sym=DINT, offset=4
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&dint_member().to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes());
        // template name "MyUdt;n=8\0"
        body.extend_from_slice(b"MyUdt;n=8\0");
        // member names
        body.extend_from_slice(b"Alpha\0");
        body.extend_from_slice(b"Beta\0");
        let def = parse_template_definition(&header, &body).unwrap();
        assert_eq!(def.name, "MyUdt");
        assert_eq!(def.members.len(), 2);
        assert_eq!(def.members[0].name, "Alpha");
        assert_eq!(def.members[0].offset, 0);
        assert_eq!(def.members[1].name, "Beta");
        assert_eq!(def.members[1].offset, 4);
    }

    #[test]
    fn decode_struct_two_dints() {
        let def = TemplateDefinition {
            name: "Pair".into(),
            crc: 0x1234,
            structure_size_bytes: 8,
            members: vec![
                TemplateMember {
                    name: "A".into(),
                    sym_type: SymType(dint_member()),
                    info: 0,
                    offset: 0,
                },
                TemplateMember {
                    name: "B".into(),
                    sym_type: SymType(dint_member()),
                    info: 0,
                    offset: 4,
                },
            ],
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&42i32.to_le_bytes());
        bytes.extend_from_slice(&(-7i32).to_le_bytes());
        let value = decode_struct(&def, &bytes, &|_| None).unwrap();
        if let TypedValue::Struct { fields, name, .. } = value {
            assert_eq!(name, "Pair");
            assert_eq!(fields["A"], TypedValue::Dint(42));
            assert_eq!(fields["B"], TypedValue::Dint(-7));
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn decode_struct_packed_bools() {
        // Three BOOL members packed into a single byte at offset 0, bits 0/1/2.
        let bool_ty = SymType(CipType::Bool as u16 & 0x00FF);
        let def = TemplateDefinition {
            name: "Flags".into(),
            crc: 0,
            structure_size_bytes: 1,
            members: vec![
                TemplateMember {
                    name: "B0".into(),
                    sym_type: bool_ty,
                    info: 0,
                    offset: 0,
                },
                TemplateMember {
                    name: "B1".into(),
                    sym_type: bool_ty,
                    info: 1,
                    offset: 0,
                },
                TemplateMember {
                    name: "B2".into(),
                    sym_type: bool_ty,
                    info: 2,
                    offset: 0,
                },
            ],
        };
        let value = decode_struct(&def, &[0b0000_0101], &|_| None).unwrap();
        if let TypedValue::Struct { fields, .. } = value {
            assert_eq!(fields["B0"], TypedValue::Bool(true));
            assert_eq!(fields["B1"], TypedValue::Bool(false));
            assert_eq!(fields["B2"], TypedValue::Bool(true));
        } else {
            panic!("expected struct");
        }
    }

    #[test]
    fn decode_struct_nested_via_resolver() {
        // Outer has one INT and one nested-struct member; the nested struct
        // has two SINT members.
        let nested = TemplateDefinition {
            name: "Inner".into(),
            crc: 0xBEEF,
            structure_size_bytes: 2,
            members: vec![
                TemplateMember {
                    name: "X".into(),
                    sym_type: SymType(CipType::Sint as u16 & 0x00FF),
                    info: 0,
                    offset: 0,
                },
                TemplateMember {
                    name: "Y".into(),
                    sym_type: SymType(CipType::Sint as u16 & 0x00FF),
                    info: 0,
                    offset: 1,
                },
            ],
        };
        let outer = TemplateDefinition {
            name: "Outer".into(),
            crc: 0xCAFE,
            structure_size_bytes: 4,
            members: vec![
                TemplateMember {
                    name: "N".into(),
                    sym_type: SymType(CipType::Int as u16 & 0x00FF),
                    info: 0,
                    offset: 0,
                },
                TemplateMember {
                    name: "Sub".into(),
                    sym_type: SymType(0x8000 | 0x0042), // struct id 0x42
                    info: 0,
                    offset: 2,
                },
            ],
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1234i16.to_le_bytes());
        bytes.push(9i8 as u8);
        bytes.push((-3i8) as u8);
        let nested_clone = nested.clone();
        let value = decode_struct(&outer, &bytes, &|id| {
            if id == 0x0042 {
                Some(nested_clone.clone())
            } else {
                None
            }
        })
        .unwrap();
        if let TypedValue::Struct { fields, .. } = value {
            assert_eq!(fields["N"], TypedValue::Int(1234));
            if let TypedValue::Struct { fields: inner, name, .. } = &fields["Sub"] {
                assert_eq!(name, "Inner");
                assert_eq!(inner["X"], TypedValue::Sint(9));
                assert_eq!(inner["Y"], TypedValue::Sint(-3));
            } else {
                panic!("nested member should be a Struct");
            }
        } else {
            panic!("expected struct");
        }
    }
}
