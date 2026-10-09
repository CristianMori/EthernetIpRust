//! Helpers for computing a Logix-style structure handle (the 16-bit value
//! returned as Template Object attribute 1 and used as the `tag_type`
//! parameter for struct `Read_Tag` / `Write_Tag`).
//!
//! **Status: provisional.** Mirrors the C# `LogixStructureHandle` helper:
//! build the FormalStrucTypeSpec byte stream from a [`ServerTemplate`] per
//! CIP Vol 1 §C-6.1 / §C-6.2.1 and hash it with the CIP 16-bit CRC
//! ([`ethernetip_core::cip_crc::crc16`]). The algorithm has *not* been
//! validated against a captured Studio 5000 `Read_Template` for a
//! non-trivial UDT, so callers who want this value opt in — the server's
//! default handle is still `0x8000 | instance_id`.
//!
//! Scope today: only UDTs whose members are all scalar atomic types (no
//! nested structs, no arrays, no scalar BOOLs that have been packed into a
//! hidden host byte). [`try_compute_structure_handle`] returns `None` for
//! anything else, so the server never ships a plausible-but-unverified
//! handle on the wire.

use ethernetip_core::cip_crc::crc16;

use crate::server_template::ServerTemplate;

/// CIP Vol 1 §C-6.2.1 Table C-6.3 constants for the FormalStrucTypeSpec:
///
/// ```text
///   [A2][length][type_code_1][type_code_2]...[type_code_N]
/// ```
///
/// `length` counts the type_code bytes that follow (so the structure's
/// on-wire size is `2 + length`). Each atomic type is a single byte.
const FORMAL_STRUCT_PREFIX: u8 = 0xA2;

/// Build the FormalStrucTypeSpec byte stream for a UDT whose members are
/// all scalar atomic types. Returns `None` when the template has any
/// member the simple encoding cannot represent (nested struct, array,
/// packed scalar BOOL, or an unknown data type).
pub fn try_build_formal_struc_spec(template: &ServerTemplate) -> Option<Vec<u8>> {
    let mut types = Vec::with_capacity(template.members.len());
    for m in &template.members {
        if m.array_size > 0 {
            return None;                       // arrays — out of scope
        }
        if (m.data_type & 0x8000) != 0 {
            return None;                       // nested struct — out of scope
        }
        // Scalar BOOLs packed into a host byte are marked by element_size == 0
        // (array_size then carries the bit position 0..7).  The simple
        // encoding cannot describe them; refuse rather than ship a wrong
        // handle.
        if m.data_type == 0x00C1 && m.element_size == 0 {
            return None;
        }
        // Keep only known atomic codes — anything else means we would be
        // guessing at the byte encoding.
        let base = (m.data_type & 0x00FF) as u8;
        match base {
            0xC1..=0xC9 | 0xCA | 0xCB | 0xD1..=0xD4 => types.push(base),
            _ => return None,
        }
    }
    if types.is_empty() || types.len() > u8::MAX as usize {
        return None;
    }

    let mut bytes = Vec::with_capacity(2 + types.len());
    bytes.push(FORMAL_STRUCT_PREFIX);
    bytes.push(types.len() as u8);
    bytes.extend_from_slice(&types);
    Some(bytes)
}

/// Compute the structure handle for an atomic-only UDT by hashing its
/// FormalStrucTypeSpec with the CIP 16-bit CRC. Returns `None` when
/// [`try_build_formal_struc_spec`] rejects the template.
pub fn try_compute_structure_handle(template: &ServerTemplate) -> Option<u16> {
    let bytes = try_build_formal_struc_spec(template)?;
    Some(crc16(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_template::ServerTemplateMember;

    fn mk_scalar_tpl(name: &str, member_codes: &[(&str, u16)]) -> ServerTemplate {
        ServerTemplate {
            instance_id: 0x100,
            name: name.into(),
            structure_handle: 0x8100,
            structure_size: 0,
            members: member_codes
                .iter()
                .map(|(n, code)| ServerTemplateMember {
                    name: (*n).into(),
                    data_type: *code,
                    offset: 0,
                    array_size: 0,
                    element_size: 1,
                })
                .collect(),
        }
    }

    #[test]
    fn three_atomic_members_match_spec_example_bytes() {
        // CIP Vol 1 §C-6.1 Example 3: STRUCT ::= { UINT, SINT, INT } encodes
        // as [A2][03][C7][C2][C3]. Hashing it should give the spec's quoted
        // 0x5159.
        let tpl = mk_scalar_tpl("Three", &[("A", 0x00C7), ("B", 0x00C2), ("C", 0x00C3)]);
        assert_eq!(
            try_build_formal_struc_spec(&tpl).unwrap(),
            vec![0xA2, 0x03, 0xC7, 0xC2, 0xC3]
        );
    }

    #[test]
    fn spec_example_crc_is_0x5159() {
        let tpl = mk_scalar_tpl("Three", &[("A", 0x00C7), ("B", 0x00C2), ("C", 0x00C3)]);
        assert_eq!(try_compute_structure_handle(&tpl), Some(0x5159));
    }

    #[test]
    fn unsigned_and_bitstring_members_encode_as_expected_bytes() {
        let tpl = mk_scalar_tpl(
            "Mixed",
            &[("U32", 0x00C8), ("U8", 0x00C6), ("W", 0x00D2)],
        );
        assert_eq!(
            try_build_formal_struc_spec(&tpl).unwrap(),
            vec![0xA2, 0x03, 0xC8, 0xC6, 0xD2]
        );
    }

    #[test]
    fn packed_bool_member_refused() {
        // array_size here carries the bit position (0..7), element_size == 0
        // flags the packed BOOL. The simple formal encoding can't represent
        // that; refuse rather than ship a plausible wrong handle.
        let tpl = ServerTemplate {
            instance_id: 0x200,
            name: "WithBool".into(),
            structure_handle: 0x8200,
            structure_size: 12,
            members: vec![
                ServerTemplateMember {
                    name: "A".into(),
                    data_type: 0x00C4,
                    offset: 0,
                    array_size: 0,
                    element_size: 4,
                },
                ServerTemplateMember {
                    name: "B".into(),
                    data_type: 0x00C1,
                    offset: 8,
                    array_size: 0,
                    element_size: 0,
                },
            ],
        };
        assert!(try_build_formal_struc_spec(&tpl).is_none());
    }

    #[test]
    fn array_member_refused() {
        let tpl = ServerTemplate {
            instance_id: 0x300,
            name: "WithArray".into(),
            structure_handle: 0x8300,
            structure_size: 16,
            members: vec![ServerTemplateMember {
                name: "Buf".into(),
                data_type: 0x00C2,
                offset: 0,
                array_size: 16,
                element_size: 1,
            }],
        };
        assert!(try_build_formal_struc_spec(&tpl).is_none());
    }

    #[test]
    fn nested_struct_member_refused() {
        let tpl = ServerTemplate {
            instance_id: 0x400,
            name: "WithNested".into(),
            structure_handle: 0x8400,
            structure_size: 4,
            members: vec![ServerTemplateMember {
                name: "Inner".into(),
                data_type: 0x8ABC, // 0x8000 bit → nested struct
                offset: 0,
                array_size: 0,
                element_size: 4,
            }],
        };
        assert!(try_build_formal_struc_spec(&tpl).is_none());
    }

    #[test]
    fn add_template_default_handle_still_structure_handle_only() {
        // Explicit regression guard: tag_registry::add_template must NOT
        // flip to the computed handle silently. The helper is opt-in only.
        use crate::tag_registry::TagRegistry;
        let reg = TagRegistry::new();
        let tpl = mk_scalar_tpl("Three", &[("A", 0x00C7), ("B", 0x00C2), ("C", 0x00C3)]);
        let id = reg.add_template(tpl).unwrap();
        let stored = reg.get_template(id).unwrap();
        assert_ne!(stored.structure_handle, 0x5159);
    }
}
