//! Walk a sequence of [`PathSegment`]s over a root [`TagEntry`], resolving
//! byte offset, resulting type code, element size, and (for BOOL members)
//! bit position inside the host byte.
//!
//! The walker mirrors the C# TagPathWalker: same set of rules, same error
//! surface. Used by the tag server's dispatcher whenever a request path
//! carries member or element segments past the root name.

use ethernetip_core::path_parse::PathSegment;

use crate::tag_registry::{TagEntry, TagRegistry};
use crate::types::CipType;

/// Successful walk result — enough for the caller to build a Read_Tag /
/// Write_Tag reply pointing at exactly the resolved sub-field of a tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkResult {
    pub offset: usize,
    pub type_code: u16,
    pub element_size: usize,
    /// `Some(0..=7)` when the target is a single BOOL member packed in a host
    /// byte, or a bit index inside a DWORD-packed BOOL array element.
    pub bit_pos: Option<u8>,
    pub template: Option<u16>,
}

/// Resolve the given segments against the root tag, using the registry's
/// template table to descend into nested struct members.
pub fn walk(
    root: &TagEntry,
    segments: &[PathSegment],
    registry: &TagRegistry,
) -> Result<WalkResult, String> {
    let mut offset = 0usize;
    let mut type_code: u16 = if root.cip_type == CipType::Struct {
        0x02A0
    } else {
        root.cip_type as u16
    };
    let mut element_size = root.cip_type.atomic_size().unwrap_or(root.element_size());
    let mut bit_pos: Option<u8> = None;
    // Pending array shape to be indexed (empty when nothing pending).
    let mut pending_dims: Option<Vec<u32>> = if !root.dims.is_empty() {
        Some(root.dims.clone())
    } else {
        None
    };
    let mut pending_dim_idx = 0usize;
    let mut pending_running: u64 = 0;
    let mut template: Option<u16> = root.template_id;
    let mut tpl_arc = template.and_then(|id| registry.get_template(id));

    // BOOL[] is DWORD-packed: bit-index rather than byte-index at the final
    // element segment.
    let root_is_bool_array = root.cip_type == CipType::Bool && !root.dims.is_empty();

    for seg in segments {
        match seg {
            PathSegment::Symbolic(name) => {
                if bit_pos.is_some() {
                    return Err(format!("cannot drill into BOOL member with `{name}`"));
                }
                if pending_dims.is_some() {
                    return Err(format!(
                        "cannot drill into array element without an index: `{name}`"
                    ));
                }
                // Look up the member and pull its fields into locals so tpl_arc
                // can be reassigned below without holding an immutable borrow.
                let (m_offset, m_type, m_array_size, m_element_size) = {
                    let tpl = tpl_arc
                        .as_ref()
                        .ok_or_else(|| format!("cannot resolve `{name}` on non-structure type"))?;
                    let member = tpl
                        .find_member(name)
                        .ok_or_else(|| format!("member `{name}` not found in `{}`", tpl.name))?;
                    (member.offset, member.data_type, member.array_size, member.element_size)
                };

                offset += m_offset;
                type_code = m_type;

                if type_code == CipType::Bool as u16 && m_element_size == 0 {
                    // Scalar BOOL member: array_size stores the bit position.
                    bit_pos = Some(m_array_size as u8);
                    element_size = 1;
                    tpl_arc = None;
                    template = None;
                } else if type_code & 0x8000 != 0 {
                    let tid = type_code & 0x0FFF;
                    let nested = registry
                        .get_template(tid)
                        .ok_or_else(|| format!("member `{name}` references unknown template 0x{tid:X}"))?;
                    element_size = nested.structure_size as usize;
                    tpl_arc = Some(nested);
                    template = Some(tid);
                    if m_array_size > 0 {
                        pending_dims = Some(vec![m_array_size]);
                        pending_dim_idx = 0;
                        pending_running = 0;
                    }
                } else {
                    tpl_arc = None;
                    template = None;
                    element_size = if m_element_size > 0 {
                        m_element_size
                    } else {
                        CipType::from_u16(type_code)
                            .and_then(|t| t.atomic_size())
                            .unwrap_or(1)
                    };
                    if m_array_size > 0 {
                        pending_dims = Some(vec![m_array_size]);
                        pending_dim_idx = 0;
                        pending_running = 0;
                    }
                }
            }
            PathSegment::Element(idx) => {
                if bit_pos.is_some() {
                    return Err("cannot index into a BOOL member".into());
                }
                let dims = pending_dims
                    .as_mut()
                    .ok_or_else(|| "element index on non-array target".to_string())?;
                let dim = dims[pending_dim_idx];
                if *idx >= dim {
                    return Err(format!(
                        "element index {idx} out of range for dim {pending_dim_idx} (size {dim})"
                    ));
                }
                pending_running = pending_running * dim as u64 + *idx as u64;
                pending_dim_idx += 1;
                if pending_dim_idx == dims.len() {
                    if root_is_bool_array {
                        offset += (pending_running / 8) as usize;
                        bit_pos = Some((pending_running % 8) as u8);
                    } else {
                        offset += pending_running as usize * element_size;
                    }
                    pending_dims = None;
                    pending_dim_idx = 0;
                    pending_running = 0;
                }
            }
            PathSegment::Logical { .. } => {
                // Class/instance/attribute segments were handled by the
                // outer dispatcher before the walker was invoked.
            }
        }
    }

    if pending_dims.is_some() {
        return Err(format!(
            "under-indexed array: expected {} element segments, got {}",
            pending_dims.as_ref().unwrap().len(),
            pending_dim_idx
        ));
    }

    Ok(WalkResult {
        offset,
        type_code,
        element_size,
        bit_pos,
        template,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_template::{ServerTemplate, ServerTemplateMember};

    fn timer_template() -> ServerTemplate {
        ServerTemplate {
            instance_id: 0x100,
            name: "Timer".into(),
            structure_handle: 0x8100,
            structure_size: 12,
            members: vec![
                ServerTemplateMember { name: "PRE".into(), data_type: 0x00C4, offset: 0, array_size: 0, element_size: 4 },
                ServerTemplateMember { name: "ACC".into(), data_type: 0x00C4, offset: 4, array_size: 0, element_size: 4 },
                ServerTemplateMember { name: "EN".into(),  data_type: 0x00C1, offset: 8, array_size: 0, element_size: 0 },
                ServerTemplateMember { name: "TT".into(),  data_type: 0x00C1, offset: 8, array_size: 1, element_size: 0 },
                ServerTemplateMember { name: "DN".into(),  data_type: 0x00C1, offset: 8, array_size: 2, element_size: 0 },
            ],
        }
    }

    #[test]
    fn resolves_scalar_member() {
        let reg = TagRegistry::new();
        let tpl_id = reg.add_template(timer_template()).unwrap();
        let inst = reg.add_struct_from_template("t1", &reg.get_template(tpl_id).unwrap()).unwrap();
        let root = reg.get_by_instance(inst).unwrap();

        let segs = vec![PathSegment::Symbolic("ACC".into())];
        let r = walk(&root, &segs, &reg).unwrap();
        assert_eq!(r.offset, 4);
        assert_eq!(r.type_code, 0x00C4);
        assert_eq!(r.bit_pos, None);
    }

    #[test]
    fn resolves_bool_member_bit_position() {
        let reg = TagRegistry::new();
        let tpl_id = reg.add_template(timer_template()).unwrap();
        let inst = reg.add_struct_from_template("t1", &reg.get_template(tpl_id).unwrap()).unwrap();
        let root = reg.get_by_instance(inst).unwrap();

        let segs = vec![PathSegment::Symbolic("DN".into())];
        let r = walk(&root, &segs, &reg).unwrap();
        assert_eq!(r.offset, 8);
        assert_eq!(r.bit_pos, Some(2));
    }

    #[test]
    fn under_indexed_multi_dim_errors() {
        let reg = TagRegistry::new();
        reg.add_multi_dim("m", CipType::Dint, &[5, 10, 4]).unwrap();
        let root = reg.get_by_name("m").unwrap();
        let segs = vec![PathSegment::Element(1), PathSegment::Element(2)];
        let err = walk(&root, &segs, &reg).unwrap_err();
        assert!(err.contains("under-indexed"), "got: {err}");
    }

    #[test]
    fn three_dim_row_major_offset() {
        let reg = TagRegistry::new();
        reg.add_multi_dim("m", CipType::Dint, &[5, 10, 4]).unwrap();
        let root = reg.get_by_name("m").unwrap();
        let segs = vec![PathSegment::Element(1), PathSegment::Element(2), PathSegment::Element(3)];
        let r = walk(&root, &segs, &reg).unwrap();
        // ((1*10+2)*4+3)*4 = 204
        assert_eq!(r.offset, 204);
    }

    #[test]
    fn bool_array_bit_index() {
        let reg = TagRegistry::new();
        reg.add_array("flags", CipType::Bool, 32).unwrap();
        let root = reg.get_by_name("flags").unwrap();
        let segs = vec![PathSegment::Element(5)];
        let r = walk(&root, &segs, &reg).unwrap();
        assert_eq!(r.offset, 0);
        assert_eq!(r.bit_pos, Some(5));
    }

    #[test]
    fn bool_array_across_dword_boundary() {
        let reg = TagRegistry::new();
        reg.add_array("big", CipType::Bool, 128).unwrap();
        let root = reg.get_by_name("big").unwrap();
        let segs = vec![PathSegment::Element(65)];
        let r = walk(&root, &segs, &reg).unwrap();
        assert_eq!(r.offset, 8);
        assert_eq!(r.bit_pos, Some(1));
    }
}
