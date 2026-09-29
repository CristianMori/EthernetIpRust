//! Server-side template layout used by [`crate::tag_registry::TagRegistry`].
//!
//! Distinct from [`crate::template::TemplateHeader`] etc, which are CLIENT-side
//! decoded views of a Template Object read off the wire. This module owns the
//! authoritative in-memory layout the server uses to answer Template_Read and
//! to drive the walker through nested struct members.

/// One resolved member of a UDT — offsets and element sizes are already
/// computed by the caller so the server never needs to recompute them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerTemplateMember {
    pub name: String,
    /// CIP data type code. When the member is itself a struct, the 0x8000
    /// bit is set and the low 12 bits are the nested template's instance id.
    pub data_type: u16,
    /// Byte offset inside the parent structure.
    pub offset: usize,
    /// Array length for member arrays; 0 for scalars.  Note: for a scalar
    /// BOOL member this field carries the bit position (0..=7) — the packing
    /// convention matches the C# implementation.
    pub array_size: u32,
    /// Bytes per element (0 for BOOL scalars — see array_size doc).
    pub element_size: usize,
}

/// A resolved UDT layout.  Populated by the transpiler or by application code
/// from an L5X export; the server does not recompute offsets.
#[derive(Debug, Clone)]
pub struct ServerTemplate {
    pub instance_id: u16,
    pub name: String,
    /// Structure handle used as the tag type parameter in Read/Write_Tag.
    pub structure_handle: u16,
    /// Total size in bytes on the wire.
    pub structure_size: u32,
    pub members: Vec<ServerTemplateMember>,
}

impl ServerTemplate {
    pub fn find_member(&self, name: &str) -> Option<&ServerTemplateMember> {
        self.members
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
    }

    /// Template Object attribute 4: definition size in 32-bit words.  Matches
    /// the C# TemplateDefinition.DefinitionSize computation.
    pub fn definition_size_dwords(&self) -> u32 {
        let mut name_bytes = self.name.len() + 1;
        for m in &self.members {
            name_bytes += m.name.len() + 1;
        }
        let total = self.members.len() * 8 + name_bytes;
        let padded = ((total + 3) / 4) * 4;
        (padded / 4) as u32 + 6
    }
}
