//! In-memory tag database used by [`crate::tag_server::TagServer`].
//!
//! Each entry has a stable [`Symbol Object`] instance id assigned at insert
//! time, an atomic CIP type or a struct type descriptor, and a data buffer
//! sized to `element_size * element_count`. Reads and writes take a lock only
//! for the update itself — the buffer is copied out to the caller.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ethernetip_core::error::{EipError, Result};

use crate::server_template::ServerTemplate;
use crate::types::CipType;

/// Combined `sym_type` bits reported for a struct entry — the top bit set
/// distinguishes structures from atomic types, and the low 12 bits are the
/// template CRC / handle. We use `0x02A0` as a stand-in when the caller
/// doesn't supply a real template.
pub const DEFAULT_STRUCT_SYM_TYPE: u16 = 0x02A0;

#[derive(Debug, Clone)]
pub struct TagEntry {
    pub instance: u32,
    pub name: String,
    /// Wire-format symbol type reported back through browse (the low byte is
    /// usually the atomic type code; struct entries have the high bit set).
    pub sym_type: u16,
    /// CIP atomic type code, or `CipType::Struct` for structures.
    pub cip_type: CipType,
    /// Number of elements — 1 for scalars, product of `dims` for arrays.
    pub element_count: u32,
    /// Array dimension sizes (empty for scalars, one entry for a 1-D array,
    /// up to three entries for a multi-dimensional array). Symbol Object
    /// attribute 8 emits three UDINTs (0-padded).
    pub dims: Vec<u32>,
    /// Template instance id when this tag is backed by a UDT — used by the
    /// walker to look up the layout via [`TagRegistry::get_template`].
    pub template_id: Option<u16>,
    /// The tag's on-wire payload. For atomics its size is
    /// `element_size * element_count`; for structures it is whatever the
    /// caller wrote.  BOOL arrays are DWORD-packed (bit-count / 8 bytes).
    pub data: Vec<u8>,
}

impl TagEntry {
    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    pub fn atomic_size(&self) -> Option<usize> {
        self.cip_type.atomic_size()
    }

    /// Bytes per element as the walker sees them (defaults to the atomic size
    /// when known; falls back to the whole buffer for opaque structs).
    pub fn element_size(&self) -> usize {
        self.atomic_size().unwrap_or(self.data.len())
    }
}

#[derive(Debug, Default)]
struct RegistryInner {
    by_instance: HashMap<u32, TagEntry>,
    by_name: HashMap<String, u32>,
    next_instance: u32,
    templates: HashMap<u16, Arc<ServerTemplate>>,
    next_template: u16,
    programs: HashMap<String, ProgramScope>,
    next_program_pseudo: u32,
    /// When true, per-write dirty tracking / observer hooks are bypassed.
    suppress_events: bool,
    /// Set of tag instance ids that were written since the last drain.
    dirty: std::collections::HashSet<u32>,
    dirty_tracking: bool,
}

/// A named program scope with its own tag table (name → tag entry).
#[derive(Debug, Default, Clone)]
pub struct ProgramScope {
    pub pseudo_instance: u32,
    pub tags: HashMap<String, TagEntry>,
    pub next_instance: u32,
}

/// Thread-safe registry of Logix tags.
#[derive(Debug, Clone, Default)]
pub struct TagRegistry {
    inner: Arc<RwLock<RegistryInner>>,
}

impl TagRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RegistryInner {
                next_instance: 1,
                next_template: 0x100,
                next_program_pseudo: 0xF000,
                ..Default::default()
            })),
        }
    }

    /// Insert a scalar atomic tag. Returns the assigned instance id.
    pub fn add_atomic(&self, name: impl Into<String>, ty: CipType) -> Result<u32> {
        self.add_array(name, ty, 1)
    }

    /// Insert a 1-D atomic array tag.  BOOL arrays are DWORD-packed and
    /// require element_count to be a multiple of 32.
    pub fn add_array(&self, name: impl Into<String>, ty: CipType, elements: u32) -> Result<u32> {
        if ty == CipType::Struct {
            return Err(EipError::Protocol(
                "add_array is for atomic types; use add_struct".into(),
            ));
        }
        let (data_size, dims) = self.compute_atomic_storage(ty, &[elements])?;
        let sym_type = ty as u16 | if elements > 1 { 1 << 13 } else { 0 };
        let data = vec![0u8; data_size];
        self.insert_entry(name.into(), sym_type, ty, elements, dims, None, data)
    }

    /// Insert a multi-dimensional atomic array tag (up to 3 dims).
    pub fn add_multi_dim(
        &self,
        name: impl Into<String>,
        ty: CipType,
        dims: &[u32],
    ) -> Result<u32> {
        if !(1..=3).contains(&dims.len()) {
            return Err(EipError::Protocol(
                "dims.len() must be 1, 2, or 3".into(),
            ));
        }
        let (data_size, dims_vec) = self.compute_atomic_storage(ty, dims)?;
        let element_count: u32 = dims.iter().product();
        let sym_type = ty as u16 | ((dims.len() as u16 & 0x03) << 13);
        let data = vec![0u8; data_size];
        self.insert_entry(name.into(), sym_type, ty, element_count, dims_vec, None, data)
    }

    fn compute_atomic_storage(&self, ty: CipType, dims: &[u32]) -> Result<(usize, Vec<u32>)> {
        let element_count: u32 = dims.iter().product();
        if ty == CipType::Bool && element_count > 1 {
            if element_count % 32 != 0 {
                return Err(EipError::Protocol(format!(
                    "BOOL array element count must be a multiple of 32 (got {element_count})"
                )));
            }
            return Ok(((element_count / 8) as usize, dims.to_vec()));
        }
        let per = ty
            .atomic_size()
            .ok_or_else(|| EipError::Protocol("unknown atomic size".into()))?;
        Ok((per * element_count as usize, dims.to_vec()))
    }

    /// Insert a struct tag with an already-encoded blob.
    pub fn add_struct(
        &self,
        name: impl Into<String>,
        template_handle: u16,
        blob: Vec<u8>,
    ) -> Result<u32> {
        let sym_type = 0x8000 | (template_handle & 0x0FFF);
        self.insert_entry(
            name.into(),
            sym_type,
            CipType::Struct,
            1,
            Vec::new(),
            Some(template_handle & 0x0FFF),
            blob,
        )
    }

    /// Insert a struct tag backed by a registered template.  Allocates a
    /// zero-initialised buffer of `template.structure_size` bytes.
    pub fn add_struct_from_template(
        &self,
        name: impl Into<String>,
        template: &ServerTemplate,
    ) -> Result<u32> {
        let sym_type = 0x8000 | (template.instance_id & 0x0FFF);
        let data = vec![0u8; template.structure_size as usize];
        self.insert_entry(
            name.into(),
            sym_type,
            CipType::Struct,
            1,
            Vec::new(),
            Some(template.instance_id),
            data,
        )
    }

    fn insert_entry(
        &self,
        name: String,
        sym_type: u16,
        cip_type: CipType,
        element_count: u32,
        dims: Vec<u32>,
        template_id: Option<u16>,
        data: Vec<u8>,
    ) -> Result<u32> {
        let mut guard = self.inner.write().unwrap();
        if guard.by_name.contains_key(&name) {
            return Err(EipError::Protocol(format!(
                "tag `{}` already registered",
                name
            )));
        }
        let instance = guard.next_instance;
        guard.next_instance = guard.next_instance.wrapping_add(1);
        // Order matters: publish to by_instance BEFORE by_name so a concurrent
        // reader that resolves the tag by name always sees a fully-published
        // instance-id entry (mirrors the C# gap-7 fix).
        let entry = TagEntry {
            instance,
            name: name.clone(),
            sym_type,
            cip_type,
            element_count,
            dims,
            template_id,
            data,
        };
        guard.by_instance.insert(instance, entry);
        guard.by_name.insert(name, instance);
        Ok(instance)
    }

    pub fn get_by_name(&self, name: &str) -> Option<TagEntry> {
        let guard = self.inner.read().unwrap();
        let instance = *guard.by_name.get(name)?;
        guard.by_instance.get(&instance).cloned()
    }

    pub fn get_by_instance(&self, instance: u32) -> Option<TagEntry> {
        self.inner
            .read()
            .unwrap()
            .by_instance
            .get(&instance)
            .cloned()
    }

    /// Replace a tag's data buffer. Length must match the registered size.
    pub fn set_by_name(&self, name: &str, data: &[u8]) -> Result<()> {
        self.set_by_name_with_flag(name, data, false)
    }

    /// Silent variant — bypasses dirty tracking.  For gap 8: the transpiler-
    /// generated scan calls this hundreds of thousands of times per scan and
    /// has no consumer for per-write notifications.
    pub fn set_by_name_silent(&self, name: &str, data: &[u8]) -> Result<()> {
        self.set_by_name_with_flag(name, data, true)
    }

    fn set_by_name_with_flag(&self, name: &str, data: &[u8], silent: bool) -> Result<()> {
        let mut guard = self.inner.write().unwrap();
        let Some(&instance) = guard.by_name.get(name) else {
            return Err(EipError::Protocol(format!("no such tag `{}`", name)));
        };
        let entry = guard.by_instance.get_mut(&instance).unwrap();
        if data.len() != entry.data.len() {
            return Err(EipError::Protocol(format!(
                "tag `{}` expects {} bytes, got {}",
                name,
                entry.data.len(),
                data.len()
            )));
        }
        entry.data.copy_from_slice(data);
        if !silent && !guard.suppress_events && guard.dirty_tracking {
            guard.dirty.insert(instance);
        }
        Ok(())
    }

    /// Write a slice at an arbitrary byte offset inside a tag's buffer.
    /// Used by the walker path after resolving `Motor.Timer.PRE` → offset.
    pub fn set_bytes_at(&self, instance: u32, offset: usize, bytes: &[u8]) -> Result<()> {
        let mut guard = self.inner.write().unwrap();
        let entry = guard
            .by_instance
            .get_mut(&instance)
            .ok_or_else(|| EipError::Protocol(format!("no tag instance {instance}")))?;
        if offset + bytes.len() > entry.data.len() {
            return Err(EipError::Protocol(format!(
                "write past end of tag (offset {offset}, len {}, capacity {})",
                bytes.len(),
                entry.data.len()
            )));
        }
        entry.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        if !guard.suppress_events && guard.dirty_tracking {
            guard.dirty.insert(instance);
        }
        Ok(())
    }

    /// Read a slice at an arbitrary byte offset from a tag's buffer.
    pub fn get_bytes_at(&self, instance: u32, offset: usize, len: usize) -> Option<Vec<u8>> {
        let guard = self.inner.read().unwrap();
        let entry = guard.by_instance.get(&instance)?;
        if offset + len > entry.data.len() {
            return None;
        }
        Some(entry.data[offset..offset + len].to_vec())
    }

    /// Atomic bit set/clear on a host byte inside a tag's buffer.  Used by
    /// the walker's BOOL bit write path so two concurrent writes to different
    /// bits of the same host byte don't stomp each other.
    pub fn atomic_set_bit(
        &self,
        instance: u32,
        offset: usize,
        bit: u8,
        value: bool,
    ) -> Result<()> {
        let mut guard = self.inner.write().unwrap();
        let entry = guard
            .by_instance
            .get_mut(&instance)
            .ok_or_else(|| EipError::Protocol(format!("no tag instance {instance}")))?;
        if offset >= entry.data.len() || bit > 7 {
            return Err(EipError::Protocol("bit or offset out of range".into()));
        }
        let mask = 1u8 << bit;
        if value {
            entry.data[offset] |= mask;
        } else {
            entry.data[offset] &= !mask;
        }
        if !guard.suppress_events && guard.dirty_tracking {
            guard.dirty.insert(instance);
        }
        Ok(())
    }

    /// Ordered list of `(instance, name, sym_type)` entries used to answer
    /// `Get_Instance_Attribute_List` sweeps. Sorted by instance id so browsing
    /// resumes correctly across chunk boundaries.
    pub fn browse_entries(&self) -> Vec<(u32, String, u16)> {
        let guard = self.inner.read().unwrap();
        let mut rows: Vec<_> = guard
            .by_instance
            .values()
            .map(|e| (e.instance, e.name.clone(), e.sym_type))
            .collect();
        // Also emit a Program:<name> pseudo-tag per registered program.
        for (name, program) in &guard.programs {
            rows.push((program.pseudo_instance, format!("Program:{name}"), 0x1068));
        }
        rows.sort_by_key(|r| r.0);
        rows
    }

    /// Array dimensions for a given tag instance — used by Symbol Object
    /// attribute 8 (which needs three UDINTs).
    pub fn dims_for(&self, instance: u32) -> Vec<u32> {
        self.inner
            .read()
            .unwrap()
            .by_instance
            .get(&instance)
            .map(|e| e.dims.clone())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().by_instance.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // --- Template management ---

    /// Register a pre-resolved template.  If `template.instance_id == 0` a
    /// fresh id is allocated in the auto range; otherwise the caller's id is
    /// used and the auto counter bumped past it.
    pub fn add_template(&self, mut template: ServerTemplate) -> Result<u16> {
        let mut guard = self.inner.write().unwrap();
        if template.instance_id == 0 {
            template.instance_id = guard.next_template;
            guard.next_template = guard.next_template.wrapping_add(1);
        } else {
            if guard.templates.contains_key(&template.instance_id) {
                return Err(EipError::Protocol(format!(
                    "template with instance id 0x{:04X} already exists",
                    template.instance_id
                )));
            }
            if template.instance_id >= guard.next_template {
                guard.next_template = template.instance_id.wrapping_add(1);
            }
        }
        let id = template.instance_id;
        guard.templates.insert(id, Arc::new(template));
        Ok(id)
    }

    pub fn get_template(&self, id: u16) -> Option<Arc<ServerTemplate>> {
        self.inner.read().unwrap().templates.get(&id).cloned()
    }

    pub fn all_templates(&self) -> Vec<Arc<ServerTemplate>> {
        self.inner.read().unwrap().templates.values().cloned().collect()
    }

    // --- Program scope management ---

    /// Register (or return the pseudo id of) a program scope by name.
    pub fn register_program(&self, name: &str) -> u32 {
        let mut guard = self.inner.write().unwrap();
        if let Some(existing) = guard.programs.get(name) {
            return existing.pseudo_instance;
        }
        let pseudo = guard.next_program_pseudo;
        guard.next_program_pseudo = guard.next_program_pseudo.wrapping_add(1);
        guard.programs.insert(
            name.to_string(),
            ProgramScope {
                pseudo_instance: pseudo,
                tags: HashMap::new(),
                next_instance: 1,
            },
        );
        pseudo
    }

    pub fn program_pseudo_id(&self, name: &str) -> Option<u32> {
        self.inner
            .read()
            .unwrap()
            .programs
            .get(name)
            .map(|p| p.pseudo_instance)
    }

    /// Add an atomic tag inside a program scope.  Returns the program-local
    /// Symbol Object instance id.
    pub fn add_program_atomic(
        &self,
        program: &str,
        name: impl Into<String>,
        ty: CipType,
    ) -> Result<u32> {
        let name = name.into();
        let size = ty
            .atomic_size()
            .ok_or_else(|| EipError::Protocol("unknown atomic size".into()))?;
        let sym_type = ty as u16;
        let mut guard = self.inner.write().unwrap();
        let program_entry = guard
            .programs
            .get_mut(program)
            .ok_or_else(|| EipError::Protocol(format!("program `{program}` not registered")))?;
        if program_entry.tags.contains_key(&name) {
            return Err(EipError::Protocol(format!(
                "tag `{name}` already registered in program `{program}`"
            )));
        }
        let inst = program_entry.next_instance;
        program_entry.next_instance = program_entry.next_instance.wrapping_add(1);
        let entry = TagEntry {
            instance: inst,
            name: name.clone(),
            sym_type,
            cip_type: ty,
            element_count: 1,
            dims: Vec::new(),
            template_id: None,
            data: vec![0u8; size],
        };
        program_entry.tags.insert(name, entry);
        Ok(inst)
    }

    /// Look up a program-scoped tag by name.
    pub fn get_program_tag(&self, program: &str, name: &str) -> Option<TagEntry> {
        let guard = self.inner.read().unwrap();
        guard.programs.get(program)?.tags.get(name).cloned()
    }

    /// Overwrite a program-scoped tag's buffer.
    pub fn set_program_tag_bytes(
        &self,
        program: &str,
        name: &str,
        offset: usize,
        bytes: &[u8],
    ) -> Result<()> {
        let mut guard = self.inner.write().unwrap();
        let program_entry = guard
            .programs
            .get_mut(program)
            .ok_or_else(|| EipError::Protocol(format!("program `{program}` not registered")))?;
        let entry = program_entry
            .tags
            .get_mut(name)
            .ok_or_else(|| EipError::Protocol(format!("no such tag `{name}` in program `{program}`")))?;
        if offset + bytes.len() > entry.data.len() {
            return Err(EipError::Protocol("write past end of tag".into()));
        }
        entry.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn all_programs(&self) -> Vec<(String, u32)> {
        self.inner
            .read()
            .unwrap()
            .programs
            .iter()
            .map(|(n, p)| (n.clone(), p.pseudo_instance))
            .collect()
    }

    // --- Gap 8: event suppression + dirty tracking ---

    pub fn set_suppress_events(&self, suppress: bool) {
        self.inner.write().unwrap().suppress_events = suppress;
    }

    pub fn enable_dirty_tracking(&self) {
        self.inner.write().unwrap().dirty_tracking = true;
    }

    pub fn disable_dirty_tracking(&self) {
        let mut g = self.inner.write().unwrap();
        g.dirty_tracking = false;
        g.dirty.clear();
    }

    pub fn drain_dirty(&self) -> Vec<u32> {
        let mut g = self.inner.write().unwrap();
        let out: Vec<u32> = g.dirty.iter().copied().collect();
        g.dirty.clear();
        out
    }
}
