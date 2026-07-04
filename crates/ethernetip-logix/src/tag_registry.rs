//! In-memory tag database used by [`crate::tag_server::TagServer`].
//!
//! Each entry has a stable [`Symbol Object`] instance id assigned at insert
//! time, an atomic CIP type or a struct type descriptor, and a data buffer
//! sized to `element_size * element_count`. Reads and writes take a lock only
//! for the update itself — the buffer is copied out to the caller.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ethernetip_core::error::{EipError, Result};

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
    /// Number of elements — 1 for scalars, >1 for arrays.
    pub element_count: u32,
    /// The tag's on-wire payload. For atomics its size is
    /// `element_count * sizeof(cip_type)`; for structures it is whatever the
    /// caller wrote.
    pub data: Vec<u8>,
}

impl TagEntry {
    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    pub fn atomic_size(&self) -> Option<usize> {
        self.cip_type.atomic_size()
    }
}

#[derive(Debug, Default)]
struct RegistryInner {
    by_instance: HashMap<u32, TagEntry>,
    by_name: HashMap<String, u32>,
    next_instance: u32,
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
                ..Default::default()
            })),
        }
    }

    /// Insert a scalar atomic tag. Returns the assigned instance id.
    pub fn add_atomic(&self, name: impl Into<String>, ty: CipType) -> Result<u32> {
        self.add_array(name, ty, 1)
    }

    /// Insert an atomic array tag with the given element count.
    pub fn add_array(&self, name: impl Into<String>, ty: CipType, elements: u32) -> Result<u32> {
        if ty == CipType::Struct {
            return Err(EipError::Protocol(
                "add_array is for atomic types; use add_struct".into(),
            ));
        }
        let size = ty
            .atomic_size()
            .ok_or_else(|| EipError::Protocol("unknown atomic size".into()))?;
        let data = vec![0u8; size * elements as usize];
        let sym_type = ty as u16;
        self.insert_entry(name.into(), sym_type, ty, elements, data)
    }

    /// Insert a struct tag with an already-encoded blob. The caller is
    /// responsible for maintaining wire-format consistency.
    pub fn add_struct(
        &self,
        name: impl Into<String>,
        template_handle: u16,
        blob: Vec<u8>,
    ) -> Result<u32> {
        let sym_type = 0x8000 | (template_handle & 0x0FFF);
        self.insert_entry(name.into(), sym_type, CipType::Struct, 1, blob)
    }

    fn insert_entry(
        &self,
        name: String,
        sym_type: u16,
        cip_type: CipType,
        element_count: u32,
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
        let entry = TagEntry {
            instance,
            name: name.clone(),
            sym_type,
            cip_type,
            element_count,
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
        rows.sort_by_key(|r| r.0);
        rows
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().by_instance.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
