//! Assembly Object registry.
//!
//! Assemblies are the produce/consume/config buckets that connections
//! reference by instance id in a `Forward_Open` connection path. This module
//! provides a plain in-memory store; higher layers own the actual data
//! movement.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ethernetip_core::error::{EipError, Result};

/// What role an assembly plays inside a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblyKind {
    /// Data flowing originator → target (scanner outputs, adapter inputs).
    Output,
    /// Data flowing target → originator (adapter outputs, scanner inputs).
    Input,
    /// Static configuration bytes carried in the Forward_Open data segment.
    Config,
}

/// One registered assembly. The data buffer is behind an `Arc<RwLock<..>>`
/// so it can be shared with a `CipAttribute` created via
/// `CipAttribute::new_shared` — that's what lets a client's
/// `Set_Attribute_Single(class=0x04, attr=3)` reach the same bytes the
/// adapter's I/O producer is streaming to the wire.
#[derive(Debug, Clone)]
pub struct Assembly {
    pub instance: u16,
    pub kind: AssemblyKind,
    pub size: usize,
    /// Shared byte buffer. Callers that want to bridge to CIP go through
    /// [`Assembly::shared_buffer`]; direct-write callers use
    /// [`AssemblyRegistry::update`].
    data: Arc<RwLock<Vec<u8>>>,
}

impl Assembly {
    pub fn new(instance: u16, kind: AssemblyKind, size: usize) -> Self {
        Self {
            instance,
            kind,
            size,
            data: Arc::new(RwLock::new(vec![0u8; size])),
        }
    }

    /// Clone the shared byte handle. Two owners of the same handle see
    /// each other's writes — used to back a CipAttribute with the same
    /// bytes an I/O loop is reading from.
    pub fn shared_buffer(&self) -> Arc<RwLock<Vec<u8>>> {
        self.data.clone()
    }
}

/// Thread-safe map of instance → [`Assembly`].
///
/// Cloning the registry hands out a new handle to the same underlying storage
/// (an `Arc<RwLock<..>>`), which is the shape scanners and adapters need to
/// share assemblies with their I/O tasks.
#[derive(Debug, Clone, Default)]
pub struct AssemblyRegistry {
    inner: Arc<RwLock<HashMap<u16, Assembly>>>,
}

impl AssemblyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an assembly, rejecting a duplicate instance id.
    ///
    /// Matches the behavior the C++/Python/C# ports converged on: two
    /// assemblies with the same instance would silently collide, so we make
    /// the second registration fail loudly.
    pub fn insert(&self, asm: Assembly) -> Result<()> {
        let mut guard = self.inner.write().unwrap();
        if guard.contains_key(&asm.instance) {
            return Err(EipError::Protocol(format!(
                "assembly instance {} already registered",
                asm.instance
            )));
        }
        guard.insert(asm.instance, asm);
        Ok(())
    }

    /// Look up an assembly by instance id and clone the current snapshot.
    pub fn snapshot(&self, instance: u16) -> Option<Assembly> {
        self.inner.read().unwrap().get(&instance).cloned()
    }

    /// Replace the data buffer of an existing assembly. Returns
    /// `EipError::Protocol` if the instance is not registered or the buffer
    /// length doesn't match.
    pub fn update(&self, instance: u16, data: &[u8]) -> Result<()> {
        let guard = self.inner.read().unwrap();
        let Some(asm) = guard.get(&instance) else {
            return Err(EipError::Protocol(format!(
                "assembly instance {} not registered",
                instance
            )));
        };
        if data.len() != asm.size {
            return Err(EipError::Protocol(format!(
                "assembly {} expects {} bytes, got {}",
                instance,
                asm.size,
                data.len()
            )));
        }
        asm.data.write().unwrap().copy_from_slice(data);
        Ok(())
    }

    /// Read out the current data of an assembly.
    pub fn read(&self, instance: u16) -> Option<Vec<u8>> {
        self.inner
            .read()
            .unwrap()
            .get(&instance)
            .map(|a| a.data.read().unwrap().clone())
    }

    /// Return the shared byte handle for an assembly so a caller (typically
    /// a `CipAttribute::new_shared`) can point at the same bytes.
    pub fn shared_buffer(&self, instance: u16) -> Option<Arc<RwLock<Vec<u8>>>> {
        self.inner
            .read()
            .unwrap()
            .get(&instance)
            .map(|a| a.shared_buffer())
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_instance_rejected() {
        let reg = AssemblyRegistry::new();
        reg.insert(Assembly::new(100, AssemblyKind::Input, 4)).unwrap();
        assert!(reg.insert(Assembly::new(100, AssemblyKind::Output, 8)).is_err());
    }

    #[test]
    fn update_and_read_roundtrip() {
        let reg = AssemblyRegistry::new();
        reg.insert(Assembly::new(150, AssemblyKind::Output, 4)).unwrap();
        reg.update(150, &[1, 2, 3, 4]).unwrap();
        assert_eq!(reg.read(150).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn update_wrong_size_rejected() {
        let reg = AssemblyRegistry::new();
        reg.insert(Assembly::new(150, AssemblyKind::Output, 4)).unwrap();
        assert!(reg.update(150, &[1, 2]).is_err());
    }
}
