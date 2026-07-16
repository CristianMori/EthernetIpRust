//! CIP Assembly Object (class 0x04). Each instance holds a fixed-size byte
//! buffer and exposes it as attribute 3 for CIP reads/writes plus the
//! usual member-count/size metadata.
//!
//! Two flavors of `add_instance`:
//!
//!  * [`add_instance`] — the CIP attribute owns its own byte buffer. Good
//!    when nobody else needs to see the bytes.
//!  * [`add_instance_shared`] — attribute 3 is backed by a caller-supplied
//!    `Arc<RwLock<Vec<u8>>>` so a CIP write and (say) an I/O producer that
//!    holds the same handle see each other's bytes. Bridges to
//!    `ethernetip_connections::AssemblyRegistry::shared_buffer` — matches
//!    the C# `AssemblyDataAttribute` pattern where the CIP attr and the
//!    I/O buffer are the same memory.

use std::sync::{Arc, RwLock};

use crate::cip::{
    class_codes, AttributeAccess, CipAttribute, CipClass, CipDataType,
};

/// Build an empty Assembly class (0x04) with the standard services. Add
/// instances via [`add_instance`].
pub fn build() -> CipClass {
    let mut cls = CipClass::new(class_codes::ASSEMBLY, "Assembly", 2);
    cls.add_standard_instance_services();
    cls
}

/// Register a new assembly instance whose data attribute owns its own
/// buffer. Silent no-op if the class already has an instance with
/// `instance_id`.
///
/// Adds attributes 1 (member count = 0), 3 (data — zero-initialised
/// buffer of `data_size` bytes, writable), and 4 (size in bytes).
/// Attribute 2 (member list) is omitted; raw byte assemblies don't carry
/// a member table.
pub fn add_instance(cls: &mut CipClass, instance_id: u32, data_size: usize) {
    let inst = cls.create_instance(instance_id);
    inst.add_attribute(CipAttribute::from_u16(
        1,
        CipDataType::Uint,
        AttributeAccess::READ,
        0,
    ));
    inst.add_attribute(CipAttribute::new(
        3,
        CipDataType::Byte,
        AttributeAccess::ALL, // read/write/get-all
        vec![0u8; data_size],
    ));
    inst.add_attribute(CipAttribute::from_u16(
        4,
        CipDataType::Uint,
        AttributeAccess::READ,
        data_size as u16,
    ));
}

/// Register a new assembly instance whose data attribute is backed by the
/// caller-supplied shared buffer. `shared`'s current length becomes the
/// advertised size (attribute 4). Silent no-op on duplicate instance id.
pub fn add_instance_shared(
    cls: &mut CipClass,
    instance_id: u32,
    shared: Arc<RwLock<Vec<u8>>>,
) {
    let data_size = shared.read().unwrap().len();
    let inst = cls.create_instance(instance_id);
    inst.add_attribute(CipAttribute::from_u16(
        1,
        CipDataType::Uint,
        AttributeAccess::READ,
        0,
    ));
    inst.add_attribute(CipAttribute::new_shared(
        3,
        CipDataType::Byte,
        AttributeAccess::ALL,
        shared,
    ));
    inst.add_attribute(CipAttribute::from_u16(
        4,
        CipDataType::Uint,
        AttributeAccess::READ,
        data_size as u16,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cip::{status, CipDispatcher, CipPath};
    use std::sync::Arc;

    #[test]
    fn instance_data_reads_zero_initialized() {
        let mut cls = build();
        add_instance(&mut cls, 100, 8);
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);

        // Get_Attribute_Single(class 0x04, instance 100, attr 3).
        let path = CipPath::parse(&[0x20, 0x04, 0x24, 0x64, 0x30, 0x03]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(r.data, vec![0u8; 8]);
    }

    #[test]
    fn instance_size_matches_creation() {
        let mut cls = build();
        add_instance(&mut cls, 100, 496);
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);

        let path = CipPath::parse(&[0x20, 0x04, 0x24, 0x64, 0x30, 0x04]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.data, 496u16.to_le_bytes().to_vec());
    }

    #[test]
    fn set_attribute_single_updates_data() {
        let mut cls = build();
        add_instance(&mut cls, 100, 4);
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);

        let path_set = CipPath::parse(&[0x20, 0x04, 0x24, 0x64, 0x30, 0x03]).unwrap();
        let r = dispatcher.dispatch(0x10, path_set, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(r.general_status, status::SUCCESS);

        let path_get = CipPath::parse(&[0x20, 0x04, 0x24, 0x64, 0x30, 0x03]).unwrap();
        let r = dispatcher.dispatch(0x0E, path_get, Vec::new());
        assert_eq!(r.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn shared_buffer_writes_through_from_cip_side() {
        // The bridge: shared byte handle → CIP attr 3. A CIP write is
        // visible in the shared buffer without going through the class.
        let shared = Arc::new(RwLock::new(vec![0u8; 4]));
        let mut cls = build();
        add_instance_shared(&mut cls, 100, shared.clone());
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);

        let path = CipPath::parse(&[0x20, 0x04, 0x24, 0x64, 0x30, 0x03]).unwrap();
        let r = dispatcher.dispatch(0x10, path, vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(*shared.read().unwrap(), vec![0xCA, 0xFE, 0xBA, 0xBE]);
    }

    #[test]
    fn shared_buffer_reads_through_from_io_side() {
        // Reverse direction: an external write to the shared buffer is
        // visible on the next CIP Get_Attribute_Single.
        let shared = Arc::new(RwLock::new(vec![0u8; 4]));
        let mut cls = build();
        add_instance_shared(&mut cls, 100, shared.clone());
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);

        shared.write().unwrap().copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        let path = CipPath::parse(&[0x20, 0x04, 0x24, 0x64, 0x30, 0x03]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.data, vec![0x11, 0x22, 0x33, 0x44]);
    }
}
