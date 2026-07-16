//! CIP Assembly Object (class 0x04). Each instance holds a fixed-size byte
//! buffer and exposes it as attribute 3 for CIP reads/writes plus the
//! usual member-count/size metadata.
//!
//! The C# sibling ties `AssemblyDataAttribute` directly to a live
//! `AssemblyInstance` buffer so CIP writes and I/O writes see the same
//! bytes. This Rust port keeps the data inside the `CipAttribute` itself
//! (each instance owns its own bytes) — enough for `Get_Attribute_Single`
//! to answer with the right contents, but doesn't currently share memory
//! with `ethernetip_connections::AssemblyRegistry`. Bridging those two
//! stores so CIP writes hit the live I/O buffer is a follow-up.

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

/// Register a new assembly instance on the given Assembly class. Fails
/// silently if the class already has an instance with `instance_id`.
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
}
