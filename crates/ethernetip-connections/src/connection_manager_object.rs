//! CIP Connection Manager Object (class 0x06). Attribute-only port —
//! registers instance 1 with the eight standard UINT counter attributes
//! so browsers can enumerate the class and read its statistics via
//! `Get_Attribute_Single`.
//!
//! Forward_Open / Large_Forward_Open / Forward_Close / Unconnected_Send are
//! *not* registered as instance services here — the Rust safety-adapter
//! and echo-adapter still handle those inline in their own
//! `handle_send_rr_data` paths. The C# sibling (`ConnectionManagerObject.cs`)
//! wires those services on the class and owns the connection lifecycle
//! through them; moving that logic into a class in Rust would require
//! porting the whole `IoConnection` runtime and is out of scope for now.
//!
//! The counter attributes stay pinned at zero — nothing here updates them
//! yet. A follow-up would tick them from the inline FO / FC handlers.
//!
//! Instance 1 attribute layout (Vol 1 §3-4.1):
//!
//!  * 1 Open Requests       — successful Forward_Open count
//!  * 2 Open Format Rejects — refused for malformed request
//!  * 3 Open Resource Rejects
//!  * 4 Open Other Rejects
//!  * 5 Close Requests
//!  * 6 Close Format Requests
//!  * 7 Close Other Requests
//!  * 8 Connection Timeouts

use ethernetip_core::cip::{
    class_codes, AttributeAccess, CipAttribute, CipClass, CipDataType,
};

/// Build a Connection Manager CIP class (0x06) with instance 1 and the
/// standard 8-attribute counter block, all read-only and zero-initialised.
pub fn build() -> CipClass {
    let mut cls = CipClass::new(class_codes::CONNECTION_MANAGER, "Connection Manager", 1);
    cls.add_standard_instance_services();
    let inst = cls.create_instance(1);
    for id in 1u16..=8 {
        inst.add_attribute(CipAttribute::from_u16(
            id,
            CipDataType::Uint,
            AttributeAccess::READ,
            0,
        ));
    }
    cls
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethernetip_core::cip::{status, CipDispatcher, CipPath};
    use std::sync::Arc;

    #[test]
    fn open_requests_attribute_reads_zero() {
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(build());
        // Get_Attribute_Single(class 0x06, instance 1, attr 1).
        let path = CipPath::parse(&[0x20, 0x06, 0x24, 0x01, 0x30, 0x01]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(r.data, 0u16.to_le_bytes().to_vec());
    }

    #[test]
    fn all_eight_counters_present() {
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(build());
        for attr_id in 1u8..=8 {
            let path = CipPath::parse(&[0x20, 0x06, 0x24, 0x01, 0x30, attr_id]).unwrap();
            let r = dispatcher.dispatch(0x0E, path, Vec::new());
            assert_eq!(r.general_status, status::SUCCESS, "attr {attr_id} missing");
        }
    }
}
