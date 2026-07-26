//! CIP Identity Object (class 0x01) — required on every EtherNet/IP device.
//! Instance 1 holds vendor id, device type, product code, revision, status,
//! serial number, and product name. Browsers hit this before anything else,
//! so shipping an empty Identity is what makes an adapter show up in EtherNet/IP
//! discovery tools at all.

use crate::cip::{
    class_codes, service_codes, AttributeAccess, CipAttribute, CipClass, CipDataType,
    CipInstance, CipServiceDefinition, CipServiceRequest, CipServiceResponse,
};

/// Device identity block — the raw values that populate Identity attributes
/// 1 through 7.
#[derive(Debug, Clone)]
pub struct IdentityInfo {
    pub vendor_id: u16,
    pub device_type: u16,
    pub product_code: u16,
    /// Major revision (attribute 4 low byte).
    pub major_revision: u8,
    /// Minor revision (attribute 4 high byte).
    pub minor_revision: u8,
    /// Device status word (attribute 5).
    pub status: u16,
    /// 32-bit serial number (attribute 6).
    pub serial_number: u32,
    /// Product name — attribute 7, encoded as SHORT_STRING (1-byte length +
    /// ASCII payload). Max 32 chars is idiomatic; the wire lets it grow
    /// longer.
    pub product_name: String,
}

/// Build an Identity CIP class (0x01) with the standard 7 attributes on
/// instance 1 plus a no-op `Reset` service (0x05).
pub fn build(identity: IdentityInfo) -> CipClass {
    let mut cls = CipClass::new(class_codes::IDENTITY, "Identity", 1);
    cls.add_standard_instance_services();
    // Reset (0x05) — success no-op for a simulator target. Some browsers
    // fire this speculatively during discovery.
    cls.add_instance_service(CipServiceDefinition::new(
        service_codes::RESET,
        "Reset",
        handle_reset,
    ));

    let inst = cls.create_instance(1);

    inst.add_attribute(CipAttribute::from_u16(
        1,
        CipDataType::Uint,
        AttributeAccess::READ,
        identity.vendor_id,
    ));
    inst.add_attribute(CipAttribute::from_u16(
        2,
        CipDataType::Uint,
        AttributeAccess::READ,
        identity.device_type,
    ));
    inst.add_attribute(CipAttribute::from_u16(
        3,
        CipDataType::Uint,
        AttributeAccess::READ,
        identity.product_code,
    ));
    // Attribute 4: revision — USINT[2] {major, minor}. Wire order matches
    // the C# / C++ / Python siblings: major first, then minor.
    inst.add_attribute(CipAttribute::new(
        4,
        CipDataType::Usint,
        AttributeAccess::READ,
        vec![identity.major_revision, identity.minor_revision],
    ));
    inst.add_attribute(CipAttribute::from_u16(
        5,
        CipDataType::Word,
        AttributeAccess::READ,
        identity.status,
    ));
    inst.add_attribute(CipAttribute::from_u32(
        6,
        CipDataType::Udint,
        AttributeAccess::READ,
        identity.serial_number,
    ));
    inst.add_attribute(CipAttribute::from_short_string(
        7,
        AttributeAccess::READ,
        &identity.product_name,
    ));

    cls
}

fn handle_reset(_inst: &mut CipInstance, req: &CipServiceRequest) -> CipServiceResponse {
    CipServiceResponse::success(req.service_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cip::{status, CipDispatcher, CipPath};
    use std::sync::Arc;

    fn make() -> Arc<CipDispatcher> {
        let cls = build(IdentityInfo {
            vendor_id: 0x0001,
            device_type: 0x000C,
            product_code: 26,
            major_revision: 1,
            minor_revision: 3,
            status: 0x0030,
            serial_number: 0xC0FF_EE42,
            product_name: "TestDevice".into(),
        });
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);
        dispatcher
    }

    #[test]
    fn vendor_id_returns_uint() {
        let d = make();
        let path = CipPath::parse(&[0x20, 0x01, 0x24, 0x01, 0x30, 0x01]).unwrap();
        let r = d.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(r.data, vec![0x01, 0x00]);
    }

    #[test]
    fn product_name_returns_short_string() {
        let d = make();
        let path = CipPath::parse(&[0x20, 0x01, 0x24, 0x01, 0x30, 0x07]).unwrap();
        let r = d.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
        // SHORT_STRING = 1-byte length + payload.
        assert_eq!(r.data[0], 10);
        assert_eq!(&r.data[1..], b"TestDevice");
    }

    #[test]
    fn revision_is_two_bytes_major_then_minor() {
        let d = make();
        let path = CipPath::parse(&[0x20, 0x01, 0x24, 0x01, 0x30, 0x04]).unwrap();
        let r = d.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.data, vec![1, 3]);
    }

    #[test]
    fn reset_service_returns_success() {
        let d = make();
        let path = CipPath::parse(&[0x20, 0x01, 0x24, 0x01]).unwrap();
        let r = d.dispatch(service_codes::RESET, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
    }
}
