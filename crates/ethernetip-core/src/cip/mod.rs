//! CIP object model — service codes, well-known classes, status codes, plus a
//! [`CipDispatcher`] that routes incoming Message Router requests through a
//! tree of registered [`CipClass`] / [`CipInstance`] / [`CipAttribute`]
//! objects.
//!
//! The framework mirrors the C# `EthernetIPSharp.Cip` module so a class ported
//! from either side reads the same on the wire. Classes are typically
//! constructed once at startup and registered on the dispatcher; the safety
//! adapter (or any other transport surface) calls [`CipDispatcher::dispatch`]
//! for every non-Connection-Manager service it receives.

pub mod attribute;
pub mod class;
pub mod data_type;
pub mod dispatcher;
pub mod instance;
pub mod path;
pub mod reply_header;
pub mod service;
pub mod standard_services;

pub use attribute::{AttributeAccess, CipAttribute};
pub use class::CipClass;
pub use data_type::CipDataType;
pub use dispatcher::CipDispatcher;
pub use instance::CipInstance;
pub use path::CipPath;
pub use reply_header::ReplyHeader;
pub use service::{
    CipServiceDefinition, CipServiceHandler, CipServiceRequest, CipServiceResponse,
};

/// CIP service codes.
pub mod service_codes {
    pub const GET_ATTRIBUTES_ALL: u8 = 0x01;
    pub const SET_ATTRIBUTES_ALL: u8 = 0x02;
    pub const RESET: u8 = 0x05;
    pub const START: u8 = 0x06;
    pub const STOP: u8 = 0x07;
    pub const CREATE: u8 = 0x08;
    pub const DELETE: u8 = 0x09;
    pub const MULTIPLE_SERVICE_PACKET: u8 = 0x0A;
    pub const APPLY_ATTRIBUTES: u8 = 0x0D;
    pub const GET_ATTRIBUTE_SINGLE: u8 = 0x0E;
    pub const SET_ATTRIBUTE_SINGLE: u8 = 0x10;
    pub const FIND_NEXT_OBJECT_INSTANCE: u8 = 0x11;
    pub const GET_INSTANCE_ATTRIBUTE_LIST: u8 = 0x55;

    // Vendor extensions used by Logix.
    pub const READ_TAG: u8 = 0x4C;
    pub const WRITE_TAG: u8 = 0x4D;
    pub const READ_TAG_FRAGMENTED: u8 = 0x52;
    pub const WRITE_TAG_FRAGMENTED: u8 = 0x53;

    // Connection Manager services.
    pub const FORWARD_CLOSE: u8 = 0x4E;
    pub const UNCONNECTED_SEND: u8 = 0x52;
    pub const FORWARD_OPEN: u8 = 0x54;
    pub const LARGE_FORWARD_OPEN: u8 = 0x5B;

    /// Bit OR'd into the service code in a reply.
    pub const REPLY_FLAG: u8 = 0x80;
}

// (Historical alias `cip::service` was replaced by `cip::service_codes`
// when the object model added a `cip::service` MODULE containing
// CipServiceRequest / Response / Definition. Callers reach the constants
// through `ethernetip_core::cip::service_codes::*`.)

/// Well-known CIP class IDs.
pub mod class_codes {
    pub const IDENTITY: u16 = 0x01;
    pub const MESSAGE_ROUTER: u16 = 0x02;
    pub const ASSEMBLY: u16 = 0x04;
    pub const CONNECTION_MANAGER: u16 = 0x06;
    pub const SAFETY_SUPERVISOR: u16 = 0x39;
    pub const SAFETY_VALIDATOR: u16 = 0x3A;
    pub const SYMBOL_OBJECT: u16 = 0x6B;
    pub const TEMPLATE_OBJECT: u16 = 0x6C;
    pub const TCP_IP_INTERFACE: u16 = 0xF5;
    pub const ETHERNET_LINK: u16 = 0xF6;
}

// (Historical alias `cip::class` was replaced by `cip::class_codes` when
// the object model added a `cip::class` MODULE containing CipClass.)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_routes_get_attribute_single() {
        // Build a class with instance 1 carrying attr 3 = 6-byte SNN.
        let mut cls = CipClass::new(0x39, "Safety Supervisor", 1);
        cls.add_standard_instance_services();
        let inst = cls.create_instance(1);
        inst.add_attribute(CipAttribute::new(
            3,
            CipDataType::Byte,
            AttributeAccess::READ,
            vec![0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D],
        ));
        let dispatcher = CipDispatcher::new();
        dispatcher.register_class(cls);

        // Path: class 0x39, instance 1, attribute 3 — Get_Attribute_Single.
        let path = CipPath::parse(&[0x20, 0x39, 0x24, 0x01, 0x30, 0x03]).unwrap();
        let response = dispatcher.dispatch(standard_services::GET_ATTRIBUTE_SINGLE, path, Vec::new());

        assert_eq!(response.general_status, status::SUCCESS);
        assert_eq!(response.data, vec![0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D]);
        assert_eq!(response.service_code, standard_services::GET_ATTRIBUTE_SINGLE | 0x80);
    }

    #[test]
    fn dispatcher_missing_class_returns_path_dest_unknown() {
        let dispatcher = CipDispatcher::new();
        let path = CipPath::parse(&[0x20, 0x39, 0x24, 0x01]).unwrap();
        let response = dispatcher.dispatch(standard_services::GET_ATTRIBUTE_SINGLE, path, Vec::new());
        assert_eq!(response.general_status, status::PATH_DESTINATION_UNKNOWN);
    }

    #[test]
    fn dispatcher_missing_instance_returns_object_does_not_exist() {
        let mut cls = CipClass::new(0x39, "Safety Supervisor", 1);
        cls.add_standard_instance_services();
        // No instances created.
        let dispatcher = CipDispatcher::new();
        dispatcher.register_class(cls);
        let path = CipPath::parse(&[0x20, 0x39, 0x24, 0x05]).unwrap();
        let response = dispatcher.dispatch(standard_services::GET_ATTRIBUTE_SINGLE, path, Vec::new());
        assert_eq!(response.general_status, status::OBJECT_DOES_NOT_EXIST);
    }

    #[test]
    fn dispatcher_custom_service_receives_body() {
        // Handler returns whatever body it received, plus a marker byte.
        let mut cls = CipClass::new(0x39, "Safety Supervisor", 1);
        cls.add_standard_instance_services();
        cls.add_instance_service(CipServiceDefinition::new(
            0x54,
            "Test_Echo",
            |_inst, req| {
                let mut body = req.data.clone();
                body.push(0xAA);
                CipServiceResponse::success_with(req.service_code, body)
            },
        ));
        cls.create_instance(1);
        let dispatcher = CipDispatcher::new();
        dispatcher.register_class(cls);

        let path = CipPath::parse(&[0x20, 0x39, 0x24, 0x01]).unwrap();
        let response = dispatcher.dispatch(0x54, path, vec![0x02]); // reset type 2
        assert_eq!(response.general_status, status::SUCCESS);
        assert_eq!(response.data, vec![0x02, 0xAA]);
    }
}

/// Selected CIP general status codes.
pub mod status {
    pub const SUCCESS: u8 = 0x00;
    pub const CONNECTION_FAILURE: u8 = 0x01;
    pub const RESOURCE_UNAVAILABLE: u8 = 0x02;
    pub const PATH_SEGMENT_ERROR: u8 = 0x04;
    pub const PATH_DESTINATION_UNKNOWN: u8 = 0x05;
    pub const PARTIAL_TRANSFER: u8 = 0x06;
    pub const SERVICE_NOT_SUPPORTED: u8 = 0x08;
    pub const INVALID_ATTRIBUTE_VALUE: u8 = 0x09;
    pub const OBJECT_STATE_CONFLICT: u8 = 0x0C;
    pub const ATTRIBUTE_NOT_SETTABLE: u8 = 0x0E;
    pub const PRIVILEGE_VIOLATION: u8 = 0x0F;
    pub const DEVICE_STATE_CONFLICT: u8 = 0x10;
    pub const REPLY_TOO_LARGE: u8 = 0x11;
    pub const NOT_ENOUGH_DATA: u8 = 0x13;
    pub const ATTRIBUTE_NOT_SUPPORTED: u8 = 0x14;
    pub const TOO_MUCH_DATA: u8 = 0x15;
    pub const OBJECT_DOES_NOT_EXIST: u8 = 0x16;
    pub const INVALID_PARAMETER: u8 = 0x20;
}
