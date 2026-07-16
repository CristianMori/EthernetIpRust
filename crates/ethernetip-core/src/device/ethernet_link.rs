//! CIP Ethernet Link Object (class 0xF6). Reports NIC speed, flags, and MAC
//! address. The C# sibling queries `NetworkInterface` for live values; here
//! we take them from the caller (or use conservative fallbacks). Wiring a
//! Rust NIC query in would need a crate like `pnet` or `network-interface`
//! — a follow-up.

use crate::cip::{
    class_codes, AttributeAccess, CipAttribute, CipClass, CipDataType,
};

/// Interface Flags bitfield (attribute 2). Bit 0 = link active, bit 1 =
/// full duplex, bits 2-4 = negotiation status (4 = forced settings used),
/// bit 5 = manual setting requires reset, bit 6 = local hardware fault.
/// `0x0F` — link active, full duplex, auto-negotiation succeeded.
pub const DEFAULT_INTERFACE_FLAGS: u32 = 0x0F;

/// Fallback MAC when the caller doesn't supply one. Locally administered
/// (bit 1 of the first octet set), placeholder OUI.
pub const FALLBACK_MAC: [u8; 6] = [0x00, 0x1C, 0x2E, 0x00, 0x00, 0x01];

/// Fallback link speed when the caller doesn't supply one — 1 Gbps.
pub const FALLBACK_SPEED_MBPS: u32 = 1000;

/// Configuration for the Ethernet Link object.
#[derive(Debug, Clone)]
pub struct EthernetLinkConfig {
    /// Interface speed in megabits per second (attribute 1).
    pub speed_mbps: u32,
    /// Interface flags bitfield (attribute 2).
    pub flags: u32,
    /// 6-byte physical (MAC) address (attribute 3).
    pub mac: [u8; 6],
}

impl Default for EthernetLinkConfig {
    fn default() -> Self {
        Self {
            speed_mbps: FALLBACK_SPEED_MBPS,
            flags: DEFAULT_INTERFACE_FLAGS,
            mac: FALLBACK_MAC,
        }
    }
}

/// Build an Ethernet Link CIP class (0xF6) with attributes 1, 2, and 3 on
/// instance 1.
pub fn build(cfg: EthernetLinkConfig) -> CipClass {
    let mut cls = CipClass::new(class_codes::ETHERNET_LINK, "Ethernet Link", 4);
    cls.add_standard_instance_services();
    let inst = cls.create_instance(1);

    inst.add_attribute(CipAttribute::from_u32(
        1,
        CipDataType::Udint,
        AttributeAccess::READ,
        cfg.speed_mbps,
    ));
    inst.add_attribute(CipAttribute::from_u32(
        2,
        CipDataType::Udint,
        AttributeAccess::READ,
        cfg.flags,
    ));
    inst.add_attribute(CipAttribute::new(
        3,
        CipDataType::Usint,
        AttributeAccess::READ,
        cfg.mac.to_vec(),
    ));

    cls
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cip::{status, CipDispatcher, CipPath};
    use std::sync::Arc;

    #[test]
    fn mac_is_6_bytes() {
        let cls = build(EthernetLinkConfig {
            mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ..Default::default()
        });
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);

        let path = CipPath::parse(&[0x20, 0xF6, 0x24, 0x01, 0x30, 0x03]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(r.data, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn speed_returns_udint_le() {
        let cls = build(EthernetLinkConfig {
            speed_mbps: 100,
            ..Default::default()
        });
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);

        let path = CipPath::parse(&[0x20, 0xF6, 0x24, 0x01, 0x30, 0x01]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.data, 100u32.to_le_bytes().to_vec());
    }
}
