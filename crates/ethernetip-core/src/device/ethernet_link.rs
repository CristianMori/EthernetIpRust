//! CIP Ethernet Link Object (class 0xF6). Reports NIC speed, flags, and MAC
//! address. With the default `live-nic` feature on, [`EthernetLinkConfig::probe`]
//! queries the host for a real MAC by matching the caller's bind IP against
//! the local NICs (via the `network-interface` crate). Speed and flags
//! remain caller-supplied — `network-interface` doesn't expose link speed
//! and CIP `Interface Flags` is more informational than measurable at the
//! socket level. Disable the `live-nic` feature to fall back to hardcoded
//! values without pulling the extra crate in.

use std::net::Ipv4Addr;

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

impl EthernetLinkConfig {
    /// Return a config whose MAC is the real MAC of the local NIC that
    /// owns `bind_ip`. Falls back to [`FALLBACK_MAC`] when the lookup
    /// fails (no matching NIC, no MAC on that NIC, or the `live-nic`
    /// feature is disabled). Speed and flags are the defaults — the
    /// caller can override them after the fact.
    #[cfg(feature = "live-nic")]
    pub fn probe(bind_ip: Ipv4Addr) -> Self {
        use network_interface::{NetworkInterface, NetworkInterfaceConfig};
        let mut cfg = Self::default();
        let Ok(nics) = NetworkInterface::show() else { return cfg };
        for nic in nics {
            if nic.addr.iter().any(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => v4 == bind_ip,
                _ => false,
            }) {
                if let Some(mac_str) = &nic.mac_addr {
                    if let Some(bytes) = parse_mac(mac_str) {
                        cfg.mac = bytes;
                        return cfg;
                    }
                }
            }
        }
        cfg
    }

    /// Fallback stub when the `live-nic` feature is off.
    #[cfg(not(feature = "live-nic"))]
    pub fn probe(_bind_ip: Ipv4Addr) -> Self {
        Self::default()
    }
}

#[cfg(feature = "live-nic")]
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    // Accepts "aa:bb:cc:dd:ee:ff" (colon-separated hex bytes). Returns
    // None on any parse failure — caller keeps the fallback.
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
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
