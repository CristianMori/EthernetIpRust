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
    /// Return a config populated from the local NIC that owns `bind_ip`.
    /// Real MAC via `network-interface`; on Windows, real link speed via
    /// `GetIfTable2`. Falls back to [`FALLBACK_MAC`] / [`FALLBACK_SPEED_MBPS`]
    /// when the lookup fails (no matching NIC, driver reports 0/negative
    /// speed, or the `live-nic` feature is disabled).
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
                        // Try to grab real link speed. Platform-specific;
                        // on non-Windows this is a no-op that leaves the
                        // fallback in place.
                        if let Some(mbps) = query_link_speed_mbps(&nic.name, cfg.mac) {
                            cfg.speed_mbps = mbps;
                        }
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

// -------------------- link-speed query (platform-specific) --------------------

/// Return the interface's TX link speed in megabits per second, or `None`
/// when the platform can't tell us. Windows implementation uses
/// `GetIfTable2` and matches rows by physical (MAC) address.
#[cfg(all(feature = "live-nic", windows))]
fn query_link_speed_mbps(_name: &str, mac: [u8; 6]) -> Option<u32> {
    use std::ptr;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_TABLE2,
    };

    unsafe {
        let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
        if GetIfTable2(&mut table as *mut _) != 0 || table.is_null() {
            return None;
        }
        let count = (*table).NumEntries as usize;
        // Table field is a flexible array; walk it via pointer arithmetic.
        let base = (*table).Table.as_ptr();
        let mut result = None;
        for i in 0..count {
            let row = &*base.add(i);
            let addr_len = row.PhysicalAddressLength as usize;
            if addr_len == 6 && row.PhysicalAddress[..6] == mac {
                // TransmitLinkSpeed is in bits per second (u64). Some
                // virtual adapters report 0 or u64::MAX — treat both as
                // "unknown" and let the caller keep the fallback.
                let bps = row.TransmitLinkSpeed;
                if bps > 0 && bps < u64::MAX {
                    let mbps = (bps / 1_000_000) as u32;
                    if mbps > 0 {
                        result = Some(mbps);
                    }
                }
                break;
            }
        }
        FreeMibTable(table as _);
        result
    }
}

/// Non-Windows / non-live-nic fallback — returns None, caller keeps
/// [`FALLBACK_SPEED_MBPS`]. A Linux implementation via netlink /
/// `/sys/class/net/<name>/speed` would slot in here.
#[cfg(all(feature = "live-nic", not(windows)))]
fn query_link_speed_mbps(_name: &str, _mac: [u8; 6]) -> Option<u32> {
    None
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
