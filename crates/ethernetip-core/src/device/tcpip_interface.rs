//! CIP TCP/IP Interface Object (class 0xF5). Reports the interface's IP
//! address, subnet mask, and configuration mode. Required by every
//! EtherNet/IP device that supports TCP.

use std::net::Ipv4Addr;

use crate::cip::{
    class_codes, AttributeAccess, CipAttribute, CipClass, CipDataType,
};

/// Configuration for the TCP/IP Interface object. Defaults produce a
/// statically-configured interface with a `/24` subnet and no gateway or
/// DNS servers — typical for a simulator or lab device.
#[derive(Debug, Clone)]
pub struct TcpIpConfig {
    pub ip_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub name_server: Ipv4Addr,
    pub name_server_2: Ipv4Addr,
    /// Interface Status word (attribute 1). `1` = interface configured.
    pub status: u32,
    /// Configuration Capability word (attribute 2). `0x04` = DHCP capable.
    pub configuration_capability: u32,
    /// Configuration Control word (attribute 3). `0x00` = static, `0x02` =
    /// DHCP.
    pub configuration_control: u32,
}

impl TcpIpConfig {
    /// Build a config with sensible defaults for the given IP: 255.255.255.0
    /// subnet, no gateway / DNS, static configuration, status = configured,
    /// DHCP-capable flag on so a browser sees the option.
    pub fn new(ip_address: Ipv4Addr) -> Self {
        Self {
            ip_address,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::UNSPECIFIED,
            name_server: Ipv4Addr::UNSPECIFIED,
            name_server_2: Ipv4Addr::UNSPECIFIED,
            status: 1,
            configuration_capability: 0x04,
            configuration_control: 0x00,
        }
    }
}

/// Build a TCP/IP Interface CIP class (0xF5) with attributes 1, 2, 3, and 5
/// populated on instance 1. Attribute 4 (Physical Link Object path) is
/// optional per Vol 2 and omitted here.
pub fn build(cfg: TcpIpConfig) -> CipClass {
    let mut cls = CipClass::new(class_codes::TCP_IP_INTERFACE, "TCP/IP Interface", 4);
    cls.add_standard_instance_services();
    let inst = cls.create_instance(1);

    inst.add_attribute(CipAttribute::from_u32(
        1,
        CipDataType::Udint,
        AttributeAccess::READ,
        cfg.status,
    ));
    inst.add_attribute(CipAttribute::from_u32(
        2,
        CipDataType::Udint,
        AttributeAccess::READ,
        cfg.configuration_capability,
    ));
    inst.add_attribute(CipAttribute::from_u32(
        3,
        CipDataType::Udint,
        AttributeAccess::READ,
        cfg.configuration_control,
    ));

    // Attribute 5: Interface Configuration struct. Layout (Vol 2 §5-3.2.2.5):
    //   IP (4) + Subnet (4) + Gateway (4) + NameServer (4) + NameServer2 (4)
    //   + DomainNameLength (u16) + DomainName (variable)
    // We advertise an empty domain name → 22 bytes total, matching the C#
    // sibling.
    let mut ifc = Vec::with_capacity(22);
    ifc.extend_from_slice(&cfg.ip_address.octets());
    ifc.extend_from_slice(&cfg.subnet_mask.octets());
    ifc.extend_from_slice(&cfg.gateway.octets());
    ifc.extend_from_slice(&cfg.name_server.octets());
    ifc.extend_from_slice(&cfg.name_server_2.octets());
    ifc.extend_from_slice(&0u16.to_le_bytes());
    inst.add_attribute(CipAttribute::new(
        5,
        CipDataType::Byte,
        AttributeAccess::READ,
        ifc,
    ));

    cls
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cip::{status, CipDispatcher, CipPath};
    use std::sync::Arc;

    #[test]
    fn interface_configuration_struct_layout() {
        let cls = build(TcpIpConfig::new(Ipv4Addr::new(192, 168, 1, 84)));
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);

        // Get_Attribute_Single(class 0xF5, instance 1, attr 5).
        let path = CipPath::parse(&[0x20, 0xF5, 0x24, 0x01, 0x30, 0x05]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(r.data.len(), 22);
        assert_eq!(&r.data[0..4], &[192, 168, 1, 84]);
        assert_eq!(&r.data[4..8], &[255, 255, 255, 0]);
        // Gateway, DNS1, DNS2 all zero; domain length 0.
        assert!(r.data[8..].iter().all(|&b| b == 0));
    }
}
