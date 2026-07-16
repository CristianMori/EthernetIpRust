//! Common CIP device objects — Identity (0x01), Assembly (0x04),
//! TCP/IP Interface (0xF5), Ethernet Link (0xF6). Each module exposes a
//! `build(...)` (or `AssemblyObject::add_instance`) helper that returns a
//! [`crate::cip::CipClass`] ready to register on a
//! [`crate::cip::CipDispatcher`].
//!
//! These are the classes every EtherNet/IP browser hits during discovery.
//! Without them, tools like RSLinx / Wireshark's ENIP discovery, or a PLC
//! configuring the device, see a blank slate and can't identify what
//! they're talking to.

pub mod assembly;
pub mod ethernet_link;
pub mod identity;
pub mod tcpip_interface;

pub use assembly::{add_instance as add_assembly_instance, build as build_assembly};
pub use ethernet_link::{
    build as build_ethernet_link, EthernetLinkConfig, DEFAULT_INTERFACE_FLAGS, FALLBACK_MAC,
    FALLBACK_SPEED_MBPS,
};
pub use identity::{build as build_identity, IdentityInfo};
pub use tcpip_interface::{build as build_tcpip_interface, TcpIpConfig};
