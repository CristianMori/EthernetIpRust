//! EtherNet/IP Class 1 (implicit I/O) building blocks.
//!
//! * [`assembly`] — in-memory Assembly Object registry.
//! * [`epio`] — Common Packet Format framing for cyclic I/O over UDP.
//! * [`forward_open`] — encode/decode `Forward_Open` and `Forward_Close` on
//!   both the originator and target sides.
//!
//! Higher-level actors (scanner / adapter) live in the modules that use these
//! primitives — they will land in follow-up commits.

pub mod adapter;
pub mod assembly;
pub mod connection_manager_object;
pub mod epio;
pub mod forward_open;
pub mod scanner;

pub use connection_manager_object::build as build_connection_manager;

pub use adapter::{
    start as start_adapter, AdapterConfig, AdapterHandle, ConnectionSummary, IO_UDP_PORT,
};
pub use scanner::{open_connection as open_scanner_connection, ScannerConfig, ScannerConnection};
pub use assembly::{Assembly, AssemblyKind, AssemblyRegistry};
pub use epio::{decode_frame, encode_frame, Frame};
pub use forward_open::{
    ForwardCloseRequest, ForwardCloseResponse, ForwardOpenRequest, ForwardOpenResponse,
    NetworkConnectionParameters, TransportClass, TriggerType,
};

pub use ethernetip_core::{EipError, Result};
