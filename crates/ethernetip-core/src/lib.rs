//! EtherNet/IP encapsulation and CIP transport primitives.
//!
//! Provides the framing layer (encapsulation header, Common Packet Format items),
//! CIP EPATH segment encoders, and a tokio-based [`EipSession`] that speaks the
//! request/response protocol on TCP 44818.

pub mod cip;
pub mod cpf;
pub mod device;
pub mod encap;
pub mod error;
pub mod path;
pub mod path_parse;
pub mod session;
pub mod unconnected_send;

pub use error::{EipError, Result};
pub use session::EipSession;

/// Default EtherNet/IP TCP port.
pub const EIP_PORT: u16 = 44818;
