//! Allen-Bradley Logix tag client.
//!
//! Speaks CIP over EtherNet/IP to ControlLogix / CompactLogix controllers,
//! providing symbolic tag reads/writes and Symbol Object enumeration.

pub mod browse;
pub mod request;
pub mod tag_client;
pub mod tag_path;
pub mod types;

pub use browse::{TagCategory, TagInfo};
pub use tag_client::{TagClient, TagClientBuilder};
pub use tag_path::AtomCache;
pub use types::{CipType, TagValue};

pub use ethernetip_core::{EipError, Result};
