//! Allen-Bradley Logix tag client.
//!
//! Speaks CIP over EtherNet/IP to ControlLogix / CompactLogix controllers,
//! providing symbolic tag reads/writes and Symbol Object enumeration.

pub mod browse;
pub mod persistence;
pub mod request;
pub mod server_template;
pub mod tag_client;
pub mod tag_path;
pub mod tag_registry;
pub mod tag_server;
pub mod template;
pub mod types;
pub mod walker;

pub use server_template::{ServerTemplate, ServerTemplateMember};
pub use walker::{walk as walk_path, WalkResult};

pub use browse::{TagCategory, TagInfo};
pub use tag_client::{TagClient, TagClientBuilder};
pub use tag_path::AtomCache;
pub use tag_registry::{TagEntry, TagRegistry};
pub use tag_server::{start as start_tag_server, TagServerConfig, TagServerHandle};
pub use template::{
    decode_struct, SymType, TemplateDefinition, TemplateHeader, TemplateMember, TypedValue,
};
pub use types::{CipType, TagValue};

pub use ethernetip_core::{EipError, Result};
