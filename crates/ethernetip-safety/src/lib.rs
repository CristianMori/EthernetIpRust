//! CIP Safety building blocks.

pub mod cpcrc;
pub mod crc;
pub mod forward_open;
pub mod frame_codec;
pub mod scanner;
pub mod segment;
pub mod types;

pub use forward_open::{
    build_safety_forward_open, SafetyAppReply, SafetyForwardOpenConfig, SafetyForwardOpenWire,
    CM_PATH,
};
pub use frame_codec::{DecodedFrame, SafetyDecodeError};
pub use scanner::{open_safety_scanner, SafetyScannerConfig, SafetyScannerConnection};

pub use segment::{SafetyNetworkSegment, SEGMENT_TYPE};
pub use types::{
    ModeByte, SafetyConfigurationId, SafetyFormat, SafetyNetworkNumber, UniqueNetworkId,
};

pub use ethernetip_core::{EipError, Result};
