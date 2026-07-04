//! CIP Safety building blocks.

pub mod cpcrc;
pub mod crc;
pub mod frame_codec;
pub mod segment;
pub mod types;

pub use frame_codec::{DecodedFrame, SafetyDecodeError};

pub use segment::{SafetyNetworkSegment, SEGMENT_TYPE};
pub use types::{
    ModeByte, SafetyConfigurationId, SafetyFormat, SafetyNetworkNumber, UniqueNetworkId,
};

pub use ethernetip_core::{EipError, Result};
