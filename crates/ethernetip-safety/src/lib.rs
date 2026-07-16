//! CIP Safety building blocks.

pub mod adapter;
pub mod cpcrc;
pub mod crc;
pub mod forward_open;
pub mod frame_codec;
pub mod scanner;
pub mod segment;
pub mod supervisor;
pub mod types;

pub use adapter::{start_safety_adapter, SafetyAdapterConfig, SafetyAdapterHandle};
pub use supervisor::{
    SafetySupervisorMode, SafetySupervisorObject, SafetySupervisorState,
    APPLY_TUNID_SERVICE, PROPOSE_TUNID_SERVICE, SAFETY_RESET_SERVICE,
};

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

pub use ethernetip_core::cip::{CipClass, CipDispatcher, CipPath};
pub use ethernetip_core::{EipError, Result};
