//! CIP Safety building blocks.
//!
//! Landing in commits:
//! 1. [`crc`] — CRC-S1/S2/S3/S4/S5 with PID/CID seed helpers.
//! 2. Safety network segment codec.
//! 3. Safety frame codec (base + extended formats).
//! 4. Safety scanner + adapter with Supervisor / Validator objects.

pub mod crc;

pub use ethernetip_core::{EipError, Result};
