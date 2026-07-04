//! Common CIP Safety types.

use ethernetip_core::error::{EipError, Result};

/// Which safety wire format a connection uses.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyFormat {
    Base = 0,
    Extended = 1,
}

/// Mode byte.
///
/// Bit layout:
/// * bit 7    — `Run_Idle`
/// * bits 6-5 — `TBD_2_Bit` (reserved)
/// * bit 4    — `N_Run_Idle` (complement of bit 7)
/// * bit 3    — `TBD_Bit` (reserved)
/// * bit 2    — `N_TBD_Bit` (complement of bit 3, always 1 when bit 3 is 0)
/// * bits 1-0 — `Ping_Count`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeByte(pub u8);

impl ModeByte {
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    pub const fn run_idle(self) -> bool {
        self.0 & 0x80 != 0
    }

    pub const fn ping_count(self) -> u8 {
        self.0 & 0x03
    }

    /// Bits used in actual/complement data CRC seeding: `raw & 0xE0`.
    pub const fn data_crc_mask(self) -> u8 {
        self.0 & 0xE0
    }

    /// Bits used in complement data CRC seeding (base format): `(raw ^ 0xFF) & 0xE0`.
    pub const fn complement_data_crc_mask(self) -> u8 {
        (self.0 ^ 0xFF) & 0xE0
    }

    /// Bits used in timestamp CRC seeding: `raw & 0x1F`.
    pub const fn timestamp_crc_mask(self) -> u8 {
        self.0 & 0x1F
    }

    /// Build a mode byte with correctly-populated redundant bits.
    pub const fn build(run_idle: bool, ping_count: u8) -> Self {
        let raw = (if run_idle { 0x80 } else { 0 }) | (ping_count & 0x03);
        Self(fill_redundant_bits(raw))
    }

    /// True iff the redundant bits are exact complements of their pairs.
    pub const fn valid(self) -> bool {
        let run = self.0 & 0x80 != 0;
        let n_run = self.0 & 0x10 != 0;
        if run == n_run {
            return false;
        }
        let tbd = self.0 & 0x08 != 0;
        let n_tbd = self.0 & 0x04 != 0;
        if tbd == n_tbd {
            return false;
        }
        true
    }
}

const fn fill_redundant_bits(raw: u8) -> u8 {
    let mut r = raw;
    if r & 0x80 == 0 {
        r |= 0x10;
    } else {
        r &= !0x10;
    }
    if r & 0x08 == 0 {
        r |= 0x04;
    } else {
        r &= !0x04;
    }
    r
}

/// 6-byte unique identifier for a safety network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SafetyNetworkNumber(pub [u8; 6]);

impl SafetyNetworkNumber {
    pub const fn zero() -> Self {
        Self([0; 6])
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 6 {
            return Err(EipError::Short {
                expected: 6,
                actual: bytes.len(),
            });
        }
        let mut out = [0u8; 6];
        out.copy_from_slice(&bytes[..6]);
        Ok(Self(out))
    }

    pub fn copy_to(&self, dst: &mut [u8]) {
        dst[..6].copy_from_slice(&self.0);
    }
}

/// Safety Configuration ID = SCCRC (4 bytes) + SCTS (6 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SafetyConfigurationId {
    pub sccrc: u32,
    pub scts: SafetyNetworkNumber,
}

impl SafetyConfigurationId {
    pub const SIZE: usize = 10;

    pub fn copy_to(&self, dst: &mut [u8]) {
        dst[0..4].copy_from_slice(&self.sccrc.to_le_bytes());
        self.scts.copy_to(&mut dst[4..10]);
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(EipError::Short {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            sccrc: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            scts: SafetyNetworkNumber::parse(&bytes[4..10])?,
        })
    }
}

/// Unique Network Identifier — either TUNID (target) or OUNID (originator).
/// SNN (6 bytes) + NodeAddress (4 bytes) = 10 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UniqueNetworkId {
    pub snn: SafetyNetworkNumber,
    pub node_address: u32,
}

impl UniqueNetworkId {
    pub const SIZE: usize = 10;

    pub fn copy_to(&self, dst: &mut [u8]) {
        self.snn.copy_to(&mut dst[0..6]);
        dst[6..10].copy_from_slice(&self.node_address.to_le_bytes());
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(EipError::Short {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            snn: SafetyNetworkNumber::parse(&bytes[0..6])?,
            node_address: u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_byte_build_has_valid_redundant_bits() {
        let mb = ModeByte::build(true, 2);
        assert!(mb.valid());
        assert!(mb.run_idle());
        assert_eq!(mb.ping_count(), 2);
    }

    #[test]
    fn mode_byte_run_and_idle_differ() {
        let run = ModeByte::build(true, 0);
        let idle = ModeByte::build(false, 0);
        assert_ne!(run.0, idle.0);
        assert!(run.valid());
        assert!(idle.valid());
    }

    #[test]
    fn mode_byte_crc_masks() {
        let mb = ModeByte::build(true, 3);
        assert_eq!(mb.data_crc_mask() & 0x1F, 0);
        assert_eq!(mb.complement_data_crc_mask() & 0x1F, 0);
        assert_eq!(mb.timestamp_crc_mask() & 0xE0, 0);
    }

    #[test]
    fn snn_round_trip() {
        let snn = SafetyNetworkNumber([1, 2, 3, 4, 5, 6]);
        let mut buf = [0u8; 6];
        snn.copy_to(&mut buf);
        assert_eq!(SafetyNetworkNumber::parse(&buf).unwrap(), snn);
    }

    #[test]
    fn unid_round_trip() {
        let unid = UniqueNetworkId {
            snn: SafetyNetworkNumber([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            node_address: 0x0102_0304,
        };
        let mut buf = [0u8; 10];
        unid.copy_to(&mut buf);
        assert_eq!(UniqueNetworkId::parse(&buf).unwrap(), unid);
    }

    #[test]
    fn scid_round_trip() {
        let s = SafetyConfigurationId {
            sccrc: 0xDEAD_BEEF,
            scts: SafetyNetworkNumber([0xA, 0xB, 0xC, 0xD, 0xE, 0xF]),
        };
        let mut buf = [0u8; 10];
        s.copy_to(&mut buf);
        assert_eq!(SafetyConfigurationId::parse(&buf).unwrap(), s);
    }
}
