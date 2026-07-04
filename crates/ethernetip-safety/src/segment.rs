//! CIP Safety network segment carried inside a `Forward_Open` connection path.
//!
//! There are three flavors, distinguished by the `format` byte immediately
//! after the segment length:
//!
//! * `0x00` — Target format. Full parameter block used by the safety validator.
//! * `0x01` — Router format. Minimal — just tells the router which
//!   connection-id / EPI / params to forward.
//! * `0x02` — Extended format. Same as target plus a max-fault counter and
//!   the initial timestamp / rollover value for the extended-format frame.

use ethernetip_core::error::{EipError, Result};

use crate::types::{SafetyNetworkNumber, UniqueNetworkId};

/// CIP Safety Network Segment type byte.
pub const SEGMENT_TYPE: u8 = 0x50;

/// One decoded / to-be-encoded safety network segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyNetworkSegment {
    /// `0x00` target, `0x01` router, `0x02` extended.
    pub format: u8,
    pub sccrc: u32,
    pub scts: SafetyNetworkNumber,
    pub time_correction_epi: u32,
    pub time_correction_params: u16,
    pub tunid: UniqueNetworkId,
    pub ounid: UniqueNetworkId,
    pub ping_interval_multiplier: u16,
    pub time_coord_msg_min_multiplier: u16,
    pub network_time_expectation_multiplier: u16,
    pub timeout_multiplier: u8,
    pub max_consumer_number: u8,
    /// Extended format only.
    pub max_fault_number: u16,
    pub cpcrc: u32,
    pub time_correction_connection_id: u32,
    /// Extended format only.
    pub initial_time_stamp: u16,
    /// Extended format only.
    pub initial_rollover_value: u16,
}

impl Default for SafetyNetworkSegment {
    fn default() -> Self {
        Self {
            format: 0x00,
            sccrc: 0,
            scts: SafetyNetworkNumber::zero(),
            time_correction_epi: 0,
            time_correction_params: 0,
            tunid: UniqueNetworkId::default(),
            ounid: UniqueNetworkId::default(),
            ping_interval_multiplier: 0,
            time_coord_msg_min_multiplier: 0,
            network_time_expectation_multiplier: 0,
            timeout_multiplier: 0,
            max_consumer_number: 1,
            max_fault_number: 0,
            cpcrc: 0,
            time_correction_connection_id: 0,
            initial_time_stamp: 0,
            initial_rollover_value: 0,
        }
    }
}

impl SafetyNetworkSegment {
    /// Total on-wire size in bytes for a given format.
    pub fn wire_size(&self) -> usize {
        match self.format {
            0x00 => 56,
            0x01 => 14,
            0x02 => 62,
            _ => 2,
        }
    }

    /// Encode into `dst`. Returns the number of bytes written.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize> {
        let is_extended = self.format == 0x02;
        if self.format == 0x01 {
            // Router flavor.
            if dst.len() < 14 {
                return Err(EipError::Short {
                    expected: 14,
                    actual: dst.len(),
                });
            }
            dst[0] = SEGMENT_TYPE;
            dst[1] = 0x06; // 6 words = 12 bytes after the 2-byte header
            dst[2] = self.format;
            dst[3] = 0; // reserved pad
            dst[4..8].copy_from_slice(&self.time_correction_connection_id.to_le_bytes());
            dst[8..12].copy_from_slice(&self.time_correction_epi.to_le_bytes());
            dst[12..14].copy_from_slice(&self.time_correction_params.to_le_bytes());
            return Ok(14);
        }
        let data_len_words: u8 = if is_extended { 0x1E } else { 0x1B };
        let expected = if is_extended { 62 } else { 56 };
        if dst.len() < expected {
            return Err(EipError::Short {
                expected,
                actual: dst.len(),
            });
        }
        let mut off = 0;
        dst[off] = SEGMENT_TYPE;
        off += 1;
        dst[off] = data_len_words;
        off += 1;
        dst[off] = self.format;
        off += 1;
        dst[off] = 0;
        off += 1;
        dst[off..off + 4].copy_from_slice(&self.sccrc.to_le_bytes());
        off += 4;
        self.scts.copy_to(&mut dst[off..off + 6]);
        off += 6;
        dst[off..off + 4].copy_from_slice(&self.time_correction_epi.to_le_bytes());
        off += 4;
        dst[off..off + 2].copy_from_slice(&self.time_correction_params.to_le_bytes());
        off += 2;
        self.tunid.copy_to(&mut dst[off..off + UniqueNetworkId::SIZE]);
        off += UniqueNetworkId::SIZE;
        self.ounid.copy_to(&mut dst[off..off + UniqueNetworkId::SIZE]);
        off += UniqueNetworkId::SIZE;
        dst[off..off + 2].copy_from_slice(&self.ping_interval_multiplier.to_le_bytes());
        off += 2;
        dst[off..off + 2].copy_from_slice(&self.time_coord_msg_min_multiplier.to_le_bytes());
        off += 2;
        dst[off..off + 2].copy_from_slice(&self.network_time_expectation_multiplier.to_le_bytes());
        off += 2;
        dst[off] = self.timeout_multiplier;
        off += 1;
        dst[off] = self.max_consumer_number;
        off += 1;
        if is_extended {
            dst[off..off + 2].copy_from_slice(&self.max_fault_number.to_le_bytes());
            off += 2;
        }
        dst[off..off + 4].copy_from_slice(&self.cpcrc.to_le_bytes());
        off += 4;
        dst[off..off + 4].copy_from_slice(&self.time_correction_connection_id.to_le_bytes());
        off += 4;
        if is_extended {
            dst[off..off + 2].copy_from_slice(&self.initial_time_stamp.to_le_bytes());
            off += 2;
            dst[off..off + 2].copy_from_slice(&self.initial_rollover_value.to_le_bytes());
            off += 2;
        }
        Ok(off)
    }

    /// Encode into a fresh `Vec`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.wire_size()];
        let n = self.encode(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Parse and return the segment plus the number of bytes consumed.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 3 {
            return Err(EipError::Short {
                expected: 3,
                actual: bytes.len(),
            });
        }
        if bytes[0] != SEGMENT_TYPE {
            return Err(EipError::Protocol(format!(
                "not a safety network segment (leader 0x{:02X})",
                bytes[0]
            )));
        }
        let data_len_words = bytes[1] as usize;
        let total = 2 + data_len_words * 2;
        let format = bytes[2];
        if bytes.len() < total {
            return Err(EipError::Short {
                expected: total,
                actual: bytes.len(),
            });
        }

        let mut seg = SafetyNetworkSegment {
            format,
            ..Default::default()
        };

        if format == 0x01 {
            seg.time_correction_connection_id =
                u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            seg.time_correction_epi =
                u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            seg.time_correction_params = u16::from_le_bytes([bytes[12], bytes[13]]);
            return Ok((seg, total));
        }

        let mut off = 4;
        seg.sccrc = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        seg.scts = SafetyNetworkNumber::parse(&bytes[off..off + 6])?;
        off += 6;
        seg.time_correction_epi = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        seg.time_correction_params = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        seg.tunid = UniqueNetworkId::parse(&bytes[off..off + UniqueNetworkId::SIZE])?;
        off += UniqueNetworkId::SIZE;
        seg.ounid = UniqueNetworkId::parse(&bytes[off..off + UniqueNetworkId::SIZE])?;
        off += UniqueNetworkId::SIZE;
        seg.ping_interval_multiplier = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        seg.time_coord_msg_min_multiplier =
            u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        seg.network_time_expectation_multiplier =
            u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        seg.timeout_multiplier = bytes[off];
        off += 1;
        seg.max_consumer_number = bytes[off];
        off += 1;

        if format == 0x02 {
            seg.max_fault_number = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
            off += 2;
        }
        seg.cpcrc = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        seg.time_correction_connection_id =
            u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;
        if format == 0x02 {
            seg.initial_time_stamp = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
            off += 2;
            seg.initial_rollover_value = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
            off += 2;
        }
        let _ = off; // suppress unused_assignments after last field
        Ok((seg, total))
    }

    /// Convenience: word length of the segment (used to compute the
    /// `path_size` byte in Forward_Open).
    pub fn word_length(&self) -> u8 {
        (self.wire_size() / 2) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target_segment() -> SafetyNetworkSegment {
        SafetyNetworkSegment {
            format: 0x00,
            sccrc: 0xDEAD_BEEF,
            scts: SafetyNetworkNumber([1, 2, 3, 4, 5, 6]),
            time_correction_epi: 10_000,
            time_correction_params: 0x2481,
            tunid: UniqueNetworkId {
                snn: SafetyNetworkNumber([9, 8, 7, 6, 5, 4]),
                node_address: 0xC0A8_0158,
            },
            ounid: UniqueNetworkId {
                snn: SafetyNetworkNumber([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                node_address: 0xC0A8_014A,
            },
            ping_interval_multiplier: 3,
            time_coord_msg_min_multiplier: 100,
            network_time_expectation_multiplier: 200,
            timeout_multiplier: 4,
            max_consumer_number: 1,
            max_fault_number: 0,
            cpcrc: 0x1234_5678,
            time_correction_connection_id: 0xCAFE_F00D,
            initial_time_stamp: 0,
            initial_rollover_value: 0,
        }
    }

    #[test]
    fn target_round_trip() {
        let seg = make_target_segment();
        let bytes = seg.to_bytes().unwrap();
        assert_eq!(bytes.len(), 56);
        let (back, consumed) = SafetyNetworkSegment::parse(&bytes).unwrap();
        assert_eq!(consumed, 56);
        assert_eq!(back, seg);
    }

    #[test]
    fn extended_round_trip() {
        let mut seg = make_target_segment();
        seg.format = 0x02;
        seg.max_fault_number = 5;
        seg.initial_time_stamp = 0x1234;
        seg.initial_rollover_value = 0x5678;
        let bytes = seg.to_bytes().unwrap();
        assert_eq!(bytes.len(), 62);
        let (back, consumed) = SafetyNetworkSegment::parse(&bytes).unwrap();
        assert_eq!(consumed, 62);
        assert_eq!(back, seg);
    }

    #[test]
    fn router_round_trip() {
        let seg = SafetyNetworkSegment {
            format: 0x01,
            time_correction_connection_id: 0xDEAD_F00D,
            time_correction_epi: 5000,
            time_correction_params: 0x2481,
            ..SafetyNetworkSegment::default()
        };
        let bytes = seg.to_bytes().unwrap();
        assert_eq!(bytes.len(), 14);
        let (back, consumed) = SafetyNetworkSegment::parse(&bytes).unwrap();
        assert_eq!(consumed, 14);
        assert_eq!(back.format, 0x01);
        assert_eq!(back.time_correction_connection_id, 0xDEAD_F00D);
        assert_eq!(back.time_correction_epi, 5000);
        assert_eq!(back.time_correction_params, 0x2481);
    }
}
