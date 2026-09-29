//! CIP 16-bit CRC (polynomial 0xA001, initial value 0, right-shift with XOR).
//!
//! Same math as CRC-16/ARC (reversed 0x8005). Matches the reference
//! implementation in CIP Vol 1 §C-7 and passes the spec's own test vectors:
//! ```
//! use ethernetip_core::cip_crc::crc16;
//! assert_eq!(crc16(&[0xA2, 0x03, 0xC7, 0xC2, 0xC3]), 0x5159);
//! assert_eq!(crc16(&[0xA2, 0x07, 0xC7, 0xA2, 0x03, 0xC7, 0xC2, 0xC3, 0xC3]), 0x26C7);
//! ```

pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bytes {
        crc ^= b as u16;
        for _ in 0..8 {
            let carry = (crc & 1) != 0;
            crc >>= 1;
            if carry {
                crc ^= 0xA001;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_spec_vector_1() {
        assert_eq!(crc16(&[0xA2, 0x03, 0xC7, 0xC2, 0xC3]), 0x5159);
    }

    #[test]
    fn matches_spec_vector_2() {
        assert_eq!(
            crc16(&[0xA2, 0x07, 0xC7, 0xA2, 0x03, 0xC7, 0xC2, 0xC3, 0xC3]),
            0x26C7
        );
    }

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(crc16(&[]), 0);
    }

    #[test]
    fn single_zero_byte_stays_zero() {
        assert_eq!(crc16(&[0x00]), 0);
    }
}
