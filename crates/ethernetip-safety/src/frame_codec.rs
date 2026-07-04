//! Safety data frame codec.
//!
//! Four wire flavors, dispatched by `(SafetyFormat, data_length ≤ 2)`:
//!
//! * Base short  — small data (≤ 2 B): mode + S1(data) + S2(complement) + ts + S1(ts)
//! * Base long   — mode + S3(data) + complement data + S3(complement) + ts + S1(ts)
//! * Ext short   — mode + S5_lo + ts + S5_hi (rollover-seeded)
//! * Ext long    — mode + S3(data) + complement + S5_lo + ts + S5_hi
//!
//! The extended-format CRCs are seeded with the *rollover count* folded into
//! the PID/CID seed, so both producer and consumer have to track the same
//! rollover value.

use crate::crc;
use crate::types::{ModeByte, SafetyFormat};

/// Successful decode result.
#[derive(Debug, Clone)]
pub struct DecodedFrame {
    pub actual_data: Vec<u8>,
    pub mode: ModeByte,
    pub timestamp: u16,
}

/// Reason a decode failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyDecodeError {
    TooShort {
        expected: usize,
        actual: usize,
    },
    /// Actual-data CRC (S1 base-short, S3 base-long) didn't match.
    ActualDataCrc,
    /// Complement-data CRC (S2 base-short, S3 base-long) didn't match.
    ComplementDataCrc,
    /// Timestamp CRC-S1 didn't match (base format).
    TimestampCrc,
    /// Extended-format short CRC-S5 didn't match.
    ExtendedShortCrc,
    /// Extended-format long CRC-S5 didn't match.
    ExtendedLongCrc,
    /// `data XOR 0xFF` didn't match the complement bytes on the wire.
    ComplementMismatch,
}

/// Total on-wire size for a data frame of `data_length` bytes.
pub fn wire_size(data_length: usize, _format: SafetyFormat) -> usize {
    if data_length <= 2 {
        data_length + 6
    } else {
        2 * data_length + 8
    }
}

/// Pull the timestamp out of the wire buffer *without* checking any CRCs.
///
/// The consumer needs this before it can compute the CRC seeds (since the
/// rollover count folds into the seed), so the safety validator peels the
/// timestamp off up front, decides whether the target's counter rolled, and
/// then verifies with the right seeds.
pub fn extract_timestamp(input: &[u8], data_len: usize, _format: SafetyFormat) -> u16 {
    let is_short = data_len <= 2;
    // Layout: data + mode + a_crc(2) + [comp(data_len) if long] + [s5_lo(2) if ext long] +
    //         [c_crc(2) if base long] + ts. For short frames: data + mode + s5_lo(2 ext)
    //         or (a_crc + c_crc)(2) base short + ts.
    // Long frames — either base (a_crc + comp + c_crc) or extended (a_crc + comp + s5_lo)
    // — always have 2*data_len + 5 bytes ahead of the timestamp.
    let off = if is_short {
        data_len + 3
    } else {
        2 * data_len + 5
    };
    if off + 2 > input.len() {
        return 0;
    }
    u16::from_le_bytes([input[off], input[off + 1]])
}

/// Encode a safety data frame.
#[allow(clippy::too_many_arguments)]
pub fn encode(
    output: &mut [u8],
    data: &[u8],
    format: SafetyFormat,
    mode: ModeByte,
    timestamp: u16,
    pid_seed_s1: u8,
    pid_seed_s3: u16,
    pid_seed_s5: u32,
    rollover_count: u16,
) -> usize {
    let is_short = data.len() <= 2;
    match (format, is_short) {
        (SafetyFormat::Base, true) => encode_base_short(output, data, mode, timestamp, pid_seed_s1),
        (SafetyFormat::Base, false) => {
            encode_base_long(output, data, mode, timestamp, pid_seed_s1, pid_seed_s3)
        }
        (SafetyFormat::Extended, true) => {
            encode_extended_short(output, data, mode, timestamp, pid_seed_s5, rollover_count)
        }
        (SafetyFormat::Extended, false) => encode_extended_long(
            output,
            data,
            mode,
            timestamp,
            pid_seed_s3,
            pid_seed_s5,
            rollover_count,
        ),
    }
}

/// Decode a safety data frame.
#[allow(clippy::too_many_arguments)]
pub fn decode(
    input: &[u8],
    data_len: usize,
    format: SafetyFormat,
    pid_seed_s1: u8,
    pid_seed_s3: u16,
    pid_seed_s5: u32,
    rollover_count: u16,
) -> Result<DecodedFrame, SafetyDecodeError> {
    let is_short = data_len <= 2;
    match (format, is_short) {
        (SafetyFormat::Base, true) => decode_base_short(input, data_len, pid_seed_s1),
        (SafetyFormat::Base, false) => {
            decode_base_long(input, data_len, pid_seed_s1, pid_seed_s3)
        }
        (SafetyFormat::Extended, true) => {
            decode_extended_short(input, data_len, pid_seed_s5, rollover_count)
        }
        (SafetyFormat::Extended, false) => {
            decode_extended_long(input, data_len, pid_seed_s3, pid_seed_s5, rollover_count)
        }
    }
}

// -------------------- base short --------------------

fn encode_base_short(
    out: &mut [u8],
    data: &[u8],
    mode: ModeByte,
    ts: u16,
    pid_seed_s1: u8,
) -> usize {
    let mut off = 0;
    out[off..off + data.len()].copy_from_slice(data);
    off += data.len();
    out[off] = mode.0;
    off += 1;

    let mask = mode.data_crc_mask();
    let mut a_crc = crc::compute_s1(&[mask], pid_seed_s1);
    a_crc = crc::compute_s1(data, a_crc);
    out[off] = a_crc;
    off += 1;

    let cmpl_mask = mode.complement_data_crc_mask();
    let mut c_crc = crc::compute_s2(&[cmpl_mask], pid_seed_s1);
    let mut comp_buf = [0u8; 2];
    for i in 0..data.len() {
        comp_buf[i] = data[i] ^ 0xFF;
    }
    c_crc = crc::compute_s2(&comp_buf[..data.len()], c_crc);
    out[off] = c_crc;
    off += 1;

    out[off..off + 2].copy_from_slice(&ts.to_le_bytes());
    off += 2;
    let ts_mask = mode.timestamp_crc_mask();
    let mut ts_crc = crc::compute_s1(&[ts_mask], pid_seed_s1);
    ts_crc = crc::compute_s1(&ts.to_le_bytes(), ts_crc);
    out[off] = ts_crc;
    off += 1;
    off
}

fn decode_base_short(
    input: &[u8],
    data_len: usize,
    pid_seed_s1: u8,
) -> Result<DecodedFrame, SafetyDecodeError> {
    let expected = data_len + 6;
    if input.len() < expected {
        return Err(SafetyDecodeError::TooShort {
            expected,
            actual: input.len(),
        });
    }
    let mut off = 0;
    let data = input[off..off + data_len].to_vec();
    off += data_len;
    let mode = ModeByte::new(input[off]);
    off += 1;
    let wire_a = input[off];
    off += 1;
    let wire_c = input[off];
    off += 1;
    let ts = u16::from_le_bytes([input[off], input[off + 1]]);
    off += 2;
    let wire_ts = input[off];

    let mask = mode.data_crc_mask();
    let mut a_crc = crc::compute_s1(&[mask], pid_seed_s1);
    a_crc = crc::compute_s1(&data, a_crc);
    if a_crc != wire_a {
        return Err(SafetyDecodeError::ActualDataCrc);
    }

    let cmpl_mask = mode.complement_data_crc_mask();
    let mut c_crc = crc::compute_s2(&[cmpl_mask], pid_seed_s1);
    let mut comp_buf = [0u8; 2];
    for i in 0..data_len {
        comp_buf[i] = data[i] ^ 0xFF;
    }
    c_crc = crc::compute_s2(&comp_buf[..data_len], c_crc);
    if c_crc != wire_c {
        return Err(SafetyDecodeError::ComplementDataCrc);
    }

    let ts_mask = mode.timestamp_crc_mask();
    let mut ts_crc = crc::compute_s1(&[ts_mask], pid_seed_s1);
    ts_crc = crc::compute_s1(&ts.to_le_bytes(), ts_crc);
    if ts_crc != wire_ts {
        return Err(SafetyDecodeError::TimestampCrc);
    }

    Ok(DecodedFrame {
        actual_data: data,
        mode,
        timestamp: ts,
    })
}

// -------------------- base long --------------------

fn encode_base_long(
    out: &mut [u8],
    data: &[u8],
    mode: ModeByte,
    ts: u16,
    pid_seed_s1: u8,
    pid_seed_s3: u16,
) -> usize {
    let mut off = 0;
    out[off..off + data.len()].copy_from_slice(data);
    off += data.len();
    out[off] = mode.0;
    off += 1;

    let mut a_crc = crc::compute_s3_byte(mode.data_crc_mask(), pid_seed_s3);
    a_crc = crc::compute_s3(data, a_crc);
    out[off..off + 2].copy_from_slice(&a_crc.to_le_bytes());
    off += 2;

    let comp_off = off;
    for i in 0..data.len() {
        out[comp_off + i] = data[i] ^ 0xFF;
    }
    let comp_slice: Vec<u8> = out[comp_off..comp_off + data.len()].to_vec();
    off += data.len();

    let mut c_crc = crc::compute_s3_byte(mode.complement_data_crc_mask(), pid_seed_s3);
    c_crc = crc::compute_s3(&comp_slice, c_crc);
    out[off..off + 2].copy_from_slice(&c_crc.to_le_bytes());
    off += 2;

    out[off..off + 2].copy_from_slice(&ts.to_le_bytes());
    off += 2;
    let ts_mask = mode.timestamp_crc_mask();
    let mut ts_crc = crc::compute_s1(&[ts_mask], pid_seed_s1);
    ts_crc = crc::compute_s1(&ts.to_le_bytes(), ts_crc);
    out[off] = ts_crc;
    off += 1;
    off
}

fn decode_base_long(
    input: &[u8],
    data_len: usize,
    pid_seed_s1: u8,
    pid_seed_s3: u16,
) -> Result<DecodedFrame, SafetyDecodeError> {
    let expected = 2 * data_len + 8;
    if input.len() < expected {
        return Err(SafetyDecodeError::TooShort {
            expected,
            actual: input.len(),
        });
    }
    let mut off = 0;
    let data = input[off..off + data_len].to_vec();
    off += data_len;
    let mode = ModeByte::new(input[off]);
    off += 1;
    let wire_a = u16::from_le_bytes([input[off], input[off + 1]]);
    off += 2;
    let comp = input[off..off + data_len].to_vec();
    off += data_len;
    let wire_c = u16::from_le_bytes([input[off], input[off + 1]]);
    off += 2;
    let ts = u16::from_le_bytes([input[off], input[off + 1]]);
    off += 2;
    let wire_ts = input[off];

    for i in 0..data_len {
        if data[i] ^ 0xFF != comp[i] {
            return Err(SafetyDecodeError::ComplementMismatch);
        }
    }
    let mut a_crc = crc::compute_s3_byte(mode.data_crc_mask(), pid_seed_s3);
    a_crc = crc::compute_s3(&data, a_crc);
    if a_crc != wire_a {
        return Err(SafetyDecodeError::ActualDataCrc);
    }
    let mut c_crc = crc::compute_s3_byte(mode.complement_data_crc_mask(), pid_seed_s3);
    c_crc = crc::compute_s3(&comp, c_crc);
    if c_crc != wire_c {
        return Err(SafetyDecodeError::ComplementDataCrc);
    }
    let ts_mask = mode.timestamp_crc_mask();
    let mut ts_crc = crc::compute_s1(&[ts_mask], pid_seed_s1);
    ts_crc = crc::compute_s1(&ts.to_le_bytes(), ts_crc);
    if ts_crc != wire_ts {
        return Err(SafetyDecodeError::TimestampCrc);
    }
    Ok(DecodedFrame {
        actual_data: data,
        mode,
        timestamp: ts,
    })
}

// -------------------- extended short --------------------

fn encode_extended_short(
    out: &mut [u8],
    data: &[u8],
    mode: ModeByte,
    ts: u16,
    pid_seed_s5: u32,
    rollover_count: u16,
) -> usize {
    let mut off = 0;
    out[off..off + data.len()].copy_from_slice(data);
    off += data.len();
    out[off] = mode.0;
    off += 1;

    let rc_seed = crc::pid_rollover_seed_s5(rollover_count, pid_seed_s5);
    let mut crc_in = [0u8; 5];
    crc_in[0] = mode.data_crc_mask();
    crc_in[1..1 + data.len()].copy_from_slice(data);
    let ts_bytes = ts.to_le_bytes();
    crc_in[1 + data.len()..3 + data.len()].copy_from_slice(&ts_bytes);
    let s5 = crc::compute_s5_raw(&crc_in[..1 + data.len() + 2], rc_seed);

    out[off..off + 2].copy_from_slice(&((s5 & 0xFFFF) as u16).to_le_bytes());
    off += 2;
    out[off..off + 2].copy_from_slice(&ts.to_le_bytes());
    off += 2;
    out[off] = ((s5 >> 16) & 0xFF) as u8;
    off += 1;
    off
}

fn decode_extended_short(
    input: &[u8],
    data_len: usize,
    pid_seed_s5: u32,
    rollover_count: u16,
) -> Result<DecodedFrame, SafetyDecodeError> {
    let expected = data_len + 6;
    if input.len() < expected {
        return Err(SafetyDecodeError::TooShort {
            expected,
            actual: input.len(),
        });
    }
    let mut off = 0;
    let data = input[off..off + data_len].to_vec();
    off += data_len;
    let mode = ModeByte::new(input[off]);
    off += 1;
    let s5_lo = u16::from_le_bytes([input[off], input[off + 1]]);
    off += 2;
    let ts = u16::from_le_bytes([input[off], input[off + 1]]);
    off += 2;
    let s5_hi = input[off];

    let rc_seed = crc::pid_rollover_seed_s5(rollover_count, pid_seed_s5);
    let mut crc_in = [0u8; 5];
    crc_in[0] = mode.data_crc_mask();
    crc_in[1..1 + data_len].copy_from_slice(&data);
    crc_in[1 + data_len..3 + data_len].copy_from_slice(&ts.to_le_bytes());
    let expected_s5 = crc::compute_s5_raw(&crc_in[..1 + data_len + 2], rc_seed);

    let wire_s5 = (s5_lo as u32) | ((s5_hi as u32) << 16);
    if wire_s5 != (expected_s5 & 0x00FF_FFFF) {
        return Err(SafetyDecodeError::ExtendedShortCrc);
    }
    Ok(DecodedFrame {
        actual_data: data,
        mode,
        timestamp: ts,
    })
}

// -------------------- extended long --------------------

fn encode_extended_long(
    out: &mut [u8],
    data: &[u8],
    mode: ModeByte,
    ts: u16,
    pid_seed_s3: u16,
    pid_seed_s5: u32,
    rollover_count: u16,
) -> usize {
    let mut off = 0;
    out[off..off + data.len()].copy_from_slice(data);
    off += data.len();
    out[off] = mode.0;
    off += 1;

    let rc_seed_s3 = crc::pid_rollover_seed_s3(rollover_count, pid_seed_s3);
    let mut a_crc = crc::compute_s3_byte(mode.data_crc_mask(), rc_seed_s3);
    a_crc = crc::compute_s3(data, a_crc);
    out[off..off + 2].copy_from_slice(&a_crc.to_le_bytes());
    off += 2;

    let comp_off = off;
    for i in 0..data.len() {
        out[comp_off + i] = data[i] ^ 0xFF;
    }
    let comp: Vec<u8> = out[comp_off..comp_off + data.len()].to_vec();
    off += data.len();

    let rc_seed_s5 = crc::pid_rollover_seed_s5(rollover_count, pid_seed_s5);
    let mut comp_crc_in = Vec::with_capacity(1 + data.len() + 2);
    comp_crc_in.push(mode.timestamp_crc_mask());
    comp_crc_in.extend_from_slice(&comp);
    comp_crc_in.extend_from_slice(&ts.to_le_bytes());
    let s5 = crc::compute_s5_raw(&comp_crc_in, rc_seed_s5);

    out[off..off + 2].copy_from_slice(&((s5 & 0xFFFF) as u16).to_le_bytes());
    off += 2;
    out[off..off + 2].copy_from_slice(&ts.to_le_bytes());
    off += 2;
    out[off] = ((s5 >> 16) & 0xFF) as u8;
    off += 1;
    off
}

fn decode_extended_long(
    input: &[u8],
    data_len: usize,
    pid_seed_s3: u16,
    pid_seed_s5: u32,
    rollover_count: u16,
) -> Result<DecodedFrame, SafetyDecodeError> {
    let expected = 2 * data_len + 8;
    if input.len() < expected {
        return Err(SafetyDecodeError::TooShort {
            expected,
            actual: input.len(),
        });
    }
    let mut off = 0;
    let data = input[off..off + data_len].to_vec();
    off += data_len;
    let mode = ModeByte::new(input[off]);
    off += 1;
    let wire_a = u16::from_le_bytes([input[off], input[off + 1]]);
    off += 2;
    let comp = input[off..off + data_len].to_vec();
    off += data_len;
    let s5_lo = u16::from_le_bytes([input[off], input[off + 1]]);
    off += 2;
    let ts = u16::from_le_bytes([input[off], input[off + 1]]);
    off += 2;
    let s5_hi = input[off];

    for i in 0..data_len {
        if data[i] ^ 0xFF != comp[i] {
            return Err(SafetyDecodeError::ComplementMismatch);
        }
    }
    let rc_seed_s3 = crc::pid_rollover_seed_s3(rollover_count, pid_seed_s3);
    let mut a_crc = crc::compute_s3_byte(mode.data_crc_mask(), rc_seed_s3);
    a_crc = crc::compute_s3(&data, a_crc);
    if a_crc != wire_a {
        return Err(SafetyDecodeError::ActualDataCrc);
    }
    let rc_seed_s5 = crc::pid_rollover_seed_s5(rollover_count, pid_seed_s5);
    let mut comp_crc_in = Vec::with_capacity(1 + data_len + 2);
    comp_crc_in.push(mode.timestamp_crc_mask());
    comp_crc_in.extend_from_slice(&comp);
    comp_crc_in.extend_from_slice(&ts.to_le_bytes());
    let expected_s5 = crc::compute_s5_raw(&comp_crc_in, rc_seed_s5);

    let wire_s5 = (s5_lo as u32) | ((s5_hi as u32) << 16);
    if wire_s5 != (expected_s5 & 0x00FF_FFFF) {
        return Err(SafetyDecodeError::ExtendedLongCrc);
    }
    Ok(DecodedFrame {
        actual_data: data,
        mode,
        timestamp: ts,
    })
}

// -------------------- time coordination --------------------

/// Build the ACK byte for a TCOO reply (bits 1:0 = ping_count, bit 3 = ping
/// response, bit 7 = odd-parity of bits 0..6).
fn build_ack_byte(ping_count_reply: u8) -> u8 {
    let mut ack = (ping_count_reply & 0x03) | 0x08;
    let mut bit_count = 0;
    for i in 0..7 {
        if (ack >> i) & 1 != 0 {
            bit_count += 1;
        }
    }
    if bit_count % 2 == 1 {
        ack |= 0x80;
    }
    ack
}

/// Base-format TCOO reply (6 bytes).
pub fn encode_time_coordination(
    output: &mut [u8],
    ping_count_reply: u8,
    consumer_time_value: u16,
    cid_seed_s3: u16,
) -> usize {
    let mut off = 0;
    let ack = build_ack_byte(ping_count_reply);
    output[off] = ack;
    off += 1;
    output[off..off + 2].copy_from_slice(&consumer_time_value.to_le_bytes());
    off += 2;
    // Alternating-bit-preserving twin of ack (bits from ack XOR 0xFF where the
    // low-nibble mask says so).
    let ack2 = (((ack ^ 0xFF) & 0x55) | (ack & 0xAA)) & 0xFF;
    output[off] = ack2;
    off += 1;
    let mut s3 = crc::compute_s3_byte(ack, cid_seed_s3);
    s3 = crc::compute_s3_u16(consumer_time_value, s3);
    output[off..off + 2].copy_from_slice(&s3.to_le_bytes());
    off += 2;
    off
}

/// Extended-format TCOO reply (6 bytes).
pub fn encode_time_coordination_extended(
    output: &mut [u8],
    ping_count_reply: u8,
    consumer_time_value: u16,
    pid_seed_s5: u32,
) -> usize {
    let mut off = 0;
    let ack = build_ack_byte(ping_count_reply);
    output[off] = ack;
    off += 1;
    output[off..off + 2].copy_from_slice(&consumer_time_value.to_le_bytes());
    off += 2;

    let s5 = crc::compute_s5_raw(&[ack], pid_seed_s5);
    let s5 = crc::compute_s5_raw(&consumer_time_value.to_le_bytes(), s5);

    output[off] = (s5 & 0xFF) as u8;
    off += 1;
    output[off] = ((s5 >> 8) & 0xFF) as u8;
    off += 1;
    output[off] = ((s5 >> 16) & 0xFF) as u8;
    off += 1;
    off
}

#[cfg(test)]
mod tests {
    use super::*;

    const PID_S1: u8 = 0xA5;
    const PID_S3: u16 = 0x1234;
    const PID_S5: u32 = 0x00CA_FE55;

    fn round_trip(format: SafetyFormat, data: &[u8]) {
        let mode = ModeByte::build(true, 2);
        let ts = 0x1234;
        let rc = 0;
        let mut buf = vec![0u8; wire_size(data.len(), format)];
        let n = encode(&mut buf, data, format, mode, ts, PID_S1, PID_S3, PID_S5, rc);
        assert_eq!(n, buf.len(), "wire_size mismatch");
        let dec = decode(&buf, data.len(), format, PID_S1, PID_S3, PID_S5, rc).unwrap();
        assert_eq!(dec.actual_data, data);
        assert_eq!(dec.mode.0, mode.0);
        assert_eq!(dec.timestamp, ts);
    }

    #[test]
    fn base_short_round_trip() {
        round_trip(SafetyFormat::Base, &[0xAB]);
        round_trip(SafetyFormat::Base, &[0xAB, 0xCD]);
    }

    #[test]
    fn base_long_round_trip() {
        round_trip(SafetyFormat::Base, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn ext_short_round_trip() {
        round_trip(SafetyFormat::Extended, &[0xAB]);
        round_trip(SafetyFormat::Extended, &[0xAB, 0xCD]);
    }

    #[test]
    fn ext_long_round_trip() {
        round_trip(SafetyFormat::Extended, &[10, 20, 30, 40, 50, 60, 70, 80]);
    }

    #[test]
    fn ext_long_rollover_changes_wire() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mode = ModeByte::build(true, 0);
        let ts = 0x1234;
        let mut a = vec![0u8; wire_size(data.len(), SafetyFormat::Extended)];
        let mut b = vec![0u8; wire_size(data.len(), SafetyFormat::Extended)];
        encode(
            &mut a,
            &data,
            SafetyFormat::Extended,
            mode,
            ts,
            PID_S1,
            PID_S3,
            PID_S5,
            0,
        );
        encode(
            &mut b,
            &data,
            SafetyFormat::Extended,
            mode,
            ts,
            PID_S1,
            PID_S3,
            PID_S5,
            1,
        );
        assert_ne!(a, b, "wire bytes must depend on rollover count");
    }

    #[test]
    fn detects_tampering() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mode = ModeByte::build(true, 0);
        let mut buf = vec![0u8; wire_size(data.len(), SafetyFormat::Base)];
        encode(
            &mut buf,
            &data,
            SafetyFormat::Base,
            mode,
            0,
            PID_S1,
            PID_S3,
            PID_S5,
            0,
        );
        buf[0] ^= 0xFF;
        let err = decode(&buf, data.len(), SafetyFormat::Base, PID_S1, PID_S3, PID_S5, 0)
            .unwrap_err();
        assert!(matches!(
            err,
            SafetyDecodeError::ComplementMismatch
                | SafetyDecodeError::ActualDataCrc
                | SafetyDecodeError::ComplementDataCrc
        ));
    }

    #[test]
    fn extract_timestamp_matches_encoded() {
        let data = [10u8, 20, 30, 40, 50, 60, 70, 80];
        let ts = 0xBEEF;
        let mut buf = vec![0u8; wire_size(data.len(), SafetyFormat::Extended)];
        encode(
            &mut buf,
            &data,
            SafetyFormat::Extended,
            ModeByte::build(true, 1),
            ts,
            PID_S1,
            PID_S3,
            PID_S5,
            0,
        );
        assert_eq!(
            extract_timestamp(&buf, data.len(), SafetyFormat::Extended),
            ts
        );
    }
}
