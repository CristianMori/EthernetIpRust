//! Connection Parameter CRC (CPCRC).
//!
//! CPCRC is a CRC-32 over a carefully-assembled slice of the Forward_Open
//! request:
//!
//! * `connection_serial` + `originator_vendor` (bytes 10..14 of the raw
//!   `Forward_Open` service data)
//! * `timeout_ticks` through `path_size` (18 bytes at offset 18)
//! * the application path as the *target* will see it — no route prefix, so
//!   the caller has to patch the `path_size` byte to what the target expects
//! * the safety network segment data (NSD), which is the byte block from the
//!   segment `format` byte onward (48 bytes for target format, 50 for
//!   extended)
//!
//! The CRC covers everything the safety validator relies on to detect a
//! misdirected connection, so getting the slice boundaries exactly right is
//! critical.

use ethernetip_core::error::{EipError, Result};

use crate::crc;

/// Compute CPCRC from raw pieces of the Forward_Open request.
///
/// * `service_data` — the full `Forward_Open` MR body (from the `priority_tick`
///   byte through the last connection-path byte).
/// * `app_path` — the connection path as the target will see it (no route
///   prefix), word-aligned.
/// * `nsd` — safety network segment data (must be 48 or 50 bytes).
/// * `effective_path_size_words` — the value the target's own `path_size`
///   byte will hold (the caller usually subtracts the route length from the
///   full-request path size).
pub fn compute_from_raw(
    service_data: &[u8],
    app_path: &[u8],
    nsd: &[u8],
    effective_path_size_words: u8,
) -> Result<u32> {
    if service_data.len() < 36 {
        return Err(EipError::Short {
            expected: 36,
            actual: service_data.len(),
        });
    }
    if nsd.len() != 48 && nsd.len() != 50 {
        return Err(EipError::Protocol(format!(
            "NSD must be 48 (target) or 50 (extended) bytes, got {}",
            nsd.len()
        )));
    }
    let mut buf = Vec::with_capacity(4 + 18 + app_path.len() + nsd.len());
    // 4 bytes: connection_serial + originator_vendor.
    buf.extend_from_slice(&service_data[10..14]);
    // 18 bytes: timeout + O→T + T→O + transport + path_size.
    buf.extend_from_slice(&service_data[18..36]);
    // Patch the trailing path_size byte to what the target sees.
    *buf.last_mut().unwrap() = effective_path_size_words;
    buf.extend_from_slice(app_path);
    buf.extend_from_slice(nsd);
    Ok(crc::compute_s4(&buf))
}
