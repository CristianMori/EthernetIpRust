//! Build the wire bytes for an `Unconnected_Send` (service 0x52) message
//! routed through the Connection Manager (class 0x06, instance 1).
//!
//! Used by scanners that need to reach a device via a backplane route path
//! — for example route `1,N` to talk to a ControlLogix CPU in slot N
//! through its 1756-EN module.
//!
//! Layout matches the reference C# `UnconnectedSendBuilder`:
//! ```text
//!   USINT priority_and_tick_time
//!   USINT timeout_ticks
//!   UINT  embedded_message_size
//!   BYTES embedded_message
//!   BYTE  pad (only if embedded_message_size is odd)
//!   USINT route_path_size_words
//!   USINT reserved (0)
//!   BYTES route_path
//! ```
//! Outer MR wraps this as service `0x52` with path `0x20 0x06 0x24 0x01`.

use crate::error::{EipError, Result};

const SERVICE_CODE: u8 = 0x52;
const DEFAULT_PRIORITY_TICK: u8 = 0x07;
const DEFAULT_TIMEOUT_TICKS: u8 = 0xF9;
const CONNECTION_MANAGER_PATH: [u8; 4] = [0x20, 0x06, 0x24, 0x01];

/// Wrap an embedded MR into an Unconnected_Send MR ready for SendRRData.
pub fn wrap(inner_mr: &[u8], route_path: &[u8]) -> Result<Vec<u8>> {
    if route_path.is_empty() {
        return Err(EipError::Protocol(
            "route path must not be empty; caller should send bare MR instead".into(),
        ));
    }
    if route_path.len() % 2 != 0 {
        return Err(EipError::Protocol(
            "route path must be an even number of bytes".into(),
        ));
    }
    let route_words = route_path.len() / 2;
    let pad_embed = inner_mr.len() % 2 != 0;
    let us_len = 2 + 2 + inner_mr.len() + usize::from(pad_embed) + 2 + route_path.len();
    let mut us = Vec::with_capacity(us_len);
    us.push(DEFAULT_PRIORITY_TICK);
    us.push(DEFAULT_TIMEOUT_TICKS);
    us.extend_from_slice(&(inner_mr.len() as u16).to_le_bytes());
    us.extend_from_slice(inner_mr);
    if pad_embed {
        us.push(0);
    }
    us.push(route_words as u8);
    us.push(0);
    us.extend_from_slice(route_path);

    let mut outer = Vec::with_capacity(2 + CONNECTION_MANAGER_PATH.len() + us.len());
    outer.push(SERVICE_CODE);
    outer.push((CONNECTION_MANAGER_PATH.len() / 2) as u8);
    outer.extend_from_slice(&CONNECTION_MANAGER_PATH);
    outer.extend_from_slice(&us);
    Ok(outer)
}

/// Build an inner MR (service + path_size_words + path + service_data) that
/// can be handed to [`wrap`] or sent as bare MR.
pub fn build_inner_mr(service_code: u8, path_bytes: &[u8], service_data: &[u8]) -> Result<Vec<u8>> {
    if path_bytes.len() % 2 != 0 {
        return Err(EipError::Protocol(
            "path must be an even number of bytes".into(),
        ));
    }
    let path_words = path_bytes.len() / 2;
    let mut buf = Vec::with_capacity(2 + path_bytes.len() + service_data.len());
    buf.push(service_code);
    buf.push(path_words as u8);
    buf.extend_from_slice(path_bytes);
    buf.extend_from_slice(service_data);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_inner_encodes_service_path_and_data() {
        let path = [0x20, 0x01, 0x24, 0x01, 0x30, 0x07];
        let inner = build_inner_mr(0x0E, &path, &[]).unwrap();
        assert_eq!(inner[0], 0x0E);
        assert_eq!(inner[1], 3); // path words
        assert_eq!(&inner[2..], &path[..]);
    }

    #[test]
    fn empty_route_errors() {
        let inner = build_inner_mr(0x0E, &[0x20, 0x01, 0x24, 0x01], &[]).unwrap();
        assert!(wrap(&inner, &[]).is_err());
    }

    #[test]
    fn odd_route_errors() {
        let inner = build_inner_mr(0x0E, &[0x20, 0x01, 0x24, 0x01], &[]).unwrap();
        assert!(wrap(&inner, &[0x01]).is_err());
    }

    #[test]
    fn matches_reference_wire_layout() {
        // Reference vector from the C# UnconnectedSendBuilder tests: embedded
        // MR = [0x0E,0x02,0x20,0x01,0x24,0x01], route = "1,0".
        let inner_mr = [0x0E, 0x02, 0x20, 0x01, 0x24, 0x01];
        let outer = wrap(&inner_mr, &[0x01, 0x00]).unwrap();
        let expected: [u8; 20] = [
            0x52, 0x02, 0x20, 0x06, 0x24, 0x01,
            0x07, 0xF9,
            0x06, 0x00,
            0x0E, 0x02, 0x20, 0x01, 0x24, 0x01,
            0x01, 0x00,
            0x01, 0x00,
        ];
        assert_eq!(outer, expected);
    }

    #[test]
    fn odd_inner_inserts_pad() {
        let inner_mr = [0x0E, 0x02, 0x20, 0x01, 0x24, 0x01, 0xAA];
        let outer = wrap(&inner_mr, &[0x01, 0x00]).unwrap();
        // Offset 8: embedded_size UINT = 7. Then 7 bytes of inner, then 1 pad.
        assert_eq!(outer[8], 7);
        // route_size at 8+2+7+1 = 18.
        assert_eq!(outer[18], 1);
        assert_eq!(outer[19], 0);
    }
}
