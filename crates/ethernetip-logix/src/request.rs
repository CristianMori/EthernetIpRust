//! Build Message Router requests, optionally wrapped in `Unconnected_Send`.
//!
//! When the caller has a routing path (e.g. `"1,0"` for a ControlLogix backplane),
//! the raw request has to be nested inside an `Unconnected_Send` addressed to
//! the Connection Manager on the local port, which does the actual bridging.
//! Without a path we send the bare request; the target's Message Router
//! interprets it directly.

use bytes::{BufMut, BytesMut};

use ethernetip_core::cip::{class_codes as class, service_codes as service};
use ethernetip_core::path::EpathWriter;

/// Build a Message Router request: `service | path_size | path | body`.
pub fn build_mr_request(service_code: u8, path: &[u8], body: &[u8]) -> Vec<u8> {
    debug_assert!(path.len() % 2 == 0, "path must be word-aligned");
    let mut buf = BytesMut::with_capacity(2 + path.len() + body.len());
    buf.put_u8(service_code);
    buf.put_u8((path.len() / 2) as u8);
    buf.put_slice(path);
    buf.put_slice(body);
    buf.to_vec()
}

/// Wrap an already-encoded MR request in an `Unconnected_Send` to Connection
/// Manager (class 0x06, instance 1). `route_path` must be the raw port/link
/// bytes (typically produced by [`ethernetip_core::path::parse_route_path`]).
pub fn wrap_unconnected_send(inner: &[u8], route_path: &[u8]) -> Vec<u8> {
    let mut path = EpathWriter::new();
    path.push_class(class::CONNECTION_MANAGER);
    path.push_instance(1);
    let cm_path = path.into_bytes();

    // priority/tick + timeout_ticks — 5 ticks of 1024 ms ≈ 5 s max response wait.
    let priority_tick: u8 = 0x0A;
    let timeout_ticks: u8 = 0x05;

    let mut body = BytesMut::new();
    body.put_u8(priority_tick);
    body.put_u8(timeout_ticks);
    body.put_u16_le(inner.len() as u16);
    body.put_slice(inner);
    // Pad the embedded message so the route path lands on a word boundary.
    if inner.len() % 2 == 1 {
        body.put_u8(0x00);
    }
    // Route path is only appended when non-empty; empty route means we're
    // relying on the target's own path resolution (bare wrap for a device that
    // still requires UnconnectedSend framing).
    if !route_path.is_empty() {
        debug_assert!(route_path.len() % 2 == 0, "route path must be word-aligned");
        body.put_u8((route_path.len() / 2) as u8);
        body.put_u8(0x00);
        body.put_slice(route_path);
    }

    build_mr_request(service::UNCONNECTED_SEND, &cm_path, &body)
}

/// Build a Multiple Service Packet (0x0A) request wrapping N embedded
/// Message Router requests. Path targets the Message Router itself
/// (class 0x02, instance 1) — Logix routes the sub-services from there.
///
/// Wire layout (Vol 1 §5-3.3.13):
///
///   MSP body:
///     UINT LE   number_of_services (N)
///     UINT LE   offset[0]     (from start of body)
///     UINT LE   offset[1]
///     ...
///     UINT LE   offset[N-1]
///     bytes     embedded MR service 0  (service | path_size | path | body)
///     bytes     embedded MR service 1
///     ...
pub fn build_multiple_service_packet(embedded: &[Vec<u8>]) -> Vec<u8> {
    let mut path = EpathWriter::new();
    path.push_class(class::MESSAGE_ROUTER);
    path.push_instance(1);
    let mr_path = path.into_bytes();

    let n = embedded.len();
    // Body header: 2 bytes for count + 2 bytes for each offset.
    let header_len = 2 + n * 2;
    let total_body_len = header_len + embedded.iter().map(|e| e.len()).sum::<usize>();

    let mut body = BytesMut::with_capacity(total_body_len);
    body.put_u16_le(n as u16);
    // First service starts right after the header.
    let mut running = header_len as u16;
    for e in embedded {
        body.put_u16_le(running);
        running += e.len() as u16;
    }
    for e in embedded {
        body.put_slice(e);
    }

    build_mr_request(service::MULTIPLE_SERVICE_PACKET, &mr_path, &body)
}

/// Parse a Multiple Service Packet reply body — everything after the MR
/// reply header (`reply_service`, reserved, general_status, ext_size,
/// ext_words). Returns one `Vec<u8>` per embedded reply, each of which
/// starts with its own reply-service byte and can be handed to
/// [`ethernetip_core::cip::ReplyHeader::parse`] for the per-service
/// status.
///
/// The MSP reply body shape mirrors the request:
///
///   UINT LE  number_of_replies (N)
///   UINT LE  offset[0]
///   ...
///   UINT LE  offset[N-1]
///   bytes    embedded reply 0
///   bytes    embedded reply 1
///   ...
pub fn parse_multiple_service_packet(body: &[u8]) -> Result<Vec<Vec<u8>>, ethernetip_core::EipError> {
    if body.len() < 2 {
        return Err(ethernetip_core::EipError::Short {
            expected: 2,
            actual: body.len(),
        });
    }
    let n = u16::from_le_bytes([body[0], body[1]]) as usize;
    let offsets_end = 2 + n * 2;
    if body.len() < offsets_end {
        return Err(ethernetip_core::EipError::Short {
            expected: offsets_end,
            actual: body.len(),
        });
    }
    let mut offsets = Vec::with_capacity(n);
    for i in 0..n {
        let off = 2 + i * 2;
        offsets.push(u16::from_le_bytes([body[off], body[off + 1]]) as usize);
    }
    let mut replies = Vec::with_capacity(n);
    for i in 0..n {
        let start = offsets[i];
        let end = if i + 1 < n { offsets[i + 1] } else { body.len() };
        if end < start || start > body.len() || end > body.len() {
            return Err(ethernetip_core::EipError::Protocol(format!(
                "MSP reply {i}: bad offsets start={start} end={end} body_len={}",
                body.len()
            )));
        }
        replies.push(body[start..end].to_vec());
    }
    Ok(replies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msp_round_trip_two_reads() {
        // Two Read_Tag(name="A", count=1) embedded services.
        let read_a = build_mr_request(service::READ_TAG, &[0x91, 0x01, b'A', 0x00], &[0x01, 0x00]);
        let read_b = build_mr_request(service::READ_TAG, &[0x91, 0x01, b'B', 0x00], &[0x01, 0x00]);
        let msp = build_multiple_service_packet(&[read_a.clone(), read_b.clone()]);
        // Peel off the outer MR request prefix (service + path_size + path).
        // Path is 4 bytes (class 0x02, instance 1) so we skip 2 + 4 = 6.
        let body = &msp[6..];
        let replies = parse_multiple_service_packet(body).unwrap();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0], read_a);
        assert_eq!(replies[1], read_b);
    }

    #[test]
    fn msp_offsets_start_after_header() {
        let inner = build_mr_request(service::READ_TAG, &[0x91, 0x01, b'X', 0x00], &[0x01, 0x00]);
        let msp = build_multiple_service_packet(&[inner.clone(), inner.clone(), inner.clone()]);
        let body = &msp[6..]; // skip outer MR header
        assert_eq!(&body[0..2], &3u16.to_le_bytes()); // count = 3
        // First offset should be header_len = 2 + 3*2 = 8.
        assert_eq!(&body[2..4], &8u16.to_le_bytes());
        assert_eq!(&body[4..6], &(8u16 + inner.len() as u16).to_le_bytes());
        assert_eq!(&body[6..8], &(8u16 + 2 * inner.len() as u16).to_le_bytes());
    }
}
