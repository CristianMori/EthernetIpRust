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
