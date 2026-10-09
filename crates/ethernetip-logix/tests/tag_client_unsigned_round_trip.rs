//! End-to-end round-trip tests for the CIP §C-6.1 unsigned and bit-string
//! atomic type family. Spins up the `TagServer` on a loopback TCP port,
//! connects a `TagClient`, writes each value, reads it back through the
//! full client → wire → server → wire → client loop.
//!
//! Covers the gap left by the in-process `unsigned_and_bitstring_types`
//! tests: the server-side storage was proven; this proves `TagClient`'s
//! typed write / `decode_read_tag` path agrees with the server-side
//! Write_Tag / Read_Tag encoder for every added type.  The on-wire
//! `tag_type` check inside the walker-aware write handler is exercised
//! for real.

use std::net::SocketAddr;

use ethernetip_logix::tag_client::TagClient;
use ethernetip_logix::tag_registry::TagRegistry;
use ethernetip_logix::tag_server::{start as start_server, TagServerConfig};
use ethernetip_logix::types::{CipType, TagValue};

async fn spawn_server(registry: TagRegistry) -> (ethernetip_logix::tag_server::TagServerHandle, SocketAddr) {
    let cfg = TagServerConfig::new(registry).tcp_bind("127.0.0.1:0".parse().unwrap());
    let handle = start_server(cfg).await.expect("server start");
    let addr = handle.tcp_addr;
    (handle, addr)
}

async fn client(addr: SocketAddr) -> TagClient {
    TagClient::builder(addr.ip().to_string())
        .port(addr.port())
        .connect()
        .await
        .expect("client connect")
}

#[tokio::test]
async fn usint_full_range_round_trips() {
    let reg = TagRegistry::new();
    reg.add_atomic("u8", CipType::Usint).unwrap();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    c.write_tag("u8", &TagValue::Usint(0xFF)).await.unwrap();
    let v = c.read_tag("u8").await.unwrap();
    assert_eq!(v, TagValue::Usint(0xFF));

    h.shutdown().await;
}

#[tokio::test]
async fn uint_full_range_round_trips() {
    let reg = TagRegistry::new();
    reg.add_atomic("u16", CipType::Uint).unwrap();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    c.write_tag("u16", &TagValue::Uint(0xFFFF)).await.unwrap();
    assert_eq!(c.read_tag("u16").await.unwrap(), TagValue::Uint(0xFFFF));

    h.shutdown().await;
}

#[tokio::test]
async fn udint_full_range_round_trips() {
    // The specific EscaFlow crash case — the type that triggered this whole
    // follow-up. Full-range value proves there's no sign-extension on
    // either side.
    let reg = TagRegistry::new();
    reg.add_atomic("u32", CipType::Udint).unwrap();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    c.write_tag("u32", &TagValue::Udint(0xFFFF_FFFF)).await.unwrap();
    assert_eq!(c.read_tag("u32").await.unwrap(), TagValue::Udint(0xFFFF_FFFF));

    h.shutdown().await;
}

#[tokio::test]
async fn ulint_full_range_round_trips() {
    let reg = TagRegistry::new();
    reg.add_atomic("u64", CipType::Ulint).unwrap();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    c.write_tag("u64", &TagValue::Ulint(0xFFFF_FFFF_FFFF_FFFF)).await.unwrap();
    assert_eq!(c.read_tag("u64").await.unwrap(), TagValue::Ulint(0xFFFF_FFFF_FFFF_FFFF));

    h.shutdown().await;
}

#[tokio::test]
async fn byte_word_dword_lword_round_trip() {
    // Bit-string types carry distinct CipType variants in Rust (unlike C#
    // where the generic Write<T> can't disambiguate byte→USINT from byte→BYTE).
    // Round-trip proves the on-wire type code is preserved end-to-end.
    let reg = TagRegistry::new();
    reg.add_atomic("b",  CipType::Byte).unwrap();
    reg.add_atomic("w",  CipType::Word).unwrap();
    reg.add_atomic("dw", CipType::Dword).unwrap();
    reg.add_atomic("lw", CipType::Lword).unwrap();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    c.write_tag("b",  &TagValue::Byte(0xAB)).await.unwrap();
    c.write_tag("w",  &TagValue::Word(0xBEEF)).await.unwrap();
    c.write_tag("dw", &TagValue::Dword(0xDEAD_BEEF)).await.unwrap();
    c.write_tag("lw", &TagValue::Lword(0xFEED_FACE_CAFE_BABE)).await.unwrap();

    assert_eq!(c.read_tag("b").await.unwrap(),  TagValue::Byte(0xAB));
    assert_eq!(c.read_tag("w").await.unwrap(),  TagValue::Word(0xBEEF));
    assert_eq!(c.read_tag("dw").await.unwrap(), TagValue::Dword(0xDEAD_BEEF));
    assert_eq!(c.read_tag("lw").await.unwrap(), TagValue::Lword(0xFEED_FACE_CAFE_BABE));

    h.shutdown().await;
}

#[tokio::test]
async fn all_added_types_round_trip_in_one_session() {
    // Reuse one TCP session across every added type.  Catches
    // state-machine / connection-handle bugs that only show up when a
    // single client issues a sequence of requests against tags of
    // different widths.
    let reg = TagRegistry::new();
    reg.add_atomic("u8",   CipType::Usint).unwrap();
    reg.add_atomic("u16",  CipType::Uint).unwrap();
    reg.add_atomic("u32",  CipType::Udint).unwrap();
    reg.add_atomic("u64",  CipType::Ulint).unwrap();
    reg.add_atomic("b8",   CipType::Byte).unwrap();
    reg.add_atomic("w16",  CipType::Word).unwrap();
    reg.add_atomic("dw32", CipType::Dword).unwrap();
    reg.add_atomic("lw64", CipType::Lword).unwrap();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    c.write_tag("u8",   &TagValue::Usint(0x12)).await.unwrap();
    c.write_tag("u16",  &TagValue::Uint(0x1234)).await.unwrap();
    c.write_tag("u32",  &TagValue::Udint(0x1234_5678)).await.unwrap();
    c.write_tag("u64",  &TagValue::Ulint(0x1234_5678_9ABC_DEF0)).await.unwrap();
    c.write_tag("b8",   &TagValue::Byte(0xAB)).await.unwrap();
    c.write_tag("w16",  &TagValue::Word(0xBEEF)).await.unwrap();
    c.write_tag("dw32", &TagValue::Dword(0xDEAD_BEEF)).await.unwrap();
    c.write_tag("lw64", &TagValue::Lword(0xFEED_FACE_CAFE_BABE)).await.unwrap();

    assert_eq!(c.read_tag("u8").await.unwrap(),   TagValue::Usint(0x12));
    assert_eq!(c.read_tag("u16").await.unwrap(),  TagValue::Uint(0x1234));
    assert_eq!(c.read_tag("u32").await.unwrap(),  TagValue::Udint(0x1234_5678));
    assert_eq!(c.read_tag("u64").await.unwrap(),  TagValue::Ulint(0x1234_5678_9ABC_DEF0));
    assert_eq!(c.read_tag("b8").await.unwrap(),   TagValue::Byte(0xAB));
    assert_eq!(c.read_tag("w16").await.unwrap(),  TagValue::Word(0xBEEF));
    assert_eq!(c.read_tag("dw32").await.unwrap(), TagValue::Dword(0xDEAD_BEEF));
    assert_eq!(c.read_tag("lw64").await.unwrap(), TagValue::Lword(0xFEED_FACE_CAFE_BABE));

    h.shutdown().await;
}

#[tokio::test]
async fn type_mismatch_rejected_by_server() {
    // Writing a different CIP code than the tag's registered type MUST
    // fail at the server. This is what proves the type-aware round-trip
    // works for the right reason (not accidental tolerance): the exact
    // tag_type check the client's typed path leans on is exercised.
    // Server returns status 0xFF with extended 0x2107 (matches C#,
    // C++, and Python ports byte-for-byte so a cross-port cross-check
    // can assert the same reply).
    let reg = TagRegistry::new();
    reg.add_atomic("u32", CipType::Udint).unwrap();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    // Dint has the same width as Udint but a different type code; server
    // must refuse rather than silently accept the bytes.
    let err = c.write_tag("u32", &TagValue::Dint(42)).await;
    assert!(err.is_err(), "expected type-mismatch error, got {:?}", err);

    h.shutdown().await;
}

// --- Struct write path (gap called out in 146a4af, fixed in the follow-up) ---

// The structure handle lives in the low 12 bits of sym_type (bit 15 marks
// "struct", bits 14-13 carry array dims, bit 12 is the system-tag flag),
// so Logix handles always fit in 12 bits. The server's Read_Tag reply
// emits `sym_type & 0x0FFF` as the handle; a Write_Tag must send the
// same value back. Tests use a 12-bit-safe handle below.
const TEST_STRUCT_HANDLE: u16 = 0x0ABC;

#[tokio::test]
async fn struct_write_wrong_handle_rejected_by_server() {
    // The on-wire write shape is [type=0x02A0][struct_handle][count][data].
    // If the client sends the wrong struct_handle, the server must reject
    // with 0xFF / 0x2107 — the same code atomic mismatches use, so
    // cross-port tests can assert the same reply shape.
    let reg = TagRegistry::new();
    reg.add_struct("blob", TEST_STRUCT_HANDLE, vec![0u8; 8]).unwrap();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let mut body = Vec::new();
    body.extend_from_slice(&0x02A0u16.to_le_bytes());
    body.extend_from_slice(&0x0BEEu16.to_le_bytes()); // wrong 12-bit handle
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&[0u8; 8]);
    let err = c.write_tag_raw("blob", &body).await;
    assert!(err.is_err(), "expected handle-mismatch error, got {:?}", err);

    h.shutdown().await;
}

#[tokio::test]
async fn struct_write_correct_handle_succeeds_and_count_uses_right_offset() {
    // The historically-broken path: before this fix, the server read
    // `count` out of body[2..4], which actually held `struct_handle` for a
    // struct write, and reached into `value` starting at body[4..] which
    // was still inside the write header. Correctly-formed struct writes
    // would misalign and the server would silently store the wrong bytes.
    let reg = TagRegistry::new();
    reg.add_struct("blob", TEST_STRUCT_HANDLE, vec![0u8; 8]).unwrap();
    let reg_probe = reg.clone();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let payload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut body = Vec::new();
    body.extend_from_slice(&0x02A0u16.to_le_bytes());
    body.extend_from_slice(&TEST_STRUCT_HANDLE.to_le_bytes()); // correct
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&payload);
    c.write_tag_raw("blob", &body).await.unwrap();

    // Bytes landed at offset 0 verbatim; nothing from the header leaked in.
    let entry = reg_probe.get_by_name("blob").unwrap();
    assert_eq!(&entry.data[..], &payload[..]);

    h.shutdown().await;
}

#[tokio::test]
async fn struct_marker_against_atomic_tag_rejected() {
    // Client sends the struct marker (0x02A0) against an atomic UDINT
    // tag. Can't possibly be valid — must fail with the same wrong-type
    // reply shape.
    let reg = TagRegistry::new();
    reg.add_atomic("u32", CipType::Udint).unwrap();
    let (h, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let mut body = Vec::new();
    body.extend_from_slice(&0x02A0u16.to_le_bytes());
    body.extend_from_slice(&0x1234u16.to_le_bytes()); // some fake handle
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    let err = c.write_tag_raw("u32", &body).await;
    assert!(err.is_err(), "expected rejection, got {:?}", err);

    h.shutdown().await;
}
