//! CIP SHORT_STRING (0xDA) coverage: metadata, in-memory helpers, and the
//! `Read_Tag` / `Write_Tag` wire shape against a running tag server.
//!
//! SHORT_STRING is distinct from the Logix predefined STRING UDT; the UDT
//! path uses the `[0x02A0][struct_handle]` structure prefix (covered in
//! `struct_wire_prefix.rs`). SHORT_STRING is atomic and carries the plain
//! 2-byte type code on the wire.
//!
//! Mirrors the C# `ShortStringTests` (PR #1, @SRCthird).

use std::net::SocketAddr;

use ethernetip_logix::tag_client::TagClient;
use ethernetip_logix::tag_registry::TagRegistry;
use ethernetip_logix::tag_server::{start as start_server, TagServerConfig};
use ethernetip_logix::types::{
    CipType, TagValue, SHORT_STRING_MAX_LENGTH, SHORT_STRING_STORAGE_SIZE,
};

const SHORT_STRING_TYPE: u16 = 0x00DA;

async fn spawn_server(
    registry: TagRegistry,
) -> (ethernetip_logix::tag_server::TagServerHandle, SocketAddr) {
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

// ---------- Metadata ----------

#[test]
fn metadata_short_string_element_size_is_81() {
    assert_eq!(SHORT_STRING_STORAGE_SIZE, 81);
    assert_eq!(SHORT_STRING_MAX_LENGTH, 80);
    assert_eq!(CipType::ShortString.atomic_size(), Some(81));
    assert_eq!(CipType::from_u16(SHORT_STRING_TYPE), Some(CipType::ShortString));
}

#[test]
fn add_atomic_short_string_registers_with_expected_layout() {
    let reg = TagRegistry::new();
    let inst = reg.add_atomic("name", CipType::ShortString).unwrap();
    let entry = reg.get_by_instance(inst).unwrap();

    assert!(entry.is_sstring());
    assert_eq!(entry.element_size(), 81);
    assert_eq!(entry.element_count, 1);
    assert_eq!(entry.data.len(), 81);
}

#[test]
fn add_array_short_string_sizes_in_eighty_one_byte_slots() {
    let reg = TagRegistry::new();
    let inst = reg.add_array("names", CipType::ShortString, 4).unwrap();
    let entry = reg.get_by_instance(inst).unwrap();

    assert_eq!(entry.element_count, 4);
    assert_eq!(entry.data.len(), 4 * 81);
}

// ---------- Helper round-trip ----------

#[test]
fn write_sstring_read_back_matches() {
    let reg = TagRegistry::new();
    reg.add_atomic("asset", CipType::ShortString).unwrap();

    reg.write_sstring("asset", 0, "Asset-32").unwrap();

    let entry = reg.get_by_name("asset").unwrap();
    assert_eq!(entry.read_sstring(0).unwrap(), "Asset-32");
    assert_eq!(entry.data[0], b"Asset-32".len() as u8);
}

#[test]
fn write_sstring_array_element_isolates_neighbors() {
    let reg = TagRegistry::new();
    reg.add_array("names", CipType::ShortString, 3).unwrap();

    reg.write_sstring("names", 0, "first").unwrap();
    reg.write_sstring("names", 1, "second-is-longer").unwrap();
    reg.write_sstring("names", 2, "third").unwrap();

    let entry = reg.get_by_name("names").unwrap();
    assert_eq!(entry.read_sstring(0).unwrap(), "first");
    assert_eq!(entry.read_sstring(1).unwrap(), "second-is-longer");
    assert_eq!(entry.read_sstring(2).unwrap(), "third");
}

#[test]
fn write_sstring_shorter_over_longer_clears_trailing_bytes() {
    let reg = TagRegistry::new();
    reg.add_atomic("asset", CipType::ShortString).unwrap();

    reg.write_sstring("asset", 0, &"x".repeat(40)).unwrap();
    reg.write_sstring("asset", 0, "hi").unwrap();

    let entry = reg.get_by_name("asset").unwrap();
    assert_eq!(entry.read_sstring(0).unwrap(), "hi");
    // Confirm no leftover 'x' tails: scan from position 3 to end must be zero.
    for i in 3..entry.data.len() {
        assert_eq!(entry.data[i], 0, "byte {i} still set after shorter write");
    }
}

#[test]
fn write_sstring_rejects_over_max_length() {
    let reg = TagRegistry::new();
    reg.add_atomic("asset", CipType::ShortString).unwrap();

    let too_long = "x".repeat(SHORT_STRING_MAX_LENGTH + 1);
    let err = reg.write_sstring("asset", 0, &too_long).unwrap_err();
    assert!(format!("{err:?}").contains("exceeds"));
}

#[test]
fn write_sstring_rejects_non_ascii() {
    let reg = TagRegistry::new();
    reg.add_atomic("asset", CipType::ShortString).unwrap();

    let err = reg.write_sstring("asset", 0, "caf\u{00E9}").unwrap_err();
    assert!(format!("{err:?}").contains("ASCII"));
}

#[test]
fn read_sstring_on_non_short_string_tag_errors() {
    let reg = TagRegistry::new();
    reg.add_atomic("rate", CipType::Dint).unwrap();
    let entry = reg.get_by_name("rate").unwrap();

    assert!(entry.read_sstring(0).is_err());
}

#[test]
fn write_sstring_out_of_range_element_errors() {
    let reg = TagRegistry::new();
    reg.add_array("names", CipType::ShortString, 2).unwrap();

    assert!(reg.write_sstring("names", 5, "nope").is_err());
}

// ---------- CIP wire shape (end-to-end via TagClient) ----------

#[tokio::test]
async fn read_tag_short_string_emits_two_byte_atomic_prefix() {
    let reg = TagRegistry::new();
    reg.add_atomic("asset", CipType::ShortString).unwrap();
    reg.write_sstring("asset", 0, "Asset-32").unwrap();

    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let raw = c.read_tag_raw("asset", 1).await.expect("read");

    // Atomic prefix: 2-byte type code, then 81-byte element payload.
    assert_eq!(raw.len(), 2 + SHORT_STRING_STORAGE_SIZE);
    let type_code = u16::from_le_bytes([raw[0], raw[1]]);
    assert_eq!(type_code, SHORT_STRING_TYPE);
    assert_eq!(raw[2], b"Asset-32".len() as u8);
    assert_eq!(&raw[3..3 + "Asset-32".len()], b"Asset-32");

    handle.shutdown().await;
}

#[tokio::test]
async fn read_tag_decodes_as_short_string_tag_value() {
    let reg = TagRegistry::new();
    reg.add_atomic("asset", CipType::ShortString).unwrap();
    reg.write_sstring("asset", 0, "Asset-32").unwrap();

    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let v = c.read_tag("asset").await.expect("read_tag");
    assert_eq!(v, TagValue::ShortString("Asset-32".to_string()));

    handle.shutdown().await;
}

#[tokio::test]
async fn write_tag_short_string_round_trips_via_client() {
    let reg = TagRegistry::new();
    reg.add_atomic("asset", CipType::ShortString).unwrap();

    let (handle, addr) = spawn_server(reg.clone()).await;
    let mut c = client(addr).await;

    c.write_tag("asset", &TagValue::ShortString("Asset-99".to_string()))
        .await
        .expect("write_tag");

    let entry = reg.get_by_name("asset").unwrap();
    assert_eq!(entry.read_sstring(0).unwrap(), "Asset-99");

    handle.shutdown().await;
}
