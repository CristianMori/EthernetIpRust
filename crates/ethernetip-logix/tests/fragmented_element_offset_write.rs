//! Write-side counterpart to `fragmented_element_offset.rs`.
//!
//! `Write_Tag_Fragmented` (0x53) was not implemented at all on the Rust
//! server before this commit — only the three read services plus
//! `Write_Tag` were wired in.  Once the handler was added, mirror the
//! read-side regression coverage so a client sending
//!
//!     Symbolic "counts" + Element 5 + Write_Tag_Fragmented
//!
//! writes element 5, not element 0, and so an atomic Write_Tag and a
//! fragmented Write_Tag against the same element segment agree.
//!
//! Based on the exploration in PR #1 (@SRCthird) on EthernetIpSharp.

use std::net::SocketAddr;

use ethernetip_logix::tag_client::TagClient;
use ethernetip_logix::tag_registry::TagRegistry;
use ethernetip_logix::tag_server::{start as start_server, TagServerConfig};
use ethernetip_logix::types::{CipType, TagValue};

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

fn make_counts_registry() -> TagRegistry {
    let reg = TagRegistry::new();
    reg.add_array("counts", CipType::Dint, 10).unwrap();
    reg
}

#[tokio::test]
async fn fragmented_write_symbolic_element_honors_element_segment() {
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    // "counts[7]" encodes as Symbolic("counts") + Element(7).  Walker offset
    // is 7 * 4 = 28.  Write a single DINT at that element.
    let payload = 7777i32.to_le_bytes();
    c.write_tag_fragmented("counts[7]", CipType::Dint as u16, None, 1, &payload)
        .await
        .expect("write_tag_fragmented");

    // Read element 7 back — it must be 7777.
    assert_eq!(
        c.read_tag("counts[7]").await.expect("read_tag"),
        TagValue::Dint(7777),
    );
    // Neighbours untouched.
    assert_eq!(
        c.read_tag("counts[6]").await.expect("read_tag"),
        TagValue::Dint(0),
    );
    assert_eq!(
        c.read_tag("counts[8]").await.expect("read_tag"),
        TagValue::Dint(0),
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn fragmented_write_whole_tag_still_starts_at_byte_zero() {
    // Regression guard: a fragmented write of the whole tag (no element
    // segment) must still begin at byte 0.
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let payload = 1234i32.to_le_bytes();
    c.write_tag_fragmented("counts", CipType::Dint as u16, None, 1, &payload)
        .await
        .expect("write_tag_fragmented");

    assert_eq!(
        c.read_tag("counts[0]").await.expect("read_tag"),
        TagValue::Dint(1234),
    );
    assert_eq!(
        c.read_tag("counts[1]").await.expect("read_tag"),
        TagValue::Dint(0),
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn fragmented_write_parity_with_atomic_write_tag() {
    // Writing to the same element segment through atomic Write_Tag and
    // Write_Tag_Fragmented must produce the same stored byte pattern.
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    // Atomic path.
    c.write_tag("counts[3]", &TagValue::Dint(999))
        .await
        .expect("write_tag atomic");

    // Fragmented path, same element.
    c.write_tag_fragmented(
        "counts[3]",
        CipType::Dint as u16,
        None,
        1,
        &999i32.to_le_bytes(),
    )
    .await
    .expect("write_tag_fragmented");

    assert_eq!(
        c.read_tag("counts[3]").await.expect("read_tag"),
        TagValue::Dint(999),
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn fragmented_write_then_read_round_trip() {
    // End-to-end: write via Write_Tag_Fragmented, read via
    // Read_Tag_Fragmented, bytes agree.  Catches offset bugs that would
    // only show up when both paths cooperate.
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    c.write_tag_fragmented(
        "counts[5]",
        CipType::Dint as u16,
        None,
        1,
        &4242i32.to_le_bytes(),
    )
    .await
    .expect("write_tag_fragmented");

    let raw = c
        .read_tag_fragmented("counts[5]", 1)
        .await
        .expect("read_tag_fragmented");
    assert_eq!(u16::from_le_bytes([raw[0], raw[1]]), CipType::Dint as u16);
    assert_eq!(
        i32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]),
        4242,
        "round-trip through fragmented write/read lost the value",
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn fragmented_write_symbol_instance_plus_element_shortcut() {
    // Exercises the Class(0x6B) + Instance(N) + Element(i) path shape —
    // what TagClient emits after `browse_tags` populates the instance
    // cache.  The read side already covered this; mirror it for writes.
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let _ = c.browse_tags().await.expect("browse_tags");

    c.write_tag_fragmented(
        "counts[2]",
        CipType::Dint as u16,
        None,
        1,
        &5555i32.to_le_bytes(),
    )
    .await
    .expect("write_tag_fragmented");

    assert_eq!(
        c.read_tag("counts[2]").await.expect("read_tag"),
        TagValue::Dint(5555),
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn fragmented_write_wrong_type_code_rejected() {
    // Type-mismatch path — the server must reply 0xFF/0x2107 just like
    // the atomic Write_Tag does.
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    // Claim the tag is a REAL (0xCA) when it's actually a DINT (0xC4).
    let err = c
        .write_tag_fragmented(
            "counts[0]",
            CipType::Real as u16,
            None,
            1,
            &0u32.to_le_bytes(),
        )
        .await
        .expect_err("wrong type code should fail");
    match err {
        ethernetip_core::EipError::Cip { status, ext } => {
            assert_eq!(status, 0xFF, "general status must be 0xFF");
            assert_eq!(ext, vec![0x2107u16], "extended status must be 0x2107");
        }
        other => panic!("expected EipError::Cip, got {other:?}"),
    }

    handle.shutdown().await;
}
