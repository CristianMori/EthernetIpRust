//! Regression tests for an asymmetry in the fragmented tag read path.
//!
//! `Read_Tag` already honored the request path's element segment (via the
//! walker for symbolic + Element paths, and via a shortcut for the
//! Class(0x6B) + Instance + Element form that `TagClient` uses after
//! `browse_tags`), but `Read_Tag_Fragmented` was discarding the walker
//! and reading from byte 0 of the tag. A client sending
//!
//!     Symbolic "counts" + Element 5 + Read_Tag_Fragmented
//!
//! got the first element back, not the fifth.
//!
//! Pulled from PR #1 exploration (@SRCthird) — the asymmetry the fix in
//! the C# port (SymbolObject.cs lines 97–109) resolved.

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

/// Populate a DINT[10] where element i = 100 + i.
fn make_counts_registry() -> TagRegistry {
    let reg = TagRegistry::new();
    reg.add_array("counts", CipType::Dint, 10).unwrap();
    let mut blob = vec![0u8; 40];
    for i in 0..10 {
        let v = 100i32 + i as i32;
        blob[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    reg.set_by_name("counts", &blob).unwrap();
    reg
}

#[tokio::test]
async fn fragmented_read_symbolic_element_honors_element_segment() {
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    // "counts[5]" encodes as Symbolic("counts") + Element(5). The server
    // resolves this through the walker, which produces offset = 5 * 4 = 20.
    // Fragmented read must honor that absolute offset.
    let raw = c
        .read_tag_fragmented("counts[5]", 1)
        .await
        .expect("read_tag_fragmented");

    // Reply payload: [type (UINT)][data...]. Expect DINT 105.
    assert_eq!(u16::from_le_bytes([raw[0], raw[1]]), CipType::Dint as u16);
    assert_eq!(
        i32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]),
        105,
        "fragmented read of counts[5] returned the wrong element"
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn fragmented_read_whole_tag_still_starts_at_byte_zero() {
    // Regression guard: the fix must not break fragmented reads without an
    // element segment — "counts" alone still begins at byte 0.
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let raw = c
        .read_tag_fragmented("counts", 1)
        .await
        .expect("read_tag_fragmented");

    assert_eq!(u16::from_le_bytes([raw[0], raw[1]]), CipType::Dint as u16);
    assert_eq!(
        i32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]),
        100,
        "whole-tag fragmented read must start at byte 0"
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn fragmented_read_parity_with_atomic_read_tag() {
    // Pin the fix by running the same symbolic+element path through both
    // the atomic Read_Tag (which already honored the element segment) and
    // Read_Tag_Fragmented. They must produce the same element value.
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let atomic = c.read_tag("counts[7]").await.expect("read_tag");
    let frag = c
        .read_tag_fragmented("counts[7]", 1)
        .await
        .expect("read_tag_fragmented");
    let frag_value = i32::from_le_bytes([frag[2], frag[3], frag[4], frag[5]]);

    assert_eq!(atomic, TagValue::Dint(107));
    assert_eq!(frag_value, 107);

    handle.shutdown().await;
}

#[tokio::test]
async fn fragmented_read_symbol_instance_plus_element_shortcut() {
    // Exercises the Class(0x6B) + Instance(N) + Element(i) path shape —
    // what TagClient emits after `browse_tags` populates the instance
    // cache. Before the fix, the instance-form shortcut dropped the
    // Element segment and produced a whole-tag read.
    let reg = make_counts_registry();
    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    // Browse to populate the atom cache so the next access emits the
    // instance-id form rather than the ANSI symbolic form.
    let _ = c.browse_tags().await.expect("browse_tags");

    let raw = c
        .read_tag_fragmented("counts[3]", 1)
        .await
        .expect("read_tag_fragmented");

    assert_eq!(u16::from_le_bytes([raw[0], raw[1]]), CipType::Dint as u16);
    assert_eq!(
        i32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]),
        103,
        "instance+element fragmented read returned the wrong element"
    );

    handle.shutdown().await;
}
