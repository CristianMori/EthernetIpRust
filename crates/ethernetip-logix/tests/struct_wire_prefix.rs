//! Regression tests for the Logix structured-tag wire contract.
//!
//! CIP Vol 1 §C-4.4.5: struct reads carry the 4-byte prefix
//! `[0x02A0][structure_handle]` ahead of the data; writes mirror it ahead
//! of the element count. libplctag and pycomm3 both enforce this split.
//! The whole-tag path in this port was correct; the walker-aware read for
//! a nested struct member emitted `[type_code][template_id]` which is
//! neither shape. This test pins the fixed behavior.
//!
//! Mirrors the C# `StructWirePrefixTests`, C++ `test_struct_wire_prefix`
//! and Python `test_struct_wire_prefix.py` sets.

use std::net::SocketAddr;

use ethernetip_logix::server_template::{ServerTemplate, ServerTemplateMember};
use ethernetip_logix::tag_client::TagClient;
use ethernetip_logix::tag_registry::TagRegistry;
use ethernetip_logix::tag_server::{start as start_server, TagServerConfig};

const STRUCT_TYPE_INDICATOR: u16 = 0x02A0;

async fn spawn_server(
    registry: TagRegistry,
) -> (
    ethernetip_logix::tag_server::TagServerHandle,
    SocketAddr,
) {
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

/// Build Motor { Speed:REAL, Timer:Timer } with Timer as a nested struct.
fn register_motor_and_timer(reg: &TagRegistry) -> (u16, u16) {
    let timer = ServerTemplate {
        instance_id: 0x100,
        name: "Timer".into(),
        structure_handle: 0x8100,
        structure_size: 8,
        members: vec![
            ServerTemplateMember {
                name: "PRE".into(),
                data_type: 0x00C4,
                offset: 0,
                array_size: 0,
                element_size: 4,
            },
            ServerTemplateMember {
                name: "ACC".into(),
                data_type: 0x00C4,
                offset: 4,
                array_size: 0,
                element_size: 4,
            },
        ],
    };
    let timer_handle = timer.structure_handle;
    let timer_id = reg.add_template(timer).unwrap();

    let motor = ServerTemplate {
        instance_id: 0x200,
        name: "Motor".into(),
        structure_handle: 0xBEEF,
        structure_size: 4 + 8,
        members: vec![
            ServerTemplateMember {
                name: "Speed".into(),
                data_type: 0x00CA, // REAL
                offset: 0,
                array_size: 0,
                element_size: 4,
            },
            ServerTemplateMember {
                name: "Timer".into(),
                data_type: 0x8000 | timer_id,
                offset: 4,
                array_size: 0,
                element_size: 8,
            },
        ],
    };
    let motor_id = reg.add_template(motor).unwrap();
    (motor_id, timer_handle)
}

#[tokio::test]
async fn read_nested_struct_member_emits_four_byte_prefix() {
    let reg = TagRegistry::new();
    let (motor_id, timer_handle) = register_motor_and_timer(&reg);
    reg.add_struct_from_template(
        "MyMotor",
        &reg.get_template(motor_id).unwrap(),
    )
    .unwrap();

    // Preload Timer.PRE = 111, Timer.ACC = 222. Motor layout:
    //   bytes 0..4   Speed (REAL, zero)
    //   bytes 4..8   Timer.PRE
    //   bytes 8..12  Timer.ACC
    let mut blob = vec![0u8; 12];
    blob[4..8].copy_from_slice(&111i32.to_le_bytes());
    blob[8..12].copy_from_slice(&222i32.to_le_bytes());
    reg.set_by_name("MyMotor", &blob).unwrap();

    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let raw = c
        .read_tag_raw("MyMotor.Timer", 1)
        .await
        .expect("read_tag_raw");

    // Expected: [0x02A0][timer.structure_handle][PRE=111][ACC=222]
    assert_eq!(raw.len(), 4 + 8, "raw bytes {:02X?}", raw);
    assert_eq!(u16::from_le_bytes([raw[0], raw[1]]), STRUCT_TYPE_INDICATOR);
    assert_eq!(u16::from_le_bytes([raw[2], raw[3]]), timer_handle);
    assert_eq!(i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]), 111);
    assert_eq!(i32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]), 222);

    handle.shutdown().await;
}

#[tokio::test]
async fn read_atomic_member_stays_two_byte_prefix() {
    // Regression guard: an atomic member read keeps the 2-byte prefix. The
    // existing `walker_dispatch::read_scalar_member_of_struct_tag` test
    // asserts via a decoded TagValue; this one asserts the raw byte shape.
    let reg = TagRegistry::new();
    let (motor_id, _) = register_motor_and_timer(&reg);
    reg.add_struct_from_template(
        "MyMotor",
        &reg.get_template(motor_id).unwrap(),
    )
    .unwrap();

    let mut blob = vec![0u8; 12];
    blob[4..8].copy_from_slice(&777i32.to_le_bytes());
    reg.set_by_name("MyMotor", &blob).unwrap();

    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let raw = c
        .read_tag_raw("MyMotor.Timer.PRE", 1)
        .await
        .expect("read_tag_raw");

    assert_eq!(raw.len(), 2 + 4, "raw bytes {:02X?}", raw);
    assert_eq!(u16::from_le_bytes([raw[0], raw[1]]), 0x00C4); // DINT
    assert_eq!(i32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]), 777);

    handle.shutdown().await;
}

#[tokio::test]
async fn read_whole_struct_tag_uses_stored_structure_handle() {
    // Pin that the whole-tag read emits the TEMPLATE's stored handle, not
    // just `sym_type & 0x0FFF`. For default-registered templates these
    // coincide, but a template with a custom structure_handle (CRC-16,
    // Studio export) must put that custom value on the wire.
    let reg = TagRegistry::new();
    let (motor_id, _) = register_motor_and_timer(&reg);
    reg.add_struct_from_template(
        "MyMotor",
        &reg.get_template(motor_id).unwrap(),
    )
    .unwrap();

    let (handle, addr) = spawn_server(reg).await;
    let mut c = client(addr).await;

    let raw = c.read_tag_raw("MyMotor", 1).await.expect("read_tag_raw");

    assert!(raw.len() >= 4);
    assert_eq!(u16::from_le_bytes([raw[0], raw[1]]), STRUCT_TYPE_INDICATOR);
    assert_eq!(
        u16::from_le_bytes([raw[2], raw[3]]),
        0xBEEF,
        "whole-tag read must use template.structure_handle (0xBEEF), got 0x{:04X}",
        u16::from_le_bytes([raw[2], raw[3]])
    );

    handle.shutdown().await;
}
