//! End-to-end tests driving the tag server dispatcher through the walker.
//! Uses TCP loopback so we exercise the same code path a real client hits.

use std::net::SocketAddr;

use ethernetip_logix::server_template::{ServerTemplate, ServerTemplateMember};
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

fn make_timer_template() -> ServerTemplate {
    ServerTemplate {
        instance_id: 0x100,
        name: "Timer".into(),
        structure_handle: 0x8100,
        structure_size: 12,
        members: vec![
            ServerTemplateMember { name: "PRE".into(), data_type: 0x00C4, offset: 0, array_size: 0, element_size: 4 },
            ServerTemplateMember { name: "ACC".into(), data_type: 0x00C4, offset: 4, array_size: 0, element_size: 4 },
            ServerTemplateMember { name: "EN".into(),  data_type: 0x00C1, offset: 8, array_size: 0, element_size: 0 },
            ServerTemplateMember { name: "TT".into(),  data_type: 0x00C1, offset: 8, array_size: 1, element_size: 0 },
            ServerTemplateMember { name: "DN".into(),  data_type: 0x00C1, offset: 8, array_size: 2, element_size: 0 },
        ],
    }
}

#[tokio::test]
async fn read_scalar_member_of_struct_tag() {
    let reg = TagRegistry::new();
    let tpl_id = reg.add_template(make_timer_template()).unwrap();
    let inst = reg.add_struct_from_template("MyTimer", &reg.get_template(tpl_id).unwrap()).unwrap();
    // Timer.ACC lives at byte 4.  Preload 6789 there.
    let mut blob = vec![0u8; 12];
    blob[4..8].copy_from_slice(&6789i32.to_le_bytes());
    reg.set_by_name("MyTimer", &blob).unwrap();
    let (handle, addr) = spawn_server(reg).await;

    let mut client = client(addr).await;
    let v = client.read_tag("MyTimer.ACC").await.expect("read");
    assert!(matches!(v, TagValue::Dint(6789)), "got {v:?}");
    handle.shutdown().await;
    let _ = inst;
}

#[tokio::test]
async fn read_bool_member_bit_position() {
    let reg = TagRegistry::new();
    let tpl_id = reg.add_template(make_timer_template()).unwrap();
    reg.add_struct_from_template("MyTimer", &reg.get_template(tpl_id).unwrap()).unwrap();
    // Set DN (bit 2 of host byte at offset 8).
    let mut blob = vec![0u8; 12];
    blob[8] = 0b0000_0100;
    reg.set_by_name("MyTimer", &blob).unwrap();
    let (handle, addr) = spawn_server(reg).await;

    let mut client = client(addr).await;
    let v = client.read_tag("MyTimer.DN").await.expect("read");
    assert!(matches!(v, TagValue::Bool(true)), "got {v:?}");
    handle.shutdown().await;
}

#[tokio::test]
async fn write_bool_member_bit_updates_only_that_bit() {
    let reg = TagRegistry::new();
    let tpl_id = reg.add_template(make_timer_template()).unwrap();
    reg.add_struct_from_template("MyTimer", &reg.get_template(tpl_id).unwrap()).unwrap();
    // Preset TT (bit 1) so we can verify it stays set.
    let mut blob = vec![0u8; 12];
    blob[8] = 0b0000_0010;
    reg.set_by_name("MyTimer", &blob).unwrap();
    let reg_probe = reg.clone();
    let (handle, addr) = spawn_server(reg).await;

    let mut client = client(addr).await;
    client.write_tag("MyTimer.DN", &TagValue::Bool(true)).await.unwrap();

    let final_entry = reg_probe.get_by_name("MyTimer").unwrap();
    assert_eq!(final_entry.data[8], 0b0000_0110, "expected TT and DN set");
    handle.shutdown().await;
}

#[tokio::test]
async fn read_multi_dim_element() {
    let reg = TagRegistry::new();
    reg.add_multi_dim("Matrix", CipType::Dint, &[5, 10, 4]).unwrap();
    // ((1*10+2)*4+3)*4 = 204
    reg.set_bytes_at(reg.get_by_name("Matrix").unwrap().instance, 204, &999i32.to_le_bytes()).unwrap();
    let (handle, addr) = spawn_server(reg).await;

    let mut client = client(addr).await;
    let v = client.read_tag("Matrix[1,2,3]").await.expect("read");
    assert!(matches!(v, TagValue::Dint(999)), "got {v:?}");
    handle.shutdown().await;
}

#[tokio::test]
async fn write_bool_array_bit() {
    let reg = TagRegistry::new();
    reg.add_array("Flags", CipType::Bool, 32).unwrap();
    let reg_probe = reg.clone();
    let (handle, addr) = spawn_server(reg).await;

    let mut client = client(addr).await;
    client.write_tag("Flags[5]", &TagValue::Bool(true)).await.unwrap();

    let entry = reg_probe.get_by_name("Flags").unwrap();
    assert_eq!(entry.data[0], 0b0010_0000);
    handle.shutdown().await;
}

#[tokio::test]
async fn program_scope_tag_read_write() {
    let reg = TagRegistry::new();
    reg.register_program("Cell");
    reg.add_program_atomic("Cell", "Rate", CipType::Dint).unwrap();
    reg.set_program_tag_bytes("Cell", "Rate", 0, &4242i32.to_le_bytes()).unwrap();
    let (handle, addr) = spawn_server(reg).await;

    let mut client = client(addr).await;
    let v = client.read_tag("Program:Cell.Rate").await.expect("read");
    assert!(matches!(v, TagValue::Dint(4242)), "got {v:?}");
    handle.shutdown().await;
}
