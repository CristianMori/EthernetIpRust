//! Lifecycle regressions for the safety adapter.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ethernetip_safety::{start_safety_adapter, SafetyAdapterConfig};
use tokio::net::{TcpListener, UdpSocket};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn wait_ports_free(tcp: SocketAddr, udp: SocketAddr, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        let t = TcpListener::bind(tcp).await;
        let u = UdpSocket::bind(udp).await;
        if t.is_ok() && u.is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn config() -> SafetyAdapterConfig {
    let mut cfg = SafetyAdapterConfig::new(1, 0x1234_5678, 2);
    cfg.tcp_bind = loopback();
    cfg.udp_bind = loopback();
    cfg
}

#[tokio::test]
async fn dropped_handle_stops_tasks_and_frees_ports() {
    let handle = start_safety_adapter(config()).await.expect("start");
    let (tcp, udp) = (handle.tcp_addr, handle.udp_addr);
    drop(handle);
    assert!(
        wait_ports_free(tcp, udp, Duration::from_secs(3)).await,
        "ports still bound after the handle was dropped"
    );
}
