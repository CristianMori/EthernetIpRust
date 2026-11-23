//! Lifecycle regressions for the Class 1 adapter: dropping the handle and
//! `shutdown()` must release the TCP and UDP ports.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ethernetip_connections::{start_adapter, AdapterConfig, AssemblyRegistry};
use tokio::net::{TcpListener, UdpSocket};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Poll until both ports can be bound again, or fail after `limit`.
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

fn config() -> AdapterConfig {
    AdapterConfig::new(AssemblyRegistry::new())
        .tcp_bind(loopback())
        .udp_bind(loopback())
}

/// Dropping the handle without `shutdown()` used to leave every background
/// task spinning (`changed()` returns `Err` forever, `borrow()` stays false)
/// with the listener and UDP socket still bound.
#[tokio::test]
async fn dropped_handle_stops_tasks_and_frees_ports() {
    let handle = start_adapter(config()).await.expect("start");
    let (tcp, udp) = (handle.tcp_addr, handle.udp_addr);
    drop(handle);
    assert!(
        wait_ports_free(tcp, udp, Duration::from_secs(3)).await,
        "ports still bound after the handle was dropped"
    );
}
