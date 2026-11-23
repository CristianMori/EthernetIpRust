//! Lifecycle regressions for the Logix tag server.

use std::time::{Duration, Instant};

use ethernetip_logix::tag_registry::TagRegistry;
use ethernetip_logix::tag_server::{start, TagServerConfig};
use tokio::net::TcpListener;

fn config() -> TagServerConfig {
    TagServerConfig::new(TagRegistry::new()).tcp_bind("127.0.0.1:0".parse().unwrap())
}

#[tokio::test]
async fn dropped_handle_stops_accept_loop_and_frees_port() {
    let handle = start(config()).await.expect("start");
    let addr = handle.tcp_addr;
    drop(handle);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpListener::bind(addr).await.is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "port still bound after handle drop");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
