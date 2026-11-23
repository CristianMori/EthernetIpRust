//! Lifecycle regressions for the Logix tag server.

use std::time::{Duration, Instant};

use ethernetip_logix::tag_registry::TagRegistry;
use ethernetip_logix::tag_server::{start, TagServerConfig};
use tokio::net::TcpListener;
use std::net::SocketAddr;

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
mod shutdown {
    use super::*;
    use tokio::net::TcpListener;
    use ethernetip_core::encap::{encode_frame, Command};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Connect and complete RegisterSession so the session task is
    /// definitely running before shutdown is requested.
    async fn connected_client(addr: SocketAddr) -> TcpStream {
        let mut c = TcpStream::connect(addr).await.expect("connect");
        let frame = encode_frame(Command::RegisterSession, 0, [0; 8], &[1, 0, 0, 0]);
        c.write_all(&frame).await.unwrap();
        // 24-byte encapsulation header + 4-byte RegisterSession body.
        let mut reply = [0u8; 28];
        c.read_exact(&mut reply).await.expect("register reply");
        c
    }

    async fn assert_eof(mut c: TcpStream) {
        let mut b = [0u8; 16];
        match tokio::time::timeout(Duration::from_secs(1), c.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes after shutdown"),
            Err(_) => panic!("client did not see EOF after shutdown"),
        }
    }

    /// An idle connected client used to keep its session task alive for up
    /// to the 60 s read timeout after `shutdown()` returned, still holding
    /// the UDP socket.
    #[tokio::test]
    async fn shutdown_with_idle_client_is_prompt_and_frees_ports() {
        let handle = start(config()).await.expect("start");
        let tcp = handle.tcp_addr;
        let client = connected_client(tcp).await;

        let t = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
            .await
            .expect("shutdown hung");
        assert!(t.elapsed() < Duration::from_secs(1), "shutdown took {:?}", t.elapsed());

        assert_eof(client).await;
        // No polling: the ports must be free the moment shutdown() returns.
        TcpListener::bind(tcp).await.expect("tcp rebind");
    }

    /// A peer that sent a header promising a body and then stalled must not
    /// hold shutdown up either.
    #[tokio::test]
    async fn shutdown_with_stalled_body_is_prompt() {
        let handle = start(config()).await.expect("start");
        let tcp = handle.tcp_addr;
        let mut client = connected_client(tcp).await;
        let mut hdr = encode_frame(Command::SendRRData, 0, [0; 8], &[]);
        hdr[2] = 100; // length = 100, but no body follows
        client.write_all(&hdr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let t = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
            .await
            .expect("shutdown hung");
        assert!(t.elapsed() < Duration::from_secs(1), "shutdown took {:?}", t.elapsed());
        assert_eof(client).await;
    }
}
