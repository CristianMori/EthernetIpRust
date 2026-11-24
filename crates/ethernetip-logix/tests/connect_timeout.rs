//! `TagClient` must bound its TCP connect: a peer that never completes the handshake
//! must not block the caller for the OS SYN timeout.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ethernetip_core::EipError;
use ethernetip_logix::TagClient;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

const SHORT: Duration = Duration::from_millis(300);

fn builder(addr: SocketAddr) -> ethernetip_logix::TagClientBuilder {
    TagClient::builder(addr.ip().to_string()).port(addr.port())
}

/// Local listener whose accept queue is full and never drained, so further
/// SYNs are dropped and a new `connect` stays pending (no external network,
/// no routing assumptions).
async fn spawn_blackhole() -> (SocketAddr, Vec<TcpStream>, TcpListener) {
    let sock = TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = sock.listen(1).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut held = Vec::new();
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => held.push(s),
            _ => break,
        }
    }
    (addr, held, listener)
}

#[tokio::test]
async fn connect_times_out_on_hanging_peer() {
    let (addr, _held, _l) = spawn_blackhole().await;
    let t = Instant::now();
    let r = builder(addr).connect_timeout(Some(SHORT)).connect().await;
    let el = t.elapsed();
    assert!(
        matches!(r, Err(EipError::Timeout(d)) if d == SHORT),
        "got {:?}",
        r.err()
    );
    assert!(el >= SHORT && el < Duration::from_secs(3), "took {el:?}");
}

#[tokio::test]
async fn default_is_bounded_and_none_disables() {
    let (addr, _held, _l) = spawn_blackhole().await;
    // None: still pending well past SHORT.
    let r = tokio::time::timeout(SHORT * 3, builder(addr).connect_timeout(None).connect()).await;
    assert!(
        r.is_err(),
        "connect_timeout(None) must not time out by itself"
    );
    // Default (5 s) is still pending after SHORT, i.e. neither immediate nor disabled-to-zero.
    let r = tokio::time::timeout(SHORT, builder(addr).connect()).await;
    assert!(
        r.is_err(),
        "default connect must still be pending after {SHORT:?}"
    );
}

#[tokio::test]
async fn refused_connect_still_fails_fast() {
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let t = Instant::now();
    let r = builder(addr).connect().await;
    assert!(matches!(r, Err(EipError::Io(_))), "got {:?}", r.err());
    assert!(t.elapsed() < Duration::from_secs(3));
}
