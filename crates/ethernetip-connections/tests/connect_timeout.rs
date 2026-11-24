//! `open_scanner_connection` must bound its TCP connect: a peer that never completes the handshake
//! must not block the caller for the OS SYN timeout.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ethernetip_connections::{
    open_scanner_connection, Assembly, AssemblyKind, AssemblyRegistry, ScannerConfig,
};
use ethernetip_core::EipError;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

const SHORT: Duration = Duration::from_millis(300);

fn config(addr: SocketAddr) -> ScannerConfig {
    let a = AssemblyRegistry::new();
    a.insert(Assembly::new(100, AssemblyKind::Input, 8)).unwrap();
    a.insert(Assembly::new(150, AssemblyKind::Output, 8)).unwrap();
    a.insert(Assembly::new(151, AssemblyKind::Config, 0)).unwrap();
    ScannerConfig::new(addr, a, 151, 150, 100, 8, 8).udp_bind("127.0.0.1:0".parse().unwrap())
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

#[test]
fn connect_timeout_defaults_to_five_seconds_and_can_be_disabled() {
    let cfg = config("127.0.0.1:1".parse().unwrap());
    assert_eq!(cfg.connect_timeout, Some(Duration::from_secs(5)));
    assert_eq!(cfg.connect_timeout(None).connect_timeout, None);
}

#[tokio::test]
async fn open_times_out_on_hanging_peer() {
    let (addr, _held, _l) = spawn_blackhole().await;
    let cfg = config(addr).connect_timeout(Some(SHORT));
    let t = Instant::now();
    let r = open_scanner_connection(cfg).await;
    let el = t.elapsed();
    assert!(matches!(r, Err(EipError::Timeout(d)) if d == SHORT), "got {:?}", r.err());
    assert!(el >= SHORT && el < Duration::from_secs(3), "took {el:?}");
}

#[tokio::test]
async fn none_disables_the_connect_bound() {
    let (addr, _held, _l) = spawn_blackhole().await;
    let cfg = config(addr).connect_timeout(None);
    let r = tokio::time::timeout(SHORT * 3, open_scanner_connection(cfg)).await;
    assert!(r.is_err(), "connect_timeout(None) must not time out by itself");
}

#[tokio::test]
async fn refused_connect_still_fails_fast() {
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let t = Instant::now();
    let r = open_scanner_connection(config(addr)).await;
    assert!(matches!(r, Err(EipError::Io(_))), "got {:?}", r.err());
    assert!(t.elapsed() < Duration::from_secs(3));
}
