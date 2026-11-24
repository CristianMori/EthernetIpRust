//! The TCP connect itself must be bounded: a peer that never completes the
//! handshake must not block the caller for the OS SYN timeout.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ethernetip_core::{EipError, EipSession, DEFAULT_CONNECT_TIMEOUT};
use tokio::net::{TcpSocket, TcpStream};

const SHORT: Duration = Duration::from_millis(300);

/// Local listener whose accept queue is full and never drained, so further
/// SYNs are dropped and a new `connect` stays pending (no external network,
/// no routing assumptions). Returns the address plus guards that keep the
/// listener and the queued connections alive.
async fn spawn_blackhole() -> (SocketAddr, Vec<TcpStream>, tokio::net::TcpListener) {
    let sock = TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = sock.listen(1).unwrap();
    let addr = listener.local_addr().unwrap();
    // Fill the backlog; connections that do not complete in a moment mean
    // the queue is saturated.
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
fn default_connect_timeout_is_five_seconds() {
    assert_eq!(DEFAULT_CONNECT_TIMEOUT, Duration::from_secs(5));
}

#[tokio::test]
async fn connect_times_out_on_hanging_peer() {
    let (addr, _held, _l) = spawn_blackhole().await;
    let t0 = Instant::now();
    let r = EipSession::connect_with_timeout(addr, Some(SHORT)).await;
    let el = t0.elapsed();
    assert!(matches!(r, Err(EipError::Timeout(d)) if d == SHORT), "got {:?}", r.err());
    assert!(el >= SHORT && el < Duration::from_secs(3), "elapsed {el:?}");
}

#[tokio::test]
async fn connect_and_register_with_timeouts_bounds_connect() {
    let (addr, _held, _l) = spawn_blackhole().await;
    let t0 = Instant::now();
    let r = EipSession::connect_and_register_with_timeouts(addr, Some(SHORT), None).await;
    assert!(matches!(r, Err(EipError::Timeout(_))), "got {:?}", r.err());
    assert!(t0.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn none_disables_the_connect_bound() {
    let (addr, _held, _l) = spawn_blackhole().await;
    // With the bound disabled the connect must still be pending well past
    // what a bound of SHORT would allow.
    let fut = EipSession::connect_with_timeout(addr, None);
    let r = tokio::time::timeout(SHORT * 3, fut).await;
    assert!(r.is_err(), "connect with None must not time out by itself");
}

#[tokio::test]
async fn refused_connect_still_fails_fast() {
    // Bind then drop to get a port with nothing listening.
    let addr = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let t0 = Instant::now();
    let r = EipSession::connect_with_timeout(addr, Some(Duration::from_secs(5))).await;
    assert!(matches!(r, Err(EipError::Io(_))), "got {:?}", r.err());
    assert!(t0.elapsed() < Duration::from_secs(3));
}
