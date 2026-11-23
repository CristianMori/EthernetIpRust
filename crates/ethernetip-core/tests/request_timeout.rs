//! Client exchanges must not wait forever on a target that stays silent.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ethernetip_core::{EipError, EipSession, DEFAULT_REQUEST_TIMEOUT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SHORT: Duration = Duration::from_millis(300);

/// Fake target: answers RegisterSession after `register_delay` (or never when
/// `answer_register` is false), then swallows everything without replying.
async fn spawn_silent_target(answer_register: bool, register_delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut first = true;
                loop {
                    let mut h = [0u8; 24];
                    if s.read_exact(&mut h).await.is_err() {
                        return;
                    }
                    let len = u16::from_le_bytes([h[2], h[3]]) as usize;
                    let mut body = vec![0u8; len];
                    if len > 0 && s.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    if first && answer_register {
                        first = false;
                        tokio::time::sleep(register_delay).await;
                        let mut r = h.to_vec();
                        r[2..4].copy_from_slice(&4u16.to_le_bytes());
                        r[4..8].copy_from_slice(&0xABCD_0001u32.to_le_bytes());
                        r.extend_from_slice(&[1, 0, 0, 0]);
                        if s.write_all(&r).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

#[test]
fn default_request_timeout_is_five_seconds() {
    assert_eq!(DEFAULT_REQUEST_TIMEOUT, Duration::from_secs(5));
}

#[tokio::test]
async fn session_defaults_to_five_seconds() {
    let addr = spawn_silent_target(true, Duration::ZERO).await;
    let s = EipSession::connect_and_register(addr).await.unwrap();
    assert_eq!(s.request_timeout(), Some(Duration::from_secs(5)));
}

#[tokio::test]
async fn silent_register_times_out() {
    let addr = spawn_silent_target(false, Duration::ZERO).await;
    let t = Instant::now();
    let r = EipSession::connect_and_register_with(addr, Some(SHORT)).await;
    assert!(matches!(r, Err(EipError::Timeout(_))), "got {:?}", r.err());
    assert!(t.elapsed() < SHORT + Duration::from_secs(1), "took {:?}", t.elapsed());
}

#[tokio::test]
async fn silent_exchange_times_out_and_resets_session() {
    let addr = spawn_silent_target(true, Duration::ZERO).await;
    let mut s = EipSession::connect_and_register_with(addr, Some(SHORT))
        .await
        .unwrap();
    assert!(s.is_registered());
    let t = Instant::now();
    let r = s.send_generic(0x0E, 1, 1, Some(1), &[], &[]).await;
    assert!(matches!(r, Err(EipError::Timeout(_))), "got {:?}", r.err());
    assert!(t.elapsed() < SHORT + Duration::from_secs(1), "took {:?}", t.elapsed());
    assert!(!s.is_registered());
    assert_eq!(s.session_handle(), 0);
    // The stream was dropped: later calls fail fast instead of desyncing.
    let t = Instant::now();
    let r = s.register().await;
    assert!(matches!(r, Err(EipError::Closed)), "got {:?}", r.err());
    assert!(t.elapsed() < Duration::from_millis(100));
}

#[tokio::test]
async fn none_disables_the_timeout() {
    let addr = spawn_silent_target(true, Duration::from_millis(700)).await;
    // Same delayed reply: bounded fails, unbounded waits and succeeds.
    let r = EipSession::connect_and_register_with(addr, Some(SHORT)).await;
    assert!(matches!(r, Err(EipError::Timeout(_))));
    let s = EipSession::connect_and_register_with(addr, None).await.unwrap();
    assert!(s.is_registered());
    assert_eq!(s.request_timeout(), None);
}
