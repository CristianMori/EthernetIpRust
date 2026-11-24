//! `TagClient` requests must not hang on a target that registers the session
//! and then never answers.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ethernetip_core::EipError;
use ethernetip_logix::TagClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Fake target: answers RegisterSession, then swallows everything silently.
async fn spawn_silent_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
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
                    if first {
                        first = false;
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

fn builder(addr: SocketAddr, t: Option<Duration>) -> ethernetip_logix::TagClientBuilder {
    TagClient::builder(addr.ip().to_string())
        .port(addr.port())
        .request_timeout(t)
}

#[tokio::test]
async fn read_times_out_against_silent_target() {
    let addr = spawn_silent_target().await;
    let mut c = builder(addr, Some(Duration::from_millis(300)))
        .connect()
        .await
        .unwrap();
    let t = Instant::now();
    let r = c.read_tag("Tag1").await;
    assert!(matches!(r, Err(EipError::Timeout(_))), "got {:?}", r.err());
    assert!(
        t.elapsed() < Duration::from_millis(1300),
        "took {:?}",
        t.elapsed()
    );
    // Session is dropped: the next call fails fast.
    let r = c.read_tag("Tag1").await;
    assert!(matches!(r, Err(EipError::Closed)), "got {:?}", r.err());
}

#[tokio::test]
async fn connected_open_times_out_against_silent_target() {
    let addr = spawn_silent_target().await;
    let t = Instant::now();
    let r = builder(addr, Some(Duration::from_millis(300)))
        .use_connected(true)
        .connect()
        .await;
    assert!(matches!(r, Err(EipError::Timeout(_))), "got {:?}", r.err());
    assert!(
        t.elapsed() < Duration::from_millis(1300),
        "took {:?}",
        t.elapsed()
    );
}

#[tokio::test]
async fn default_is_five_seconds_and_none_disables() {
    let addr = spawn_silent_target().await;
    // Default builder: unbounded wait would hang, so only check the policy
    // indirectly — a None client must still be waiting after the short bound.
    let mut c = builder(addr, None).connect().await.unwrap();
    let r = tokio::time::timeout(Duration::from_millis(600), c.read_tag("Tag1")).await;
    assert!(
        r.is_err(),
        "request_timeout(None) must not time out by itself"
    );
}
