//! `open_safety_scanner` must not hang on a target that registers the session
//! and then never answers the Forward_Open.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ethernetip_core::EipError;
use ethernetip_safety::forward_open::SafetyForwardOpenConfig;
use ethernetip_safety::{open_safety_scanner, SafetyScannerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn config(addr: SocketAddr) -> SafetyScannerConfig {
    let server = SafetyForwardOpenConfig {
        consumed_data_size: 8,
        produced_data_size: 8,
        ..SafetyForwardOpenConfig::default()
    };
    SafetyScannerConfig::new(addr, server).udp_bind("127.0.0.1:0".parse().unwrap())
}

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

#[test]
fn request_timeout_defaults_to_five_seconds_and_can_be_disabled() {
    let cfg = config("127.0.0.1:1".parse().unwrap());
    assert_eq!(cfg.request_timeout, Some(Duration::from_secs(5)));
    assert_eq!(cfg.request_timeout(None).request_timeout, None);
}

#[tokio::test]
async fn open_times_out_against_silent_target() {
    let addr = spawn_silent_target().await;
    let cfg = config(addr).request_timeout(Some(Duration::from_millis(300)));
    let t = Instant::now();
    let r = open_safety_scanner(cfg).await;
    assert!(matches!(r, Err(EipError::Timeout(_))), "got {:?}", r.err());
    assert!(
        t.elapsed() < Duration::from_millis(1300),
        "took {:?}",
        t.elapsed()
    );
}
