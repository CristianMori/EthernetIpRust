//! `SafetyScannerConnection::close` must not hang on a target that keeps the
//! TCP session open but never answers the Forward_Close.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ethernetip_safety::forward_open::SafetyForwardOpenConfig;
use ethernetip_safety::{
    open_safety_scanner, start_safety_adapter, SafetyAdapterConfig, SafetyScannerConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// TCP forwarder that can be told to swallow everything coming back from the
/// upstream while leaving both sockets open — i.e. a silent target.
async fn spawn_blackhole_proxy(upstream: SocketAddr, mute: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect(upstream).await.unwrap();
        let (mut cr, mut cw) = client.into_split();
        let (mut sr, mut sw) = server.into_split();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok(n) = cr.read(&mut buf).await {
                if n == 0 || sw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        let mut buf = [0u8; 2048];
        while let Ok(n) = sr.read(&mut buf).await {
            if n == 0 {
                break;
            }
            if !mute.load(Ordering::SeqCst) && cw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        // Keep the client half open while muted: dropping `cw` here would
        // send FIN and turn the silent target into a closed one.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    addr
}

#[tokio::test]
async fn close_returns_within_timeout_against_silent_target() {
    let mut acfg = SafetyAdapterConfig::new(1, 0x1234_5678, 8);
    acfg.tcp_bind = "127.0.0.1:0".parse().unwrap();
    acfg.udp_bind = "127.0.0.1:0".parse().unwrap();
    let adapter = start_safety_adapter(acfg).await.expect("adapter");
    let mute = Arc::new(AtomicBool::new(false));
    let proxy = spawn_blackhole_proxy(adapter.tcp_addr, mute.clone()).await;

    let server = SafetyForwardOpenConfig {
        consumed_data_size: 8,
        produced_data_size: 8,
        ..SafetyForwardOpenConfig::default()
    };
    let cfg = SafetyScannerConfig::new(proxy, server)
        .udp_bind("127.0.0.1:0".parse().unwrap())
        .close_timeout(Duration::from_millis(300));
    let conn = open_safety_scanner(cfg).await.expect("open");

    mute.store(true, Ordering::SeqCst);
    let t = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), conn.close())
        .await
        .expect("close() hung on a silent target")
        .expect("close");
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "close took {:?}",
        t.elapsed()
    );

    adapter.shutdown().await;
}
