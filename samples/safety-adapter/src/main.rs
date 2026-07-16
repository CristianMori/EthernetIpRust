//! Minimal safety adapter — accepts one safety Forward_Open, decodes O→T
//! safety frames with rollover-aware CRC verification, and emits periodic
//! TCOO responses so the scanner transitions to run.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ethernetip_safety::{
    start_safety_adapter, CipDispatcher, SafetyAdapterConfig, SafetyNetworkNumber,
    SafetySupervisorObject, SafetyValidatorObject,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "safety_adapter=info,ethernetip_safety=info".into()),
        )
        .init();

    let mut tcp_bind: SocketAddr = "0.0.0.0:44818".parse().unwrap();
    let mut udp_bind: SocketAddr = "0.0.0.0:2222".parse().unwrap();
    let mut peer_udp_port: u16 = 2222;
    let mut input_size: usize = 8;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--tcp" => tcp_bind = args.next().context("--tcp needs a bind")?.parse()?,
            "--udp" => udp_bind = args.next().context("--udp needs a bind")?.parse()?,
            "--peer-udp-port" => peer_udp_port = args.next().context("--peer-udp-port needs a number")?.parse()?,
            "--input-size" => input_size = args.next().context("--input-size needs a number")?.parse()?,
            other => anyhow::bail!("unexpected argument `{}`", other),
        }
    }

    // Build a Safety Supervisor (class 0x39, instance 1) and a Safety
    // Validator (class 0x3A, one instance per open safety connection —
    // pre-created here so a scanner's `Get_Attribute_Single` against
    // class 0x3A / instance 1 returns something instead of
    // OBJECT_DOES_NOT_EXIST). Register both on a shared dispatcher; the
    // safety adapter will route any MR service that isn't
    // FORWARD_OPEN / FORWARD_CLOSE through it.
    let mut supervisor = SafetySupervisorObject::new(
        SafetyNetworkNumber([0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D]),
        0xC0A80154,
    );
    supervisor.start();
    let dispatcher = Arc::new(CipDispatcher::new());
    dispatcher.register_class(supervisor.into_cip_class());

    let mut validator = SafetyValidatorObject::new();
    dispatcher.register_class(validator.into_cip_class());
    // Pre-allocate one Validator instance so browsers can see it before
    // any connection opens. Real deployments create these lazily on FO
    // acceptance via `create_instance_via_dispatcher`.
    let _preallocated = validator.create_instance_via_dispatcher(
        &dispatcher,
        Default::default(),
    );

    let cfg = SafetyAdapterConfig::new(0x0001, 0xC0FFEE01, input_size)
        .tcp_bind(tcp_bind)
        .udp_bind(udp_bind)
        .peer_udp_port(peer_udp_port)
        .dispatcher(dispatcher);
    let handle = start_safety_adapter(cfg).await?;

    println!(
        "safety-adapter listening: TCP {} / UDP {} (peer UDP port {})",
        handle.tcp_addr, handle.udp_addr, peer_udp_port
    );
    println!("Ctrl+C to stop.\n");

    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    ticker.tick().await;
    let mut count: i32 = 0;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = ticker.tick() => {
                count = count.wrapping_add(1);
                let rx = handle.rx_valid.load(Ordering::Relaxed);
                let crc = handle.rx_crc_fail.load(Ordering::Relaxed);
                let tx = handle.tx_tcoo.load(Ordering::Relaxed);
                let open = handle.connection_open.load(Ordering::Relaxed);
                let inp = handle.input_data.lock().await;
                let d0 = if inp.len() >= 1 { inp[0] } else { 0 };
                let d1 = if inp.len() >= 2 { inp[1] } else { 0 };
                let d2 = if inp.len() >= 3 { inp[2] } else { 0 };
                let d3 = if inp.len() >= 4 { inp[3] } else { 0 };
                drop(inp);
                print!(
                    "\r[tick {count:>6}] open={open} rx={rx} crc_fail={crc} tcoo_tx={tx}  data=[{d0:02X} {d1:02X} {d2:02X} {d3:02X}]  "
                );
                use std::io::Write;
                let _ = std::io::stdout().flush();
                if count % 25 == 0 {
                    println!();
                }
            }
        }
    }
    println!("\nstopping...");
    handle.shutdown().await;
    Ok(())
}
