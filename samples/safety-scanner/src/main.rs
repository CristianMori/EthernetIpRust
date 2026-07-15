//! Minimal safety scanner — opens a safety Forward_Open (server direction)
//! and, with `--client`, a second Forward_Open (client direction) so it also
//! consumes target-produced T→O safety data. Writes a wall-clock counter
//! into the O→T output and prints per-tick statistics.
//!
//! Usage:
//!   safety-scanner [--adapter IP:PORT] [--udp BIND] [--peer-udp-port N]
//!                  [--rpi-ms N] [--data-size N] [--client]

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use ethernetip_safety::{
    open_safety_scanner, SafetyForwardOpenConfig, SafetyNetworkNumber, SafetyScannerConfig,
    UniqueNetworkId,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "safety_scanner=info,ethernetip_safety=info".into()),
        )
        .init();

    let mut adapter: SocketAddr = "127.0.0.1:44818".parse().unwrap();
    // Ephemeral default — the scanner's chosen endpoint is advertised via
    // Sockaddr Info T→O so the adapter knows where to send safety frames.
    let mut udp_bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut peer_udp_port: u16 = 2222;
    let mut rpi_ms: u32 = 50;
    let mut data_size: u16 = 8;
    let mut open_client = false;
    let mut tunid = UniqueNetworkId::default();
    let mut consumed_asm: u32 = 300;
    let mut produced_asm: u32 = 301;
    let mut config_asm: u32 = 302;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--adapter" => adapter = args.next().context("--adapter needs an addr")?.parse()?,
            "--udp" => udp_bind = args.next().context("--udp needs a bind")?.parse()?,
            "--peer-udp-port" => peer_udp_port = args.next().context("--peer-udp-port needs a number")?.parse()?,
            "--rpi-ms" => rpi_ms = args.next().context("--rpi-ms needs a number")?.parse()?,
            "--data-size" => data_size = args.next().context("--data-size needs a number")?.parse()?,
            "--client" => open_client = true,
            "--snn" => {
                tunid.snn = parse_snn(&args.next().context("--snn needs 12 hex chars")?)?;
            }
            "--node" => {
                tunid.node_address =
                    parse_hex_u32(&args.next().context("--node needs a hex value")?)?;
            }
            "--consumed" => consumed_asm = args.next().context("--consumed needs a number")?.parse()?,
            "--produced" => produced_asm = args.next().context("--produced needs a number")?.parse()?,
            "--config" => config_asm = args.next().context("--config needs a number")?.parse()?,
            other => anyhow::bail!("unexpected argument `{}`", other),
        }
    }

    let rpi_us = rpi_ms.saturating_mul(1000).max(1000);
    let server = SafetyForwardOpenConfig {
        consumed_assembly: consumed_asm,
        produced_assembly: produced_asm,
        config_assembly: config_asm,
        consumed_data_size: data_size,
        produced_data_size: data_size,
        rpi_us,
        o_to_t_rpi_us: rpi_us,
        t_to_o_rpi_us: rpi_us,
        tunid,
        ..SafetyForwardOpenConfig::default()
    };
    let mut cfg = SafetyScannerConfig::new(adapter, server)
        .udp_bind(udp_bind)
        .peer_udp_port(peer_udp_port);
    if open_client {
        // Client leg swaps the O↔T assemblies so target's produce path shows
        // up as the scanner's consume path.
        let client = SafetyForwardOpenConfig {
            consumed_assembly: produced_asm,
            produced_assembly: consumed_asm,
            config_assembly: config_asm,
            consumed_data_size: data_size,
            produced_data_size: data_size,
            rpi_us,
            o_to_t_rpi_us: rpi_us,
            t_to_o_rpi_us: rpi_us,
            tunid,
            ..SafetyForwardOpenConfig::default()
        };
        cfg = cfg.client(client);
    }

    println!(
        "opening safety scanner: adapter={} udp={} rpi={}ms data={}B",
        adapter, udp_bind, rpi_ms, data_size
    );
    let conn = open_safety_scanner(cfg).await?;
    println!(
        "opened server  OT=0x{:08X} TO=0x{:08X} target UDP={}  app_reply=(vendor=0x{:04X} serial=0x{:08X} sv_inst={})",
        conn.server_o_to_t_id,
        conn.server_t_to_o_id,
        conn.target_udp,
        conn.target_app_reply.target_vendor_id,
        conn.target_app_reply.target_device_serial,
        conn.target_app_reply.target_connection_serial,
    );
    if let (Some(ot), Some(to)) = (conn.client_o_to_t_id, conn.client_t_to_o_id) {
        println!("opened client  OT=0x{ot:08X} TO=0x{to:08X}");
    }

    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    ticker.tick().await;
    let mut count: i32 = 0;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = ticker.tick() => {
                count = count.wrapping_add(1);
                {
                    let mut d = conn.output_data.lock().await;
                    let bytes = count.to_le_bytes();
                    let n = bytes.len().min(d.len());
                    d[..n].copy_from_slice(&bytes[..n]);
                }
                let tx = conn.tx_count.load(Ordering::Relaxed);
                let tcoo = conn.tcoo_count.load(Ordering::Relaxed);
                let run = conn.consumer_active.load(Ordering::Relaxed);
                let rx = conn.rx_count.load(Ordering::Relaxed);
                let crc_fail = conn.rx_crc_fail.load(Ordering::Relaxed);
                let tcoo_tx = conn.tcoo_tx.load(Ordering::Relaxed);
                let in0 = {
                    let d = conn.input_data.lock().await;
                    if d.len() >= 4 {
                        i32::from_le_bytes([d[0], d[1], d[2], d[3]])
                    } else { 0 }
                };
                print!(
                    "\r[tick {count:>6}] out[0]={count:>10} in[0]={in0:>10} tx={tx} tcoo_rx={tcoo} rx={rx} crc_fail={crc_fail} tcoo_tx={tcoo_tx} run={run} "
                );
                use std::io::Write;
                let _ = std::io::stdout().flush();
                if count % 25 == 0 {
                    println!();
                }
            }
        }
    }
    println!("\nclosing...");
    conn.close().await?;
    Ok(())
}

fn parse_hex_u32(s: &str) -> Result<u32> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    Ok(u32::from_str_radix(t, 16)?)
}

fn parse_snn(s: &str) -> Result<SafetyNetworkNumber> {
    let hex: String = s.chars().filter(|c| !"_- ".contains(*c)).collect();
    anyhow::ensure!(hex.len() == 12, "SNN must be 12 hex chars (got {})", hex.len());
    let mut bytes = [0u8; 6];
    // Human-readable form is big-endian ("4D90_0101_A35C") but on the wire the
    // 6-byte SNN is little-endian, matching the C# adapter's parser.
    for i in 0..6 {
        bytes[5 - i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(SafetyNetworkNumber(bytes))
}
