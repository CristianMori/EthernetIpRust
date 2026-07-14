//! Minimal Class 1 scanner. Opens a Forward_Open against an adapter and
//! writes a wall-clock counter into its O→T assembly on every tick, printing
//! the first DINT of the T→O assembly it reads back.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use ethernetip_connections::{
    open_scanner_connection, Assembly, AssemblyKind, AssemblyRegistry, ScannerConfig, IO_UDP_PORT,
};

const OUTPUT_INSTANCE: u16 = 102; // O→T (scanner writes)
const INPUT_INSTANCE: u16 = 100; // T→O (scanner reads)
const CONFIG_INSTANCE: u16 = 105;
const OUTPUT_SIZE: u16 = 496;
const INPUT_SIZE: u16 = 500;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "echo_scanner=info,ethernetip_connections=info".into()),
        )
        .init();

    let mut adapter_addr: SocketAddr = "127.0.0.1:44818".parse().unwrap();
    // Default to an ephemeral UDP port so the scanner can coexist with a
    // co-located adapter (which owns 2222) without a port conflict. The
    // chosen endpoint gets handed to the adapter via Sockaddr Info T→O.
    let mut udp_bind: SocketAddr = SocketAddr::from(([0, 0, 0, 0], 0));
    let _ = IO_UDP_PORT; // keep the import warning-free — 2222 is the default on the adapter side.
    let mut rpi_ms: u32 = 20;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--adapter" => {
                adapter_addr = args
                    .next()
                    .context("--adapter needs an addr like 192.168.1.10:44818")?
                    .parse()?;
            }
            "--udp" => {
                udp_bind = args
                    .next()
                    .context("--udp needs a bind spec like 0.0.0.0:2222")?
                    .parse()?;
            }
            "--rpi-ms" => {
                rpi_ms = args
                    .next()
                    .context("--rpi-ms needs a number")?
                    .parse()?;
            }
            other => anyhow::bail!("unexpected argument `{}`", other),
        }
    }

    let assemblies = AssemblyRegistry::new();
    assemblies.insert(Assembly::new(
        OUTPUT_INSTANCE,
        AssemblyKind::Output,
        OUTPUT_SIZE as usize,
    ))?;
    assemblies.insert(Assembly::new(
        INPUT_INSTANCE,
        AssemblyKind::Input,
        INPUT_SIZE as usize,
    ))?;

    let rpi_us = (rpi_ms as u32).saturating_mul(1000).max(1_000);
    let cfg = ScannerConfig::new(
        adapter_addr,
        assemblies.clone(),
        CONFIG_INSTANCE,
        OUTPUT_INSTANCE,
        INPUT_INSTANCE,
        OUTPUT_SIZE,
        INPUT_SIZE,
    )
    .udp_bind(udp_bind)
    .rpi(rpi_us, rpi_us);

    println!(
        "opening scanner: adapter={} udp={} rpi={}ms",
        adapter_addr, udp_bind, rpi_ms
    );
    let conn = open_scanner_connection(cfg).await?;
    println!(
        "opened OT=0x{:08X} TO=0x{:08X} actual RPI ot={}us to={}us",
        conn.o_to_t_conn_id,
        conn.t_to_o_conn_id,
        conn.o_to_t_actual_rpi_us,
        conn.t_to_o_actual_rpi_us,
    );

    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    ticker.tick().await;
    let mut count: i32 = 0;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = ticker.tick() => {
                count = count.wrapping_add(1);
                // Stamp a counter into the O→T assembly's first DINT.
                let mut out = assemblies.read(OUTPUT_INSTANCE).unwrap_or_default();
                let bytes = count.to_le_bytes();
                if out.len() >= 4 {
                    out[..4].copy_from_slice(&bytes);
                    let _ = assemblies.update(OUTPUT_INSTANCE, &out);
                }
                let inp = assemblies.read(INPUT_INSTANCE).unwrap_or_default();
                let in0 = if inp.len() >= 4 {
                    i32::from_le_bytes([inp[0], inp[1], inp[2], inp[3]])
                } else { 0 };
                let rx = conn.rx_count.load(std::sync::atomic::Ordering::Relaxed);
                let tx = conn.tx_count.load(std::sync::atomic::Ordering::Relaxed);
                print!(
                    "\r[tick {count:>6}] Out[0]={count:>10} In[0]={in0:>10} rx={rx} tx={tx} "
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
