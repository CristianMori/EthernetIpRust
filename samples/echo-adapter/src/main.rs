//! Minimal Class 1 adapter — mirrors the C++/Python/C# echo module.
//!
//! Hosts three assemblies (input 100, output 102, config 105) and prints a
//! heartbeat that summarizes packet counts and connection state. Any external
//! scanner (this repo's, the C#, C++, or Python ports') can point at
//! `<host>:44818` and open a Class 1 connection.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use ethernetip_connections::{
    start_adapter, Assembly, AssemblyKind, AssemblyRegistry, AdapterConfig, IO_UDP_PORT,
};

const INPUT_INSTANCE: u16 = 100;
const OUTPUT_INSTANCE: u16 = 102;
const CONFIG_INSTANCE: u16 = 105;
const INPUT_SIZE: usize = 500; // 125 DINTs
const OUTPUT_SIZE: usize = 496; // 124 DINTs
const CONFIG_SIZE: usize = 10;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "echo_adapter=info,ethernetip_connections=info".into()),
        )
        .init();

    let mut tcp_bind: SocketAddr = "0.0.0.0:44818".parse().unwrap();
    let mut udp_bind: SocketAddr = SocketAddr::from(([0, 0, 0, 0], IO_UDP_PORT));
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--tcp" => {
                tcp_bind = args
                    .next()
                    .context("--tcp needs a bind spec like 0.0.0.0:44818")?
                    .parse()?;
            }
            "--udp" => {
                udp_bind = args
                    .next()
                    .context("--udp needs a bind spec like 0.0.0.0:2222")?
                    .parse()?;
            }
            other => anyhow::bail!("unexpected argument `{}`", other),
        }
    }

    let assemblies = AssemblyRegistry::new();
    assemblies.insert(Assembly::new(INPUT_INSTANCE, AssemblyKind::Input, INPUT_SIZE))?;
    assemblies.insert(Assembly::new(OUTPUT_INSTANCE, AssemblyKind::Output, OUTPUT_SIZE))?;
    assemblies.insert(Assembly::new(CONFIG_INSTANCE, AssemblyKind::Config, CONFIG_SIZE))?;

    // Seed the T→O assembly with a 1..=125 DINT ramp so scanners see a
    // recognizable pattern on the very first cyclic frame.
    let mut ramp = vec![0u8; INPUT_SIZE];
    for i in 0..125 {
        let v = (i as i32 + 1).to_le_bytes();
        let off = i * 4;
        ramp[off..off + 4].copy_from_slice(&v);
    }
    assemblies.update(INPUT_INSTANCE, &ramp)?;

    let handle = start_adapter(
        AdapterConfig::new(assemblies.clone())
            .tcp_bind(tcp_bind)
            .udp_bind(udp_bind),
    )
    .await?;

    println!(
        "echo-adapter listening: TCP {} / UDP {}",
        handle.tcp_addr, handle.udp_addr,
    );
    println!(
        "assemblies: input {} ({} B), output {} ({} B), config {} ({} B)",
        INPUT_INSTANCE, INPUT_SIZE, OUTPUT_INSTANCE, OUTPUT_SIZE, CONFIG_INSTANCE, CONFIG_SIZE
    );
    println!("Ctrl+C to stop.\n");

    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    ticker.tick().await;
    let mut tick_count = 0i32;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = ticker.tick() => {
                tick_count = tick_count.wrapping_add(1);
                let mut ramp = assemblies.read(INPUT_INSTANCE).unwrap_or_default();
                let counter_bytes = tick_count.to_le_bytes();
                ramp[..4].copy_from_slice(&counter_bytes);
                assemblies.update(INPUT_INSTANCE, &ramp)?;

                let out = assemblies.read(OUTPUT_INSTANCE).unwrap_or_default();
                let out0 = if out.len() >= 4 {
                    i32::from_le_bytes([out[0], out[1], out[2], out[3]])
                } else {
                    0
                };
                let conns = handle.connection_count().await;
                print!(
                    "\r[tick {tick_count:>6}] Out[0]={out0:>10}  Conns={conns}  "
                );
                use std::io::Write;
                let _ = std::io::stdout().flush();
                if tick_count % 25 == 0 {
                    println!();
                }
            }
        }
    }
    println!("\nstopping...");
    handle.shutdown().await;
    Ok(())
}
