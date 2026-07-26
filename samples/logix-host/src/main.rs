//! Tiny Logix-style tag server. Registers a handful of tags and answers
//! Read_Tag / Write_Tag / Read_Tag_Fragmented / Get_Instance_Attribute_List
//! from any originator.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use ethernetip_logix::{start_tag_server, CipType, TagRegistry, TagServerConfig};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "logix_host=info,ethernetip_logix=info".into()),
        )
        .init();

    let mut bind: SocketAddr = "0.0.0.0:44818".parse().unwrap();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--bind" => {
                bind = args
                    .next()
                    .context("--bind needs a socket like 0.0.0.0:44818")?
                    .parse()?;
            }
            other => anyhow::bail!("unexpected argument `{}`", other),
        }
    }

    let registry = TagRegistry::new();
    let rate = registry.add_atomic("rate", CipType::Dint)?;
    let temperature = registry.add_atomic("temperature", CipType::Real)?;
    let counts = registry.add_array("counts", CipType::Int, 10)?;
    let big_blob = vec![0xAA; 812];
    let framework = registry.add_struct("Framework", 0x0807, big_blob)?;

    // Seed initial values.
    registry.set_by_name("rate", &534i32.to_le_bytes())?;
    registry.set_by_name("temperature", &72.5f32.to_le_bytes())?;
    {
        let mut buf = vec![0u8; 20];
        for i in 0..10 {
            let v = (i as i16 + 1).to_le_bytes();
            buf[i * 2..i * 2 + 2].copy_from_slice(&v);
        }
        registry.set_by_name("counts", &buf)?;
    }

    let handle = start_tag_server(TagServerConfig::new(registry.clone()).tcp_bind(bind)).await?;
    println!(
        "logix-host listening on {} — tags:\n  rate            DINT  = 534           (instance {rate})\n  temperature     REAL  = 72.5          (instance {temperature})\n  counts          INT[10] = 1..10       (instance {counts})\n  Framework       STRUCT (812 B blob)   (instance {framework})",
        handle.tcp_addr,
    );
    println!("Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.ok();
    println!("stopping...");
    handle.shutdown().await;
    Ok(())
}
