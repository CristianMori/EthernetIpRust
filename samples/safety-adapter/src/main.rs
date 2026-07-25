//! Minimal safety adapter — accepts one safety Forward_Open, decodes O→T
//! safety frames with rollover-aware CRC verification, and emits periodic
//! TCOO responses so the scanner transitions to run.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use ethernetip_safety::{
    device, start_safety_adapter, CipDispatcher, ConnectionManagerObject, SafetyAdapterConfig,
    SafetyNetworkNumber, SafetySupervisorObject, SafetyValidatorObject,
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
    // Safety identity — defaults keep the historical values; override to
    // match a live Studio 5000 config with --snn / --node / --vendor /
    // --serial. `--bind` is convenience shorthand for --tcp <ip>:44818 +
    // --udp <ip>:2222, since the safety adapter always uses those ports.
    let mut snn = SafetyNetworkNumber([0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D]);
    let mut node_addr: u32 = 0xC0A80154;
    let mut vendor_id: u16 = 0x0001;
    let mut serial: u32 = 0xC0FFEE01;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--tcp" => tcp_bind = args.next().context("--tcp needs a bind")?.parse()?,
            "--udp" => udp_bind = args.next().context("--udp needs a bind")?.parse()?,
            "--peer-udp-port" => peer_udp_port = args.next().context("--peer-udp-port needs a number")?.parse()?,
            "--input-size" => input_size = args.next().context("--input-size needs a number")?.parse()?,
            "--bind" => {
                let ip: Ipv4Addr = args
                    .next()
                    .context("--bind needs an IPv4 address")?
                    .parse()
                    .context("--bind must be an IPv4 address")?;
                tcp_bind = SocketAddr::from((ip, 44818));
                udp_bind = SocketAddr::from((ip, 2222));
            }
            "--snn" => {
                let s = args.next().context("--snn needs 12 hex chars")?;
                snn = parse_snn(&s)?;
            }
            "--node" => {
                let s = args.next().context("--node needs a number")?;
                node_addr = parse_hex_or_dec(&s).context("--node parse")?;
            }
            "--vendor" => {
                let s = args.next().context("--vendor needs a number")?;
                vendor_id = parse_hex_or_dec(&s).context("--vendor parse")? as u16;
            }
            "--serial" => {
                let s = args.next().context("--serial needs a number")?;
                serial = parse_hex_or_dec(&s).context("--serial parse")?;
            }
            other => anyhow::bail!("unexpected argument `{}`", other),
        }
    }

    // Build the standard device CIP classes so browsers see something on
    // discovery: Identity (0x01), TCP/IP Interface (0xF5), Ethernet Link
    // (0xF6), Connection Manager (0x06). All read-only, all zero-cost —
    // they just answer Get_Attribute_Single.
    let dispatcher = Arc::new(CipDispatcher::new());
    dispatcher.register_class(device::build_identity(device::IdentityInfo {
        vendor_id,
        device_type: 0x000C, // Communications Adapter
        product_code: 26,
        major_revision: 1,
        minor_revision: 1,
        status: 0x0030, // Owned + Configured
        serial_number: serial,
        product_name: "Rust Safety Adapter".into(),
    }));
    let bind_ip = match tcp_bind.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => Ipv4Addr::new(127, 0, 0, 1),
    };
    dispatcher.register_class(device::build_tcpip_interface(device::TcpIpConfig::new(
        bind_ip,
    )));
    dispatcher.register_class(device::build_ethernet_link(
        device::EthernetLinkConfig::probe(bind_ip),
    ));
    let mut cm = ConnectionManagerObject::new();
    dispatcher.register_class(cm.into_cip_class());

    // Safety-specific classes on the same dispatcher: Supervisor (0x39,
    // instance 1) and Validator (0x3A, one instance per accepted safety
    // FO — the instance id becomes the target-side sv_inst that feeds
    // PID / CID seed derivation).
    let mut supervisor = SafetySupervisorObject::new(snn, node_addr);
    // No supervisor.start() here — the adapter transitions the state
    // machine Idle → Executing on the first accepted FO (matches the
    // C# SafetyDevice pattern) and back to Idle on the last FC.
    dispatcher.register_class(supervisor.into_cip_class());
    let supervisor = Arc::new(supervisor);

    let mut validator = SafetyValidatorObject::new();
    dispatcher.register_class(validator.into_cip_class());
    let validator = Arc::new(validator);

    let cfg = SafetyAdapterConfig::new(vendor_id, serial, input_size)
        .tcp_bind(tcp_bind)
        .udp_bind(udp_bind)
        .peer_udp_port(peer_udp_port)
        .dispatcher(dispatcher)
        .validator(validator)
        .supervisor(supervisor);
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

/// Parse `"4D8D_00B4_12C9"` (visual high→low) into the wire-order byte
/// array. Underscores/dashes/spaces stripped. Matches the C++ / C# /
/// Python samples' `parse_snn` helper.
fn parse_snn(s: &str) -> Result<SafetyNetworkNumber> {
    let hex: String = s
        .chars()
        .filter(|c| !matches!(*c, '_' | '-' | ' '))
        .collect();
    if hex.len() != 12 {
        anyhow::bail!("SNN needs 12 hex chars, got {}", hex.len());
    }
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[5 - i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .context("SNN parse")?;
    }
    Ok(SafetyNetworkNumber(out))
}

/// Parse `"0xC0A8014B"` (hex) or `"123"` (decimal) into a u32.
fn parse_hex_or_dec(s: &str) -> Result<u32> {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Ok(u32::from_str_radix(rest, 16)?)
    } else {
        Ok(t.parse()?)
    }
}
