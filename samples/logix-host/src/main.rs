//! Tiny Logix-style tag server. Registers every atomic CIP type the Logix
//! tag protocol exposes (BOOL, SINT/INT/DINT/LINT, USINT/UINT/UDINT/ULINT,
//! REAL/LREAL, BYTE/WORD/DWORD/LWORD, SHORT_STRING) plus a small UDT and
//! answers Read_Tag / Write_Tag / Read_Tag_Fragmented / Write_Tag_Fragmented
//! / Get_Instance_Attribute_List, as well as the encap-level ListIdentity
//! and ListServices and the Class 3 explicit-messaging path (Forward_Open /
//! Forward_Close / SendUnitData). That full surface is what makes pycomm3
//! happy — see `tests/pycomm3/test_pycomm3_roundtrip.py`.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use ethernetip_logix::{start_tag_server, CipType, IdentityInfo, TagRegistry, TagServerConfig};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "logix_host=info,ethernetip_logix=info".into()),
        )
        .init();

    let mut bind: SocketAddr = "0.0.0.0:44818".parse().unwrap();
    let mut explicit_port: Option<u16> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--bind" => {
                bind = args
                    .next()
                    .context("--bind needs a socket like 0.0.0.0:44818")?
                    .parse()?;
            }
            "--port" => {
                explicit_port = Some(
                    args.next()
                        .context("--port needs a value")?
                        .parse()
                        .context("--port must be a u16")?,
                );
            }
            other => anyhow::bail!("unexpected argument `{}`", other),
        }
    }
    if let Some(p) = explicit_port {
        // --port overrides --bind's port but keeps 127.0.0.1 as the host so
        // pytest can race the server to a free port without opening the
        // listener up to the LAN.
        bind = SocketAddr::from(([127, 0, 0, 1], p));
    }

    let registry = TagRegistry::new();

    // One tag per atomic CIP type. Names and initial values must match the
    // Python port's test_pycomm3_roundtrip.py seed set — the pytest
    // round-trip at tests/pycomm3/ reads these exact names and verifies
    // these exact initial values before writing new ones.
    registry.add_atomic("TestBool", CipType::Bool)?;
    registry.set_by_name("TestBool", &[1u8])?;

    registry.add_atomic("TestSint", CipType::Sint)?;
    registry.set_by_name("TestSint", &(-5i8).to_le_bytes())?;
    registry.add_atomic("TestInt", CipType::Int)?;
    registry.set_by_name("TestInt", &(-1234i16).to_le_bytes())?;
    registry.add_atomic("TestDint", CipType::Dint)?;
    registry.set_by_name("TestDint", &(-1_000_000i32).to_le_bytes())?;
    registry.add_atomic("TestLint", CipType::Lint)?;
    registry.set_by_name("TestLint", &(-1i64).to_le_bytes())?;

    registry.add_atomic("TestUsint", CipType::Usint)?;
    registry.set_by_name("TestUsint", &[42u8])?;
    registry.add_atomic("TestUint", CipType::Uint)?;
    registry.set_by_name("TestUint", &0xBEEFu16.to_le_bytes())?;
    registry.add_atomic("TestUdint", CipType::Udint)?;
    registry.set_by_name("TestUdint", &0xDEADBEEFu32.to_le_bytes())?;
    registry.add_atomic("TestUlint", CipType::Ulint)?;
    registry.set_by_name("TestUlint", &1_234_567_890_123u64.to_le_bytes())?;

    registry.add_atomic("TestReal", CipType::Real)?;
    registry.set_by_name("TestReal", &3.14f32.to_le_bytes())?;
    registry.add_atomic("TestLreal", CipType::Lreal)?;
    registry.set_by_name("TestLreal", &3.141592653589793f64.to_le_bytes())?;

    registry.add_atomic("TestByte", CipType::Byte)?;
    registry.set_by_name("TestByte", &[0xABu8])?;
    registry.add_atomic("TestWord", CipType::Word)?;
    registry.set_by_name("TestWord", &0x1234u16.to_le_bytes())?;
    registry.add_atomic("TestDword", CipType::Dword)?;
    registry.set_by_name("TestDword", &0xDEADBEEFu32.to_le_bytes())?;
    registry.add_atomic("TestLword", CipType::Lword)?;
    registry.set_by_name("TestLword", &0x1234_5678_9ABC_DEF0u64.to_le_bytes())?;

    // SHORT_STRING: 81-byte slot (1 USINT length + 80 ASCII bytes). Seeded
    // empty so the pycomm3 write of "hello" shows up as "hello\0..." in a
    // Read_Tag reply.
    registry.add_atomic("TestShortString", CipType::ShortString)?;

    let identity = IdentityInfo {
        vendor_id: 1,
        device_type: 0x000E,
        product_code: 65,
        major_revision: 20,
        minor_revision: 11,
        status: 0x0030,
        serial_number: 0x1234_5678,
        product_name: "PyCommRoundTripTarget".into(),
    };

    let handle = start_tag_server(
        TagServerConfig::new(registry.clone())
            .tcp_bind(bind)
            .identity(identity),
    )
    .await?;
    println!(
        "logix-host listening on {} — atomic tag surface for pycomm3 round-trip",
        handle.tcp_addr,
    );
    println!("Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.ok();
    println!("stopping...");
    handle.shutdown().await;
    Ok(())
}
