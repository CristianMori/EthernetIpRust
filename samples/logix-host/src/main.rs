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
use ethernetip_logix::{
    start_tag_server, CipType, IdentityInfo, ServerTemplate, ServerTemplateMember, TagRegistry,
    TagServerConfig,
};

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

    // ---- Yellow-row coverage ---------------------------------------------
    // Keeps names and seed values aligned with the sibling Python port's
    // test_pycomm3_roundtrip.py (commit 620fce4) so one pytest file can
    // target either host.

    // 1-D array of atomics: DintArr[10] seeded 100..109.
    registry.add_array("DintArr", CipType::Dint, 10)?;
    let mut dint_buf = Vec::with_capacity(40);
    for i in 0..10i32 {
        dint_buf.extend_from_slice(&(100i32 + i).to_le_bytes());
    }
    registry.set_by_name("DintArr", &dint_buf)?;

    // Bit of atomic (DINT): FlagsDint seeded with alternating bits.
    registry.add_atomic("FlagsDint", CipType::Dint)?;
    registry.set_by_name("FlagsDint", &0b1010_1010_1010_1010u32.to_le_bytes())?;

    // BOOL array (DWORD-packed): Flags32[32].
    registry.add_array("Flags32", CipType::Bool, 32)?;

    // Multi-dim array: Matrix[2,3] row-major, element value = 10*r + c.
    registry.add_multi_dim("Matrix", CipType::Dint, &[2, 3])?;
    let mut mat_buf = Vec::with_capacity(24);
    for r in 0..2i32 {
        for c in 0..3i32 {
            mat_buf.extend_from_slice(&(10 * r + c).to_le_bytes());
        }
    }
    registry.set_by_name("Matrix", &mat_buf)?;

    // Logix STRING UDT: LEN:DINT + DATA:SINT[82], 88 bytes total (padded to
    // a 4-byte boundary). pycomm3 recognises this specific shape as a Logix
    // STRING and returns it as a Python str.
    let string_tpl_id = registry.add_template(ServerTemplate {
        instance_id: 0,
        name: "STRING".into(),
        structure_handle: 0, // auto = instance_id
        structure_size: 88,
        members: vec![
            ServerTemplateMember {
                name: "LEN".into(),
                data_type: 0x00C4, // DINT
                offset: 0,
                array_size: 0,
                element_size: 4,
            },
            ServerTemplateMember {
                name: "DATA".into(),
                data_type: 0x00C2, // SINT
                offset: 4,
                array_size: 82, // array member
                element_size: 1,
            },
        ],
    })?;
    let string_tpl = registry
        .get_template(string_tpl_id)
        .expect("STRING template just registered");
    registry.add_struct_from_template("Greeting", &string_tpl)?;
    let hello = b"Hello pycomm3";
    let mut gbuf = vec![0u8; 88];
    gbuf[..4].copy_from_slice(&(hello.len() as u32).to_le_bytes());
    gbuf[4..4 + hello.len()].copy_from_slice(hello);
    registry.set_by_name("Greeting", &gbuf)?;
    // Array of STRING UDT (GreetingArr[3]).
    registry.add_struct_array_from_template("GreetingArr", &string_tpl, 3)?;

    // User UDT: Motor { Speed:REAL, Fault:BOOL, RunCount:DINT } — 12 bytes.
    //   REAL  at 0 (align 4),
    //   BOOL  at 4 (align 1, one byte),
    //   DINT  at 8 (align 4).  Trailing padding brings total to 12.
    // Fault's bit position lives in the template-member's array_size field
    // (pycomm3 reads it as the bit index inside the byte at offset 4). We
    // store the BOOL as a plain byte (0x01 / 0x00) at offset 4 so a
    // whole-byte Read_Tag / Write_Tag on MotorA.Fault reads bit 0 cleanly.
    let motor_tpl_id = registry.add_template(ServerTemplate {
        instance_id: 0,
        name: "Motor".into(),
        structure_handle: 0,
        structure_size: 12,
        members: vec![
            ServerTemplateMember {
                name: "Speed".into(),
                data_type: 0x00CA, // REAL
                offset: 0,
                array_size: 0,
                element_size: 4,
            },
            ServerTemplateMember {
                name: "Fault".into(),
                data_type: 0x00C1, // BOOL
                offset: 4,
                array_size: 0, // bit position for pycomm3
                element_size: 1,
            },
            ServerTemplateMember {
                name: "RunCount".into(),
                data_type: 0x00C4, // DINT
                offset: 8,
                array_size: 0,
                element_size: 4,
            },
        ],
    })?;
    let motor_tpl = registry
        .get_template(motor_tpl_id)
        .expect("Motor template just registered");
    registry.add_struct_from_template("MotorA", &motor_tpl)?;
    let mut motor_buf = vec![0u8; 12];
    motor_buf[..4].copy_from_slice(&3.14f32.to_le_bytes());
    motor_buf[4] = 1; // Fault = true (byte-encoded BOOL)
    motor_buf[8..12].copy_from_slice(&42i32.to_le_bytes());
    registry.set_by_name("MotorA", &motor_buf)?;
    // Array of Motor UDT (MotorArr[3]) — exercises `MotorArr[1].Speed`.
    registry.add_struct_array_from_template("MotorArr", &motor_tpl, 3)?;

    // TIMER { EN:BOOL, TT:BOOL, DN:BOOL, PRE:DINT, ACC:DINT } — Logix exposes
    // TIMER / COUNTER / CONTROL as predefined structures, but on the wire
    // they are plain UDTs: the server emits a template via Template Object
    // (0x6C) and member access goes through the same TagName.FieldName
    // plumbing as any user UDT. BOOLs are byte-encoded (like Motor.Fault)
    // then padded to the next DINT boundary. Total structure_size = 12.
    let timer_tpl_id = registry.add_template(ServerTemplate {
        instance_id: 0,
        name: "TIMER".into(),
        structure_handle: 0,
        structure_size: 12,
        members: vec![
            ServerTemplateMember {
                name: "EN".into(),
                data_type: 0x00C1, // BOOL
                offset: 0,
                array_size: 0,
                element_size: 1,
            },
            ServerTemplateMember {
                name: "TT".into(),
                data_type: 0x00C1, // BOOL
                offset: 1,
                array_size: 0,
                element_size: 1,
            },
            ServerTemplateMember {
                name: "DN".into(),
                data_type: 0x00C1, // BOOL
                offset: 2,
                array_size: 0,
                element_size: 1,
            },
            ServerTemplateMember {
                name: "PRE".into(),
                data_type: 0x00C4, // DINT
                offset: 4,
                array_size: 0,
                element_size: 4,
            },
            ServerTemplateMember {
                name: "ACC".into(),
                data_type: 0x00C4, // DINT
                offset: 8,
                array_size: 0,
                element_size: 4,
            },
        ],
    })?;
    let timer_tpl = registry
        .get_template(timer_tpl_id)
        .expect("TIMER template just registered");
    registry.add_struct_from_template("MyTimer", &timer_tpl)?;
    let mut timer_buf = vec![0u8; 12];
    timer_buf[0] = 1; // EN = true
    timer_buf[4..8].copy_from_slice(&1000i32.to_le_bytes()); // PRE
    timer_buf[8..12].copy_from_slice(&250i32.to_le_bytes()); // ACC
    registry.set_by_name("MyTimer", &timer_buf)?;

    // MixerAOI { Enable:BOOL, Setpoint:REAL, Done:BOOL, Steps:DINT } — a
    // stand-in for an AOI's backing tag. On the wire this is identical to a
    // user UDT; registering it here proves pycomm3's `TagName.FieldName`
    // access works for AOI-backing shapes too. Natural-alignment layout:
    //   Enable  at  0 (BOOL, 1 byte)
    //   Setpoint at 4 (REAL, 4 bytes, aligned to 4)
    //   Done    at  8 (BOOL, 1 byte)
    //   Steps   at 12 (DINT, 4 bytes, aligned to 4)
    // structure_size = 16.
    let aoi_tpl_id = registry.add_template(ServerTemplate {
        instance_id: 0,
        name: "MixerAOI".into(),
        structure_handle: 0,
        structure_size: 16,
        members: vec![
            ServerTemplateMember {
                name: "Enable".into(),
                data_type: 0x00C1, // BOOL
                offset: 0,
                array_size: 0,
                element_size: 1,
            },
            ServerTemplateMember {
                name: "Setpoint".into(),
                data_type: 0x00CA, // REAL
                offset: 4,
                array_size: 0,
                element_size: 4,
            },
            ServerTemplateMember {
                name: "Done".into(),
                data_type: 0x00C1, // BOOL
                offset: 8,
                array_size: 0,
                element_size: 1,
            },
            ServerTemplateMember {
                name: "Steps".into(),
                data_type: 0x00C4, // DINT
                offset: 12,
                array_size: 0,
                element_size: 4,
            },
        ],
    })?;
    let aoi_tpl = registry
        .get_template(aoi_tpl_id)
        .expect("MixerAOI template just registered");
    registry.add_struct_from_template("MyAOI", &aoi_tpl)?;
    let mut aoi_buf = vec![0u8; 16];
    aoi_buf[0] = 1; // Enable = true
    aoi_buf[4..8].copy_from_slice(&42.5f32.to_le_bytes()); // Setpoint
    aoi_buf[8] = 0; // Done = false
    aoi_buf[12..16].copy_from_slice(&7i32.to_le_bytes()); // Steps
    registry.set_by_name("MyAOI", &aoi_buf)?;
    // ----------------------------------------------------------------------

    // ---- Program-scoped tags ---------------------------------------------
    // pycomm3 enumerates these when LogixDriver is opened with
    // init_program_tags=True.  Names and seed values match the sibling
    // Python port's test_pycomm3_roundtrip.py so one pytest file can target
    // either host.
    //   Program:MainProgram.LocalDint   (DINT  = 42)
    //   Program:MainProgram.LocalReal   (REAL  = 3.14)
    //   Program:MainProgram.LocalMotor  (Motor UDT: Speed=2.5,
    //                                    Fault=true, RunCount=99)
    registry.register_program("MainProgram");
    registry.add_program_atomic("MainProgram", "LocalDint", CipType::Dint)?;
    registry.set_program_tag_bytes("MainProgram", "LocalDint", 0, &42i32.to_le_bytes())?;
    registry.add_program_atomic("MainProgram", "LocalReal", CipType::Real)?;
    registry.set_program_tag_bytes("MainProgram", "LocalReal", 0, &3.14f32.to_le_bytes())?;
    registry.add_program_struct_from_template("MainProgram", "LocalMotor", &motor_tpl)?;
    let mut local_motor_buf = vec![0u8; 12];
    local_motor_buf[..4].copy_from_slice(&2.5f32.to_le_bytes());
    local_motor_buf[4] = 1; // Fault = true
    local_motor_buf[8..12].copy_from_slice(&99i32.to_le_bytes());
    registry.set_program_tag_bytes("MainProgram", "LocalMotor", 0, &local_motor_buf)?;
    // ----------------------------------------------------------------------

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
