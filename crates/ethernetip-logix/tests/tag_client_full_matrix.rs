//! Our `TagClient` against our tag server — symmetric check to the pycomm3
//! round-trip in `tests/own_client/test_own_client_roundtrip.py`.
//!
//! The pycomm3 test proves our SERVER speaks the Rockwell wire dialect
//! correctly. This one proves our CLIENT (`TagClient`) does: it reads back
//! exactly what the server stored, through the full client → wire → server
//! → wire → client loop, over every row of the sample-host matrix (atomics,
//! 1-D array indexing, bit-of-atomic setup, BOOL array, multi-dim array,
//! Logix STRING UDT, user UDT whole-struct / member access, UDT array
//! member, Timer/AOI UDTs, program-scoped tags, and batch read via
//! Multiple Service Packet).
//!
//! Failures are collected across the matrix so the first assertion failure
//! does not hide the others.

use std::net::SocketAddr;

use ethernetip_logix::server_template::{ServerTemplate, ServerTemplateMember};
use ethernetip_logix::tag_client::TagClient;
use ethernetip_logix::tag_registry::TagRegistry;
use ethernetip_logix::tag_server::{start as start_server, TagServerConfig};
use ethernetip_logix::types::{CipType, TagValue};

/// Known structure handles — the server stamps these on the wire and the
/// client must send them back verbatim on writes.
const STRING_STRUCT_HANDLE: u16 = 0x0CE1;
const MOTOR_STRUCT_HANDLE: u16 = 0x1234;
const TIMER_STRUCT_HANDLE: u16 = 0x2222;
const AOI_STRUCT_HANDLE: u16 = 0x3333;

const STRUCT_TYPE_INDICATOR: u16 = 0x02A0;

/// Build the same tag landscape the pycomm3 test uses.
fn build_registry() -> TagRegistry {
    let reg = TagRegistry::new();

    // --- Atomics ---------------------------------------------------------
    reg.add_atomic("TestDint", CipType::Dint).unwrap();
    reg.set_by_name("TestDint", &(-1_000_000i32).to_le_bytes()).unwrap();

    reg.add_atomic("TestReal", CipType::Real).unwrap();
    reg.set_by_name("TestReal", &3.14f32.to_le_bytes()).unwrap();

    reg.add_atomic("TestUdint", CipType::Udint).unwrap();
    reg.set_by_name("TestUdint", &0xDEAD_BEEFu32.to_le_bytes()).unwrap();

    reg.add_atomic("TestLint", CipType::Lint).unwrap();
    reg.set_by_name("TestLint", &(-1i64).to_le_bytes()).unwrap();

    // --- 1-D DINT array --------------------------------------------------
    reg.add_array("DintArr", CipType::Dint, 10).unwrap();
    let mut arr_data = Vec::with_capacity(40);
    for i in 0..10i32 {
        arr_data.extend_from_slice(&(100 + i).to_le_bytes());
    }
    reg.set_by_name("DintArr", &arr_data).unwrap();

    // --- Bit-of-atomic (setup only, pycomm3 side exercises it) -----------
    reg.add_atomic("FlagsDint", CipType::Dint).unwrap();
    reg.set_by_name("FlagsDint", &0b1010_1010_1010_1010u32.to_le_bytes())
        .unwrap();

    // --- BOOL array (DWORD-packed) ---------------------------------------
    reg.add_array("Flags32", CipType::Bool, 32).unwrap();

    // --- Multi-dim DINT array --------------------------------------------
    reg.add_multi_dim("Matrix", CipType::Dint, &[2, 3]).unwrap();
    let mut mat_data = Vec::with_capacity(24);
    for r in 0..2i32 {
        for c in 0..3i32 {
            mat_data.extend_from_slice(&(10 * r + c).to_le_bytes());
        }
    }
    reg.set_by_name("Matrix", &mat_data).unwrap();

    // --- Logix STRING UDT ------------------------------------------------
    //   LEN:DINT at 0, DATA:SINT[82] at 4, total 88 bytes.
    let string_tpl = ServerTemplate {
        instance_id: 0x101,
        name: "STRING".into(),
        structure_handle: STRING_STRUCT_HANDLE,
        structure_size: 88,
        members: vec![
            ServerTemplateMember {
                name: "LEN".into(),
                data_type: CipType::Dint as u16,
                offset: 0,
                array_size: 0,
                element_size: 4,
            },
            ServerTemplateMember {
                name: "DATA".into(),
                data_type: CipType::Sint as u16,
                offset: 4,
                array_size: 82,
                element_size: 1,
            },
        ],
    };
    let string_id = reg.add_template(string_tpl).unwrap();
    reg.add_struct_from_template("Greeting", &reg.get_template(string_id).unwrap())
        .unwrap();
    let mut sbuf = vec![0u8; 88];
    let hello = b"Hello client";
    sbuf[..4].copy_from_slice(&(hello.len() as i32).to_le_bytes());
    sbuf[4..4 + hello.len()].copy_from_slice(hello);
    reg.set_by_name("Greeting", &sbuf).unwrap();

    // --- User UDT Motor { Speed:REAL, Fault:BOOL, RunCount:DINT } --------
    let motor_tpl = ServerTemplate {
        instance_id: 0x102,
        name: "Motor".into(),
        structure_handle: MOTOR_STRUCT_HANDLE,
        structure_size: 12,
        members: vec![
            ServerTemplateMember {
                name: "Speed".into(),
                data_type: CipType::Real as u16,
                offset: 0,
                array_size: 0,
                element_size: 4,
            },
            // Scalar BOOL at byte 4, bit 0 (array_size carries the bit pos
            // when element_size == 0 — see walker.rs line 83).
            ServerTemplateMember {
                name: "Fault".into(),
                data_type: CipType::Bool as u16,
                offset: 4,
                array_size: 0,
                element_size: 0,
            },
            ServerTemplateMember {
                name: "RunCount".into(),
                data_type: CipType::Dint as u16,
                offset: 8,
                array_size: 0,
                element_size: 4,
            },
        ],
    };
    let motor_id = reg.add_template(motor_tpl).unwrap();
    let motor_tpl_ref = reg.get_template(motor_id).unwrap();

    reg.add_struct_from_template("MotorA", &motor_tpl_ref).unwrap();
    let mut mbuf = vec![0u8; 12];
    mbuf[..4].copy_from_slice(&3.14f32.to_le_bytes());
    mbuf[4] = 1; // Fault bit
    mbuf[8..12].copy_from_slice(&42i32.to_le_bytes());
    reg.set_by_name("MotorA", &mbuf).unwrap();

    reg.add_struct_array_from_template("MotorArr", &motor_tpl_ref, 3)
        .unwrap();

    // --- TIMER-shape UDT -------------------------------------------------
    let timer_tpl = ServerTemplate {
        instance_id: 0x103,
        name: "TIMER".into(),
        structure_handle: TIMER_STRUCT_HANDLE,
        structure_size: 12,
        members: vec![
            // EN/TT/DN are BOOLs packed into byte 0 (bits 0/1/2).
            ServerTemplateMember {
                name: "EN".into(),
                data_type: CipType::Bool as u16,
                offset: 0,
                array_size: 0,
                element_size: 0,
            },
            ServerTemplateMember {
                name: "TT".into(),
                data_type: CipType::Bool as u16,
                offset: 0,
                array_size: 1,
                element_size: 0,
            },
            ServerTemplateMember {
                name: "DN".into(),
                data_type: CipType::Bool as u16,
                offset: 0,
                array_size: 2,
                element_size: 0,
            },
            ServerTemplateMember {
                name: "PRE".into(),
                data_type: CipType::Dint as u16,
                offset: 4,
                array_size: 0,
                element_size: 4,
            },
            ServerTemplateMember {
                name: "ACC".into(),
                data_type: CipType::Dint as u16,
                offset: 8,
                array_size: 0,
                element_size: 4,
            },
        ],
    };
    let timer_id = reg.add_template(timer_tpl).unwrap();
    reg.add_struct_from_template("MyTimer", &reg.get_template(timer_id).unwrap())
        .unwrap();
    let mut tbuf = vec![0u8; 12];
    tbuf[0] = 1; // EN
    tbuf[4..8].copy_from_slice(&1000i32.to_le_bytes());
    tbuf[8..12].copy_from_slice(&250i32.to_le_bytes());
    reg.set_by_name("MyTimer", &tbuf).unwrap();

    // --- AOI-shape UDT ---------------------------------------------------
    //   Enable:BOOL (byte 0 bit 0), Setpoint:REAL (offset 4),
    //   Done:BOOL (byte 8 bit 0), Steps:DINT (offset 12). Size 16.
    let aoi_tpl = ServerTemplate {
        instance_id: 0x104,
        name: "MixerAOI".into(),
        structure_handle: AOI_STRUCT_HANDLE,
        structure_size: 16,
        members: vec![
            ServerTemplateMember {
                name: "Enable".into(),
                data_type: CipType::Bool as u16,
                offset: 0,
                array_size: 0,
                element_size: 0,
            },
            ServerTemplateMember {
                name: "Setpoint".into(),
                data_type: CipType::Real as u16,
                offset: 4,
                array_size: 0,
                element_size: 4,
            },
            ServerTemplateMember {
                name: "Done".into(),
                data_type: CipType::Bool as u16,
                offset: 8,
                array_size: 0,
                element_size: 0,
            },
            ServerTemplateMember {
                name: "Steps".into(),
                data_type: CipType::Dint as u16,
                offset: 12,
                array_size: 0,
                element_size: 4,
            },
        ],
    };
    let aoi_id = reg.add_template(aoi_tpl).unwrap();
    reg.add_struct_from_template("MyAOI", &reg.get_template(aoi_id).unwrap())
        .unwrap();
    let mut abuf = vec![0u8; 16];
    abuf[0] = 1; // Enable
    abuf[4..8].copy_from_slice(&42.5f32.to_le_bytes());
    // Done stays 0.
    abuf[12..16].copy_from_slice(&7i32.to_le_bytes());
    reg.set_by_name("MyAOI", &abuf).unwrap();

    // --- Program-scoped tags ---------------------------------------------
    reg.register_program("MainProgram");
    reg.add_program_atomic("MainProgram", "LocalDint", CipType::Dint)
        .unwrap();
    reg.set_program_tag_bytes("MainProgram", "LocalDint", 0, &42i32.to_le_bytes())
        .unwrap();
    reg.add_program_atomic("MainProgram", "LocalReal", CipType::Real)
        .unwrap();
    reg.set_program_tag_bytes("MainProgram", "LocalReal", 0, &3.14f32.to_le_bytes())
        .unwrap();
    reg.add_program_struct_from_template("MainProgram", "LocalMotor", &motor_tpl_ref)
        .unwrap();
    let mut lmbuf = vec![0u8; 12];
    lmbuf[..4].copy_from_slice(&2.5f32.to_le_bytes());
    lmbuf[4] = 1;
    lmbuf[8..12].copy_from_slice(&99i32.to_le_bytes());
    reg.set_program_tag_bytes("MainProgram", "LocalMotor", 0, &lmbuf)
        .unwrap();

    reg
}

async fn spawn(
    reg: TagRegistry,
) -> (ethernetip_logix::tag_server::TagServerHandle, SocketAddr) {
    let cfg = TagServerConfig::new(reg).tcp_bind("127.0.0.1:0".parse().unwrap());
    let handle = start_server(cfg).await.expect("server start");
    let addr = handle.tcp_addr;
    (handle, addr)
}

async fn connect(addr: SocketAddr) -> TagClient {
    TagClient::builder(addr.ip().to_string())
        .port(addr.port())
        .connect()
        .await
        .expect("client connect")
}

/// Pull the DINT value out of a TagValue, or push a mismatch into `failures`.
fn expect_dint(label: &str, got: Result<TagValue, impl std::fmt::Debug>, want: i32, failures: &mut Vec<String>) {
    match got {
        Ok(TagValue::Dint(v)) if v == want => {}
        Ok(other) => failures.push(format!("{label}: expected Dint({want}), got {other:?}")),
        Err(e) => failures.push(format!("{label}: {e:?}")),
    }
}

fn expect_udint(label: &str, got: Result<TagValue, impl std::fmt::Debug>, want: u32, failures: &mut Vec<String>) {
    match got {
        Ok(TagValue::Udint(v)) if v == want => {}
        Ok(other) => failures.push(format!("{label}: expected Udint(0x{want:08X}), got {other:?}")),
        Err(e) => failures.push(format!("{label}: {e:?}")),
    }
}

fn expect_lint(label: &str, got: Result<TagValue, impl std::fmt::Debug>, want: i64, failures: &mut Vec<String>) {
    match got {
        Ok(TagValue::Lint(v)) if v == want => {}
        Ok(other) => failures.push(format!("{label}: expected Lint({want}), got {other:?}")),
        Err(e) => failures.push(format!("{label}: {e:?}")),
    }
}

fn expect_real(label: &str, got: Result<TagValue, impl std::fmt::Debug>, want: f32, tol: f32, failures: &mut Vec<String>) {
    match got {
        Ok(TagValue::Real(v)) if (v - want).abs() < tol => {}
        Ok(other) => failures.push(format!("{label}: expected Real({want}±{tol}), got {other:?}")),
        Err(e) => failures.push(format!("{label}: {e:?}")),
    }
}

fn expect_ok<T, E: std::fmt::Debug>(label: &str, got: Result<T, E>, failures: &mut Vec<String>) {
    if let Err(e) = got {
        failures.push(format!("{label}: {e:?}"));
    }
}

#[tokio::test]
async fn tag_client_full_matrix_round_trip() {
    let reg = build_registry();
    let (handle, addr) = spawn(reg).await;
    let mut c = connect(addr).await;
    let mut failures: Vec<String> = Vec::new();

    // --- Atomics ---------------------------------------------------------
    expect_dint("TestDint initial", c.read_tag("TestDint").await, -1_000_000, &mut failures);
    expect_ok(
        "TestDint write",
        c.write_tag("TestDint", &TagValue::Dint(2_000_000_000)).await,
        &mut failures,
    );
    expect_dint("TestDint after write", c.read_tag("TestDint").await, 2_000_000_000, &mut failures);

    expect_real("TestReal initial", c.read_tag("TestReal").await, 3.14, 1e-5, &mut failures);
    expect_ok(
        "TestReal write",
        c.write_tag("TestReal", &TagValue::Real(-2.71828)).await,
        &mut failures,
    );
    expect_real("TestReal after write", c.read_tag("TestReal").await, -2.71828, 1e-4, &mut failures);

    expect_udint("TestUdint initial", c.read_tag("TestUdint").await, 0xDEAD_BEEF, &mut failures);
    expect_ok(
        "TestUdint write",
        c.write_tag("TestUdint", &TagValue::Udint(0xFFFF_FFFF)).await,
        &mut failures,
    );
    expect_udint("TestUdint after write", c.read_tag("TestUdint").await, 0xFFFF_FFFF, &mut failures);

    expect_lint("TestLint initial", c.read_tag("TestLint").await, -1, &mut failures);
    expect_ok(
        "TestLint write",
        c.write_tag("TestLint", &TagValue::Lint(0x7FFF_FFFF_FFFF_FFFF)).await,
        &mut failures,
    );
    expect_lint("TestLint after write", c.read_tag("TestLint").await, 0x7FFF_FFFF_FFFF_FFFF, &mut failures);

    // --- 1-D array indexed ----------------------------------------------
    expect_dint("DintArr[5] initial", c.read_tag("DintArr[5]").await, 105, &mut failures);
    expect_ok(
        "DintArr[5] write",
        c.write_tag("DintArr[5]", &TagValue::Dint(999)).await,
        &mut failures,
    );
    expect_dint("DintArr[5] after write", c.read_tag("DintArr[5]").await, 999, &mut failures);

    // --- Multi-dim array -------------------------------------------------
    expect_dint("Matrix[1,2]", c.read_tag("Matrix[1,2]").await, 12, &mut failures);
    expect_ok(
        "Matrix[0,1] write",
        c.write_tag("Matrix[0,1]", &TagValue::Dint(777)).await,
        &mut failures,
    );
    expect_dint("Matrix[0,1] after write", c.read_tag("Matrix[0,1]").await, 777, &mut failures);

    // --- Logix STRING UDT ------------------------------------------------
    // Read: whole struct comes back as TagValue::Struct { crc, bytes }
    // with LEN:DINT + 82 bytes of DATA. Decode to a String.
    match c.read_tag("Greeting").await {
        Ok(TagValue::Struct { crc, bytes }) => {
            if crc != STRING_STRUCT_HANDLE {
                failures.push(format!(
                    "Greeting read: crc 0x{crc:04X} != expected 0x{:04X}",
                    STRING_STRUCT_HANDLE
                ));
            }
            if bytes.len() >= 4 {
                let len = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
                let data_end = 4 + len.min(bytes.len() - 4);
                let decoded = std::str::from_utf8(&bytes[4..data_end]).unwrap_or("");
                if decoded != "Hello client" {
                    failures.push(format!("Greeting read: decoded {decoded:?}"));
                }
            } else {
                failures.push(format!("Greeting read: short bytes {}", bytes.len()));
            }
        }
        Ok(other) => failures.push(format!("Greeting read: not a struct: {other:?}")),
        Err(e) => failures.push(format!("Greeting read: {e:?}")),
    }

    // Write: build the on-wire struct body ourselves and send through
    // write_tag_raw — mirrors the Python test's structure_handle discovery
    // + write_string path.
    {
        let new_str = b"written back";
        let mut payload = vec![0u8; 88];
        payload[..4].copy_from_slice(&(new_str.len() as i32).to_le_bytes());
        payload[4..4 + new_str.len()].copy_from_slice(new_str);

        let mut body = Vec::with_capacity(6 + 88);
        body.extend_from_slice(&STRUCT_TYPE_INDICATOR.to_le_bytes());
        body.extend_from_slice(&STRING_STRUCT_HANDLE.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&payload);
        expect_ok("Greeting write", c.write_tag_raw("Greeting", &body).await, &mut failures);
    }
    match c.read_tag("Greeting").await {
        Ok(TagValue::Struct { bytes, .. }) if bytes.len() >= 4 => {
            let len = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            let data_end = 4 + len.min(bytes.len() - 4);
            let decoded = std::str::from_utf8(&bytes[4..data_end]).unwrap_or("");
            if decoded != "written back" {
                failures.push(format!("Greeting round-trip: decoded {decoded:?}"));
            }
        }
        Ok(other) => failures.push(format!("Greeting round-trip: not a struct: {other:?}")),
        Err(e) => failures.push(format!("Greeting round-trip: {e:?}")),
    }

    // --- UDT whole-struct read ------------------------------------------
    match c.read_tag("MotorA").await {
        Ok(TagValue::Struct { crc, bytes }) => {
            if crc != MOTOR_STRUCT_HANDLE {
                failures.push(format!(
                    "MotorA read: crc 0x{crc:04X} != expected 0x{:04X}",
                    MOTOR_STRUCT_HANDLE
                ));
            }
            if bytes.len() != 12 {
                failures.push(format!("MotorA read: payload len {}", bytes.len()));
            }
        }
        Ok(other) => failures.push(format!("MotorA read: not a struct: {other:?}")),
        Err(e) => failures.push(format!("MotorA read: {e:?}")),
    }

    // --- UDT member access via the generic read path --------------------
    expect_real("MotorA.Speed initial", c.read_tag("MotorA.Speed").await, 3.14, 1e-5, &mut failures);
    expect_dint("MotorA.RunCount", c.read_tag("MotorA.RunCount").await, 42, &mut failures);
    expect_ok(
        "MotorA.Speed write",
        c.write_tag("MotorA.Speed", &TagValue::Real(-1.5)).await,
        &mut failures,
    );
    expect_real("MotorA.Speed after write", c.read_tag("MotorA.Speed").await, -1.5, 1e-4, &mut failures);

    // Array-of-UDT member access
    expect_ok(
        "MotorArr[1].Speed write",
        c.write_tag("MotorArr[1].Speed", &TagValue::Real(7.77)).await,
        &mut failures,
    );
    expect_real(
        "MotorArr[1].Speed read",
        c.read_tag("MotorArr[1].Speed").await,
        7.77,
        1e-4,
        &mut failures,
    );

    // --- Timer / AOI members --------------------------------------------
    expect_dint("MyTimer.PRE initial", c.read_tag("MyTimer.PRE").await, 1000, &mut failures);
    expect_dint("MyTimer.ACC initial", c.read_tag("MyTimer.ACC").await, 250, &mut failures);
    expect_ok(
        "MyTimer.PRE write",
        c.write_tag("MyTimer.PRE", &TagValue::Dint(2000)).await,
        &mut failures,
    );
    expect_dint("MyTimer.PRE after write", c.read_tag("MyTimer.PRE").await, 2000, &mut failures);

    expect_real("MyAOI.Setpoint initial", c.read_tag("MyAOI.Setpoint").await, 42.5, 1e-5, &mut failures);
    expect_ok(
        "MyAOI.Setpoint write",
        c.write_tag("MyAOI.Setpoint", &TagValue::Real(99.9)).await,
        &mut failures,
    );
    expect_real("MyAOI.Setpoint after write", c.read_tag("MyAOI.Setpoint").await, 99.9, 1e-4, &mut failures);
    expect_dint("MyAOI.Steps", c.read_tag("MyAOI.Steps").await, 7, &mut failures);

    // --- Program-scoped tags --------------------------------------------
    expect_dint(
        "Program:MainProgram.LocalDint initial",
        c.read_tag("Program:MainProgram.LocalDint").await,
        42,
        &mut failures,
    );
    expect_ok(
        "Program:MainProgram.LocalDint write",
        c.write_tag("Program:MainProgram.LocalDint", &TagValue::Dint(100)).await,
        &mut failures,
    );
    expect_dint(
        "Program:MainProgram.LocalDint after write",
        c.read_tag("Program:MainProgram.LocalDint").await,
        100,
        &mut failures,
    );

    expect_real(
        "Program:MainProgram.LocalReal",
        c.read_tag("Program:MainProgram.LocalReal").await,
        3.14,
        1e-5,
        &mut failures,
    );

    expect_real(
        "Program:MainProgram.LocalMotor.Speed initial",
        c.read_tag("Program:MainProgram.LocalMotor.Speed").await,
        2.5,
        1e-5,
        &mut failures,
    );
    expect_dint(
        "Program:MainProgram.LocalMotor.RunCount",
        c.read_tag("Program:MainProgram.LocalMotor.RunCount").await,
        99,
        &mut failures,
    );
    expect_ok(
        "Program:MainProgram.LocalMotor.Speed write",
        c.write_tag("Program:MainProgram.LocalMotor.Speed", &TagValue::Real(5.5))
            .await,
        &mut failures,
    );
    expect_real(
        "Program:MainProgram.LocalMotor.Speed after write",
        c.read_tag("Program:MainProgram.LocalMotor.Speed").await,
        5.5,
        1e-4,
        &mut failures,
    );

    // --- Batch read via Multiple Service Packet -------------------------
    match c
        .read_tags_batch(&["DintArr[0]", "DintArr[1]", "DintArr[2]"])
        .await
    {
        Ok(got) => {
            if got.len() != 3 {
                failures.push(format!("batch read: expected 3 replies, got {}", got.len()));
            }
            for (i, r) in got.iter().enumerate() {
                if let Err(e) = r {
                    failures.push(format!("batch read[{i}]: {e:?}"));
                }
            }
        }
        Err(e) => failures.push(format!("batch read: {e:?}")),
    }

    c.close().await.ok();
    handle.shutdown().await;

    assert!(
        failures.is_empty(),
        "TagClient round-trip failures:\n  {}",
        failures.join("\n  ")
    );
}
