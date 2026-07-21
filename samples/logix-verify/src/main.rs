//! End-to-end tag-client verification against a live ControlLogix.
//!
//! Runs all read/write features in one session:
//!   1. Session + browse (controller + program scopes)
//!   2. Atomic reads (DINT / REAL / BOOL if present)
//!   3. Struct read (raw)
//!   4. UDT template introspection + typed decode
//!   5. Multiple Service Packet batched reads (+ timing vs sequential)
//!   6. Fragmented read on a struct
//!   7. Class 3 explicit connection
//!   8. Class 3 reopen-on-drop across a forced connection drop
//!   9. Write + verify (round-trips a DINT: read → write same value → read back)
//!
//! Usage: logix-verify [host] [--path 1,0]
//!   host default 192.168.1.96, path default 1,0

use std::env;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ethernetip_logix::{SymType, TagClient, TagInfo, TagValue, TypedValue};

fn ok(msg: &str) {
    println!("  \u{2713} {msg}");
}
fn info(msg: &str) {
    println!("    {msg}");
}
fn fail(msg: &str) {
    println!("  \u{2717} {msg}");
}
fn section(n: u8, name: &str) {
    println!("\n\u{2500}\u{2500}\u{2500} step {n}: {name} \u{2500}\u{2500}\u{2500}");
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(e) = run().await {
        eprintln!("\nFATAL: {:#}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<()> {
    let mut host = "192.168.1.96".to_string();
    let mut path = "1,0".to_string();
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--path" => path = args.next().context("--path needs value")?,
            other if !other.starts_with("--") => host = other.to_string(),
            other => anyhow::bail!("unknown arg `{}`", other),
        }
    }

    println!("logix-verify — target {host} path {path}");

    // 1) session + browse
    section(1, "session + browse");
    let t0 = Instant::now();
    let mut client = TagClient::builder(&host)
        .path(&path)
        .connect()
        .await
        .context("connect")?;
    ok(&format!(
        "registered in {:?}, session 0x{:08X}",
        t0.elapsed(),
        client.session_handle()
    ));
    let tags = client.browse_tags().await.context("browse")?;
    ok(&format!("controller-scope tags: {}", tags.len()));

    // Split into user-visible vs internal.
    let (user_tags, hidden): (Vec<&TagInfo>, Vec<&TagInfo>) = tags
        .iter()
        .partition(|t| !is_internal(&t.name));
    info(&format!(
        "user-visible: {}, hidden (__/Map:/Task:/Program:/UDI:): {}",
        user_tags.len(),
        hidden.len()
    ));

    // Enumerate program scopes.
    let programs: Vec<&TagInfo> = tags
        .iter()
        .filter(|t| t.name.starts_with("Program:"))
        .collect();
    ok(&format!("program scopes: {}", programs.len()));
    for p in &programs {
        let program_name = p.name.strip_prefix("Program:").unwrap_or(&p.name);
        match client.browse_program_tags(program_name).await {
            Ok(pt) => info(&format!("  {program_name}: {} tags", pt.len())),
            Err(e) => info(&format!("  {program_name}: browse failed ({e})")),
        }
    }

    // Print the first user-visible tags for context.
    if !user_tags.is_empty() {
        info("first 10 user tags:");
        for t in user_tags.iter().take(10) {
            info(&format!(
                "    {:<32} sym=0x{:04X} {}",
                t.name,
                t.sym_type,
                describe_sym(SymType(t.sym_type))
            ));
        }
    }

    // 2) atomic reads
    section(2, "atomic reads");
    let a_dint = user_tags.iter().find(|t| atomic_code(t) == Some(0x00C4));
    let a_real = user_tags.iter().find(|t| atomic_code(t) == Some(0x00CA));
    let a_bool = user_tags.iter().find(|t| atomic_code(t) == Some(0x00C1));
    for (label, opt) in [("DINT", a_dint), ("REAL", a_real), ("BOOL", a_bool)] {
        match opt {
            Some(t) => match client.read_tag(&t.name).await {
                Ok(v) => ok(&format!("{label} {} = {:?}", t.name, v)),
                Err(e) => fail(&format!("{label} {}: {e}", t.name)),
            },
            None => info(&format!("no {label} tag in user scope")),
        }
    }

    // 3) struct read (raw)
    section(3, "struct read (raw)");
    let a_struct = user_tags
        .iter()
        .find(|t| SymType(t.sym_type).is_struct() && !t.name.starts_with("Map:"));
    let mut struct_tag_name: Option<String> = None;
    let mut struct_template_id: Option<u16> = None;
    if let Some(t) = a_struct {
        struct_tag_name = Some(t.name.clone());
        struct_template_id = SymType(t.sym_type).template_id();
        match client.read_tag(&t.name).await {
            Ok(TagValue::Struct { crc, bytes }) => ok(&format!(
                "{} = struct crc=0x{:04X} len={}",
                t.name,
                crc,
                bytes.len()
            )),
            Ok(v) => fail(&format!("{} not a struct: {:?}", t.name, v)),
            Err(e) => fail(&format!("{}: {e}", t.name)),
        }
    } else {
        info("no user-scope struct tag found — skipping");
    }

    // 4) UDT template introspection + typed decode
    section(4, "UDT template introspection + typed decode");
    if let (Some(name), Some(tid)) = (struct_tag_name.as_ref(), struct_template_id) {
        match client.fetch_template(tid).await {
            Ok(def) => {
                ok(&format!(
                    "template {} (crc=0x{:04X}, {} bytes, {} members)",
                    def.name,
                    def.crc,
                    def.structure_size_bytes,
                    def.members.len()
                ));
                for m in def.members.iter().take(8) {
                    info(&format!(
                        "  @{:>3}  {:<24} sym=0x{:04X} {}",
                        m.offset,
                        m.name,
                        m.sym_type.0,
                        describe_sym(m.sym_type)
                    ));
                }
                if def.members.len() > 8 {
                    info(&format!("  ... ({} more)", def.members.len() - 8));
                }
                match client.read_tag_typed(name).await {
                    Ok(TypedValue::Struct { name: n, fields, .. }) => {
                        ok(&format!("typed decode of {name} → {n} ({} fields)", fields.len()));
                        for (k, v) in fields.iter().take(8) {
                            info(&format!("  {k}: {:?}", v));
                        }
                        if fields.len() > 8 {
                            info(&format!("  ... ({} more)", fields.len() - 8));
                        }
                    }
                    Ok(v) => fail(&format!("typed decode returned non-struct: {:?}", v)),
                    Err(e) => fail(&format!("typed decode: {e}")),
                }
            }
            Err(e) => fail(&format!("fetch_template({tid}): {e}")),
        }
    } else {
        info("no struct tag / template id — skipping");
    }

    // 5) MSP batched reads + timing
    section(5, "Multiple Service Packet batched reads");
    let mut batch_names: Vec<&str> = Vec::new();
    for t in user_tags.iter() {
        if atomic_code(t).is_some() {
            batch_names.push(&t.name);
            if batch_names.len() == 5 {
                break;
            }
        }
    }
    if batch_names.is_empty() {
        info("no atomic tags for a batch — skipping");
    } else {
        // sequential baseline
        let t_seq = Instant::now();
        let mut seq_results = Vec::with_capacity(batch_names.len());
        for n in &batch_names {
            seq_results.push(client.read_tag(n).await);
        }
        let seq = t_seq.elapsed();
        // batched
        let t_batch = Instant::now();
        let batch = client.read_tags_batch(&batch_names).await;
        let bt = t_batch.elapsed();
        match batch {
            Ok(rs) => {
                ok(&format!(
                    "batch OK: {}/{} succeeded; batch {:?} vs sequential {:?}",
                    rs.iter().filter(|r| r.is_ok()).count(),
                    rs.len(),
                    bt,
                    seq
                ));
                for (n, r) in batch_names.iter().zip(rs.iter()) {
                    match r {
                        Ok(v) => info(&format!("  {n} = {:?}", v)),
                        Err(e) => info(&format!("  {n}: {e}")),
                    }
                }
                // Cross-check: batch results should match sequential.
                let mut mismatch = 0;
                for (s, b) in seq_results.iter().zip(rs.iter()) {
                    match (s, b) {
                        (Ok(a), Ok(b)) if a != b => mismatch += 1,
                        _ => {}
                    }
                }
                if mismatch == 0 {
                    ok("batch == sequential for every tag");
                } else {
                    fail(&format!("{mismatch} values differ between batch/sequential"));
                }
            }
            Err(e) => fail(&format!("batch: {e}")),
        }
    }

    // 6) fragmented read
    section(6, "fragmented read");
    // Pick a struct large enough to plausibly need fragmentation, else fall
    // back to the same one we found earlier. Any struct works — the client
    // internally decides based on the reply status. We call the fragmented
    // path directly to prove it also works standalone.
    if let Some(name) = struct_tag_name.as_ref() {
        let t_frag = Instant::now();
        match client.read_tag_fragmented(name, 1).await {
            Ok(bytes) => ok(&format!(
                "read_tag_fragmented({name}) → {} bytes in {:?}",
                bytes.len(),
                t_frag.elapsed()
            )),
            Err(e) => fail(&format!("read_tag_fragmented({name}): {e}")),
        }
    } else {
        info("no struct tag — skipping");
    }

    // 9 relies on knowing a safe target; check for a scratch DINT.
    let scratch_dint: Option<String> = user_tags
        .iter()
        .find(|t| atomic_code(t) == Some(0x00C4) && looks_scratchable(&t.name))
        .map(|t| t.name.clone());

    // Drop the unconnected client — steps 7/8 use a fresh Class 3 client.
    client.close().await.ok();

    // 7) Class 3 explicit connection
    section(7, "Class 3 explicit connection");
    let t_c3 = Instant::now();
    let c3 = TagClient::builder(&host)
        .path(&path)
        .use_connected(true)
        .connect()
        .await;
    let mut c3 = match c3 {
        Ok(c) => {
            ok(&format!(
                "Class 3 opened in {:?}, class3_open = {}",
                t_c3.elapsed(),
                c.is_class3_open()
            ));
            c
        }
        Err(e) => {
            fail(&format!("Class 3 open: {e}"));
            return Ok(()); // rest of steps depend on Class 3
        }
    };
    if let Some(dint) = a_dint {
        match c3.read_tag(&dint.name).await {
            Ok(v) => ok(&format!("Class 3 read {} = {:?}", dint.name, v)),
            Err(e) => fail(&format!("Class 3 read: {e}")),
        }
    }
    c3.close().await.ok();

    // 8) Class 3 reopen-on-drop across a forced idle timeout
    section(8, "Class 3 reopen-on-drop");
    let mut c3r = TagClient::builder(&host)
        .path(&path)
        .use_connected(true)
        .reopen_on_drop(true)
        .connect()
        .await
        .context("reopen-on-drop connect")?;
    ok("opened Class 3 with reopen_on_drop = true");
    // Warm-up read to prove the connection is alive.
    if let Some(dint) = a_dint {
        match c3r.read_tag(&dint.name).await {
            Ok(v) => info(&format!("pre-idle read {} = {:?}", dint.name, v)),
            Err(e) => info(&format!("pre-idle read: {e}")),
        }
    }
    // The Class 3 RPI is 2.5 s and Logix drops the connection at
    // ~4× the RPI without traffic. Sleep 12 s to guarantee the peer
    // has torn it down.
    info("sleeping 12 s to let the peer drop the Class 3 connection...");
    tokio::time::sleep(Duration::from_secs(12)).await;
    if let Some(dint) = a_dint {
        let t_reopen = Instant::now();
        match c3r.read_tag(&dint.name).await {
            Ok(v) => ok(&format!(
                "post-idle read {} = {:?} in {:?} (reopen worked)",
                dint.name,
                v,
                t_reopen.elapsed()
            )),
            Err(e) => fail(&format!("post-idle read: {e}")),
        }
        info(&format!("class3_open after retry = {}", c3r.is_class3_open()));
    }
    c3r.close().await.ok();

    // 9) write + verify
    section(9, "write + verify");
    if let Some(name) = scratch_dint.as_ref() {
        let mut wc = TagClient::builder(&host)
            .path(&path)
            .connect()
            .await
            .context("write connect")?;
        let before = wc.read_tag(name).await.context("read-before")?;
        ok(&format!("before: {name} = {:?}", before));
        let TagValue::Dint(v_before) = before else {
            fail("scratch tag not a DINT after all — skipping write");
            wc.close().await.ok();
            return Ok(());
        };
        // Round-trip: write the same value back, then a distinctive value,
        // then restore. Never leave the tag changed.
        let probe = v_before.wrapping_add(1);
        wc.write_tag(name, &TagValue::Dint(probe))
            .await
            .context("write probe")?;
        let mid = wc.read_tag(name).await.context("read after probe")?;
        match mid {
            TagValue::Dint(v) if v == probe => ok(&format!("wrote probe {} and read back {}", probe, v)),
            other => fail(&format!("probe mismatch: expected {} got {:?}", probe, other)),
        }
        wc.write_tag(name, &TagValue::Dint(v_before))
            .await
            .context("write restore")?;
        let after = wc.read_tag(name).await.context("read after restore")?;
        match after {
            TagValue::Dint(v) if v == v_before => ok(&format!("restored {name} to {}", v)),
            other => fail(&format!("restore mismatch: expected {} got {:?}", v_before, other)),
        }
        wc.close().await.ok();
    } else {
        info("no obvious scratch DINT (name doesn't contain SCRATCH/TEST/TMP/DEBUG) — skipping write");
    }

    // 10) DIAGNOSTIC: no-cache re-run of the failing paths.
    //     Fresh unconnected client, NO browse → the atom cache stays
    //     empty → every read goes out as a pure ANSI symbolic segment
    //     (0x91 "name") instead of the cached bare instance segment
    //     (0x24 id). If the reads now succeed, the encode-with-cache
    //     shortcut is emitting a path form the controller won't route
    //     over Unconnected_Send.
    section(10, "DIAGNOSTIC — no-cache symbolic reads");
    let mut diag = TagClient::builder(&host)
        .path(&path)
        .connect()
        .await
        .context("diag connect")?;
    ok("connected without browsing → atom cache is empty");
    let probe_names: Vec<&str> = ["StopMolues", "StopComm", "TestModule:I"]
        .iter()
        .copied()
        .collect();
    for n in &probe_names {
        match diag.read_tag(n).await {
            Ok(v) => ok(&format!("symbolic read {n} = {:?}", v)),
            Err(e) => fail(&format!("symbolic read {n}: {e}")),
        }
    }
    // MSP with symbolic segments — proves the batch itself isn't broken.
    match diag.read_tags_batch(&probe_names).await {
        Ok(rs) => {
            let ok_n = rs.iter().filter(|r| r.is_ok()).count();
            ok(&format!(
                "symbolic MSP batch: {}/{} succeeded",
                ok_n,
                rs.len()
            ));
            for (n, r) in probe_names.iter().zip(rs.iter()) {
                match r {
                    Ok(v) => info(&format!("  {n} = {:?}", v)),
                    Err(e) => info(&format!("  {n}: {e}")),
                }
            }
        }
        Err(e) => fail(&format!("symbolic MSP batch: {e}")),
    }
    diag.close().await.ok();

    println!("\ndone.");
    Ok(())
}

fn atomic_code(t: &TagInfo) -> Option<u16> {
    let s = SymType(t.sym_type);
    if s.is_struct() {
        None
    } else {
        s.atomic_type_code()
    }
}

fn describe_sym(s: SymType) -> String {
    if s.is_struct() {
        let dims = s.array_dims();
        let id = s.template_id().unwrap();
        if dims == 0 {
            format!("struct(template_id=0x{:03X})", id)
        } else {
            format!("struct[{}D](template_id=0x{:03X})", dims, id)
        }
    } else {
        let code = s.atomic_type_code().unwrap();
        let name = match code {
            0x00C1 => "BOOL",
            0x00C2 => "SINT",
            0x00C3 => "INT",
            0x00C4 => "DINT",
            0x00C5 => "LINT",
            0x00C6 => "USINT",
            0x00C7 => "UINT",
            0x00C8 => "UDINT",
            0x00C9 => "ULINT",
            0x00CA => "REAL",
            0x00CB => "LREAL",
            _ => "atomic",
        };
        let dims = s.array_dims();
        if dims == 0 {
            name.to_string()
        } else {
            format!("{name}[{}D]", dims)
        }
    }
}

fn is_internal(name: &str) -> bool {
    name.starts_with("__")
        || name.starts_with("Map:")
        || name.starts_with("Task:")
        || name.starts_with("Program:")
        || name.starts_with("UDI:")
        || name.starts_with("Routine:")
        || name.starts_with("AddOnInstructionDefinition:")
        || name.starts_with("DataType:")
        || name.starts_with("Module:")
}

fn looks_scratchable(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    ["SCRATCH", "TEST", "TMP", "DEBUG"]
        .iter()
        .any(|k| up.contains(k))
}
