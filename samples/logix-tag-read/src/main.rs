use std::env;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result};
use ethernetip_logix::{TagClient, TagValue};

fn usage() {
    eprintln!("usage: logix-tag-read <host> [--path 1,0] [--tag Name]");
    eprintln!("       (default host: 192.168.1.96, default path: 1,0)");
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(err) = run().await {
        eprintln!("error: {:#}", err);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<()> {
    let mut host = "192.168.1.96".to_string();
    let mut path = Some("1,0".to_string());
    let mut tag: Option<String> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                usage();
                return Ok(());
            }
            "--path" => {
                path = Some(
                    args.next()
                        .context("--path needs a value like `1,0`")?,
                );
            }
            "--no-path" => path = None,
            "--tag" => {
                tag = Some(args.next().context("--tag needs a value")?);
            }
            other if !other.starts_with("--") => host = other.to_string(),
            other => {
                usage();
                anyhow::bail!("unrecognized argument `{}`", other);
            }
        }
    }

    println!("Connecting to {host} (path = {:?}) ...", path);
    let started = Instant::now();
    let mut builder = TagClient::builder(host.clone());
    if let Some(p) = path.as_ref() {
        builder = builder.path(p.clone());
    }
    let mut client = builder.connect().await.context("connect failed")?;
    println!(
        "registered in {:?}, session handle 0x{:08X}",
        started.elapsed(),
        client.session_handle()
    );

    println!("\n--- browse_tags ---");
    let tags = client.browse_tags().await.context("browse failed")?;
    println!("discovered {} tags", tags.len());
    for entry in tags.iter().take(10) {
        println!(
            "  {:<32} instance=0x{:X} sym_type=0x{:04X} {:?}",
            entry.name, entry.instance_id, entry.sym_type, entry.category
        );
    }
    if tags.len() > 10 {
        println!("  ... ({} more)", tags.len() - 10);
    }

    if let Some(tag_name) = tag.as_deref() {
        println!("\n--- read_tag({tag_name}) ---");
        match client.read_tag(tag_name).await {
            Ok(v) => print_value(tag_name, &v),
            Err(e) => println!("read failed: {e}"),
        }
    } else if let Some(first_dint) = tags.iter().find(|t| t.sym_type & 0xFF == 0xC4) {
        println!(
            "\n--- auto-read first DINT tag: {} ---",
            first_dint.name
        );
        match client.read_tag(&first_dint.name).await {
            Ok(v) => print_value(&first_dint.name, &v),
            Err(e) => println!("read failed: {e}"),
        }
    }

    client.close().await.context("close failed")?;
    println!("\nclosed cleanly.");
    Ok(())
}

fn print_value(name: &str, v: &TagValue) {
    match v {
        TagValue::Bool(b) => println!("  {name} = {b}"),
        TagValue::Sint(x) => println!("  {name} = {x}i8"),
        TagValue::Int(x) => println!("  {name} = {x}i16"),
        TagValue::Dint(x) => println!("  {name} = {x}i32"),
        TagValue::Lint(x) => println!("  {name} = {x}i64"),
        TagValue::Usint(x) => println!("  {name} = {x}u8"),
        TagValue::Uint(x) => println!("  {name} = {x}u16"),
        TagValue::Udint(x) => println!("  {name} = {x}u32"),
        TagValue::Ulint(x) => println!("  {name} = {x}u64"),
        TagValue::Real(x) => println!("  {name} = {x}f32"),
        TagValue::Lreal(x) => println!("  {name} = {x}f64"),
        TagValue::Struct { crc, bytes } => {
            println!(
                "  {name} = struct(crc=0x{crc:04X}, {} bytes)",
                bytes.len()
            );
        }
    }
}
