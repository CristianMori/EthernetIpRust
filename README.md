# EthernetIPRust

[![crates.io](https://img.shields.io/crates/v/ethernetip-core)](https://crates.io/crates/ethernetip-core)
[![Downloads](https://img.shields.io/crates/d/ethernetip-core)](https://crates.io/crates/ethernetip-core)
[![docs.rs](https://img.shields.io/docsrs/ethernetip-core)](https://docs.rs/ethernetip-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

An idiomatic async Rust implementation of EtherNet/IP and CIP Safety, focused on communicating with Allen-Bradley ControlLogix and CompactLogix controllers and on building interoperable **adapters** (targets / I/O slaves) and **scanners** (originators / I/O masters).

Sibling of [EthernetIpSharp](https://github.com/CristianMori/EthernetIpSharp), [EthernetIpCpp](https://github.com/CristianMori/EthernetIpCpp), and [EthernetIpPython](https://github.com/CristianMori/EthernetIpPython). Same wire behavior, Rust API on top of tokio.

This repository's workspace version is **0.2.0** (Rust 1.75+, edition 2021, Apache-2.0). `cargo add` installs the current crates.io release; the badges show that published version.

---

## Install

```sh
cargo add ethernetip-logix          # Logix tag client/server
cargo add ethernetip-connections    # Class 1 I/O adapter/scanner
cargo add ethernetip-safety         # CIP Safety
cargo add ethernetip-core           # encapsulation + CIP codecs
```

The quickstart uses `#[tokio::main]`, so the binary also needs `tokio` with the `macros` and `rt-multi-thread` features (the same runtime features this workspace enables):

```sh
cargo add tokio --features macros,rt-multi-thread
```

| Crate | What it is |
|---|---|
| [ethernetip-core](https://crates.io/crates/ethernetip-core) | EtherNet/IP encapsulation and CIP transport primitives |
| [ethernetip-logix](https://crates.io/crates/ethernetip-logix) | Allen-Bradley Logix tag client on top of ethernetip-core |
| [ethernetip-connections](https://crates.io/crates/ethernetip-connections) | EtherNet/IP Class 1 implicit I/O: assemblies, Forward_Open, EPIO framing |
| [ethernetip-safety](https://crates.io/crates/ethernetip-safety) | CIP Safety primitives, safety segment, safety frame codec, safety scanner/adapter |

API docs: [ethernetip-core](https://docs.rs/ethernetip-core), [ethernetip-logix](https://docs.rs/ethernetip-logix), [ethernetip-connections](https://docs.rs/ethernetip-connections), [ethernetip-safety](https://docs.rs/ethernetip-safety).

## 30-second quickstart

Reads tags from a controller that exposes the Logix symbol service on the address you connect to (CompactLogix, or any direct connection with no backplane hop). Tag names below are examples — use names that exist on your controller. For a ControlLogix CPU behind an Ethernet module, use the `path("1,0")` builder in [Logix tag client](#logix-tag-client). No PLC on the bench? Pair this with the [`logix-host`](samples/logix-host/) sample on `127.0.0.1` ([Samples](#samples)).

```rust
use ethernetip_logix::{Result, TagClient};

#[tokio::main]
async fn main() -> Result<()> {
    // CompactLogix or EN-hosted symbol service — no backplane route required.
    let mut client = TagClient::connect("192.168.1.96").await?;

    let value = client.read_tag("rate").await?;             // atomic
    let raw   = client.read_tag_raw("Framework", 1).await?; // struct (fragmented)

    // Array element access — Studio 5000 syntax works directly.
    let third = client.read_tag("counts[3]").await?;
    let nested = client.read_tag("Temp[10].AnotherArray[4]").await?;
    let multi = client.read_tag("matrix[1,2,3]").await?;

    // browse_tags populates an internal Symbol-Object instance-ID cache. After
    // this call every subsequent tag access uses the short instance segment
    // instead of the full ANSI symbolic name — no API change, just less wire.
    let tags = client.browse_tags().await?;

    println!("rate = {value:?}");
    println!("Framework = {} bytes, {} tags", raw.len(), tags.len());
    println!("counts[3] = {third:?}, nested = {nested:?}, matrix = {multi:?}");
    Ok(())
}
```

`TagValue` implements `Debug`. Routing, Class 3, writes, and the adapter/scanner setups are in [Quick start](#quick-start).

---

## Table of contents

- [Install](#install)
- [30-second quickstart](#30-second-quickstart)
- [Features](#features)
- [Architecture](#architecture)
- [Project layout](#project-layout)
- [Quick start](#quick-start)
  - [Standard adapter (Generic Ethernet Module)](#standard-adapter-generic-ethernet-module)
  - [CIP Safety adapter](#cip-safety-adapter)
  - [Standard I/O scanner](#standard-io-scanner)
  - [CIP Safety scanner](#cip-safety-scanner)
  - [Logix tag client](#logix-tag-client)
  - [Logix tag server](#logix-tag-server)
- [Samples](#samples)
- [Building and testing](#building-and-testing)
- [Library reference](#library-reference)
- [CIP services supported](#cip-services-supported)
- [CIP Safety details](#cip-safety-details)
- [Interop matrix](#interop-matrix)
- [Known limitations](#known-limitations)
- [Related projects](#related-projects)
- [License](#license)

---

## Features

**Standard EtherNet/IP**
- TCP encapsulation (port 44818) — `RegisterSession`, `SendRRData`, `SendUnitData`, `UnRegisterSession`
- UDP I/O transport (port 2222) — Class 1 implicit messaging
- `Forward_Open` / `Forward_Close` with typed request/response codecs
- 32-bit run/idle header handling on Class 1 O→T (per Generic Ethernet Module)
- CIP Class 1 sequence counter emitted / peeled per frame
- Dedicated tokio task per connection with `MissedTickBehavior::Skip` for jitter-tolerant RPI timing
- Opt-in CIP device classes on a `CipDispatcher`: Identity (0x01), Assembly (0x04), TCP/IP Interface (0xF5), and Ethernet Link (0xF6) in `ethernetip_core::device`, plus Connection Manager (0x06) in `ethernetip-connections`. The `echo-adapter` and `safety-adapter` samples register Identity, TCP/IP Interface, and Ethernet Link. With no dispatcher, the standard adapter answers `Forward_Open` / `Forward_Close` and returns `SERVICE_NOT_SUPPORTED` for every other Message Router service. `ethernetip-core`'s default `live-nic` feature fills Ethernet Link MAC and link speed from the host; disabling it falls back to a hardcoded MAC and 1 Gbps.

**CIP Safety (originator and target)**
- CRC-S1, S2, S3, S4 (CRC-32), and S5 (24-bit) with PID/CID and rollover-folded seeds
- Base Format and Extended Format safety frames (short and long variants) — encode + decode
- Connection Parameter CRC (CPCRC) computation and patching into the safety segment
- Safety Network Segment parse/encode (target / router / extended formats)
- Time Coordination (TCOO) message — base-format encode with CRC-S3 and extended with CRC-S5
- Consumer-side target-timestamp rollover tracking (essential — the 16-bit safety timestamp wraps every ~8.4 s and CRC-S5 fails without this)
- Producer-side own-timestamp rollover tracking on the scanner, seeded from the safety segment's `InitialRolloverValue` so the target's validator stays in CRC-S5 sync across every wrap
- Safety Forward_Open builder with the assembly-shortcut connection path and app-reply parsing
- Server direction by default (this process produces O→T safety data and listens for the target's TCOO). `SafetyScannerConfig::client` opens a second Forward_Open that consumes target-produced T→O safety data, tracks that timestamp's rollover before the CRC check, and sends a TCOO reply when `ping_count` changes. The [`safety-scanner`](samples/safety-scanner/) sample exposes this as `--client`.
- **Safety Supervisor Object (class 0x39)** on top of a pluggable `CipClass` / `CipDispatcher` framework — all eight standard attributes (State, Mode, SNN, Configuration Lock, SCID, CFUNID, TUNID, Output Owners) and the three commissioning services (`Safety_Reset` including type-2 Reset Ownership, `Propose_TUNID`, `Apply_TUNID`)
- **Safety Validator Object (class 0x3A)** — optional on the safety adapter via `SafetyAdapterConfig::validator`. Each accepted safety Forward_Open can get an instance, and that instance id becomes the `sv_inst` component of the target-side PID/CID seeds. Attribute 1 is validator state and attribute 2 is validator type. Runtime counters on `SafetyValidatorInstanceState` are not CIP attributes.
- Safety scanner (server direction) and safety adapter soaked against the C# port: 0 CRC failures over 3 minutes and ~21 timestamp rollovers. Those runs are the ones in the [interop matrix](#interop-matrix).

**Logix tag protocol**
- `Read_Tag` (0x4C), `Write_Tag` (0x4D), `Read_Tag_Fragmented` (0x52) — auto-falls-back to fragmented on `PARTIAL_TRANSFER` (0x06) or `REPLY_TOO_LARGE` (0x11)
- `write_tag` for a single atomic element. Structures go through `write_tag_raw` with a caller-built `type + count + data` body (`write_tag` returns a protocol error for `CipType::Struct`).
- `read_tags_batch` / `write_tags_batch` — one round-trip via Multiple Service Packet (0x0A). Each embedded service keeps its own status. A ControlLogix typically accepts about 500 bytes of embedded services before `REPLY_TOO_LARGE` on the batch as a whole.
- Tag browsing via `Get_Instance_Attribute_List` (0x55) with automatic partial-transfer chaining
- Array indexer syntax in tag names: `counts[3]`, `Temp[10].AnotherArray[4]`, Studio 5000 multi-dim `arr[1,2,3]`
- ControlLogix backplane routing via a libplctag-style `path` (e.g. `"1,0"` for backplane → slot 0) — every request gets wrapped in `Unconnected_Send` addressed to the Connection Manager
- Opt-in Class 3 connected explicit messaging (`use_connected(true)`) — opens a Forward_Open at `connect()` and rides `SendUnitData` for every subsequent request
- Opt-in `reopen_on_drop(true)` — on Class 3, a `CONNECTION_FAILURE` (0x01), `DEVICE_STATE_CONFLICT` (0x10), or an I/O error closes the connection, opens it again, and retries that request once. Off by default.
- Instance-ID cache populated transparently by `browse_tags` so later reads emit a short Symbol Object logical instance segment instead of the full ANSI symbolic name
- Template Object (class 0x6C) reads via `fetch_template`. `read_tag_typed` turns a structure into a named-field `TypedValue` after `browse_tags` (or `browse_program_tags`) has stored the tag's `sym_type`. `read_tag_typed_with_template` takes a template id you already know.
- `TagClient` for real PLCs; `TagServer` + `TagRegistry` for a Logix-style responder
- `EipSession::send_generic(service, class, instance, attribute, data, route)` — idiomatic CIP request wrapper with optional `Unconnected_Send` backplane routing

**Logix tag server (Studio-5000-compatible)**
- Full CIP Vol 1 §C-6.1 elementary type family — `CipType::Bool`, signed integers (`Sint`/`Int`/`Dint`/`Lint`), unsigned integers (`Usint`/`Uint`/`Udint`/`Ulint`), floats (`Real`/`Lreal`), and bit strings (`Byte`/`Word`/`Dword`/`Lword`)
- Program-scoped tags — a request path prefixed with `Program:Cell` resolves against that program's per-scope tag table
- Nested UDT templates via `ServerTemplate` + `TagRegistry::add_template` — pre-resolved layout registration for L5X exports (AOI backing structures with 32-per-DINT BOOL packing, STRING)
- Segment-aware path walker (`walker::walk`) — member drilling, element indexing, BOOL bit access; a request for `Motor.Timer.PRE`, `Motor.DN`, `Line[2].Speed`, `Matrix[1,2,3]` returns the right bytes and type
- Multi-dimensional arrays (`TagRegistry::add_multi_dim`) with row-major indexing and under-index detection
- DWORD-packed BOOL arrays (`add_array(_, Bool, 32)` occupies 4 bytes; `Flags[5]` addresses bit 5 of byte 0)
- `TagRegistry::atomic_set_bit` for concurrent-safe BOOL bit writes
- `set_by_name_silent`, `set_suppress_events`, `enable_dirty_tracking` / `drain_dirty` for the transpiler-generated scan hot path
- `persistence::save` / `load` — compact binary snapshot of every tag buffer, byte-for-byte compatible with the C#, Python, and C++ ports
- Documented tearing model: aligned scalar reads/writes are atomic on x86/x64; multi-scalar struct reads may tear (matches 1756 behavior)

**Diagnostics**
- Structured tracing via the `tracing` crate — set `RUST_LOG=debug` for per-request detail
- Public counters on connections (`tx_count`, `rx_count`, `rx_crc_fail`, `tcoo_count`, `consumer_active`)
- Heavy in-source comments explaining wire layouts, seed derivation, and rollover quirks

---

## Architecture

Four workspace crates with one-way dependencies:

```
                     ┌────────────────────────┐
                     │ ethernetip-core        │
                     │ (encap, CPF, EPATH,    │
                     │  EipSession)           │
                     └───────────┬────────────┘
                                 │
        ┌────────────────────────┼─────────────────────┐
        │                        │                     │
┌───────▼────────────┐  ┌────────▼───────────┐        │
│ ethernetip-logix   │  │ ethernetip-        │        │
│ (TagClient,        │  │ connections        │        │
│  TagServer,        │  │ (Assembly, EPIO,   │        │
│  TagRegistry)      │  │  Forward_Open,     │        │
└────────────────────┘  │  Scanner, Adapter) │        │
                        └────────┬───────────┘        │
                                 │                    │
                        ┌────────▼───────────┐        │
                        │ ethernetip-safety  │◄───────┘
                        │ (CRCs, segment,    │
                        │  frame codec, TCOO,│
                        │  safety scanner,   │
                        │  safety adapter)   │
                        └────────────────────┘
```

- **`ethernetip-core`** — Pure wire types: encapsulation header, CPF envelope + items, CIP status codes + service codes + class ids, EPATH segment writer (`EpathWriter`), libplctag route-path parser, `EipSession` (tokio TCP client for `RegisterSession` / `SendRRData` / `SendUnitData`), the CIP object framework (`cip::CipDispatcher` / `CipClass` / `CipInstance` / `CipAttribute` / `CipServiceDefinition` + standard `Get_Attribute_Single` / `Set_Attribute_Single` / `Get_Attributes_All` handlers), and the device classes in `device` (Identity, Assembly, TCP/IP Interface, Ethernet Link). No I/O beyond that one client session.
- **`ethernetip-logix`** — Logix tag protocol on top of `EipSession`. `TagClient` for talking to a real PLC (browse, read, write, fragmented, Multiple Service Packet batches, Template Object decode, Class 3, routing, instance cache, opt-in reopen). `TagServer` for hosting an in-memory `TagRegistry` and answering `Read_Tag` / `Write_Tag` / `Get_Instance_Attribute_List`.
- **`ethernetip-connections`** — Class 1 building blocks: `AssemblyRegistry` (thread-safe assembly store), EPIO codec (UDP CPF frames — no interface-handle prefix, CIP sequence at start of ConnectedData, optional 32-bit run/idle header O→T only), `ForwardOpenRequest` / `ForwardOpenResponse` / `ForwardCloseRequest` / `ForwardCloseResponse` codecs with typed `NetworkConnectionParameters`, a Connection Manager object (class 0x06), plus a target-side `Adapter` and an originator-side `Scanner` handle.
- **`ethernetip-safety`** — CIP Safety: `crc` (S1-S5 with PID / rollover seed helpers), `types` (`ModeByte`, `SafetyNetworkNumber`, `SafetyConfigurationId`, `UniqueNetworkId`), `segment::SafetyNetworkSegment` codec, `cpcrc::compute_from_raw`, `frame_codec` (all four base / extended, short / long paths + TCOO), `forward_open::build_safety_forward_open`, `scanner::open_safety_scanner` (server direction, plus an optional client-direction leg), `adapter::start_safety_adapter`, `supervisor::SafetySupervisorObject` (class 0x39), `validator::SafetyValidatorObject` (class 0x3A).

---

## Project layout

```
crates/
  ethernetip-core/          Encapsulation, CPF, EPATH, EipSession, CIP object framework, device classes
  ethernetip-logix/         TagClient + TagServer + TagRegistry
  ethernetip-connections/   Class 1 building blocks + Scanner/Adapter + Connection Manager
  ethernetip-safety/        CIP Safety CRCs, segment, frame codec, scanner, adapter, supervisor, validator

samples/
  logix-tag-read/           Reads a tag from a live PLC or the logix-host sample
  logix-verify/             One-session check of browse, atomics, UDT decode, MSP, Class 3, write-back
  logix-host/               Tiny Logix-style tag server (hosts DINT/REAL/INT[]/STRUCT tags)
  echo-adapter/             Non-safety adapter — mirrors the C++/Python/C# echo module
  echo-scanner/             Non-safety scanner — pairs with echo-adapter
  safety-adapter/           Safety adapter — decodes O→T with rollover tracking, emits TCOO
  safety-scanner/           Safety scanner — O→T producer; `--client` adds the T→O consumer leg

Cargo.toml                  Workspace with shared dependencies
LICENSE                     Apache-2.0
```

---

## Quick start

### Standard adapter (Generic Ethernet Module)

```rust
use std::net::SocketAddr;
use ethernetip_connections::{
    start_adapter, Assembly, AssemblyKind, AssemblyRegistry, AdapterConfig,
};

let assemblies = AssemblyRegistry::new();
assemblies.insert(Assembly::new(100, AssemblyKind::Input,  500))?; // T→O
assemblies.insert(Assembly::new(102, AssemblyKind::Output, 496))?; // O→T
assemblies.insert(Assembly::new(105, AssemblyKind::Config,  10))?;

let handle = start_adapter(
    AdapterConfig::new(assemblies.clone())
        .tcp_bind("0.0.0.0:44818".parse::<SocketAddr>()?)
        .udp_bind("0.0.0.0:2222".parse::<SocketAddr>()?),
)
.await?;

// Update produced data — the PLC sees this in its Input tag.
let ramp: Vec<u8> = (1..=125_i32).flat_map(|v| v.to_le_bytes()).collect();
assemblies.update(100, &ramp)?;

// Read what the PLC sent us.
let out = assemblies.read(102).unwrap_or_default();
```

### CIP Safety adapter

```rust
use ethernetip_safety::{
    start_safety_adapter, SafetyAdapterConfig, SafetyNetworkNumber, UniqueNetworkId,
};

// Node address = the target's IP packed BE as u32.
let tunid = UniqueNetworkId {
    snn: SafetyNetworkNumber([0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D]),
    node_address: 0xC0A80154,   // 192.168.1.84
};

let handle = start_safety_adapter(
    SafetyAdapterConfig::new(
        /* target_vendor */ 0x0001,
        /* target_serial */ 0xC0FFEE42,
        /* input_data_size */ 8,
    )
    .tunid(tunid),
)
.await?;

// input_data is populated by the consumer as valid frames arrive.
let input = handle.input_data.lock().await.clone();
```

### CIP Safety Supervisor (class 0x39) on the adapter

```rust
use std::sync::Arc;
use ethernetip_safety::{
    start_safety_adapter, CipDispatcher, SafetyAdapterConfig, SafetyNetworkNumber,
    SafetySupervisorObject,
};

// Build the Supervisor with our SNN + node address, then transition to
// Executing (Run) so the connection manager will accept safety FOs.
let mut supervisor = SafetySupervisorObject::new(
    SafetyNetworkNumber([0xC9, 0x12, 0xB4, 0x00, 0x8D, 0x4D]),
    0xC0A80154,
);
supervisor.start();

// Register the Supervisor's CipClass on a shared dispatcher. Any Message
// Router request that isn't FORWARD_OPEN / FORWARD_CLOSE — including
// Safety_Reset with reset_type = 2 (Reset Ownership) — flows through here.
let dispatcher = Arc::new(CipDispatcher::new());
dispatcher.register_class(supervisor.into_cip_class());

let handle = start_safety_adapter(
    SafetyAdapterConfig::new(0x0001, 0xC0FFEE42, /*input_size*/ 8)
        .dispatcher(dispatcher),
)
.await?;
```

### Standard I/O scanner

```rust
use ethernetip_connections::{
    open_scanner_connection, Assembly, AssemblyKind, AssemblyRegistry, ScannerConfig,
};

let assemblies = AssemblyRegistry::new();
assemblies.insert(Assembly::new(102, AssemblyKind::Output, 496))?; // O→T we write
assemblies.insert(Assembly::new(100, AssemblyKind::Input,  500))?; // T→O we read

let cfg = ScannerConfig::new(
    "192.168.1.84:44818".parse()?,
    assemblies.clone(),
    /*config*/ 105, /*ot_asm*/ 102, /*to_asm*/ 100,
    /*ot_size*/ 496, /*to_size*/ 500,
)
.rpi(10_000, 10_000);   // 10 ms

let conn = open_scanner_connection(cfg).await?;
// Write into the O→T assembly and it'll ship on the next tick:
assemblies.update(102, &[1, 2, 3, 4, /* ... */])?;
```

### CIP Safety scanner

```rust
use ethernetip_safety::{
    open_safety_scanner, SafetyForwardOpenConfig, SafetyScannerConfig,
};

let server = SafetyForwardOpenConfig {
    consumed_assembly: 300,
    produced_assembly: 301,
    config_assembly:   302,
    consumed_data_size: 8,
    produced_data_size: 8,
    rpi_us: 50_000,
    // TUNID / OUNID / SCID / initial timestamp go here — see the sample.
    ..SafetyForwardOpenConfig::default()
};

let cfg = SafetyScannerConfig::new("192.168.1.76:44818".parse()?, server)
    .originator(0x0001, 0x1234_5678);

let conn = open_safety_scanner(cfg).await?;
// Write into conn.output_data — the producer stamps it with the current
// mode byte / timestamp / rollover-seeded CRCs on every tick.
```

That opens the server direction (this process produces O→T). `SafetyScannerConfig::client(other_config)` adds the T→O consumer leg. The safety scanner binds an ephemeral UDP port by default and advertises it in a Sockaddr Info T→O item.

### Logix tag client

A complete `main` is in the [30-second quickstart](#30-second-quickstart). The same calls:

```rust
use ethernetip_logix::TagClient;

// CompactLogix or EN-hosted symbol service — no backplane route required.
let mut client = TagClient::connect("192.168.1.96").await?;

let value = client.read_tag("rate").await?;             // atomic
let raw   = client.read_tag_raw("Framework", 1).await?; // struct (fragmented)

// Array element access — Studio 5000 syntax works directly.
let third = client.read_tag("counts[3]").await?;
let nested = client.read_tag("Temp[10].AnotherArray[4]").await?;
let multi = client.read_tag("matrix[1,2,3]").await?;

// browse_tags populates an internal Symbol-Object instance-ID cache. After
// this call every subsequent tag access uses the short instance segment
// instead of the full ANSI symbolic name — no API change, just less wire.
let tags = client.browse_tags().await?;
```

For a **ControlLogix chassis** where the CPU is at a separate backplane slot, pass a libplctag-style route:

```rust
// Walk from a 1756-EN2T at .96 to the CPU at slot 0.
let mut client = TagClient::builder("192.168.1.96").path("1,0").connect().await?;
let rate = client.read_tag("rate").await?;
```

For hot polling loops, opt in to Class 3 connected explicit messaging. Every subsequent request rides `SendUnitData`; `close()` sends a proper `Forward_Close`.

```rust
let mut client = TagClient::builder("192.168.1.96")
    .path("1,0")
    .use_connected(true)
    .connect()
    .await?;
for _ in 0..10_000 {
    let _ = client.read_tag("rate").await?;
}
client.close().await?;
```

### Logix tag server

```rust
use ethernetip_logix::{start_tag_server, CipType, TagRegistry, TagServerConfig};

let registry = TagRegistry::new();
registry.add_atomic("rate", CipType::Dint)?;
registry.add_atomic("temperature", CipType::Real)?;
registry.add_array("counts", CipType::Int, 10)?;

registry.set_by_name("rate", &1500_i32.to_le_bytes())?;
registry.set_by_name("temperature", &72.5_f32.to_le_bytes())?;

let handle = start_tag_server(TagServerConfig::new(registry.clone())).await?;
```

---

## Samples

Seven runnable binaries under `samples/`. Each one has a header comment block listing the CLI options. `publish = false` on every sample — they are workspace members, not crates.io packages.

| Sample | Role | Safety | Brief |
|---|---|---|---|
| `logix-tag-read` | Client | No | Browse + read a Logix tag by name (fragmented for structs, Class 3 optional) |
| `logix-verify` | Client | No | One session against a live controller: browse, atomic reads, raw and typed struct reads, Multiple Service Packet, fragmented read, Class 3, Class 3 reopen-on-drop. The write step runs only for a DINT whose name contains `SCRATCH`, `TEST`, `TMP`, or `DEBUG`: it stores value+1, reads it back, then restores the original. |
| `logix-host` | Target | No | Tiny Logix-style tag server — hosts DINT / REAL / INT[10] / STRUCT tags |
| `echo-adapter` | Target | No | Generic-Ethernet-Module adapter — 100/102/105 assemblies, seeded 1..125 ramp |
| `echo-scanner` | Scanner | No | Class 1 scanner — pairs with `echo-adapter` |
| `safety-adapter` | Target | Yes | Safety adapter — rollover-aware CRC verification and TCOO producer |
| `safety-scanner` | Scanner | Yes | Safety scanner — produces O→T safety frames; `--client` also consumes T→O |

Run any sample with `cargo run --release -p <name> -- [args]`. Defaults are wired so `echo-scanner` can talk to `echo-adapter` on the same machine (adapter uses `--peer-udp-port` to keep the loopback pair from colliding on UDP 2222):

```sh
# Terminal 1
cargo run --release -p echo-adapter -- --tcp 127.0.0.1:44818 --udp 0.0.0.0:2222 --peer-udp-port 2223

# Terminal 2
cargo run --release -p echo-scanner -- --adapter 127.0.0.1:44818 --udp 0.0.0.0:2223 --rpi-ms 20
```

Same pattern for safety on top of `safety-adapter` + `safety-scanner`.

For a full sample overview see [`samples/README.md`](samples/README.md).

---

## Building and testing

```sh
# Build everything
cargo build --release

# Run the unit test suite
cargo test

# Run one crate's tests
cargo test -p ethernetip-safety
```

Requirements: Rust 1.75+ (2021 edition), tokio runtime. `ethernetip-core` defaults the `live-nic` feature on (optional `network-interface` crate; on Windows, `windows-sys` for `GetIfTable2` when that feature is enabled).

The test suite covers CIP path encoding + parsing (round-trips, array indexers, multi-dim, program scope, cache paths), Forward_Open request/response codecs, EPIO frame round-trips (with and without run/idle, CIP sequence roundtrip), safety CRC check values against the reference implementations (S1=0x4C, S2=0xBF, S3=0x9516 for "123456789"; S4=0x340BC6D9), safety frame codec round-trips for every (format, size) combination, safety segment round-trips (target / router / extended), and Forward_Open + CPCRC patching.

---

## Library reference

### `ethernetip-core`

| Type | What it is |
|---|---|
| `EipSession` | tokio TCP client that owns a `RegisterSession` handle and dispatches `SendRRData` / `SendUnitData`. |
| `encap::Header`, `encap::Command` | 24-byte encapsulation header + typed command codes. |
| `cpf::Envelope`, `cpf::Item`, `cpf::encode_envelope` | Common Packet Format envelope + items (used inside TCP CPF only — UDP EPIO omits the interface-handle / timeout prefix, see `ethernetip-connections::epio`). |
| `path::EpathWriter` | EPATH byte writer that handles symbolic segments, logical class/instance/attribute/element in 8/16/32-bit forms, and word-alignment padding. |
| `path::parse_route_path` | libplctag-style `"1,0"` port/link decoder. |
| `cip::ReplyHeader` | Message Router reply prefix parser (service \| reply flag, general status, extended status). |
| `cip::service_codes`, `cip::class_codes`, `cip::status` | Const modules with well-known service / class / status codes. |
| `cip::CipDispatcher` | Registry + router for CIP object requests — resolves `class → instance → service → handler`. Locked internally so it can be shared across sessions via `Arc`. |
| `cip::CipClass`, `cip::CipInstance`, `cip::CipAttribute`, `cip::AttributeAccess`, `cip::CipDataType` | Object framework primitives — pluggable class definitions with instances, typed attributes, and per-attribute access flags. |
| `cip::CipServiceDefinition`, `cip::CipServiceHandler`, `cip::CipServiceRequest`, `cip::CipServiceResponse` | Service dispatch types — handlers close over any state they need and are registered per class at class- or instance-level. |
| `cip::CipPath` | Message Router request path parser (class / instance / attribute / member logical segments; skips port + electronic-key + symbolic segments). |
| `cip::standard_services` | Ready-made `Get_Attribute_Single` / `Set_Attribute_Single` / `Get_Attributes_All` handlers. `CipClass::new` registers class-level `Get_Attribute_Single` and `Get_Attributes_All`. `add_standard_instance_services` registers all three at instance level; the device classes, Connection Manager, Safety Supervisor, and Safety Validator call it. |
| `device` | Identity (0x01), Assembly (0x04), TCP/IP Interface (0xF5), Ethernet Link (0xF6). Each `build(...)` helper returns a `CipClass` ready to `register_class` on a dispatcher. |
| `EipError` | Central error type — I/O, EIP encapsulation status, CIP general status + extended, short buffer, protocol violation. |

### `ethernetip-logix`

| Type | What it is |
|---|---|
| `TagClient` | Async tag client. Optional libplctag-style routing `path`, `use_connected` for Class 3, and `reopen_on_drop` for one Class 3 retry. `browse_tags` fills a Symbol-Object instance-ID cache. Also `write_tag` / `write_tag_raw`, `read_tags_batch` / `write_tags_batch`, `browse_program_tags`, `fetch_template`, `read_tag_typed`, and `read_tag_typed_with_template`. |
| `TagClientBuilder` | Builder used by `TagClient::builder`. |
| `AtomCache` | The instance-ID cache — controller-scope and program-scope maps. |
| `TagServer`, `start_tag_server`, `TagServerConfig` | TCP listener that answers `Read_Tag` / `Write_Tag` / `Read_Tag_Fragmented` / `Get_Instance_Attribute_List` against a `TagRegistry`. Transparently unwraps `Unconnected_Send`-wrapped requests. |
| `TagRegistry`, `TagEntry` | Thread-safe in-memory tag store indexed by both name and Symbol Object instance id. |
| `TagValue`, `CipType` | Tag value enum + wire-format type codes. `TagValue` is `Debug`; it has no `Display` impl. |
| `TypedValue`, `TemplateDefinition`, `SymType` | Named-field decode of a Template Object definition (`template` module). |
| `TagInfo`, `TagCategory` | Browse result — instance id, name, sym_type, controller / program scope. |

### `ethernetip-connections`

| Type | What it is |
|---|---|
| `AssemblyRegistry`, `Assembly`, `AssemblyKind` | Thread-safe in-memory assembly store shared between scanner/adapter and their I/O tasks. Duplicate-instance registration is rejected up front. |
| `epio::Frame`, `epio::encode_frame`, `epio::decode_frame` | UDP EPIO frame with CIP Class 1 sequence count, optional 32-bit run/idle header, and Sequenced Address / Connected Data items. |
| `ForwardOpenRequest` / `ForwardOpenResponse` / `ForwardCloseRequest` / `ForwardCloseResponse` | Symmetric encode + decode for both sides of a Class 1 connection. |
| `NetworkConnectionParameters` | Typed 16-bit params (priority, connection type, size, variable/fixed). |
| `TransportClass`, `TriggerType` | Transport-class byte helpers. |
| `ConnectionManagerObject` | Connection Manager (class 0x06) used by the adapter to own Forward_Open / Forward_Close rows. |
| `Adapter`, `AdapterConfig`, `start_adapter`, `AdapterHandle` | Target-side FO acceptor + EPIO consumer + T→O producer (on an ephemeral send socket to avoid Windows loopback quirks). One `active_conn_id` per TCP session. Optional `CipDispatcher`. Successful Forward_Open replies include a Sockaddr Info O→T item. |
| `Scanner`, `ScannerConfig`, `open_scanner_connection`, `ScannerConnection` | Originator-side Forward_Open + O→T producer + T→O consumer + clean Forward_Close on `close()`. |

### `ethernetip-safety`

| Type | What it is |
|---|---|
| `crc::compute_s1..s5`, `crc::compute_s5_raw` | The five safety CRCs with byte + u16 fast paths for S3. |
| `crc::pid_cid_seed_s1..s5`, `crc::pid_rollover_seed_s3` / `_s5` | PID/CID seed helpers and rollover folding. |
| `ModeByte`, `SafetyFormat`, `SafetyNetworkNumber`, `SafetyConfigurationId`, `UniqueNetworkId` | Strongly-typed safety identifiers. |
| `SafetyNetworkSegment`, `segment::SEGMENT_TYPE` | Forward_Open safety segment codec (target / router / extended). |
| `cpcrc::compute_from_raw` | CPCRC (CRC-S4) over the exact slice the target validator hashes. |
| `frame_codec::encode`, `frame_codec::decode`, `frame_codec::extract_timestamp`, `frame_codec::wire_size` | Base / extended, short / long safety data frame codec + rollover-aware timestamp peek. |
| `frame_codec::encode_time_coordination`, `frame_codec::encode_time_coordination_extended` | Base and extended TCOO reply encoders. |
| `build_safety_forward_open`, `SafetyForwardOpenConfig`, `SafetyAppReply` | Originator-side safety FO builder with CPCRC patching + reply parser. |
| `open_safety_scanner`, `SafetyScannerConfig`, `SafetyScannerConnection` | Safety scanner. Server direction produces O→T safety data. `SafetyScannerConfig::client` adds a T→O consumer and TCOO replies. `input_data` fills as valid client-leg frames arrive. |
| `start_safety_adapter`, `SafetyAdapterConfig`, `SafetyAdapterHandle` | Safety adapter with target-timestamp rollover tracking and a TCOO producer. Optional `CipDispatcher`, `SafetyValidatorObject`, and `SafetySupervisorObject`. Active safety connections are stored in a `HashMap` keyed by connection id. |
| `SafetySupervisorObject`, `SafetySupervisorState`, `SafetySupervisorMode` | CIP Safety Supervisor Object (class 0x39). Owns state / mode / SNN / TUNID / SCID; registers 8 attrs and 3 services (Safety_Reset with Reset Ownership, Propose_TUNID, Apply_TUNID). Hand its `CipClass` to a dispatcher via `into_cip_class()`; push post-registration state transitions with `sync_to_dispatcher()`. |
| `SafetyValidatorObject`, `SafetyValidatorState`, `SafetyValidatorInstanceState` | CIP Safety Validator Object (class 0x3A). Per-connection instances; state and type are `Get_Attribute_Single` attributes. Runtime counters stay off the CIP attribute set. |

---

## CIP services supported

| Service | Code | Description |
|---|---|---|
| Get Instance Attribute List | 0x55 | Browse tags / instances (paginated) — client + server |
| Read Tag | 0x4C | Read tag data (symbolic or instance ID) — client + server |
| Write Tag | 0x4D | Write tag data — client + server. `write_tag` covers one atomic element; structures use `write_tag_raw`. |
| Read Tag Fragmented | 0x52 | Chunked read for large tags — client + server (auto-fallback on client). Same numeric code as Unconnected Send; different object. |
| Multiple Service Packet | 0x0A | Batch embedded Read Tag / Write Tag services — `read_tags_batch` / `write_tags_batch` on the client |
| Forward Open | 0x54 | Establish I/O connection — scanner + adapter (Class 1 and Class 3) |
| Forward Close | 0x4E | Close I/O connection — scanner + adapter |
| Unconnected Send | 0x52 | Connection Manager service. Wraps every routed MR request — client-side only. Same numeric code as Read Tag Fragmented. |
| Get Attribute Single | 0x0E | Standard attribute read on any class registered with a `CipDispatcher` (Identity, TCP/IP Interface, Ethernet Link, Safety Supervisor, Safety Validator, …) |
| Set Attribute Single | 0x10 | Standard attribute write, when the attribute's access flags allow it |
| Get Attributes All | 0x01 | Standard all-attributes read, registered with the other two by `CipClass::add_standard_instance_services` |

Still absent from the codecs: `Write Tag Fragmented` (0x53) and `Large Forward Open` (0x5B). The numeric constants exist on `ethernetip_core::cip::service_codes`; nothing in the workspace builds those requests.

---

## CIP Safety details

CIP Safety is a SIL-3-capable layer on top of standard EtherNet/IP. This library implements the wire-level pieces (CRCs, segment, CPCRC, frame codec, TCOO) plus an originator and a target.

**A "safety connection" is a pair of two underlying connections** — server and client — one in each direction for full bidirectional safety. The scanner defaults to the server direction: it produces O→T safety data and treats T→O on that connection as the target's TCOO, which flips `consumer_active` so later produced frames leave the idle state. `SafetyScannerConfig::client` opens the other leg on the next `Forward_Open` (transport class/trigger `0x20`: the target produces T→O). That consumer peels the timestamp, advances its rollover count when the delta wraps (`delta < -0x4000`), then decodes, and it sends a TCOO reply when the target's ping count changes. `input_data` on `SafetyScannerConnection` is that client leg. The [interop matrix](#interop-matrix) records server-direction soaks.

**Rollover tracking (consumer):** The consumer must track the target's 16-bit timestamp rollover *before* verifying the CRC, since the rollover count folds into the CRC-S5 seed. Missing a wrap turns into "CRC fails for every subsequent frame until reconnect". The Rust adapter's consumer peels the on-wire timestamp first, advances its rollover counter when the delta wraps (`delta < -0x4000`), and then decodes with the up-to-date seed. The scanner's client leg does the same.

**Rollover tracking (producer):** The scanner has the symmetric problem — it must fold its own outgoing rollover into the S5 seed on every produced frame, and it must snapshot both the timestamp and the rollover *before* advancing them so the wrap frame carries a consistent `(old_ts, old_rollover)` pair. Reading rollover after the bump would emit `(old_ts, new_rollover)` on the wrap boundary, which the consumer can't verify — one CRC failure per wrap. Both counters are seeded from the safety segment's `InitialTimestamp` / `InitialRolloverValue` so both ends agree from frame 1.

**Safety Supervisor Object (class 0x39):** implemented on the pluggable object framework in `ethernetip_core::cip`. Instance 1 carries the eight standard attributes (State, Mode, SNN, Configuration Lock, SCID, CFUNID, TUNID, Output Connection Point Owners) and the three commissioning services — `Safety_Reset` (0x54, with type 0 device / 1 factory / **2 Reset Ownership** clearing CFUNID + owner list + SCID + pending TUNID), `Propose_TUNID` (0x56), `Apply_TUNID` (0x57). The safety-adapter sample constructs one, registers it on a `CipDispatcher`, and hands the dispatcher to `SafetyAdapterConfig::dispatcher` — any Message Router request that isn't FORWARD_OPEN / FORWARD_CLOSE is routed through it. `SafetyAdapterConfig::supervisor` can also take an `Arc<SafetySupervisorObject>` directly; the adapter calls `start()` on the first accepted Forward_Open and `reset()` when the last connection closes.

**Safety Validator Object (class 0x3A):** `SafetyValidatorObject` allocates one CIP instance per safety connection. Attribute 1 is the validator state (Idle / Executing / Faulted) and attribute 2 is the validator type. Install it with `SafetyAdapterConfig::validator` so the accepted Forward_Open's instance id is the `sv_inst` inside the target-side PID/CID seeds. The module is deliberately thin: CRC verification still runs on the adapter's own connection state, and the counters on `SafetyValidatorInstanceState` (`packets_produced`, `crc_errors`, and the rest) are not CIP attributes.

---

## Interop matrix

Only tested combinations are listed; blank means not attempted in the initial release.

| From ↓ / To → | Rust | C# | C++ | Python | Live PLC (192.168.1.96 ControlLogix) | Live 1734-IB8S |
|---|---|---|---|---|---|---|
| Rust TagClient | — | — | — | — | ✅ browse + DINT + UDT (fragmented) + Class 3 | — |
| Rust Scanner | ✅ | ✅ (both directions bit-exact) |  |  |  |  |
| Rust Adapter | ✅ | ⚠ O→T works, T→O not received on Windows loopback |  |  |  |  |
| Rust Safety scanner | ✅ (0 CRC fails) | ✅ (0 CRC fails over 3 min / ~21 rollovers) |  |  |  | — |
| Rust Safety adapter | ✅ (0 CRC fails) | ✅ (0 CRC fails over 3 min / ~21 rollovers, after upstream C# scanner rollover fix) |  |  |  |  |
| Rust Safety Supervisor (class 0x39) | unit-tested in `supervisor.rs` (`Get_Attribute_Single`, `Safety_Reset` including type 2 and an invalid type, `Propose_TUNID`, `Apply_TUNID`, state sync after register) — not yet exercised over the wire against any other port or a live PLC | | | | | |

The Rust ↔ C# gap was where the last round of wire-format bugs was found — see the [Known limitations](#known-limitations) section.

<!-- TODO: owner — refresh this matrix for Sockaddr Info, the safety scanner client leg (`SafetyScannerConfig::client`), Safety Validator (0x3A), and the device classes. Do not mark a cell until you have re-run it. -->

---

## Known limitations

- **Rust adapter → C# scanner T→O on Windows loopback**, as recorded in the interop matrix: T→O was not delivered even though the wire format was correct and `send_to` returned success. Adapters now attach a Sockaddr Info O→T item to a successful Forward_Open reply, and scanners advertise their UDP endpoint in Sockaddr Info T→O. The standard adapter still produces T→O from an ephemeral UDP socket.
<!-- TODO: owner — retest that Windows loopback pair and replace this bullet with the result. -->
- **Class 3 reopen is one retry, and only when you ask.** `TagClientBuilder::reopen_on_drop(true)` re-Forward_Opens after `CONNECTION_FAILURE` (0x01), `DEVICE_STATE_CONFLICT` (0x10), or an I/O error, then retries the request once. Class 1 scanner and adapter connections that time out stay down until the caller opens them again.
- **One Class 1 Forward_Open per TCP session on the standard adapter** (`active_conn_id: Option<u32>`). The safety adapter keeps active connections in a `HashMap<u32, ActiveConnection>`.
- **The standard adapter rejects `SendUnitData`.** Its session loop returns a protocol error for that encapsulation command. Class 3 explicit messaging lives on `TagClient`.
- **`write_tag` covers one atomic element.** Structures use `write_tag_raw`. There is no `Write Tag Fragmented` (0x53) client, and no `Large Forward Open` (0x5B) codec.
- **Safety Validator counters stay off the wire.** State and type answer `Get_Attribute_Single`. `packets_produced`, `crc_errors`, and the other fields on `SafetyValidatorInstanceState` are local only.
- **Assembly contents don't survive restart.** Tag values do — use `persistence::save` / `load` for a compact cross-port binary snapshot.
- **Client-direction safety soaks are not in the interop matrix.** The code path and the `safety-scanner --client` flag exist; the recorded C# soaks are the server direction.
<!-- TODO: owner — if you have soaked `SafetyScannerConfig::client` against another port or a live safety device, add that row. -->

---

## Related projects

Part of a family of open-source robotics / industrial-automation libraries by @CristianMori:

- **EtherNet/IP + CIP Safety:** [Python](https://github.com/CristianMori/EthernetIpPython) · [C#](https://github.com/CristianMori/EthernetIpSharp) · [Rust](https://github.com/CristianMori/EthernetIpRust) · [C++](https://github.com/CristianMori/EthernetIpCpp)
- **PLC tooling:** [MoriFixPlc](https://github.com/CristianMori/MoriFixPlc) (portable PLC HAL) · [EscaFlow](https://github.com/CristianMori/Mori.EscaFlow) (PLC transpiler)
- **ROS in pure C#:** [Mori.RosSharp](https://github.com/CristianMori/Mori.RosSharp) (ROS 1) · [Mori.Ros2Sharp](https://github.com/CristianMori/Mori.Ros2Sharp) (ROS 2)
- **Simulation & vision:** [GemelliStudio](https://github.com/CristianMori/GemelliStudio) · [LocateAnythingSharp](https://github.com/CristianMori/LocateAnythingSharp) · [Mori.SkyScope](https://github.com/CristianMori/Mori.SkyScope)
- **AI agents:** [Deckhand](https://github.com/CristianMori/DeckHand)

---

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.

```
Copyright 2026 Cristian Mori

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
