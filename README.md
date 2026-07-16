# EthernetIPRust

An idiomatic async Rust implementation of EtherNet/IP and CIP Safety, focused on communicating with Allen-Bradley Logix controllers and building interoperable **adapters** (targets / I/O slaves) and **scanners** (originators / I/O masters).

Sibling of [EthernetIPSharp](../EthernetIPSharp), [EthernetIPCpp](../EthernetIPCpp), and [EthernetIPPython](../EthernetIPPython). Same wire behavior, Rust API on top of tokio.

---

## Table of contents

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

**CIP Safety (originator and target)**
- CRC-S1, S2, S3, S4 (CRC-32), and S5 (24-bit) with PID/CID and rollover-folded seeds
- Base Format and Extended Format safety frames (short and long variants) — encode + decode
- Connection Parameter CRC (CPCRC) computation and patching into the safety segment
- Safety Network Segment parse/encode (target / router / extended formats)
- Time Coordination (TCOO) message — base-format encode with CRC-S3 and extended with CRC-S5
- Consumer-side target-timestamp rollover tracking (essential — the 16-bit safety timestamp wraps every ~8.4 s and CRC-S5 fails without this)
- Producer-side own-timestamp rollover tracking on the scanner, seeded from the safety segment's `InitialRolloverValue` so the target's validator stays in CRC-S5 sync across every wrap
- Safety Forward_Open builder with the assembly-shortcut connection path and app-reply parsing
- **Safety Supervisor Object (class 0x39)** on top of a pluggable `CipClass` / `CipDispatcher` framework — all eight standard attributes (State, Mode, SNN, Configuration Lock, SCID, CFUNID, TUNID, Output Owners) and the three commissioning services (`Safety_Reset` including type-2 Reset Ownership, `Propose_TUNID`, `Apply_TUNID`)
- Interop-tested against C#, both directions, over 3-minute soaks with 0 CRC failures across ~21 timestamp rollover boundaries

**Logix tag protocol**
- `Read_Tag` (0x4C), `Write_Tag` (0x4D), `Read_Tag_Fragmented` (0x52) — auto-falls-back to fragmented on `PARTIAL_TRANSFER` (0x06) or `REPLY_TOO_LARGE` (0x11)
- Tag browsing via `Get_Instance_Attribute_List` (0x55) with automatic partial-transfer chaining
- Array indexer syntax in tag names: `counts[3]`, `Temp[10].AnotherArray[4]`, Studio 5000 multi-dim `arr[1,2,3]`
- ControlLogix backplane routing via a libplctag-style `path` (e.g. `"1,0"` for backplane → slot 0) — every request gets wrapped in `Unconnected_Send` addressed to the Connection Manager
- Opt-in Class 3 connected explicit messaging (`use_connected(true)`) — opens a Forward_Open at `connect()` and rides `SendUnitData` for every subsequent request
- Instance-ID cache populated transparently by `browse_tags` so later reads emit a short Symbol Object logical instance segment instead of the full ANSI symbolic name
- `TagClient` for real PLCs; `TagServer` + `TagRegistry` for a Logix-style responder

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

- **`ethernetip-core`** — Pure wire types: encapsulation header, CPF envelope + items, CIP status codes + service codes + class ids, EPATH segment writer (`EpathWriter`), libplctag route-path parser, `EipSession` (tokio TCP client for `RegisterSession` / `SendRRData` / `SendUnitData`), and the CIP object framework (`cip::CipDispatcher` / `CipClass` / `CipInstance` / `CipAttribute` / `CipServiceDefinition` + standard `Get_Attribute_Single` / `Set_Attribute_Single` / `Get_Attributes_All` handlers) that classes like Safety Supervisor plug into. No I/O beyond that one client session.
- **`ethernetip-logix`** — Logix tag protocol on top of `EipSession`. `TagClient` for talking to a real PLC (browse, read, write, fragmented, Class 3, routing, instance cache). `TagServer` for hosting an in-memory `TagRegistry` and answering `Read_Tag` / `Write_Tag` / `Get_Instance_Attribute_List`.
- **`ethernetip-connections`** — Class 1 building blocks: `AssemblyRegistry` (thread-safe assembly store), EPIO codec (UDP CPF frames — no interface-handle prefix, CIP sequence at start of ConnectedData, optional 32-bit run/idle header O→T only), `ForwardOpenRequest` / `ForwardOpenResponse` / `ForwardCloseRequest` / `ForwardCloseResponse` codecs with typed `NetworkConnectionParameters`, plus a target-side `Adapter` and an originator-side `Scanner` handle.
- **`ethernetip-safety`** — CIP Safety: `crc` (S1-S5 with PID / rollover seed helpers), `types` (`ModeByte`, `SafetyNetworkNumber`, `SafetyConfigurationId`, `UniqueNetworkId`), `segment::SafetyNetworkSegment` codec, `cpcrc::compute_from_raw`, `frame_codec` (all four base / extended, short / long paths + TCOO), `forward_open::build_safety_forward_open`, `scanner::open_safety_scanner`, `adapter::start_safety_adapter`, `supervisor::SafetySupervisorObject` (class 0x39 on top of the CIP object framework — Reset Ownership / Propose / Apply TUNID).

---

## Project layout

```
crates/
  ethernetip-core/          Encapsulation, CPF, EPATH, EipSession — no higher-layer deps
  ethernetip-logix/         TagClient + TagServer + TagRegistry
  ethernetip-connections/   Class 1 building blocks + Scanner/Adapter
  ethernetip-safety/        CIP Safety CRCs, segment, frame codec, scanner, adapter

samples/
  logix-tag-read/           Reads a tag from a live PLC or the logix-host sample
  logix-host/               Tiny Logix-style tag server (hosts DINT/REAL/INT[]/STRUCT tags)
  echo-adapter/             Non-safety adapter — mirrors the C++/Python/C# echo module
  echo-scanner/             Non-safety scanner — pairs with echo-adapter
  safety-adapter/           Safety adapter — decodes O→T with rollover tracking, emits TCOO
  safety-scanner/           Safety scanner (server direction) — produces O→T safety frames

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

### Logix tag client

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

Six runnable binaries under `samples/`. Each one has a header comment block listing the CLI options.

| Sample | Role | Safety | Brief |
|---|---|---|---|
| `logix-tag-read` | Client | No | Browse + read a Logix tag by name (fragmented for structs, Class 3 optional) |
| `logix-host` | Target | No | Tiny Logix-style tag server — hosts DINT / REAL / INT[10] / STRUCT tags |
| `echo-adapter` | Target | No | Generic-Ethernet-Module adapter — 100/102/105 assemblies, seeded 1..125 ramp |
| `echo-scanner` | Scanner | No | Class 1 scanner — pairs with `echo-adapter` |
| `safety-adapter` | Target | Yes | Safety adapter — rollover-aware CRC verification and TCOO producer |
| `safety-scanner` | Scanner | Yes | Safety scanner (server direction) — produces O→T safety frames |

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

# Run the unit test suite (57 tests across all crates as of the initial cut)
cargo test

# Run one crate's tests
cargo test -p ethernetip-safety
```

Requirements: Rust 1.75+ (2021 edition), tokio runtime.

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
| `cip::ReplyHeader` | Message Router reply prefix parser (service | reply flag, general status, extended status). |
| `cip::service_codes`, `cip::class_codes`, `cip::status` | Const modules with well-known service / class / status codes. |
| `cip::CipDispatcher` | Registry + router for CIP object requests — resolves `class → instance → service → handler`. Locked internally so it can be shared across sessions via `Arc`. |
| `cip::CipClass`, `cip::CipInstance`, `cip::CipAttribute`, `cip::AttributeAccess`, `cip::CipDataType` | Object framework primitives — pluggable class definitions with instances, typed attributes, and per-attribute access flags. |
| `cip::CipServiceDefinition`, `cip::CipServiceHandler`, `cip::CipServiceRequest`, `cip::CipServiceResponse` | Service dispatch types — handlers close over any state they need and are registered per class at class- or instance-level. |
| `cip::CipPath` | Message Router request path parser (class / instance / attribute / member logical segments; skips port + electronic-key + symbolic segments). |
| `cip::standard_services` | Ready-made `Get_Attribute_Single` / `Set_Attribute_Single` / `Get_Attributes_All` handlers, auto-registered by `CipClass::new` / `add_standard_instance_services`. |
| `EipError` | Central error type — I/O, EIP encapsulation status, CIP general status + extended, short buffer, protocol violation. |

### `ethernetip-logix`

| Type | What it is |
|---|---|
| `TagClient` | Async tag client. Accepts an optional libplctag-style routing `path` and a `use_connected` flag for Class 3 connected explicit messaging. `browse_tags` populates an internal Symbol-Object instance-ID cache that shortens every later tag path. |
| `TagClientBuilder` | Builder used by `TagClient::builder`. |
| `AtomCache` | The instance-ID cache — controller-scope and program-scope maps. |
| `TagServer`, `start_tag_server`, `TagServerConfig` | TCP listener that answers `Read_Tag` / `Write_Tag` / `Read_Tag_Fragmented` / `Get_Instance_Attribute_List` against a `TagRegistry`. Transparently unwraps `Unconnected_Send`-wrapped requests. |
| `TagRegistry`, `TagEntry` | Thread-safe in-memory tag store indexed by both name and Symbol Object instance id. |
| `TagValue`, `CipType` | Tag value enum + wire-format type codes. |
| `TagInfo`, `TagCategory` | Browse result — instance id, name, sym_type, controller / program scope. |

### `ethernetip-connections`

| Type | What it is |
|---|---|
| `AssemblyRegistry`, `Assembly`, `AssemblyKind` | Thread-safe in-memory assembly store shared between scanner/adapter and their I/O tasks. Duplicate-instance registration is rejected up front. |
| `epio::Frame`, `epio::encode_frame`, `epio::decode_frame` | UDP EPIO frame with CIP Class 1 sequence count, optional 32-bit run/idle header, and Sequenced Address / Connected Data items. |
| `ForwardOpenRequest` / `ForwardOpenResponse` / `ForwardCloseRequest` / `ForwardCloseResponse` | Symmetric encode + decode for both sides of a Class 1 connection. |
| `NetworkConnectionParameters` | Typed 16-bit params (priority, connection type, size, variable/fixed). |
| `TransportClass`, `TriggerType` | Transport-class byte helpers. |
| `Adapter`, `AdapterConfig`, `start_adapter`, `AdapterHandle` | Target-side FO acceptor + EPIO consumer + T→O producer (on an ephemeral send socket to avoid Windows loopback quirks). |
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
| `open_safety_scanner`, `SafetyScannerConfig`, `SafetyScannerConnection` | Safety scanner (server direction — we produce O→T safety data). |
| `start_safety_adapter`, `SafetyAdapterConfig`, `SafetyAdapterHandle` | Safety adapter with target-timestamp rollover tracking and a TCOO producer. Accepts an optional `CipDispatcher` so registered classes (Safety Supervisor, ...) handle their own Message Router services. |
| `SafetySupervisorObject`, `SafetySupervisorState`, `SafetySupervisorMode` | CIP Safety Supervisor Object (class 0x39). Owns state / mode / SNN / TUNID / SCID; registers 8 attrs and 3 services (Safety_Reset with Reset Ownership, Propose_TUNID, Apply_TUNID). Hand its `CipClass` to a dispatcher via `into_cip_class()`; push post-registration state transitions with `sync_to_dispatcher()`. |

---

## CIP services supported

| Service | Code | Description |
|---|---|---|
| Get Instance Attribute List | 0x55 | Browse tags / instances (paginated) — client + server |
| Read Tag | 0x4C | Read tag data (symbolic or instance ID) — client + server |
| Write Tag | 0x4D | Write tag data — client + server |
| Read Tag Fragmented | 0x52 | Chunked read for large tags — client + server (auto-fallback on client) |
| Forward Open | 0x54 | Establish I/O connection — scanner + adapter (Class 1 and Class 3) |
| Forward Close | 0x4E | Close I/O connection — scanner + adapter |
| Unconnected Send | 0x52 | Wraps every routed MR request — client-side only |

Not yet: `Multiple Service Packet` (0x0A), `Write Tag Fragmented` (0x53), `Get_Attribute_Single` (0x0E) for identity / TCP-IP-Interface / Ethernet-Link objects, `Large Forward Open` (0x5B).

---

## CIP Safety details

CIP Safety is a SIL-3-capable layer on top of standard EtherNet/IP. This library implements the wire-level pieces (CRCs, segment, CPCRC, frame codec, TCOO) plus a minimal originator (server direction: we produce O→T safety data) and a minimal target (accepts a safety FO, decodes O→T with rollover tracking, emits base-format TCOO).

**A "safety connection" is a pair of two underlying connections** — server and client — one in each direction for full bidirectional safety. The current Rust implementation covers the server side end-to-end and stubs the client side. The other three ports do both.

**Rollover tracking (consumer):** The consumer must track the target's 16-bit timestamp rollover *before* verifying the CRC, since the rollover count folds into the CRC-S5 seed. Missing a wrap turns into "CRC fails for every subsequent frame until reconnect". The Rust adapter's consumer peels the on-wire timestamp first, advances its rollover counter when the delta wraps (`delta < -0x4000`), and then decodes with the up-to-date seed.

**Rollover tracking (producer):** The scanner has the symmetric problem — it must fold its own outgoing rollover into the S5 seed on every produced frame, and it must snapshot both the timestamp and the rollover *before* advancing them so the wrap frame carries a consistent `(old_ts, old_rollover)` pair. Reading rollover after the bump would emit `(old_ts, new_rollover)` on the wrap boundary, which the consumer can't verify — one CRC failure per wrap. Both counters are seeded from the safety segment's `InitialTimestamp` / `InitialRolloverValue` so both ends agree from frame 1.

**Safety Supervisor Object (class 0x39):** implemented on the new pluggable object framework in `ethernetip_core::cip`. Instance 1 carries the eight standard attributes (State, Mode, SNN, Configuration Lock, SCID, CFUNID, TUNID, Output Connection Point Owners) and the three commissioning services — `Safety_Reset` (0x54, with type 0 device / 1 factory / **2 Reset Ownership** clearing CFUNID + owner list + SCID + pending TUNID), `Propose_TUNID` (0x56), `Apply_TUNID` (0x57). The safety-adapter sample constructs one, registers it on a `CipDispatcher`, and hands the dispatcher to `SafetyAdapterConfig::dispatcher` — any Message Router request that isn't FORWARD_OPEN / FORWARD_CLOSE is routed through it.

**What's still stubbed:** The Safety Validator Object (class 0x3A) — per-connection instance state, per-connection PID / CID / rollover attributes, `Safety_Reset` at the connection level — is not implemented; the safety adapter continues to own the connection state directly rather than routing through a Validator instance.

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
| Rust Safety Supervisor (class 0x39) | unit-tested (14 tests, `Safety_Reset` incl. Reset Ownership + `Propose_TUNID` + `Apply_TUNID` + `Get_Attribute_Single` on 8 attrs) — not yet exercised over the wire against any other port or a live PLC |

The Rust ↔ C# gap was where the last round of wire-format bugs was found — see the [Known limitations](#known-limitations) section.

---

## Known limitations

- **Rust adapter → C# scanner T→O on Windows loopback** is not delivered even though the wire format is correct and `send_to` returns success. Likely a Windows-specific wildcard-bind quirk that would need Sockaddr Info CPF item hand-off to work around cleanly.
- **Safety scanner has server direction only** — target-produced T→O safety data + our TCOO reply lands as follow-up. C++ / C# / Python ports do both.
- **No CIP Safety Validator object (class 0x3A)** — the safety adapter still fakes the connection-instance state that a real Validator would own; `Get_Attribute_Single` against class 0x3A does not respond. The Safety Supervisor (class 0x39) *is* implemented on the new CIP object framework — see [CIP Safety details](#cip-safety-details).
- **CIP object framework only covers Safety Supervisor** — Identity (0x01), TCP/IP Interface (0xF5), Ethernet Link (0xF6), and Connection Manager (0x06) are still inlined into the adapter's request handler instead of being pluggable CIP objects on top of `ethernetip_core::cip::CipClass`.
- **No Multiple Service Packet (0x0A)** batching in the tag client.
- **No UDT template introspection** — struct reads return opaque bytes plus the type-CRC handle.
- **No reopen-on-drop** for Class 1 or Class 3 — connections that time out have to be reopened by the caller.
- **In-memory only** — assembly contents, tag values, and connection state don't survive restart.
- **Single-connection per session** on both the standard adapter and the safety adapter (extending is a matter of moving `active_conn_id: Option<u32>` to `HashMap<u32, _>`).

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
