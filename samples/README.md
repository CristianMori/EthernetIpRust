# EthernetIPRust Samples

Six runnable binaries that exercise the library as either an EtherNet/IP **adapter** (target / I/O slave) or a **scanner** (originator / I/O master), with and without CIP Safety, plus a Logix tag client and a Logix tag server.

| Sample | Role | Safety | What it does |
|---|---|---|---|
| [`logix-tag-read`](logix-tag-read/) | Client | No | Browses a Logix controller's tag list and reads one tag by name; auto-uses `Read_Tag_Fragmented` for structures |
| [`logix-host`](logix-host/) | Target | No | Tiny Logix-style tag server — hosts DINT / REAL / INT[10] / STRUCT tags and answers `Read_Tag` / `Write_Tag` / `Get_Instance_Attribute_List` |
| [`echo-adapter`](echo-adapter/) | Target | No | Generic-Ethernet-Module adapter — 100/102/105 assemblies, input 100 seeded with a 1..125 ramp |
| [`echo-scanner`](echo-scanner/) | Scanner | No | Class 1 scanner — pairs with `echo-adapter` for an end-to-end loopback |
| [`safety-adapter`](safety-adapter/) | Target | Yes | Safety adapter — accepts a safety Forward_Open, decodes O→T with target-timestamp rollover tracking, emits base-format TCOO |
| [`safety-scanner`](safety-scanner/) | Scanner | Yes | Safety scanner (server direction) — produces O→T safety frames with rollover-seeded CRCs |

## Running

All samples build in the workspace:

```sh
cargo build --release
```

Then run them with `cargo run --release -p <name> -- [args]` or invoke the built binary directly from `target/release/<name>[.exe]`. CLI options use `--key value` form — see the header comment block at the top of each `src/main.rs` for the full list.

```sh
# Logix tag client — points at a real PLC on the LAN
cargo run --release -p logix-tag-read -- 192.168.1.96 --tag rate
cargo run --release -p logix-tag-read -- 192.168.1.96 --no-path --tag temperature
cargo run --release -p logix-tag-read -- 192.168.1.96 --connected --tag Program:MainProgram.Framework

# Logix tag server — bind default 0.0.0.0:44818 with a preset tag catalog
cargo run --release -p logix-host

# Standard adapter — defaults match the C++/Python/C# echo modules
cargo run --release -p echo-adapter -- --tcp 0.0.0.0:44818 --udp 0.0.0.0:2222

# Standard scanner — default target is 127.0.0.1
cargo run --release -p echo-scanner -- --adapter 127.0.0.1:44818 --rpi-ms 20

# Safety adapter — accepts one safety FO, decodes O→T, emits TCOO
cargo run --release -p safety-adapter -- --tcp 0.0.0.0:44818 --udp 0.0.0.0:2222 --input-size 8

# Safety scanner (server direction) — sends O→T safety frames at RPI
cargo run --release -p safety-scanner -- --adapter 127.0.0.1:44818 --rpi-ms 50 --data-size 8

# Safety scanner with explicit TUNID + assembly instances — needed against
# adapters that validate the target's UNID (SNN+node) or that only register
# specific assembly instances. SNN parsing matches the C# convention: the
# visual form "4D90_0101_A35C" maps to bytes {5C, A3, 01, 01, 90, 4D}
# little-endian on the wire.
cargo run --release -p safety-scanner -- \
    --adapter 192.168.204.1:44818 --rpi-ms 50 --data-size 1 \
    --snn 4D90_0101_A35C --node 0xC0A8CC01 \
    --consumed 1 --produced 2 --config 197
```

## End-to-end loopback pairs

The scanners default their peer at `127.0.0.1`, so the pair of samples can be run on a single machine. UDP 2222 can only be bound once per IP on Windows, so the standard-adapter sample takes a `--peer-udp-port` override that lets scanner and adapter share a host by using different UDP ports for the two roles:

```sh
# Terminal 1: adapter receives O→T on 2222, sends T→O to 2223
cargo run --release -p echo-adapter -- --tcp 127.0.0.1:44818 --udp 0.0.0.0:2222 --peer-udp-port 2223

# Terminal 2: scanner receives T→O on 2223, sends O→T to 2222
cargo run --release -p echo-scanner -- --adapter 127.0.0.1:44818 --udp 0.0.0.0:2223 --rpi-ms 20
```

Same pattern for the safety pair:

```sh
# Terminal 1
cargo run --release -p safety-adapter -- --tcp 127.0.0.1:44818 --udp 0.0.0.0:2222 --peer-udp-port 2223 --input-size 8

# Terminal 2
cargo run --release -p safety-scanner -- --adapter 127.0.0.1:44818 --udp 0.0.0.0:2223 --peer-udp-port 2222 --rpi-ms 50 --data-size 8
```

## Logix tag client + server pair

`logix-host` hosts a fixed catalog of atomic and struct tags; `logix-tag-read` browses and reads. Both default to TCP 44818 so a single terminal pair works:

```sh
# Terminal 1
cargo run --release -p logix-host

# Terminal 2
cargo run --release -p logix-tag-read -- 127.0.0.1 --no-path --tag rate
```

`logix-tag-read` also works against a real ControlLogix (with a `--path` for backplane routing) and against a CompactLogix / EN-hosted symbol service (with `--no-path`).

## What you need on the other end

- **`logix-tag-read`** — A real Allen-Bradley PLC on the LAN, or the bundled `logix-host` sample. For a routed ControlLogix use `--path 1,0` (backplane, slot 0); for direct connect use `--no-path`.
- **`logix-host`** — Any Logix-style client. `logix-tag-read` is the natural pair; pycomm3, RSLogix MSG instructions, and pyeeip also work against it.
- **`echo-adapter`** — Any EtherNet/IP scanner. In Studio 5000, add the adapter as a "Generic Ethernet Module" with Data-DINT format, Input Assembly = 100 (size 125), Output Assembly = 102 (size 124), Config = 105 (size 10). The defaults match.
- **`echo-scanner`** — Any Class 1 adapter (this repo's `echo-adapter`, the C#/C++/Python echo modules, or a real device configured to expose Class 1 assemblies).
- **`safety-adapter`** — A safety scanner (this repo's `safety-scanner`, the C# `SampleSafetyScanner`, or a real ControlLogix with a safety I/O module configured to target this adapter's IP + SNN + electronic key + SCID). Verified against the C# scanner over a 3-min soak (~9000 frames, ~21 rollover boundaries, 0 CRC failures) — see the top-level [README](../README.md#interop-matrix) for the full status.
- **`safety-scanner`** — A safety adapter (this repo's `safety-adapter`, the C# `SafetyAdapterSample`, or a real 1734-IB8S once the Safety Validator objects land). Adapters that validate the target's UNID or that only expose specific assembly instances need `--snn` / `--node` / `--consumed` / `--produced` / `--config` overrides.
