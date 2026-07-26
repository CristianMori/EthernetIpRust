# ethernetip-safety

CIP Safety on top of
[`ethernetip-core`](https://crates.io/crates/ethernetip-core) +
[`ethernetip-connections`](https://crates.io/crates/ethernetip-connections).

Covers the safety-plane pieces:

- **Base and Extended safety wire codec** with CRC-S1, CRC-S3,
  complement-CRC-S3, and CRC-S5. Rollover folded into the CRC-S5
  seed so 16-bit timestamp wraps at ~8.4 s don't invalidate frames.
- **CPCRC** (Configuration Path CRC) for safety Forward_Open
  validation.
- **Safety Network Segment** encode/decode (leader 0x50).
- **Safety Supervisor** (class 0x39) and **Safety Validator**
  (class 0x3A) object scaffolding.
- **Safety Forward_Open builder** — assembles the FO body + safety
  segment for an originator.
- **Safety adapter (target)** — accepts safety FOs, runs both
  server-role consumer (TCOO emission) and client-role producer
  (data emission) paths, drives Supervisor state Idle ↔ Executing
  from connection lifecycle.
- **Safety scanner (originator)** — opens safety connections,
  verifies incoming data against rollover-tracked seeds.

Verified live end-to-end against a ControlLogix on wired LAN.

## Related crates

- [`ethernetip-core`](https://crates.io/crates/ethernetip-core)
- [`ethernetip-connections`](https://crates.io/crates/ethernetip-connections)
- [`ethernetip-logix`](https://crates.io/crates/ethernetip-logix)

## License

Apache-2.0.
