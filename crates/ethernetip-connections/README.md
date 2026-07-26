# ethernetip-connections

EtherNet/IP Class 1 (implicit / cyclic I/O) transport on top of
[`ethernetip-core`](https://crates.io/crates/ethernetip-core).

Covers the pieces you need to run either side of a Class 1 connection:

- **Forward_Open / Forward_Close / Unconnected_Send** encoders and
  decoders (Vol 1 spec-aligned).
- **Connection Manager object** (class 0x06) with real connection-table
  ownership and FO/FC delegation.
- **Connection-path parser** that handles Electronic Key (0x34),
  Simple Data Segment config payloads, Safety Network Segment, the
  standard Generic Ethernet Module path, safety FO layouts, and the
  Logix Emulate wrapper prefix.
- **Assembly registry** with shared byte buffers (bridgeable to CIP
  attributes so `Set_Attribute_Single` and the I/O producer read from
  the same bytes).
- **EPIO codec** for cyclic UDP frames.
- **Adapter** (`start_adapter`) and **scanner** (`open_scanner_connection`)
  wire-ready implementations.
- **Watchdog** that starts the connection-timeout timer on the first
  received frame (CIP Vol 1 §3-4.5.2), not at FO accept.

Verified live against ControlLogix hardware.

## Related crates

- [`ethernetip-core`](https://crates.io/crates/ethernetip-core)
- [`ethernetip-safety`](https://crates.io/crates/ethernetip-safety)
- [`ethernetip-logix`](https://crates.io/crates/ethernetip-logix)

## License

Apache-2.0.
