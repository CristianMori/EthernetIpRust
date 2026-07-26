# ethernetip-logix

Allen-Bradley Logix (ControlLogix / CompactLogix) tag client on top of
[`ethernetip-core`](https://crates.io/crates/ethernetip-core).

Speaks CIP over EtherNet/IP to a Logix controller:

- **`TagClient`** — connect, register, browse the Symbol Object list,
  read/write tags by name.
- **Symbol Object browse** with cursor-based pagination and
  program-scope enumeration (`Program:MainProgram.MyTag`).
- **Multiple Service Packet (0x0A)** — batched read/write in a single
  round-trip.
- **Class 3 explicit connections** with optional reopen-on-drop after
  an idle timeout.
- **Fragmented reads** for large structures and long strings.
- **UDT Template Object (class 0x6C) introspection** — fetch template
  metadata + definition and typed-decode a `TagValue::Struct` into
  named fields (recursive, nested-struct-aware).
- **Symbol path encoding** with Symbol Object class prefix on cached
  instance segments (required for `Unconnected_Send` reads to route).

Verified live against a ControlLogix.

## Related crates

- [`ethernetip-core`](https://crates.io/crates/ethernetip-core)
- [`ethernetip-connections`](https://crates.io/crates/ethernetip-connections)
- [`ethernetip-safety`](https://crates.io/crates/ethernetip-safety)

## License

Apache-2.0.
