# ethernetip-core

Core EtherNet/IP and CIP building blocks: encapsulation framing,
session handling, Common Packet Format, and a CIP object model
(class / instance / attribute / dispatcher) that higher layers plug
their own service handlers into.

Provides the low-level primitives every other crate in the
`ethernetip-*` family depends on. Register standard device objects
(Identity, TCP/IP Interface, Ethernet Link, Assembly) with
`device::*` builders; add your own class with `CipClass::new` + a
`CipDispatcher`.

## Features

- `live-nic` (default): probe the local NIC's MAC and TX link speed for
  the Ethernet Link CIP class. Disable with
  `default-features = false` to fall back to hardcoded MAC + 1 Gbps
  (useful for hermetic tests).

## Related crates

- [`ethernetip-connections`](https://crates.io/crates/ethernetip-connections)
  — Class 1 implicit I/O (Forward_Open, assemblies, EPIO codec, adapter/scanner).
- [`ethernetip-safety`](https://crates.io/crates/ethernetip-safety)
  — CIP Safety codec, supervisor/validator, safety adapter/scanner.
- [`ethernetip-logix`](https://crates.io/crates/ethernetip-logix)
  — Allen-Bradley Logix tag client (browse, read/write, UDT decode).

## License

Apache-2.0.
