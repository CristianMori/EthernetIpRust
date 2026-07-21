//! Parse the Forward_Open connection path — the application-path portion
//! of a Class 1 open that names the config, O→T, and T→O assemblies.
//!
//! Ported line-by-line from `EthernetIPSharp.Connections.ConnectionPathParser`
//! so the two libraries handle the same real-world PLC paths identically.
//! Handles:
//!
//!   * Standard Generic Ethernet Module: `20 04 24 xx 2C yy 2C zz`
//!     (Class Assembly + config instance + O→T conn point + T→O conn point).
//!   * Safety FO: three `20 04 24 xx` pairs and no connection points.
//!   * Electronic key segments (`0x34` fmt 4/5).
//!   * Port / data / network segments — skipped by their exact wire length.
//!   * Simple Data Segment (`0x80`) captured as the config-assembly payload.
//!   * Safety Network Segment (`0x50`) captured for the safety layer.
//!   * Logix Emulate wrapper (`21 00 FC 04 2C 01`) stripped from the head.
//!
//! Deliberately resilient — malformed / truncated paths still return
//! whatever was parsable so higher-level rejection logic can produce a
//! precise CIP error.

use crate::forward_open::ForwardOpenRequest;

/// Extracted assembly instances and payloads from a Forward_Open path.
///
/// Field semantics match the C# `ConnectionPathResult` — every `Option`
/// is `Some` only when the corresponding segment was found in the path.
#[derive(Debug, Default, Clone)]
pub struct ConnectionPathResult {
    /// Configuration assembly instance (typically Instance segment right
    /// after class 0x04). `None` when the path didn't carry one.
    pub config_assembly: Option<u32>,
    /// O→T assembly (scanner produces, adapter consumes).
    pub consumed_assembly: Option<u32>,
    /// T→O assembly (adapter produces, scanner consumes).
    pub produced_assembly: Option<u32>,
    /// True when a `0x34` Electronic Key segment was present.
    pub has_electronic_key: bool,
    /// Safety Network Segment (leader `0x50`) — full segment including
    /// the length byte, so a downstream safety layer can validate the
    /// TUNID / SCID directly.
    pub safety_segment: Option<Vec<u8>>,
    /// Bytes carried in a Simple Data Segment (`0x80`) — the Generic
    /// Ethernet Module contract uses this for the initial config
    /// assembly contents the originator wants pushed at open time.
    /// Empty when the segment isn't present.
    pub config_data: Vec<u8>,
}

/// Maximum connection-point / instance segments we bother remembering.
/// The largest real path we've seen carries 3 instances (safety FO).
const MAX_INSTANCE_IDS: usize = 8;
const MAX_CONNECTION_POINTS: usize = 4;

/// Parse a Forward_Open connection path.
///
/// The `request` parameter is used for the one-connection-point fallback
/// (some Generic Ethernet Modules carry a single conn point that names
/// both the O→T and T→O assemblies when only one direction is open).
pub fn parse(path: &[u8], request: &ForwardOpenRequest) -> ConnectionPathResult {
    // Strip the Logix Emulate wrapper `21 00 FC 04 2C 01` from the head
    // when present. Some originators prepend it before the real path;
    // stripping keeps the rest of the parser oblivious to the source.
    let path = if path.len() >= 6
        && path[0] == 0x21
        && path[1] == 0x00
        && path[2] == 0xFC
        && path[3] == 0x04
        && path[4] == 0x2C
        && path[5] == 0x01
    {
        &path[6..]
    } else {
        path
    };

    let mut result = ConnectionPathResult::default();
    let mut current_class: Option<u32> = None;
    let mut current_instance: Option<u32> = None;

    let mut connection_points: [u32; MAX_CONNECTION_POINTS] = [0; MAX_CONNECTION_POINTS];
    let mut conn_point_count = 0usize;
    let mut instance_ids: [u32; MAX_INSTANCE_IDS] = [0; MAX_INSTANCE_IDS];
    let mut instance_count = 0usize;

    let mut offset = 0usize;
    while offset < path.len() {
        let seg = path[offset];
        let seg_type = seg & 0xE0;

        // Electronic key `0x34` MUST be checked BEFORE the generic
        // Logical-Segment branch: `0x34 & 0xE0 == 0x20`, so a naive
        // seg_type dispatch treats it as an unknown Logical Segment
        // and mis-decodes the 8-byte key payload as further segments.
        // The C# reference has the same check-ordering bug — its
        // `hasKey` branch is unreachable in practice — but this port
        // fixes it so `has_electronic_key` is meaningful and the
        // 8-byte key is skipped atomically. Any real electronic-key
        // enforcement (non-zero vendor/device/prod bytes) would
        // silently break the C# parser; this branch order avoids
        // that.
        if seg == 0x34 {
            // Electronic key segment: [0x34] [fmt] [key bytes].
            // Format 4 and 5 both carry 8 bytes (vendor(2), dev_type(2),
            // prod_code(2), maj_rev(1), min_rev(1)).
            result.has_electronic_key = true;
            offset += 1;
            if offset >= path.len() {
                break;
            }
            let key_format = path[offset];
            offset += 1;
            let key_data_size = match key_format {
                4 | 5 => 8,
                _ => 0,
            };
            offset += key_data_size;
            continue;
        }

        if seg_type == 0x20 {
            // Logical segment.
            //   Bits [4:2] = logical type (0=Class, 1=Instance, 2=Member,
            //     3=Connection Point, 4=Attribute).
            //   Bits [1:0] = format (0=8-bit, 1=16-bit, 2=32-bit).
            let logical_type = seg & 0x1C;
            let format = seg & 0x03;
            offset += 1;

            let value: u32 = match format {
                0x00 => {
                    // 8-bit.
                    if offset >= path.len() {
                        break;
                    }
                    let v = path[offset] as u32;
                    offset += 1;
                    v
                }
                0x01 => {
                    // 16-bit — pad to word boundary before reading.
                    if offset % 2 != 0 {
                        offset += 1;
                    }
                    if offset + 2 > path.len() {
                        break;
                    }
                    let v = u16::from_le_bytes([path[offset], path[offset + 1]]) as u32;
                    offset += 2;
                    v
                }
                _ => {
                    // 32-bit (not seen in real GEM paths) — bail rather
                    // than fabricate an interpretation.
                    break;
                }
            };

            match logical_type {
                0x00 => {
                    // Class ID.
                    current_class = Some(value);
                }
                0x04 => {
                    // Instance ID.
                    current_instance = Some(value);
                    if instance_count < MAX_INSTANCE_IDS {
                        instance_ids[instance_count] = value;
                        instance_count += 1;
                    }
                }
                0x0C => {
                    // Connection Point (assembly instance for I/O paths).
                    if conn_point_count < MAX_CONNECTION_POINTS {
                        connection_points[conn_point_count] = value;
                        conn_point_count += 1;
                    }
                }
                0x10 => {
                    // Attribute ID — skip.
                }
                _ => {
                    // Unknown logical type — leave it, keep going.
                }
            }
        } else if seg_type == 0x00 {
            // Port segment.
            //   Short:    [port_id | 0x00] [link_addr]  (2 bytes)
            //   Extended: [port_id | 0x10] [link_len] [link_bytes] pad
            let extended = (seg & 0x10) != 0;
            offset += 1;
            if extended {
                if offset >= path.len() {
                    break;
                }
                let addr_size = path[offset] as usize;
                offset += 1;
                offset += addr_size;
                if offset % 2 != 0 {
                    offset += 1;
                }
            } else {
                if offset >= path.len() {
                    break;
                }
                offset += 1;
            }
        } else if seg_type == 0x80 {
            // Simple Data Segment `0x80` — carries the config assembly
            // payload the originator wants pushed at connect time. Not to
            // be confused with `0x91` (ANSI Extended Symbolic) which is a
            // symbolic-read tag path, never seen in a connection path.
            offset += 1;
            if offset >= path.len() {
                break;
            }
            let data_size_words = path[offset] as usize;
            offset += 1;
            let data_bytes = data_size_words * 2;
            if offset + data_bytes > path.len() {
                break;
            }
            result.config_data = path[offset..offset + data_bytes].to_vec();
            offset += data_bytes;
        } else if seg_type == 0x40 {
            // Network segment. `0x50` = Safety Network Segment; other
            // simple network segments in this range still carry a
            // word-count byte at offset+1.
            if seg == 0x50 {
                if offset + 1 >= path.len() {
                    break;
                }
                let seg_data_words = path[offset + 1] as usize;
                let seg_total_bytes = 2 + seg_data_words * 2;
                if offset + seg_total_bytes > path.len() {
                    break;
                }
                result.safety_segment =
                    Some(path[offset..offset + seg_total_bytes].to_vec());
                offset += seg_total_bytes;
            } else {
                offset += 1;
                if offset >= path.len() {
                    break;
                }
                let words = path[offset] as usize;
                offset += 1;
                offset += words * 2;
            }
        } else {
            // Unknown segment class — stop rather than risk misalignment.
            break;
        }
    }

    // Selection logic — same disambiguation the C# parser does.
    if current_class == Some(0x04) && conn_point_count >= 2 {
        // Standard Generic Ethernet Module: class 0x04 + config instance
        // + two connection points (O→T, T→O).
        result.config_assembly = current_instance;
        result.consumed_assembly = Some(connection_points[0]);
        result.produced_assembly = Some(connection_points[1]);
    } else if current_class == Some(0x04) && conn_point_count == 1 {
        // Half-open: only one direction has a real assembly. Which
        // direction gets it depends on which NetworkConnectionParameters
        // are non-null.
        result.config_assembly = current_instance;
        let o_null = request.o_to_t_params.connection_type == 0;
        let t_null = request.t_to_o_params.connection_type == 0;
        match (o_null, t_null) {
            (false, false) => {
                // Both directions want the same instance.
                result.consumed_assembly = Some(connection_points[0]);
                result.produced_assembly = Some(connection_points[0]);
            }
            (false, true) => {
                result.consumed_assembly = Some(connection_points[0]);
            }
            _ => {
                result.produced_assembly = Some(connection_points[0]);
            }
        }
    } else if current_class == Some(0x04) && conn_point_count == 0 && instance_count >= 3 {
        // Safety format: `20 04 24 <cfg> 20 04 24 <ot> 20 04 24 <to>`
        // — three class+instance pairs, no connection points.
        result.config_assembly = Some(instance_ids[0]);
        result.consumed_assembly = Some(instance_ids[1]);
        result.produced_assembly = Some(instance_ids[2]);
    } else if conn_point_count >= 2 {
        // No class 0x04 but two conn points — assume standard O→T / T→O
        // order. Rare in the wild but matches C# behavior.
        result.consumed_assembly = Some(connection_points[0]);
        result.produced_assembly = Some(connection_points[1]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward_open::NetworkConnectionParameters;

    fn dummy_request() -> ForwardOpenRequest {
        ForwardOpenRequest {
            priority_tick: 0,
            timeout_ticks: 0,
            o_to_t_connection_id: 0,
            t_to_o_connection_id: 0,
            connection_serial: 0,
            originator_vendor: 0,
            originator_serial: 0,
            connection_timeout_mult: 0,
            o_to_t_rpi_us: 0,
            o_to_t_params: NetworkConnectionParameters {
                redundant_owner: false,
                connection_type: 2, // P2P (non-null)
                priority: 0,
                variable_size: false,
                size: 0,
            },
            t_to_o_rpi_us: 0,
            t_to_o_params: NetworkConnectionParameters {
                redundant_owner: false,
                connection_type: 2,
                priority: 0,
                variable_size: false,
                size: 0,
            },
            transport_type: 0,
            connection_path: Vec::new(),
        }
    }

    #[test]
    fn parses_live_controllogix_gem_path() {
        // Real bytes captured from a ControlLogix at 192.168.1.96 pointing
        // at the echo-adapter's Generic Ethernet Module. Config=105,
        // consumed=102, produced=100, plus 5 words of zero config data.
        let path: &[u8] = &[
            0x34, 0x04, // Electronic Key, format 4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8 key bytes
            0x20, 0x04, // Class = Assembly
            0x24, 0x69, // Instance = 105 (config)
            0x2C, 0x66, // Conn point = 102 (O→T)
            0x2C, 0x64, // Conn point = 100 (T→O)
            0x80, 0x05, // Data segment, 5 words
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let r = parse(path, &dummy_request());
        assert!(r.has_electronic_key);
        assert_eq!(r.config_assembly, Some(105));
        assert_eq!(r.consumed_assembly, Some(102));
        assert_eq!(r.produced_assembly, Some(100));
        assert!(r.safety_segment.is_none());
        assert_eq!(r.config_data, vec![0u8; 10]);
    }

    #[test]
    fn strips_logix_emulate_wrapper() {
        // Wrapper: 21 00 FC 04 2C 01 followed by a normal GEM path.
        let mut path = vec![0x21, 0x00, 0xFC, 0x04, 0x2C, 0x01];
        path.extend_from_slice(&[
            0x20, 0x04, 0x24, 0x01, 0x2C, 0x02, 0x2C, 0x03,
        ]);
        let r = parse(&path, &dummy_request());
        assert_eq!(r.config_assembly, Some(1));
        assert_eq!(r.consumed_assembly, Some(2));
        assert_eq!(r.produced_assembly, Some(3));
    }

    #[test]
    fn safety_format_three_instance_pairs() {
        // Class 0x04 + 3 instance ids, no conn points.
        let path: &[u8] = &[
            0x20, 0x04, 0x24, 0x10, // class + inst 16 (config)
            0x20, 0x04, 0x24, 0x11, // class + inst 17 (O→T)
            0x20, 0x04, 0x24, 0x12, // class + inst 18 (T→O)
        ];
        let r = parse(path, &dummy_request());
        assert_eq!(r.config_assembly, Some(16));
        assert_eq!(r.consumed_assembly, Some(17));
        assert_eq!(r.produced_assembly, Some(18));
    }

    #[test]
    fn captures_safety_segment() {
        // `50 <words> <data...>` alongside a normal GEM path.
        let mut path = vec![
            0x34, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, // ekey
            0x50, 0x04, 1, 2, 3, 4, 5, 6, 7, 8,   // safety seg: 4 words
            0x20, 0x04, 0x24, 0x01, // class + inst
            0x2C, 0x02, 0x2C, 0x03, // two conn points
        ];
        let _ = path.len();
        let r = parse(&path, &dummy_request());
        assert_eq!(r.consumed_assembly, Some(2));
        assert_eq!(r.produced_assembly, Some(3));
        assert!(r.safety_segment.is_some());
        assert_eq!(r.safety_segment.as_ref().unwrap()[0], 0x50);
        assert_eq!(r.safety_segment.as_ref().unwrap().len(), 2 + 4 * 2);
    }

    #[test]
    fn empty_path_yields_all_none() {
        let r = parse(&[], &dummy_request());
        assert!(r.consumed_assembly.is_none());
        assert!(r.produced_assembly.is_none());
        assert!(r.config_assembly.is_none());
        assert!(!r.has_electronic_key);
    }

    #[test]
    fn one_conn_point_both_directions() {
        // Half-open where a single conn point serves both O→T and T→O.
        let path: &[u8] = &[
            0x20, 0x04, 0x24, 0x05, // class + config inst
            0x2C, 0x07,             // single conn point
        ];
        let mut req = dummy_request();
        // Both connection types non-null → both directions get the CP.
        req.o_to_t_params.connection_type = 2;
        req.t_to_o_params.connection_type = 2;
        let r = parse(path, &req);
        assert_eq!(r.consumed_assembly, Some(7));
        assert_eq!(r.produced_assembly, Some(7));
    }
}
