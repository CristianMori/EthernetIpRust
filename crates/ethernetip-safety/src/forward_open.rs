//! Build a safety `Forward_Open` request body.
//!
//! The request looks like a normal Class 1 Forward_Open with a safety network
//! segment appended to the connection path. CPCRC is computed after the
//! segment is emitted with a zero placeholder, then patched back into the
//! serialized bytes.

use ethernetip_core::error::Result;

use crate::cpcrc;
use crate::frame_codec::wire_size;
use crate::segment::SafetyNetworkSegment;
use crate::types::{SafetyConfigurationId, SafetyFormat, UniqueNetworkId};

/// Standard Connection Manager path: class 0x06 instance 1.
pub const CM_PATH: [u8; 4] = [0x20, 0x06, 0x24, 0x01];

/// One direction of a safety connection.
#[derive(Debug, Clone)]
pub struct SafetyForwardOpenConfig {
    pub consumed_assembly: u32,
    pub produced_assembly: u32,
    pub config_assembly: u32,

    /// Application data size for the O→T direction (bytes, before safety framing).
    pub consumed_data_size: u16,
    /// Application data size for the T→O direction (bytes, before safety framing).
    pub produced_data_size: u16,

    /// Default RPI in microseconds; the per-direction fields override when non-zero.
    pub rpi_us: u32,
    pub o_to_t_rpi_us: u32,
    pub t_to_o_rpi_us: u32,

    pub format: SafetyFormat,

    pub tunid: UniqueNetworkId,
    pub ounid: UniqueNetworkId,
    pub scid: SafetyConfigurationId,

    pub ping_interval_multiplier: u16,
    pub time_coord_msg_min_multiplier: u16,
    pub network_time_expectation_multiplier: u16,
    pub timeout_multiplier: u8,
    pub max_fault_number: u16,

    pub initial_timestamp: u16,
    pub initial_rollover_value: u16,

    pub connection_timeout_multiplier: u8,
    pub priority_time_tick: u8,
    pub timeout_ticks: u8,

    /// Non-zero overrides the auto-computed wire size for that direction.
    pub o_to_t_connection_size: u16,
    pub t_to_o_connection_size: u16,
}

impl Default for SafetyForwardOpenConfig {
    fn default() -> Self {
        Self {
            consumed_assembly: 0,
            produced_assembly: 0,
            config_assembly: 0,
            consumed_data_size: 0,
            produced_data_size: 0,
            rpi_us: 10_000,
            o_to_t_rpi_us: 0,
            t_to_o_rpi_us: 0,
            format: SafetyFormat::Base,
            tunid: UniqueNetworkId::default(),
            ounid: UniqueNetworkId::default(),
            scid: SafetyConfigurationId::default(),
            ping_interval_multiplier: 100,
            time_coord_msg_min_multiplier: 50,
            network_time_expectation_multiplier: 200,
            timeout_multiplier: 2,
            max_fault_number: 2,
            initial_timestamp: 0xFFFF,
            initial_rollover_value: 0xFFFF,
            connection_timeout_multiplier: 1,
            priority_time_tick: 0x05,
            timeout_ticks: 156,
            o_to_t_connection_size: 0,
            t_to_o_connection_size: 0,
        }
    }
}

/// Built Forward_Open wire bytes ready for a Message Router send.
#[derive(Debug, Clone)]
pub struct SafetyForwardOpenWire {
    /// Full Forward_Open MR service data (priority/tick through end of path).
    pub service_data: Vec<u8>,
    /// CM request path (`{0x20, 0x06, 0x24, 0x01}`).
    pub cm_path: [u8; 4],
    /// Chosen O→T connection id (populated by the caller after target reply).
    pub t_to_o_connection_id: u32,
}

fn assembly_shortcut_path(cfg: &SafetyForwardOpenConfig) -> Vec<u8> {
    vec![
        0x20,
        0x04,
        0x24,
        (cfg.config_assembly & 0xFF) as u8,
        0x2C,
        (cfg.consumed_assembly & 0xFF) as u8,
        0x2C,
        (cfg.produced_assembly & 0xFF) as u8,
    ]
}

/// Build a safety Forward_Open. `transport_class_trigger` is 0xA0 for server
/// direction (target consumes O→T) or 0x20 for client direction (target
/// produces T→O). `route_prefix` is optional routing bytes that will NOT be
/// included in the CPCRC. `app_path`, if non-empty, replaces the standard
/// assembly shortcut (electronic key + assembly path); it IS covered by CPCRC.
pub fn build_safety_forward_open(
    cfg: &SafetyForwardOpenConfig,
    conn_serial: u16,
    orig_vendor: u16,
    orig_serial: u32,
    transport_class_trigger: u8,
    route_prefix: &[u8],
    app_path: &[u8],
) -> Result<SafetyForwardOpenWire> {
    let owned_app_path;
    let app_path_slice: &[u8] = if app_path.is_empty() {
        owned_app_path = assembly_shortcut_path(cfg);
        &owned_app_path
    } else {
        app_path
    };

    let is_extended = cfg.format == SafetyFormat::Extended;

    // Build the safety segment with cpcrc=0 (patched below).
    let seg = SafetyNetworkSegment {
        format: if is_extended { 0x02 } else { 0x00 },
        sccrc: cfg.scid.sccrc,
        scts: if cfg.scid.sccrc != 0 {
            cfg.scid.scts
        } else {
            Default::default()
        },
        time_correction_epi: 0,
        time_correction_params: 0,
        tunid: cfg.tunid,
        ounid: cfg.ounid,
        ping_interval_multiplier: cfg.ping_interval_multiplier,
        time_coord_msg_min_multiplier: cfg.time_coord_msg_min_multiplier,
        network_time_expectation_multiplier: cfg.network_time_expectation_multiplier,
        timeout_multiplier: cfg.timeout_multiplier,
        max_consumer_number: 1,
        max_fault_number: cfg.max_fault_number,
        cpcrc: 0,
        time_correction_connection_id: 0xFFFF_FFFF,
        initial_time_stamp: cfg.initial_timestamp,
        initial_rollover_value: cfg.initial_rollover_value,
    };
    let safety_seg = seg.to_bytes()?;

    // Assemble the connection path: route + app_path + safety segment.
    let mut conn_path =
        Vec::with_capacity(route_prefix.len() + app_path_slice.len() + safety_seg.len());
    conn_path.extend_from_slice(route_prefix);
    conn_path.extend_from_slice(app_path_slice);
    conn_path.extend_from_slice(&safety_seg);

    // Compute wire sizes.
    let ot_size = if cfg.o_to_t_connection_size != 0 {
        cfg.o_to_t_connection_size
    } else {
        wire_size(cfg.consumed_data_size as usize, cfg.format) as u16
    };
    let to_size = if cfg.t_to_o_connection_size != 0 {
        cfg.t_to_o_connection_size
    } else {
        wire_size(cfg.produced_data_size as usize, cfg.format) as u16
    };

    // P2P + High Priority + Fixed (safety requires these).
    let ot_params: u16 = 0x4400 | (ot_size & 0x01FF);
    let to_params: u16 = 0x4400 | (to_size & 0x01FF);

    let to_conn_id: u32 = 0x1000_0000 | conn_serial as u32;

    let ot_rpi = if cfg.o_to_t_rpi_us != 0 {
        cfg.o_to_t_rpi_us
    } else {
        cfg.rpi_us
    };
    let to_rpi = if cfg.t_to_o_rpi_us != 0 {
        cfg.t_to_o_rpi_us
    } else {
        cfg.rpi_us
    };

    // Assemble the Forward_Open service data.
    let mut fwd = vec![0u8; 36 + conn_path.len()];
    let mut off = 0;
    fwd[off] = cfg.priority_time_tick;
    off += 1;
    fwd[off] = cfg.timeout_ticks;
    off += 1;
    fwd[off..off + 4].copy_from_slice(&0u32.to_le_bytes()); // OT ID = 0 (target picks)
    off += 4;
    fwd[off..off + 4].copy_from_slice(&to_conn_id.to_le_bytes());
    off += 4;
    fwd[off..off + 2].copy_from_slice(&conn_serial.to_le_bytes());
    off += 2;
    fwd[off..off + 2].copy_from_slice(&orig_vendor.to_le_bytes());
    off += 2;
    fwd[off..off + 4].copy_from_slice(&orig_serial.to_le_bytes());
    off += 4;
    fwd[off] = cfg.connection_timeout_multiplier;
    off += 1;
    // 3 reserved bytes
    off += 3;
    fwd[off..off + 4].copy_from_slice(&ot_rpi.to_le_bytes());
    off += 4;
    fwd[off..off + 2].copy_from_slice(&ot_params.to_le_bytes());
    off += 2;
    fwd[off..off + 4].copy_from_slice(&to_rpi.to_le_bytes());
    off += 4;
    fwd[off..off + 2].copy_from_slice(&to_params.to_le_bytes());
    off += 2;
    fwd[off] = transport_class_trigger;
    off += 1;
    fwd[off] = (conn_path.len() / 2) as u8;
    off += 1;
    fwd[off..off + conn_path.len()].copy_from_slice(&conn_path);

    // Compute CPCRC and patch it into the safety segment bytes inside `fwd`.
    let safety_off_in_conn_path = route_prefix.len() + app_path_slice.len();
    let nsd_size = if is_extended { 50 } else { 48 };
    let nsd = &conn_path[safety_off_in_conn_path..safety_off_in_conn_path + nsd_size];
    let effective_path_size_words = ((app_path_slice.len() + safety_seg.len()) / 2) as u8;
    let cpcrc_value = cpcrc::compute_from_raw(&fwd, app_path_slice, nsd, effective_path_size_words)?;

    // CPCRC offset from the 0x50 segment byte: 48 (Base) or 50 (Extended).
    let cpcrc_abs = 36 + safety_off_in_conn_path + nsd_size;
    fwd[cpcrc_abs..cpcrc_abs + 4].copy_from_slice(&cpcrc_value.to_le_bytes());

    Ok(SafetyForwardOpenWire {
        service_data: fwd,
        cm_path: CM_PATH,
        t_to_o_connection_id: to_conn_id,
    })
}

/// Parsed safety application reply — the payload that comes back after the
/// standard Forward_Open reply header. Base (10 bytes) and Extended (14 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SafetyAppReply {
    pub consumer_number: u16,
    pub target_vendor_id: u16,
    pub target_device_serial: u32,
    pub target_connection_serial: u16,
    /// Extended format only.
    pub initial_timestamp: u16,
    /// Extended format only.
    pub initial_rollover_value: u16,
}

impl SafetyAppReply {
    pub fn parse(bytes: &[u8]) -> Self {
        let mut r = Self::default();
        if bytes.len() < 10 {
            return r;
        }
        r.consumer_number = u16::from_le_bytes([bytes[0], bytes[1]]);
        r.target_vendor_id = u16::from_le_bytes([bytes[2], bytes[3]]);
        r.target_device_serial =
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        r.target_connection_serial = u16::from_le_bytes([bytes[8], bytes[9]]);
        if bytes.len() >= 14 {
            r.initial_timestamp = u16::from_le_bytes([bytes[10], bytes[11]]);
            r.initial_rollover_value = u16::from_le_bytes([bytes[12], bytes[13]]);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SafetyNetworkNumber;

    fn cfg() -> SafetyForwardOpenConfig {
        SafetyForwardOpenConfig {
            consumed_assembly: 300,
            produced_assembly: 301,
            config_assembly: 302,
            consumed_data_size: 8,
            produced_data_size: 8,
            rpi_us: 10_000,
            format: SafetyFormat::Base,
            tunid: UniqueNetworkId {
                snn: SafetyNetworkNumber([1, 2, 3, 4, 5, 6]),
                node_address: 0xC0A8_0158,
            },
            ounid: UniqueNetworkId {
                snn: SafetyNetworkNumber([9, 8, 7, 6, 5, 4]),
                node_address: 0xC0A8_014A,
            },
            ..SafetyForwardOpenConfig::default()
        }
    }

    #[test]
    fn base_fo_builds_and_patches_cpcrc() {
        let wire = build_safety_forward_open(&cfg(), 0x0001, 0x0001, 0x1234_5678, 0xA0, &[], &[])
            .unwrap();
        assert_eq!(wire.cm_path, CM_PATH);
        // Segment starts after the 36-byte FO prefix + shortcut path (8 bytes) — no route.
        let seg_start = 36 + 8;
        // Segment sanity — leader 0x50, format 0x00, and CPCRC at offset 48.
        assert_eq!(wire.service_data[seg_start], 0x50);
        assert_eq!(wire.service_data[seg_start + 2], 0x00);
        let cpcrc_bytes = &wire.service_data[seg_start + 48..seg_start + 52];
        let cpcrc = u32::from_le_bytes(cpcrc_bytes.try_into().unwrap());
        assert_ne!(cpcrc, 0, "CPCRC must be non-zero after patch");
    }

    #[test]
    fn cpcrc_depends_on_app_path() {
        let a = build_safety_forward_open(&cfg(), 1, 1, 1, 0xA0, &[], &[]).unwrap();
        let mut cfg2 = cfg();
        cfg2.produced_assembly = 999;
        let b = build_safety_forward_open(&cfg2, 1, 1, 1, 0xA0, &[], &[]).unwrap();
        let seg_start = 36 + 8;
        assert_ne!(
            &a.service_data[seg_start + 48..seg_start + 52],
            &b.service_data[seg_start + 48..seg_start + 52]
        );
    }

    #[test]
    fn extended_layout_offsets() {
        let mut c = cfg();
        c.format = SafetyFormat::Extended;
        let wire = build_safety_forward_open(&c, 1, 1, 1, 0xA0, &[], &[]).unwrap();
        let seg_start = 36 + 8;
        assert_eq!(wire.service_data[seg_start + 2], 0x02, "extended format byte");
        // Extended CPCRC is at segment offset 50.
        let cpcrc_bytes = &wire.service_data[seg_start + 50..seg_start + 54];
        assert_ne!(u32::from_le_bytes(cpcrc_bytes.try_into().unwrap()), 0);
    }
}
