//! Forward_Open and Forward_Close codecs.
//!
//! Both sides of a Class 1 connection setup need the same wire structure —
//! this module provides a symmetric `encode`/`decode` pair so a scanner can
//! build a request and an adapter can parse it, and vice versa for the
//! response. `Forward_Close` gets the same treatment.

use bytes::{Buf, BufMut, BytesMut};

use ethernetip_core::error::{EipError, Result};

/// Transport class byte (bit 7 = server/client, bits 3..0 = class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportClass {
    Class0,
    Class1,
    Class2,
    Class3,
}

impl TransportClass {
    pub fn as_u8(self, is_server: bool, trigger: TriggerType) -> u8 {
        let class_bits = match self {
            Self::Class0 => 0,
            Self::Class1 => 1,
            Self::Class2 => 2,
            Self::Class3 => 3,
        };
        let trigger_bits = match trigger {
            TriggerType::Cyclic => 0,
            TriggerType::ChangeOfState => 1,
            TriggerType::Application => 2,
        };
        (if is_server { 0x80 } else { 0x00 }) | (trigger_bits << 4) | class_bits
    }
}

/// Production trigger for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerType {
    Cyclic,
    ChangeOfState,
    Application,
}

/// 16-bit Network Connection Parameters (Vol 1 3-5.5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkConnectionParameters {
    pub redundant_owner: bool,
    /// 0 = Null, 1 = Multicast, 2 = Point-to-Point, 3 = Reserved.
    pub connection_type: u8,
    /// 0 = Low, 1 = High, 2 = Scheduled, 3 = Urgent.
    pub priority: u8,
    pub variable_size: bool,
    /// Size in bytes (max 511 for 16-bit form).
    pub size: u16,
}

impl NetworkConnectionParameters {
    pub fn encode(self) -> u16 {
        let mut v: u16 = self.size & 0x01FF;
        if self.variable_size {
            v |= 0x0200;
        }
        v |= (self.priority as u16 & 0x03) << 10;
        v |= (self.connection_type as u16 & 0x03) << 13;
        if self.redundant_owner {
            v |= 0x8000;
        }
        v
    }

    pub fn decode(raw: u16) -> Self {
        Self {
            size: raw & 0x01FF,
            variable_size: raw & 0x0200 != 0,
            priority: ((raw >> 10) & 0x03) as u8,
            connection_type: ((raw >> 13) & 0x03) as u8,
            redundant_owner: raw & 0x8000 != 0,
        }
    }
}

/// One encoded Forward_Open request body (without the `service` and path
/// bytes — those are added by the request builder).
#[derive(Debug, Clone)]
pub struct ForwardOpenRequest {
    pub priority_tick: u8,
    pub timeout_ticks: u8,
    pub o_to_t_connection_id: u32,
    pub t_to_o_connection_id: u32,
    pub connection_serial: u16,
    pub originator_vendor: u16,
    pub originator_serial: u32,
    /// Watchdog multiplier code (0..7 → ×4, ×8, ×16, ×32, ×64, ×128, ×256, ×512).
    pub connection_timeout_mult: u8,
    pub o_to_t_rpi_us: u32,
    pub o_to_t_params: NetworkConnectionParameters,
    pub t_to_o_rpi_us: u32,
    pub t_to_o_params: NetworkConnectionParameters,
    /// Encoded transport class byte (use `TransportClass::as_u8`).
    pub transport_type: u8,
    /// The connection application path (typically route bytes + assembly
    /// segments); the leading `path_size` byte is added by the encoder.
    pub connection_path: Vec<u8>,
}

impl ForwardOpenRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(36 + self.connection_path.len());
        buf.put_u8(self.priority_tick);
        buf.put_u8(self.timeout_ticks);
        buf.put_u32_le(self.o_to_t_connection_id);
        buf.put_u32_le(self.t_to_o_connection_id);
        buf.put_u16_le(self.connection_serial);
        buf.put_u16_le(self.originator_vendor);
        buf.put_u32_le(self.originator_serial);
        buf.put_u8(self.connection_timeout_mult);
        buf.put_slice(&[0, 0, 0]); // reserved
        buf.put_u32_le(self.o_to_t_rpi_us);
        buf.put_u16_le(self.o_to_t_params.encode());
        buf.put_u32_le(self.t_to_o_rpi_us);
        buf.put_u16_le(self.t_to_o_params.encode());
        buf.put_u8(self.transport_type);
        assert!(self.connection_path.len() % 2 == 0, "path must be word-aligned");
        buf.put_u8((self.connection_path.len() / 2) as u8);
        buf.put_slice(&self.connection_path);
        buf.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 36 {
            return Err(EipError::Short {
                expected: 36,
                actual: bytes.len(),
            });
        }
        let mut c = bytes;
        let priority_tick = c.get_u8();
        let timeout_ticks = c.get_u8();
        let o_to_t_connection_id = c.get_u32_le();
        let t_to_o_connection_id = c.get_u32_le();
        let connection_serial = c.get_u16_le();
        let originator_vendor = c.get_u16_le();
        let originator_serial = c.get_u32_le();
        let connection_timeout_mult = c.get_u8();
        c.advance(3); // reserved
        let o_to_t_rpi_us = c.get_u32_le();
        let o_to_t_params = NetworkConnectionParameters::decode(c.get_u16_le());
        let t_to_o_rpi_us = c.get_u32_le();
        let t_to_o_params = NetworkConnectionParameters::decode(c.get_u16_le());
        let transport_type = c.get_u8();
        let path_words = c.get_u8() as usize;
        let path_bytes = path_words * 2;
        if c.remaining() < path_bytes {
            return Err(EipError::Short {
                expected: path_bytes,
                actual: c.remaining(),
            });
        }
        let mut connection_path = vec![0u8; path_bytes];
        c.copy_to_slice(&mut connection_path);
        Ok(Self {
            priority_tick,
            timeout_ticks,
            o_to_t_connection_id,
            t_to_o_connection_id,
            connection_serial,
            originator_vendor,
            originator_serial,
            connection_timeout_mult,
            o_to_t_rpi_us,
            o_to_t_params,
            t_to_o_rpi_us,
            t_to_o_params,
            transport_type,
            connection_path,
        })
    }
}

/// Forward_Open success response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardOpenResponse {
    pub o_to_t_connection_id: u32,
    pub t_to_o_connection_id: u32,
    pub connection_serial: u16,
    pub originator_vendor: u16,
    pub originator_serial: u32,
    pub o_to_t_actual_rpi_us: u32,
    pub t_to_o_actual_rpi_us: u32,
    /// Optional application reply bytes (may be zero-length).
    pub app_reply: Vec<u8>,
}

impl ForwardOpenResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(26 + self.app_reply.len());
        buf.put_u32_le(self.o_to_t_connection_id);
        buf.put_u32_le(self.t_to_o_connection_id);
        buf.put_u16_le(self.connection_serial);
        buf.put_u16_le(self.originator_vendor);
        buf.put_u32_le(self.originator_serial);
        buf.put_u32_le(self.o_to_t_actual_rpi_us);
        buf.put_u32_le(self.t_to_o_actual_rpi_us);
        assert!(self.app_reply.len() % 2 == 0, "app_reply must be word-aligned");
        buf.put_u8((self.app_reply.len() / 2) as u8);
        buf.put_u8(0);
        buf.put_slice(&self.app_reply);
        buf.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 26 {
            return Err(EipError::Short {
                expected: 26,
                actual: bytes.len(),
            });
        }
        let mut c = bytes;
        let o_to_t_connection_id = c.get_u32_le();
        let t_to_o_connection_id = c.get_u32_le();
        let connection_serial = c.get_u16_le();
        let originator_vendor = c.get_u16_le();
        let originator_serial = c.get_u32_le();
        let o_to_t_actual_rpi_us = c.get_u32_le();
        let t_to_o_actual_rpi_us = c.get_u32_le();
        let reply_size_words = c.get_u8() as usize;
        c.advance(1); // reserved
        let reply_bytes = reply_size_words * 2;
        if c.remaining() < reply_bytes {
            return Err(EipError::Short {
                expected: reply_bytes,
                actual: c.remaining(),
            });
        }
        let mut app_reply = vec![0u8; reply_bytes];
        c.copy_to_slice(&mut app_reply);
        Ok(Self {
            o_to_t_connection_id,
            t_to_o_connection_id,
            connection_serial,
            originator_vendor,
            originator_serial,
            o_to_t_actual_rpi_us,
            t_to_o_actual_rpi_us,
            app_reply,
        })
    }
}

/// Forward_Close request body.
#[derive(Debug, Clone)]
pub struct ForwardCloseRequest {
    pub priority_tick: u8,
    pub timeout_ticks: u8,
    pub connection_serial: u16,
    pub originator_vendor: u16,
    pub originator_serial: u32,
    pub connection_path: Vec<u8>,
}

impl ForwardCloseRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(12 + self.connection_path.len());
        buf.put_u8(self.priority_tick);
        buf.put_u8(self.timeout_ticks);
        buf.put_u16_le(self.connection_serial);
        buf.put_u16_le(self.originator_vendor);
        buf.put_u32_le(self.originator_serial);
        assert!(self.connection_path.len() % 2 == 0, "path must be word-aligned");
        buf.put_u8((self.connection_path.len() / 2) as u8);
        buf.put_u8(0);
        buf.put_slice(&self.connection_path);
        buf.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            return Err(EipError::Short {
                expected: 12,
                actual: bytes.len(),
            });
        }
        let mut c = bytes;
        let priority_tick = c.get_u8();
        let timeout_ticks = c.get_u8();
        let connection_serial = c.get_u16_le();
        let originator_vendor = c.get_u16_le();
        let originator_serial = c.get_u32_le();
        let path_words = c.get_u8() as usize;
        c.advance(1);
        let path_bytes = path_words * 2;
        if c.remaining() < path_bytes {
            return Err(EipError::Short {
                expected: path_bytes,
                actual: c.remaining(),
            });
        }
        let mut connection_path = vec![0u8; path_bytes];
        c.copy_to_slice(&mut connection_path);
        Ok(Self {
            priority_tick,
            timeout_ticks,
            connection_serial,
            originator_vendor,
            originator_serial,
            connection_path,
        })
    }
}

/// Forward_Close response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardCloseResponse {
    pub connection_serial: u16,
    pub originator_vendor: u16,
    pub originator_serial: u32,
    pub app_reply: Vec<u8>,
}

impl ForwardCloseResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(10 + self.app_reply.len());
        buf.put_u16_le(self.connection_serial);
        buf.put_u16_le(self.originator_vendor);
        buf.put_u32_le(self.originator_serial);
        assert!(self.app_reply.len() % 2 == 0, "app_reply must be word-aligned");
        buf.put_u8((self.app_reply.len() / 2) as u8);
        buf.put_u8(0);
        buf.put_slice(&self.app_reply);
        buf.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 10 {
            return Err(EipError::Short {
                expected: 10,
                actual: bytes.len(),
            });
        }
        let mut c = bytes;
        let connection_serial = c.get_u16_le();
        let originator_vendor = c.get_u16_le();
        let originator_serial = c.get_u32_le();
        let reply_size_words = c.get_u8() as usize;
        c.advance(1);
        let reply_bytes = reply_size_words * 2;
        if c.remaining() < reply_bytes {
            return Err(EipError::Short {
                expected: reply_bytes,
                actual: c.remaining(),
            });
        }
        let mut app_reply = vec![0u8; reply_bytes];
        c.copy_to_slice(&mut app_reply);
        Ok(Self {
            connection_serial,
            originator_vendor,
            originator_serial,
            app_reply,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_params() -> NetworkConnectionParameters {
        NetworkConnectionParameters {
            redundant_owner: false,
            connection_type: 2,
            priority: 1,
            variable_size: false,
            size: 504,
        }
    }

    #[test]
    fn network_params_roundtrip() {
        let p = sample_params();
        let round = NetworkConnectionParameters::decode(p.encode());
        assert_eq!(p, round);
    }

    #[test]
    fn transport_byte_bit_layout() {
        // Class 3, server, application-triggered → 0xA3 (matches Logix Class 3).
        let byte = TransportClass::Class3.as_u8(true, TriggerType::Application);
        assert_eq!(byte, 0xA3);
    }

    #[test]
    fn forward_open_roundtrip() {
        let req = ForwardOpenRequest {
            priority_tick: 0x07,
            timeout_ticks: 0x09,
            o_to_t_connection_id: 0,
            t_to_o_connection_id: 0x8000_1234,
            connection_serial: 0x1234,
            originator_vendor: 1,
            originator_serial: 0xABCD_1234,
            connection_timeout_mult: 3,
            o_to_t_rpi_us: 2_500_000,
            o_to_t_params: sample_params(),
            t_to_o_rpi_us: 2_500_000,
            t_to_o_params: sample_params(),
            transport_type: 0xA3,
            connection_path: vec![0x20, 0x02, 0x24, 0x01],
        };
        let bytes = req.encode();
        let back = ForwardOpenRequest::decode(&bytes).unwrap();
        assert_eq!(back.priority_tick, req.priority_tick);
        assert_eq!(back.connection_path, req.connection_path);
        assert_eq!(back.t_to_o_connection_id, req.t_to_o_connection_id);
        assert_eq!(back.transport_type, req.transport_type);
    }

    #[test]
    fn forward_open_response_roundtrip() {
        let resp = ForwardOpenResponse {
            o_to_t_connection_id: 0xDEAD_BEEF,
            t_to_o_connection_id: 0xCAFE_F00D,
            connection_serial: 0x1234,
            originator_vendor: 1,
            originator_serial: 0xABCD_1234,
            o_to_t_actual_rpi_us: 5000,
            t_to_o_actual_rpi_us: 5000,
            app_reply: vec![],
        };
        assert_eq!(ForwardOpenResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn forward_close_roundtrip() {
        let req = ForwardCloseRequest {
            priority_tick: 0x07,
            timeout_ticks: 0x09,
            connection_serial: 0x1234,
            originator_vendor: 1,
            originator_serial: 0xABCD_1234,
            connection_path: vec![0x20, 0x02, 0x24, 0x01],
        };
        assert_eq!(
            ForwardCloseRequest::decode(&req.encode()).unwrap().connection_serial,
            req.connection_serial
        );

        let resp = ForwardCloseResponse {
            connection_serial: 0x1234,
            originator_vendor: 1,
            originator_serial: 0xABCD_1234,
            app_reply: vec![],
        };
        assert_eq!(ForwardCloseResponse::decode(&resp.encode()).unwrap(), resp);
    }
}
