//! CIP EPATH segment encoders.
//!
//! Every helper writes into an [`EpathWriter`] that keeps track of the byte
//! stream. Word-align padding is inserted automatically where the spec requires
//! it (ANSI symbolic segment with odd length, and after logical segments whose
//! value doesn't fit in the low byte).

use bytes::BufMut;

/// Growable EPATH byte buffer. Not thread-safe.
#[derive(Debug, Default, Clone)]
pub struct EpathWriter {
    buf: Vec<u8>,
}

impl EpathWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Current byte length of the encoded path.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Length in 16-bit words (used for the leading `path_size` byte of an EPATH).
    pub fn word_len(&self) -> u8 {
        assert!(self.buf.len() % 2 == 0, "EPATH must be word-aligned");
        (self.buf.len() / 2) as u8
    }

    /// Take the raw bytes out.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Copy of the current bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// ANSI Extended Symbolic segment (`0x91 <len> <chars...> [pad]`).
    pub fn push_symbolic(&mut self, name: &str) {
        let bytes = name.as_bytes();
        assert!(bytes.len() <= u8::MAX as usize, "symbolic name too long");
        self.buf.push(0x91);
        self.buf.push(bytes.len() as u8);
        self.buf.extend_from_slice(bytes);
        if bytes.len() % 2 == 1 {
            self.buf.push(0x00);
        }
    }

    /// Logical class segment.
    pub fn push_class(&mut self, class_id: u16) {
        self.push_logical(0x20, class_id as u32);
    }

    /// Logical instance segment.
    pub fn push_instance(&mut self, instance: u32) {
        self.push_logical(0x24, instance);
    }

    /// Logical attribute segment.
    pub fn push_attribute(&mut self, attr: u16) {
        self.push_logical(0x30, attr as u32);
    }

    /// Logical element segment (used for array indices).
    pub fn push_element(&mut self, index: u32) {
        self.push_logical(0x28, index);
    }

    fn push_logical(&mut self, base_op: u8, value: u32) {
        if value <= 0xFF {
            self.buf.push(base_op);
            self.buf.push(value as u8);
        } else if value <= 0xFFFF {
            self.buf.push(base_op | 0x01);
            self.buf.push(0x00);
            self.buf.put_u16_le(value as u16);
        } else {
            self.buf.push(base_op | 0x02);
            self.buf.push(0x00);
            self.buf.put_u32_le(value);
        }
    }

    /// Raw byte append — escape hatch for callers that already have segments.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }
}

/// Encode a libplctag-style routing path like `"1,0"` or `"1,0,2,1"`.
///
/// The string is a comma-separated list of `port,link` pairs. `port` values of
/// 15 or higher would need extended port encoding; that is currently rejected
/// with `None`. Empty input returns an empty path (the caller decides whether
/// to route through the Connection Manager at all).
pub fn parse_route_path(spec: &str) -> Option<Vec<u8>> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Some(Vec::new());
    }
    let tokens: Vec<&str> = spec.split(',').map(str::trim).collect();
    if tokens.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(tokens.len());
    for pair in tokens.chunks(2) {
        let port: u16 = pair[0].parse().ok()?;
        let link: u32 = pair[1].parse().ok()?;
        if port == 0 || port >= 15 {
            return None;
        }
        // Simple 8-bit link: port byte low nibble = port, link byte follows.
        if link > 0xFF {
            return None;
        }
        out.push(port as u8);
        out.push(link as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbolic_pads_odd_length() {
        let mut w = EpathWriter::new();
        w.push_symbolic("abc");
        assert_eq!(w.as_bytes(), &[0x91, 0x03, b'a', b'b', b'c', 0x00]);
    }

    #[test]
    fn symbolic_no_pad_even_length() {
        let mut w = EpathWriter::new();
        w.push_symbolic("ab");
        assert_eq!(w.as_bytes(), &[0x91, 0x02, b'a', b'b']);
    }

    #[test]
    fn class_instance_small() {
        let mut w = EpathWriter::new();
        w.push_class(0x02);
        w.push_instance(1);
        assert_eq!(w.as_bytes(), &[0x20, 0x02, 0x24, 0x01]);
    }

    #[test]
    fn instance_wide() {
        let mut w = EpathWriter::new();
        w.push_instance(0x1234);
        assert_eq!(w.as_bytes(), &[0x25, 0x00, 0x34, 0x12]);
    }

    #[test]
    fn parse_route_basic() {
        assert_eq!(parse_route_path("1,0"), Some(vec![0x01, 0x00]));
        assert_eq!(parse_route_path("1,0,2,1"), Some(vec![0x01, 0x00, 0x02, 0x01]));
        assert_eq!(parse_route_path(""), Some(vec![]));
        assert_eq!(parse_route_path("1"), None);
    }
}
