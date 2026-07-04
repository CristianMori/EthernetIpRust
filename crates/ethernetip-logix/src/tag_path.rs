//! Parse Logix tag names into a CIP EPATH.
//!
//! Supports:
//! * plain names — `MyTag`
//! * dotted members — `Motor.Speed`
//! * array indexers — `MyArr[3]`, `MyArr[1,2,3]` (multi-dim)
//! * nested arrays — `Temp[10].AnotherArray[4]`
//! * program scope — `Program:MainProgram.MyLocal`
//!
//! When an [`AtomCache`] is provided (populated by `TagClient::browse_tags`),
//! the first-level tag name is replaced with a Symbol Object logical instance
//! segment — smaller on the wire than the full ANSI symbolic segment, and
//! immune to name-length limits.

use std::collections::HashMap;

use ethernetip_core::error::{EipError, Result};
use ethernetip_core::path::EpathWriter;

/// Two-level cache of Logix Symbol Object instance IDs.
///
/// * `controller` maps every controller-scope tag name to its Symbol Object
///   instance id (including the `Program:<name>` symbols that anchor program
///   scopes).
/// * `programs` maps a program name (without the `Program:` prefix) to the
///   instance ids of its local tags.
#[derive(Debug, Default, Clone)]
pub struct AtomCache {
    controller: HashMap<String, u32>,
    programs: HashMap<String, HashMap<String, u32>>,
}

impl AtomCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_controller(&mut self, name: impl Into<String>, id: u32) {
        self.controller.insert(name.into(), id);
    }

    pub fn insert_program(
        &mut self,
        program: impl Into<String>,
        name: impl Into<String>,
        id: u32,
    ) {
        self.programs
            .entry(program.into())
            .or_default()
            .insert(name.into(), id);
    }

    pub fn get_controller(&self, name: &str) -> Option<u32> {
        self.controller.get(name).copied()
    }

    pub fn get_program(&self, program: &str, name: &str) -> Option<u32> {
        self.programs.get(program)?.get(name).copied()
    }

    pub fn clear(&mut self) {
        self.controller.clear();
        self.programs.clear();
    }

    pub fn controller_len(&self) -> usize {
        self.controller.len()
    }
}

/// Encode a Logix tag name into a Message Router path with no cache lookups.
///
/// Equivalent to calling [`encode_with_cache`] with an empty [`AtomCache`].
pub fn encode_symbolic(name: &str) -> Result<Vec<u8>> {
    encode_with_cache(name, &AtomCache::new())
}

/// Encode a Logix tag name, substituting Symbol Object instance segments for
/// the first-level identifier(s) when the cache has an entry.
pub fn encode_with_cache(name: &str, cache: &AtomCache) -> Result<Vec<u8>> {
    if name.is_empty() {
        return Err(EipError::Protocol("empty tag name".into()));
    }
    let segments = split_dotted(name);
    let mut writer = EpathWriter::new();
    let mut consumed = 0usize;

    // Case 1: program-scope tag with both anchors cached
    //         → sym("Program:X") + INST(local_id)
    if segments.len() >= 2 {
        if let Some(program_tail) = segments[0].strip_prefix("Program:") {
            let (program, program_idx) = split_indexers(segments[0])?;
            if !program_idx.is_empty() {
                return Err(EipError::Protocol(format!(
                    "program-scope prefix cannot carry an index: `{}`",
                    segments[0]
                )));
            }
            let (local_name, local_idx) = split_indexers(segments[1])?;
            if program_tail.is_empty() || local_name.is_empty() {
                return Err(EipError::Protocol(format!(
                    "empty component in `{}`",
                    name
                )));
            }
            if let Some(local_id) = cache.get_program(program_tail, local_name) {
                writer.push_symbolic(program);
                writer.push_instance(local_id);
                for idx in local_idx {
                    writer.push_element(idx);
                }
                consumed = 2;
            }
        }
    }

    // Case 2: controller-scope tag whose first segment is cached
    //         → INST(controller_id).
    //
    // Skip this shortcut for `Program:X` anchors — Logix will not accept a
    // program instance segment without the leading symbolic marker.
    if consumed == 0 {
        let (first, first_idx) = split_indexers(segments[0])?;
        if first.is_empty() {
            return Err(EipError::Protocol(format!(
                "empty path component in `{}`",
                name
            )));
        }
        if !first.starts_with("Program:") {
            if let Some(id) = cache.get_controller(first) {
                writer.push_instance(id);
                for idx in first_idx {
                    writer.push_element(idx);
                }
                consumed = 1;
            }
        }
    }

    // Anything not covered by the cache falls through to full ANSI symbolic
    // segments, one per remaining dotted component.
    for segment in &segments[consumed..] {
        let (base, indices) = split_indexers(segment)?;
        if base.is_empty() {
            return Err(EipError::Protocol(format!(
                "empty path component in `{}`",
                name
            )));
        }
        if consumed == 0 {
            if let Some(program_tail) = base.strip_prefix("Program:") {
                if program_tail.is_empty() {
                    return Err(EipError::Protocol("empty program name".into()));
                }
            }
        }
        writer.push_symbolic(base);
        for element in indices {
            writer.push_element(element);
        }
        consumed = consumed.saturating_add(1);
    }

    Ok(writer.into_bytes())
}

/// Split `Root.Sub[1].Other` on top-level dots without breaking `Program:Foo`.
fn split_dotted(name: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    for (i, ch) in name.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => depth -= 1,
            '.' if depth == 0 => {
                parts.push(&name[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&name[start..]);
    parts
}

/// Extract the base identifier and any bracket indices from `Foo[1,2]`.
fn split_indexers(segment: &str) -> Result<(&str, Vec<u32>)> {
    let bracket = segment.find('[');
    let Some(open) = bracket else {
        return Ok((segment, Vec::new()));
    };
    if !segment.ends_with(']') {
        return Err(EipError::Protocol(format!(
            "unbalanced brackets in `{}`",
            segment
        )));
    }
    let base = &segment[..open];
    let inside = &segment[open + 1..segment.len() - 1];
    let mut indices = Vec::new();
    for piece in inside.split(',') {
        let piece = piece.trim();
        let idx: u32 = piece.parse().map_err(|_| {
            EipError::Protocol(format!("invalid index `{}` in `{}`", piece, segment))
        })?;
        indices.push(idx);
    }
    Ok((base, indices))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_name() {
        let p = encode_symbolic("MyTag").unwrap();
        assert_eq!(p, vec![0x91, 0x05, b'M', b'y', b'T', b'a', b'g', 0x00]);
    }

    #[test]
    fn indexed() {
        let p = encode_symbolic("Arr[3]").unwrap();
        assert_eq!(p, vec![0x91, 0x03, b'A', b'r', b'r', 0x00, 0x28, 0x03]);
    }

    #[test]
    fn multi_dim() {
        let p = encode_symbolic("Arr[1,2,3]").unwrap();
        assert_eq!(
            p,
            vec![0x91, 0x03, b'A', b'r', b'r', 0x00, 0x28, 0x01, 0x28, 0x02, 0x28, 0x03]
        );
    }

    #[test]
    fn nested_arrays() {
        let p = encode_symbolic("Temp[10].Sub[4]").unwrap();
        assert_eq!(
            p,
            vec![
                0x91, 0x04, b'T', b'e', b'm', b'p', 0x28, 0x0A, 0x91, 0x03, b'S', b'u', b'b', 0x00,
                0x28, 0x04,
            ]
        );
    }

    #[test]
    fn program_scope() {
        let p = encode_symbolic("Program:MainProgram.Local").unwrap();
        assert_eq!(&p[..2], &[0x91, 0x13]);
        assert_eq!(&p[2..21], b"Program:MainProgram");
        assert_eq!(p[21], 0x00);
        assert_eq!(&p[22..24], &[0x91, 0x05]);
        assert_eq!(&p[24..29], b"Local");
        assert_eq!(p[29], 0x00);
    }

    #[test]
    fn large_index() {
        let p = encode_symbolic("Big[256]").unwrap();
        assert_eq!(
            p,
            vec![0x91, 0x03, b'B', b'i', b'g', 0x00, 0x29, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn rejects_unbalanced() {
        assert!(encode_symbolic("Bad[1").is_err());
    }

    #[test]
    fn cached_controller_tag_uses_instance_segment() {
        let mut cache = AtomCache::new();
        cache.insert_controller("FreeRunningTimer", 0x42);
        let p = encode_with_cache("FreeRunningTimer", &cache).unwrap();
        assert_eq!(p, vec![0x24, 0x42]);
    }

    #[test]
    fn cached_controller_tag_with_member() {
        let mut cache = AtomCache::new();
        cache.insert_controller("Motor", 7);
        let p = encode_with_cache("Motor.Speed", &cache).unwrap();
        assert_eq!(
            p,
            vec![0x24, 0x07, 0x91, 0x05, b'S', b'p', b'e', b'e', b'd', 0x00]
        );
    }

    #[test]
    fn cached_controller_tag_with_index_and_member() {
        let mut cache = AtomCache::new();
        cache.insert_controller("Arr", 3);
        let p = encode_with_cache("Arr[5].Sub", &cache).unwrap();
        assert_eq!(
            p,
            vec![0x24, 0x03, 0x28, 0x05, 0x91, 0x03, b'S', b'u', b'b', 0x00]
        );
    }

    #[test]
    fn cached_program_scope() {
        let mut cache = AtomCache::new();
        cache.insert_controller("Program:MainProgram", 4);
        cache.insert_program("MainProgram", "Framework", 2);
        let p = encode_with_cache("Program:MainProgram.Framework", &cache).unwrap();
        assert_eq!(&p[..2], &[0x91, 0x13]);
        assert_eq!(&p[2..21], b"Program:MainProgram");
        assert_eq!(p[21], 0x00);
        assert_eq!(&p[22..24], &[0x24, 0x02]);
    }

    #[test]
    fn cache_miss_falls_back_to_symbolic() {
        let cache = AtomCache::new();
        let cached = encode_with_cache("UnknownTag", &cache).unwrap();
        let bare = encode_symbolic("UnknownTag").unwrap();
        assert_eq!(cached, bare);
    }

    #[test]
    fn program_prefix_never_uses_bare_instance() {
        // Even when Program:X is in the controller cache, we must not emit
        // INST(id) as the first segment — Logix rejects that form. Falling
        // back to a symbolic Program:X segment keeps the read valid.
        let mut cache = AtomCache::new();
        cache.insert_controller("Program:MainProgram", 4);
        let p = encode_with_cache("Program:MainProgram.Framework", &cache).unwrap();
        assert_eq!(&p[..2], &[0x91, 0x13]);
        assert_eq!(&p[2..21], b"Program:MainProgram");
    }
}
