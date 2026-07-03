//! Parse Logix tag names into a CIP EPATH.
//!
//! Supports:
//! * plain names — `MyTag`
//! * dotted members — `Motor.Speed`
//! * array indexers — `MyArr[3]`, `MyArr[1,2,3]` (multi-dim)
//! * nested arrays — `Temp[10].AnotherArray[4]`
//! * program scope — `Program:MainProgram.MyLocal`
//!
//! The program-scope prefix `Program:Name` is emitted as a single ANSI
//! symbolic segment (not split on the `:`).

use ethernetip_core::error::{EipError, Result};
use ethernetip_core::path::EpathWriter;

/// Encode a Logix tag name into a Message Router path.
///
/// Returns the raw EPATH bytes (no leading `path_size` byte — that gets added
/// by the request builder because it also needs to include the service code).
pub fn encode_symbolic(name: &str) -> Result<Vec<u8>> {
    if name.is_empty() {
        return Err(EipError::Protocol("empty tag name".into()));
    }
    let mut writer = EpathWriter::new();
    for (idx, segment) in split_dotted(name).into_iter().enumerate() {
        let (base, indices) = split_indexers(segment)?;
        if base.is_empty() {
            return Err(EipError::Protocol(format!(
                "empty path component in `{}`",
                name
            )));
        }
        if idx == 0 {
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
        assert_eq!(
            p,
            vec![0x91, 0x03, b'A', b'r', b'r', 0x00, 0x28, 0x03]
        );
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
        // Program:MainProgram is 19 chars (odd) => padded, then "Local" is 5 chars (odd) => padded.
        assert_eq!(&p[..2], &[0x91, 0x13]);
        assert_eq!(&p[2..21], b"Program:MainProgram");
        assert_eq!(p[21], 0x00);
        assert_eq!(&p[22..24], &[0x91, 0x05]);
        assert_eq!(&p[24..29], b"Local");
        assert_eq!(p[29], 0x00);
    }

    #[test]
    fn large_index() {
        // 0x100 should use 16-bit form.
        let p = encode_symbolic("Big[256]").unwrap();
        assert_eq!(
            p,
            vec![
                0x91, 0x03, b'B', b'i', b'g', 0x00, 0x29, 0x00, 0x00, 0x01
            ]
        );
    }

    #[test]
    fn rejects_unbalanced() {
        assert!(encode_symbolic("Bad[1").is_err());
    }
}
