//! Binary save / restore for [`crate::tag_registry::TagRegistry`] tag data.
//!
//! Byte-for-byte compatible with the C# `TagDatabasePersistence` on the
//! EthernetIPSharp side.  Format v1 documented there and mirrored here so a
//! file saved from any of the four ports (C#, C++, Rust, Python) loads
//! into any other.
//!
//! Semantics: saves tag BUFFER CONTENTS keyed by name; assumes the schema
//! (templates + tag shapes) has been re-registered before load. Tolerant of
//! added / removed / renamed tags between versions.

use std::io::{Read, Write};

use crate::tag_registry::TagRegistry;

const MAGIC: [u8; 4] = *b"EIPS";
const VERSION: u8 = 1;

/// Report of what happened during [`load`].
#[derive(Debug, Default, Clone)]
pub struct LoadResult {
    pub tags_restored: usize,
    pub tags_skipped: usize,
    pub warnings: Vec<String>,
}

/// Write every controller-scope and program-scope tag's buffer to `w`.
pub fn save<W: Write>(reg: &TagRegistry, mut w: W) -> std::io::Result<()> {
    // Header: magic + version + 3 reserved bytes = 8 bytes total.
    w.write_all(&MAGIC)?;
    w.write_all(&[VERSION, 0, 0, 0])?;

    // Controller tag section.
    let mut controller: Vec<_> = reg.browse_entries();
    // Filter out synthetic Program:* pseudo-rows (instance in 0xF000..).
    controller.retain(|(inst, name, _)| *inst < 0xF000 && !name.starts_with("Program:"));
    controller.sort_by_key(|r| r.0);
    write_u32(&mut w, controller.len() as u32)?;
    for (inst, _name, _sym) in &controller {
        if let Some(entry) = reg.get_by_instance(*inst) {
            write_tag_record(&mut w, &entry.name, entry.sym_type & 0x0FFF | (entry.sym_type & 0x8000), &entry.data)?;
            // NB: for compat with the C# format we serialize the tag_type
            // parameter used in Read/Write_Tag (either the atomic type code
            // or the struct handle). Keep the same computation as the C#
            // side: tag.TagType directly.  In Rust, that's the CIP type for
            // atomics or the low 12 bits of sym_type for structs.
        }
    }

    // Program tag section.
    let programs = reg.all_programs();
    write_u32(&mut w, programs.len() as u32)?;
    for (program_name, _) in &programs {
        write_string(&mut w, program_name)?;
        let mut ptags: Vec<_> = reg
            .program_tags(program_name)
            .into_iter()
            .collect();
        ptags.sort_by_key(|(_, t)| t.instance);
        write_u32(&mut w, ptags.len() as u32)?;
        for (_, entry) in &ptags {
            write_tag_record(&mut w, &entry.name, entry.sym_type & 0x0FFF | (entry.sym_type & 0x8000), &entry.data)?;
        }
    }
    Ok(())
}

/// Restore tag buffer contents from a stream written by [`save`].
pub fn load<R: Read>(reg: &TagRegistry, mut r: R) -> std::io::Result<LoadResult> {
    let mut header = [0u8; 8];
    r.read_exact(&mut header)?;
    if header[..4] != MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a TagDatabase snapshot: bad magic",
        ));
    }
    let version = header[4];
    if version > VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("snapshot version {version} is newer than this loader ({VERSION})"),
        ));
    }

    let mut result = LoadResult::default();

    let controller_count = read_u32(&mut r)?;
    for _ in 0..controller_count {
        restore_one(&mut r, reg, None, &mut result)?;
    }

    let program_count = read_u32(&mut r)?;
    for _ in 0..program_count {
        let program_name = read_string(&mut r)?;
        let tag_count = read_u32(&mut r)?;
        let has_program = reg.program_pseudo_id(&program_name).is_some();
        for _ in 0..tag_count {
            if has_program {
                restore_one(&mut r, reg, Some(program_name.as_str()), &mut result)?;
            } else {
                // Consume + skip.
                skip_tag_record(&mut r)?;
                result.tags_skipped += 1;
                result
                    .warnings
                    .push(format!("Program '{program_name}' not registered — skipping tag records"));
            }
        }
    }
    Ok(result)
}

fn restore_one<R: Read>(
    r: &mut R,
    reg: &TagRegistry,
    program: Option<&str>,
    result: &mut LoadResult,
) -> std::io::Result<()> {
    let name = read_string(r)?;
    let tag_type = read_u16(r)?;
    let data_size = read_u32(r)? as usize;
    let mut buffer = vec![0u8; data_size];
    r.read_exact(&mut buffer)?;

    let entry = match program {
        Some(p) => reg.get_program_tag(p, &name),
        None => reg.get_by_name(&name),
    };
    let Some(entry) = entry else {
        result.tags_skipped += 1;
        result
            .warnings
            .push(format!("Tag '{name}' not registered — skipping"));
        return Ok(());
    };
    let file_type = tag_type & 0x0FFF | (tag_type & 0x8000);
    let entry_type = entry.sym_type & 0x0FFF | (entry.sym_type & 0x8000);
    if file_type != entry_type {
        result.tags_skipped += 1;
        result.warnings.push(format!(
            "Tag '{name}' tag_type mismatch (file=0x{file_type:04X}, current=0x{entry_type:04X}) — skipping"
        ));
        return Ok(());
    }
    if entry.data.len() != data_size {
        result.tags_skipped += 1;
        result.warnings.push(format!(
            "Tag '{name}' data_size mismatch (file={data_size}, current={}) — skipping",
            entry.data.len()
        ));
        return Ok(());
    }
    let ok = if let Some(p) = program {
        reg.set_program_tag_bytes(p, &name, 0, &buffer).is_ok()
    } else {
        reg.set_by_name_silent(&name, &buffer).is_ok()
    };
    if ok {
        result.tags_restored += 1;
    } else {
        result.tags_skipped += 1;
        result.warnings.push(format!("Tag '{name}' write failed"));
    }
    Ok(())
}

fn skip_tag_record<R: Read>(r: &mut R) -> std::io::Result<()> {
    let _name = read_string(r)?;
    let _tag_type = read_u16(r)?;
    let data_size = read_u32(r)? as usize;
    let mut discard = vec![0u8; data_size];
    r.read_exact(&mut discard)?;
    Ok(())
}

fn write_tag_record<W: Write>(w: &mut W, name: &str, tag_type: u16, data: &[u8]) -> std::io::Result<()> {
    write_string(w, name)?;
    write_u16(w, tag_type)?;
    write_u32(w, data.len() as u32)?;
    w.write_all(data)
}

fn write_u16<W: Write>(w: &mut W, v: u16) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_u32<W: Write>(w: &mut W, v: u32) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_string<W: Write>(w: &mut W, s: &str) -> std::io::Result<()> {
    let bytes = s.as_bytes();
    write_u16(w, bytes.len() as u16)?;
    w.write_all(bytes)
}

fn read_u16<R: Read>(r: &mut R) -> std::io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32<R: Read>(r: &mut R) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_string<R: Read>(r: &mut R) -> std::io::Result<String> {
    let len = read_u16(r)? as usize;
    let mut b = vec![0u8; len];
    r.read_exact(&mut b)?;
    String::from_utf8(b)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CipType;

    fn make_schema() -> TagRegistry {
        let reg = TagRegistry::new();
        reg.add_atomic("rate", CipType::Dint).unwrap();
        reg.add_array("arr", CipType::Dint, 8).unwrap();
        reg.add_array("flags", CipType::Bool, 32).unwrap();
        reg
    }

    #[test]
    fn round_trip_preserves_values() {
        let reg = make_schema();
        reg.set_by_name("rate", &12345i32.to_le_bytes()).unwrap();
        let mut arr = [0u8; 32];
        for i in 0..8 {
            arr[i * 4..(i + 1) * 4].copy_from_slice(&(100 + i as i32).to_le_bytes());
        }
        reg.set_by_name("arr", &arr).unwrap();
        reg.set_by_name("flags", &[0xAB, 0xCD, 0xEF, 0x12]).unwrap();

        let mut buf = Vec::new();
        save(&reg, &mut buf).unwrap();

        let reg2 = make_schema();
        let result = load(&reg2, &buf[..]).unwrap();
        assert_eq!(result.tags_restored, 3);
        assert_eq!(result.tags_skipped, 0);
        assert_eq!(reg2.get_by_name("rate").unwrap().data, 12345i32.to_le_bytes());
        assert_eq!(reg2.get_by_name("arr").unwrap().data, arr);
        assert_eq!(reg2.get_by_name("flags").unwrap().data, [0xAB, 0xCD, 0xEF, 0x12]);
    }

    #[test]
    fn load_missing_tag_skipped_with_warning() {
        let reg = make_schema();
        reg.set_by_name("rate", &7i32.to_le_bytes()).unwrap();

        let mut buf = Vec::new();
        save(&reg, &mut buf).unwrap();

        let reg2 = TagRegistry::new();
        reg2.add_atomic("rate", CipType::Dint).unwrap();
        // arr and flags missing from reg2.

        let result = load(&reg2, &buf[..]).unwrap();
        assert_eq!(result.tags_restored, 1);
        assert_eq!(result.tags_skipped, 2);
        assert!(result.warnings.iter().any(|w| w.contains("'arr'")));
    }

    #[test]
    fn program_scope_round_trip() {
        let reg = TagRegistry::new();
        reg.add_atomic("controller_tag", CipType::Dint).unwrap();
        reg.set_by_name("controller_tag", &111i32.to_le_bytes()).unwrap();
        reg.register_program("Cell");
        reg.add_program_atomic("Cell", "Rate", CipType::Dint).unwrap();
        reg.set_program_tag_bytes("Cell", "Rate", 0, &222i32.to_le_bytes()).unwrap();

        let mut buf = Vec::new();
        save(&reg, &mut buf).unwrap();

        let reg2 = TagRegistry::new();
        reg2.add_atomic("controller_tag", CipType::Dint).unwrap();
        reg2.register_program("Cell");
        reg2.add_program_atomic("Cell", "Rate", CipType::Dint).unwrap();

        let result = load(&reg2, &buf[..]).unwrap();
        assert_eq!(result.tags_restored, 2);
        assert_eq!(
            reg2.get_program_tag("Cell", "Rate").unwrap().data,
            222i32.to_le_bytes()
        );
    }

    #[test]
    fn bad_magic_errors() {
        let reg = TagRegistry::new();
        let bytes = [0u8; 8];
        assert!(load(&reg, &bytes[..]).is_err());
    }

    #[test]
    fn future_version_errors() {
        let reg = TagRegistry::new();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&[99, 0, 0, 0]);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // no controller tags
        bytes.extend_from_slice(&0u32.to_le_bytes()); // no programs
        assert!(load(&reg, &bytes[..]).is_err());
    }
}
