//! Tests for the full CIP elementary type family on the Logix tag server:
//! signed/unsigned 8..64-bit integers plus the bit-string family
//! (BYTE/WORD/DWORD/LWORD). Mirrors the C# UnsignedAndBitStringTypeTests.

use std::io::Cursor;

use ethernetip_logix::persistence::{load, save};
use ethernetip_logix::tag_registry::TagRegistry;
use ethernetip_logix::types::CipType;

#[test]
fn atomic_size_matches_spec_for_every_added_type() {
    assert_eq!(CipType::Sint.atomic_size(),  Some(1));
    assert_eq!(CipType::Usint.atomic_size(), Some(1));
    assert_eq!(CipType::Byte.atomic_size(),  Some(1));
    assert_eq!(CipType::Int.atomic_size(),   Some(2));
    assert_eq!(CipType::Uint.atomic_size(),  Some(2));
    assert_eq!(CipType::Word.atomic_size(),  Some(2));
    assert_eq!(CipType::Dint.atomic_size(),  Some(4));
    assert_eq!(CipType::Udint.atomic_size(), Some(4));
    assert_eq!(CipType::Dword.atomic_size(), Some(4));
    assert_eq!(CipType::Real.atomic_size(),  Some(4));
    assert_eq!(CipType::Lint.atomic_size(),  Some(8));
    assert_eq!(CipType::Ulint.atomic_size(), Some(8));
    assert_eq!(CipType::Lword.atomic_size(), Some(8));
    assert_eq!(CipType::Lreal.atomic_size(), Some(8));
}

#[test]
fn from_u16_recognizes_every_added_code() {
    assert_eq!(CipType::from_u16(0x00C6), Some(CipType::Usint));
    assert_eq!(CipType::from_u16(0x00C7), Some(CipType::Uint));
    assert_eq!(CipType::from_u16(0x00C8), Some(CipType::Udint));
    assert_eq!(CipType::from_u16(0x00C9), Some(CipType::Ulint));
    assert_eq!(CipType::from_u16(0x00D1), Some(CipType::Byte));
    assert_eq!(CipType::from_u16(0x00D2), Some(CipType::Word));
    assert_eq!(CipType::from_u16(0x00D3), Some(CipType::Dword));
    assert_eq!(CipType::from_u16(0x00D4), Some(CipType::Lword));
}

#[test]
fn add_atomic_udint_succeeds() {
    // The specific EscaFlow crash: UDINT was previously an unknown type.
    let reg = TagRegistry::new();
    let inst = reg.add_atomic("counter", CipType::Udint).unwrap();
    let entry = reg.get_by_instance(inst).unwrap();
    assert_eq!(entry.data.len(), 4);
}

#[test]
fn boundary_values_round_trip_without_sign_extension() {
    let reg = TagRegistry::new();

    reg.add_atomic("u8",  CipType::Usint).unwrap();
    reg.add_atomic("u16", CipType::Uint).unwrap();
    reg.add_atomic("u32", CipType::Udint).unwrap();
    reg.add_atomic("u64", CipType::Ulint).unwrap();

    reg.set_by_name("u8",  &[0xFFu8]).unwrap();
    reg.set_by_name("u16", &0xFFFFu16.to_le_bytes()).unwrap();
    reg.set_by_name("u32", &0xFFFF_FFFFu32.to_le_bytes()).unwrap();
    reg.set_by_name("u64", &0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes()).unwrap();

    let u8_entry = reg.get_by_name("u8").unwrap();
    assert_eq!(u8_entry.data[0], 0xFF);
    let u16_entry = reg.get_by_name("u16").unwrap();
    assert_eq!(u16::from_le_bytes([u16_entry.data[0], u16_entry.data[1]]), 0xFFFF);
    let u32_entry = reg.get_by_name("u32").unwrap();
    assert_eq!(u32::from_le_bytes([u32_entry.data[0], u32_entry.data[1], u32_entry.data[2], u32_entry.data[3]]), 0xFFFF_FFFFu32);
    let u64_entry = reg.get_by_name("u64").unwrap();
    assert_eq!(
        u64::from_le_bytes([u64_entry.data[0], u64_entry.data[1], u64_entry.data[2], u64_entry.data[3],
                             u64_entry.data[4], u64_entry.data[5], u64_entry.data[6], u64_entry.data[7]]),
        0xFFFF_FFFF_FFFF_FFFFu64
    );
}

#[test]
fn bit_string_types_allocate_correct_width() {
    let reg = TagRegistry::new();
    let b = reg.add_atomic("b", CipType::Byte).unwrap();
    let w = reg.add_atomic("w", CipType::Word).unwrap();
    let dw = reg.add_atomic("dw", CipType::Dword).unwrap();
    let lw = reg.add_atomic("lw", CipType::Lword).unwrap();
    assert_eq!(reg.get_by_instance(b).unwrap().data.len(), 1);
    assert_eq!(reg.get_by_instance(w).unwrap().data.len(), 2);
    assert_eq!(reg.get_by_instance(dw).unwrap().data.len(), 4);
    assert_eq!(reg.get_by_instance(lw).unwrap().data.len(), 8);
}

#[test]
fn add_array_of_udint_allocates_n_times_4_bytes() {
    let reg = TagRegistry::new();
    reg.add_array("arr", CipType::Udint, 16).unwrap();
    let entry = reg.get_by_name("arr").unwrap();
    assert_eq!(entry.data.len(), 64);
}

#[test]
fn persistence_round_trips_unsigned_and_bitstring_tags() {
    let reg = TagRegistry::new();
    reg.add_atomic("u8",  CipType::Usint).unwrap();
    reg.add_atomic("u16", CipType::Uint).unwrap();
    reg.add_atomic("u32", CipType::Udint).unwrap();
    reg.add_atomic("u64", CipType::Ulint).unwrap();
    reg.add_atomic("b8",  CipType::Byte).unwrap();
    reg.add_atomic("w16", CipType::Word).unwrap();
    reg.add_atomic("dw32",CipType::Dword).unwrap();
    reg.add_atomic("lw64",CipType::Lword).unwrap();

    reg.set_by_name("u8",  &[0xABu8]).unwrap();
    reg.set_by_name("u16", &0xBEEFu16.to_le_bytes()).unwrap();
    reg.set_by_name("u32", &0xDEAD_BEEFu32.to_le_bytes()).unwrap();
    reg.set_by_name("u64", &0xFEED_FACE_CAFE_BABEu64.to_le_bytes()).unwrap();
    reg.set_by_name("b8",  &[0xFFu8]).unwrap();
    reg.set_by_name("w16", &0xFFFEu16.to_le_bytes()).unwrap();
    reg.set_by_name("dw32",&0x1122_3344u32.to_le_bytes()).unwrap();
    reg.set_by_name("lw64",&0x1122_3344_5566_7788u64.to_le_bytes()).unwrap();

    let mut buf = Vec::new();
    save(&reg, &mut buf).unwrap();

    let reg2 = TagRegistry::new();
    reg2.add_atomic("u8",  CipType::Usint).unwrap();
    reg2.add_atomic("u16", CipType::Uint).unwrap();
    reg2.add_atomic("u32", CipType::Udint).unwrap();
    reg2.add_atomic("u64", CipType::Ulint).unwrap();
    reg2.add_atomic("b8",  CipType::Byte).unwrap();
    reg2.add_atomic("w16", CipType::Word).unwrap();
    reg2.add_atomic("dw32",CipType::Dword).unwrap();
    reg2.add_atomic("lw64",CipType::Lword).unwrap();

    let result = load(&reg2, Cursor::new(&buf)).unwrap();
    assert_eq!(result.tags_restored, 8);
    assert_eq!(result.tags_skipped, 0);
    assert_eq!(reg2.get_by_name("u32").unwrap().data,
                0xDEAD_BEEFu32.to_le_bytes().to_vec());
    assert_eq!(reg2.get_by_name("u64").unwrap().data,
                0xFEED_FACE_CAFE_BABEu64.to_le_bytes().to_vec());
    assert_eq!(reg2.get_by_name("lw64").unwrap().data,
                0x1122_3344_5566_7788u64.to_le_bytes().to_vec());
}
