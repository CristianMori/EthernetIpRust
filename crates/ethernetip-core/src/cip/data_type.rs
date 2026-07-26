//! CIP elementary data-type codes. Informational metadata carried by
//! [`CipAttribute`] — the framework doesn't enforce reads / writes against
//! the declared type. Callers who need typed access convert the attribute's
//! raw bytes themselves.

/// CIP elementary data-type codes (Vol 1 App C.2).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipDataType {
    Bool = 0x00C1,
    Sint = 0x00C2,
    Int = 0x00C3,
    Dint = 0x00C4,
    Lint = 0x00C5,
    Usint = 0x00C6,
    Uint = 0x00C7,
    Udint = 0x00C8,
    Ulint = 0x00C9,
    Real = 0x00CA,
    Lreal = 0x00CB,
    Stime = 0x00CC,
    Date = 0x00CD,
    TimeOfDay = 0x00CE,
    DateAndTime = 0x00CF,
    String = 0x00D0,
    Byte = 0x00D1,
    Word = 0x00D2,
    Dword = 0x00D3,
    Lword = 0x00D4,
    String2 = 0x00D5,
    Ftime = 0x00D6,
    Ltime = 0x00D7,
    Itime = 0x00D8,
    StringN = 0x00D9,
    ShortString = 0x00DA,
    Time = 0x00DB,
    Epath = 0x00DC,
    EngUnit = 0x00DD,
    StringI = 0x00DE,
    // Structured / vendor types
    Struct = 0x02A0,
    Array = 0x02A1,
}
