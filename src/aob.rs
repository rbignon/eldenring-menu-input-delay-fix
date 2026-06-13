//! Platform-independent array-of-bytes (AOB) pattern matching and the menu
//! input-accept delay signature. `Some(b)` matches that byte exactly; `None`
//! is a wildcard. The Windows-specific module scan and patch that build on this
//! live in `crate::patch`.

/// One byte of an AOB pattern: `Some(b)` matches exactly, `None` is a wildcard.
pub type PatternByte = Option<u8>;

/// AOB of the 1.12+ threshold setter. `None` wildcards the call rel32
/// (bytes 10-13) and the destination field disp8 (byte 18), so the pattern
/// survives those varying across builds. Matches exactly one function on builds
/// with the delay (validated 1.12, 1.13); does not match the inert 1.11 form.
pub const SETTER_PATTERN: &[PatternByte] = &[
    Some(0x40),
    Some(0x53),
    Some(0x48),
    Some(0x83),
    Some(0xEC),
    Some(0x20),
    Some(0x48),
    Some(0x8B),
    Some(0xD9),
    Some(0xE8),
    None,
    None,
    None,
    None,
    Some(0xF3),
    Some(0x0F),
    Some(0x11),
    Some(0x43),
    None,
    Some(0x48),
    Some(0x8B),
    Some(0xC3),
    Some(0x48),
    Some(0x83),
    Some(0xC4),
    Some(0x20),
    Some(0x5B),
    Some(0xC3),
];

/// `mov rax, rcx ; ret` -- the inert 1.11 stub. Overwrites the first 4 bytes
/// of the setter prologue, which zeroes the threshold for every dialog.
pub const STUB: [u8; 4] = [0x48, 0x8B, 0xC1, 0xC3];
