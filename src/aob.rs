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

/// True if `pattern` matches `haystack` starting at `offset`.
/// Caller guarantees `offset + pattern.len() <= haystack.len()`.
fn matches_at(haystack: &[u8], offset: usize, pattern: &[PatternByte]) -> bool {
    pattern
        .iter()
        .enumerate()
        .all(|(j, p)| p.map_or(true, |b| haystack[offset + j] == b))
}

/// Index of the first place `pattern` matches in `haystack`, or `None`.
/// An empty pattern never matches.
pub fn find_first(haystack: &[u8], pattern: &[PatternByte]) -> Option<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return None;
    }
    let last = haystack.len() - pattern.len();
    (0..=last).find(|&i| matches_at(haystack, i, pattern))
}

/// Index of the match iff `pattern` occurs exactly once in `haystack`.
/// `Err(0)` = no match (including an empty pattern); `Err(2)` = two or more
/// matches (ambiguous). The caller uses this to refuse to patch when the
/// target is missing or not unique.
pub fn find_unique(haystack: &[u8], pattern: &[PatternByte]) -> Result<usize, usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return Err(0);
    }
    let last = haystack.len() - pattern.len();
    let mut found: Option<usize> = None;
    for i in 0..=last {
        if matches_at(haystack, i, pattern) {
            if found.is_some() {
                return Err(2); // two or more matches: ambiguous
            }
            found = Some(i);
        }
    }
    found.ok_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_first_matches_with_wildcard() {
        let buf = [0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00];
        let pat = [Some(0x12), None, Some(0x56), Some(0x78)];
        assert_eq!(find_first(&buf, &pat), Some(2));
    }

    #[test]
    fn find_first_none_when_absent() {
        assert_eq!(find_first(&[0u8; 8], &[Some(0xAA), Some(0xBB)]), None);
    }

    #[test]
    fn find_first_none_for_empty_pattern() {
        assert_eq!(find_first(&[0u8; 4], &[]), None);
    }

    #[test]
    fn find_unique_returns_single_match() {
        let buf = [0x90, 0x12, 0x34, 0x90];
        assert_eq!(find_unique(&buf, &[Some(0x12), Some(0x34)]), Ok(1));
    }

    #[test]
    fn find_unique_errs_zero_when_absent() {
        assert_eq!(find_unique(&[0u8; 8], &[Some(0xAA)]), Err(0));
    }

    #[test]
    fn find_unique_errs_two_when_ambiguous() {
        let buf = [0xAB, 0x00, 0xAB, 0x00];
        assert_eq!(find_unique(&buf, &[Some(0xAB)]), Err(2));
    }

    #[test]
    fn find_unique_respects_wildcards() {
        let buf = [0x12, 0xFF, 0x34, 0x12, 0x00, 0x99];
        assert_eq!(find_unique(&buf, &[Some(0x12), None, Some(0x34)]), Ok(0));
    }

    /// The pattern must discriminate a delay-active (1.12+) setter from the
    /// inert 1.11 stub form. This fails if the pattern is edited so it no
    /// longer distinguishes the two, which is the property the mod relies on.
    #[test]
    fn setter_pattern_matches_active_setter_only() {
        // 1.12+ setter body: prologue, call <getter> (rel32 filled), then
        // `movss [rbx+0x18],xmm0`, epilogue. Matches SETTER_PATTERN exactly.
        let active = [
            0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, // push;sub;mov rbx,rcx
            0xE8, 0x11, 0x22, 0x33, 0x44, // call rel32 (arbitrary)
            0xF3, 0x0F, 0x11, 0x43, 0x18, // movss [rbx+0x18],xmm0
            0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3, // mov rax,rbx;add;pop;ret
        ];
        assert_eq!(find_unique(&active, SETTER_PATTERN), Ok(0));

        // 1.11 inert stub form: `mov rax,rcx; ret` followed by padding. Long
        // enough for the scan to attempt every offset; must not match.
        let mut inert = vec![0xCCu8; 64];
        inert[..STUB.len()].copy_from_slice(&STUB);
        assert_eq!(find_first(&inert, SETTER_PATTERN), None);
    }
}
