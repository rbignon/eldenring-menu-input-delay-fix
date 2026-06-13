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

/// Like [`find_unique`], but the scan is restricted to `regions` (each a
/// `(start, end)` byte range within `haystack`, `end` exclusive). Uniqueness is
/// global across all regions: `Ok(i)` for exactly one match, `Err(0)` for none,
/// `Err(2)` for two or more. Regions extending past the buffer are clamped;
/// regions too small for the pattern are skipped.
pub fn find_unique_in_regions(
    haystack: &[u8],
    regions: &[(usize, usize)],
    pattern: &[PatternByte],
) -> Result<usize, usize> {
    if pattern.is_empty() {
        return Err(0);
    }
    let mut found: Option<usize> = None;
    for &(start, end) in regions {
        let end = end.min(haystack.len());
        if end < start || end - start < pattern.len() {
            continue;
        }
        for i in start..=(end - pattern.len()) {
            if matches_at(haystack, i, pattern) {
                if found.is_some() {
                    return Err(2); // two or more matches: ambiguous
                }
                found = Some(i);
            }
        }
    }
    found.ok_or(0)
}

/// Parse the section table of a mapped PE `image` and return the byte ranges
/// (offsets into `image`, i.e. RVAs) of every section flagged executable
/// (`IMAGE_SCN_MEM_EXECUTE`). Restricting the setter scan to these avoids a
/// spurious pattern hit in `.data`/`.rdata`. Returns an empty vec if the headers
/// do not parse, so the caller can fall back to scanning the whole image. Pure
/// byte parsing (no Win32), hence unit-tested here.
pub fn executable_section_ranges(image: &[u8]) -> Vec<(usize, usize)> {
    const IMAGE_SCN_MEM_EXECUTE: usize = 0x2000_0000;
    let mut out = Vec::new();
    let rd_u16 = |o: usize| -> Option<usize> {
        image
            .get(o..o + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
    };
    let rd_u32 = |o: usize| -> Option<usize> {
        image
            .get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    if image.get(0..2) != Some(b"MZ".as_slice()) {
        return out;
    }
    let Some(e_lfanew) = rd_u32(0x3C) else {
        return out;
    };
    if image.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0".as_slice()) {
        return out;
    }
    let file_header = e_lfanew + 4;
    let (Some(num_sections), Some(size_opt)) = (rd_u16(file_header + 2), rd_u16(file_header + 16))
    else {
        return out;
    };
    let sect_start = file_header + 20 + size_opt;
    for i in 0..num_sections {
        let s = sect_start + i * 40;
        let (Some(vsize), Some(vaddr), Some(chars)) =
            (rd_u32(s + 8), rd_u32(s + 12), rd_u32(s + 36))
        else {
            break;
        };
        if chars & IMAGE_SCN_MEM_EXECUTE != 0 && vsize > 0 {
            let end = (vaddr + vsize).min(image.len());
            if vaddr < end {
                out.push((vaddr, end));
            }
        }
    }
    out
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

    #[test]
    fn regions_scan_only_within_regions() {
        // Two `AB` occurrences: one at 1 (inside the region), one at 5 (outside).
        let buf = [0x00, 0xAB, 0x00, 0x00, 0x00, 0xAB, 0x00];
        // Region covers only the first occurrence -> unique match at 1.
        assert_eq!(
            find_unique_in_regions(&buf, &[(0, 3)], &[Some(0xAB)]),
            Ok(1)
        );
        // No region covers a match.
        assert_eq!(
            find_unique_in_regions(&buf, &[(2, 5)], &[Some(0xAB)]),
            Err(0)
        );
        // Both occurrences in scope across regions -> ambiguous.
        assert_eq!(
            find_unique_in_regions(&buf, &[(0, 3), (4, 7)], &[Some(0xAB)]),
            Err(2)
        );
    }

    #[test]
    fn regions_clamp_and_skip_out_of_range() {
        let buf = [0xAB, 0xCD];
        // End past the buffer is clamped; still finds the match.
        assert_eq!(
            find_unique_in_regions(&buf, &[(0, 999)], &[Some(0xCD)]),
            Ok(1)
        );
        // Region too small for the pattern is skipped (no panic).
        assert_eq!(
            find_unique_in_regions(&buf, &[(0, 1)], &[Some(0xAB), Some(0xCD)]),
            Err(0)
        );
    }

    #[test]
    fn executable_section_ranges_parses_exec_sections() {
        // Minimal PE: MZ, e_lfanew=0x40, "PE\0\0", 2 sections, optional header 0.
        // Section 0 (.text) executable; section 1 (.data) not.
        let mut img = vec![0u8; 0x2000];
        img[0..2].copy_from_slice(b"MZ");
        img[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
        img[0x40..0x44].copy_from_slice(b"PE\0\0");
        let fh = 0x44;
        img[fh + 2..fh + 4].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
        img[fh + 16..fh + 18].copy_from_slice(&0u16.to_le_bytes()); // SizeOfOptionalHeader
        let sect = fh + 20; // = 0x58
        const EXEC: u32 = 0x2000_0000;
        // section 0: VA 0x1000, VSize 0x100, executable
        img[sect + 8..sect + 12].copy_from_slice(&0x100u32.to_le_bytes());
        img[sect + 12..sect + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        img[sect + 36..sect + 40].copy_from_slice(&EXEC.to_le_bytes());
        // section 1: VA 0x1200, VSize 0x100, NOT executable
        let s1 = sect + 40;
        img[s1 + 8..s1 + 12].copy_from_slice(&0x100u32.to_le_bytes());
        img[s1 + 12..s1 + 16].copy_from_slice(&0x1200u32.to_le_bytes());
        img[s1 + 36..s1 + 40].copy_from_slice(&0u32.to_le_bytes());

        assert_eq!(executable_section_ranges(&img), vec![(0x1000, 0x1100)]);
    }

    #[test]
    fn executable_section_ranges_keeps_every_exec_section() {
        // Elden Ring ships TWO executable `.text` sections; the setter lives in
        // one of them, so the scan must keep both (never exclude a real `.text`).
        // Layout: exec, non-exec, exec.
        const EXEC: u32 = 0x2000_0000;
        let mut img = vec![0u8; 0x3000];
        img[0..2].copy_from_slice(b"MZ");
        img[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        img[0x40..0x44].copy_from_slice(b"PE\0\0");
        let fh = 0x44;
        img[fh + 2..fh + 4].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
        img[fh + 16..fh + 18].copy_from_slice(&0u16.to_le_bytes());
        let sect = fh + 20;
        let mut write = |i: usize, vaddr: u32, vsize: u32, chars: u32| {
            let s = sect + i * 40;
            img[s + 8..s + 12].copy_from_slice(&vsize.to_le_bytes());
            img[s + 12..s + 16].copy_from_slice(&vaddr.to_le_bytes());
            img[s + 36..s + 40].copy_from_slice(&chars.to_le_bytes());
        };
        write(0, 0x1000, 0x100, EXEC); // .text
        write(1, 0x1200, 0x100, 0); // .rdata (not exec)
        write(2, 0x2000, 0x80, EXEC); // second .text
        assert_eq!(
            executable_section_ranges(&img),
            vec![(0x1000, 0x1100), (0x2000, 0x2080)]
        );
    }

    #[test]
    fn executable_section_ranges_empty_on_garbage() {
        assert!(executable_section_ranges(&[0u8; 4]).is_empty());
        assert!(executable_section_ranges(b"not a pe at all").is_empty());
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
