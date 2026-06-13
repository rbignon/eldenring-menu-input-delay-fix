//! Windows-only: locate the menu input-accept delay setter in the live
//! `eldenring.exe` image and revert it to the inert 1.11 stub. The pure
//! pattern matching lives in [`crate::aob`].

use std::ffi::c_void;
use std::sync::OnceLock;

use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::aob::{executable_section_ranges, find_unique_in_regions, SETTER_PATTERN, STUB};

/// Result of an install attempt. Carries no I/O; the entry layer logs it.
#[derive(Debug, Clone)]
pub enum InstallOutcome {
    /// Setter found and reverted to the 1.11 stub at `addr`.
    Patched { addr: usize },
    /// No match: build has no delay or the signature drifted.
    NotFound,
    /// More than one match; refused to patch for safety.
    Ambiguous,
    /// Could not query the `eldenring.exe` module.
    ModuleInfoFailed,
    /// The memory write failed; carries the formatted Win32 error.
    WriteFailed(String),
}

/// Computed once per process; repeated calls to [`install`] return the cached
/// outcome and never patch twice.
static OUTCOME: OnceLock<InstallOutcome> = OnceLock::new();

/// Base address and image size of the main module (`eldenring.exe`), or `None`
/// if querying the module info fails.
fn module_base_and_size() -> Option<(usize, usize)> {
    unsafe {
        // Passing None returns a handle to the executable that loaded this DLL,
        // i.e. eldenring.exe.
        let module: HMODULE = GetModuleHandleW(None).ok()?;
        let mut info = MODULEINFO::default();
        if GetModuleInformation(
            GetCurrentProcess(),
            module,
            &mut info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )
        .is_err()
        {
            return None;
        }
        Some((info.lpBaseOfDll as usize, info.SizeOfImage as usize))
    }
}

/// Overwrite `bytes.len()` bytes at `addr` inside an executable page: flip to
/// RWX, write, restore the original protection, flush the instruction cache.
///
/// # Safety
/// `addr` must point at `bytes.len()` bytes inside a mapped module image, and
/// overwriting them must produce valid code.
unsafe fn patch_bytes(addr: usize, bytes: &[u8]) -> windows::core::Result<()> {
    let mut old = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        addr as *const c_void,
        bytes.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old,
    )?;
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
    let mut restored = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(addr as *const c_void, bytes.len(), old, &mut restored)?;
    FlushInstructionCache(
        GetCurrentProcess(),
        Some(addr as *const c_void),
        bytes.len(),
    )?;
    Ok(())
}

/// Locate the setter and revert it. Side-effecting; runs once via [`OUTCOME`].
fn compute_install() -> InstallOutcome {
    let Some((base, size)) = module_base_and_size() else {
        return InstallOutcome::ModuleInfoFailed;
    };
    if size == 0 {
        return InstallOutcome::ModuleInfoFailed;
    }
    // SAFETY: `base`/`size` come from `GetModuleInformation`; the OS keeps the
    // image mapped for the process lifetime, so the range is valid for reads.
    // The shared borrow `mem` lives only for the scan and is dropped before
    // `patch_bytes` (which takes a raw `usize`), so no mutable alias of these
    // bytes exists while `mem` is held.
    let mem = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    // Scan only executable sections (avoids a stray pattern hit in data). If the
    // PE headers do not parse, fall back to the whole image so we never regress
    // to "cannot find it".
    let mut regions = executable_section_ranges(mem);
    if regions.is_empty() {
        regions.push((0, size));
    }
    match find_unique_in_regions(mem, &regions, SETTER_PATTERN) {
        Ok(off) => {
            let addr = base + off;
            // SAFETY: `addr = base + off`, and `find_unique_in_regions`
            // guarantees `off + SETTER_PATTERN.len() <= region_end <= size`;
            // since `STUB.len()` (4) is less than `SETTER_PATTERN.len()` (28),
            // the 4-byte write lies wholly inside the mapped image. STUB is
            // valid x86-64 (`mov rax,rcx; ret`) that replaces the prologue.
            match unsafe { patch_bytes(addr, &STUB) } {
                Ok(()) => InstallOutcome::Patched { addr },
                Err(e) => InstallOutcome::WriteFailed(e.to_string()),
            }
        }
        Err(0) => InstallOutcome::NotFound,
        Err(_) => InstallOutcome::Ambiguous,
    }
}

/// Apply the menu input-accept delay removal. Idempotent: the work runs at most
/// once per process; later calls return the same outcome.
pub fn install() -> InstallOutcome {
    OUTCOME.get_or_init(compute_install).clone()
}
