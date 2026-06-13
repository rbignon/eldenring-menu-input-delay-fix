//! EldenringMenufix: a standalone DLL that removes the Elden Ring 1.12+ menu
//! input-accept delay ("prevent accidental skips") by reverting the per-dialog
//! threshold setter to its inert 1.11 form. See `README.md`.
//!
//! The cross-platform pattern matching lives in [`aob`]; all Win32 work (the
//! `DllMain`, the module scan, and the memory write) is `#[cfg(windows)]`.

pub mod aob;

#[cfg(windows)]
mod patch;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::fs::File;
#[cfg(windows)]
use std::io::Write;
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use windows::Win32::Foundation::{HINSTANCE, HMODULE};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
#[cfg(windows)]
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

#[cfg(windows)]
use crate::patch::InstallOutcome;

/// Directory containing this DLL, resolved from its own module handle.
#[cfg(windows)]
fn dll_directory(hmodule: HINSTANCE) -> Option<PathBuf> {
    let mut buffer = [0u16; 260];
    let len = unsafe { GetModuleFileNameW(Some(HMODULE(hmodule.0)), &mut buffer) } as usize;
    if len == 0 || len >= buffer.len() {
        return None;
    }
    let path = String::from_utf16_lossy(&buffer[..len]);
    PathBuf::from(path).parent().map(|p| p.to_path_buf())
}

/// One-line, human-readable description of an install outcome for the log.
#[cfg(windows)]
fn describe(outcome: &InstallOutcome) -> String {
    match outcome {
        InstallOutcome::Patched { addr } => {
            format!("menu input delay removed (setter patched at 0x{addr:X})")
        }
        InstallOutcome::NotFound => {
            "setter not found; build has no delay or the signature drifted, running unpatched"
                .to_string()
        }
        InstallOutcome::Ambiguous => {
            "setter pattern matched more than once; refusing to patch for safety".to_string()
        }
        InstallOutcome::ModuleInfoFailed => {
            "could not query the eldenring.exe module; running unpatched".to_string()
        }
        InstallOutcome::WriteFailed(e) => format!("memory write failed ({e}); running unpatched"),
    }
}

/// Write the startup outcome to `EldenringMenufix.log` next to the DLL,
/// truncating any previous run. Best-effort: I/O errors are ignored (the patch
/// outcome is unaffected by whether the log was written).
#[cfg(windows)]
fn write_log(hmodule: HINSTANCE, outcome: &InstallOutcome) {
    let Some(dir) = dll_directory(hmodule) else {
        return;
    };
    let Ok(mut file) = File::create(dir.join("EldenringMenufix.log")) else {
        return;
    };
    let _ = writeln!(file, "EldenringMenufix loaded.");
    let _ = writeln!(file, "{}", describe(outcome));
}

/// Worker body: install the patch, then log the outcome. Runs on a spawned
/// thread so no scan or file I/O happens under the Windows loader lock.
#[cfg(windows)]
fn run(hmodule: HINSTANCE) {
    let outcome = patch::install();
    write_log(hmodule, &outcome);
}

/// DLL entry point. On process attach, spawn the worker thread and return
/// immediately; never do real work under the loader lock.
///
/// # Safety
/// Standard `DllMain` contract; invoked by the Windows loader.
#[cfg(windows)]
#[no_mangle]
#[allow(clippy::missing_safety_doc, non_snake_case)]
pub unsafe extern "system" fn DllMain(
    hmodule: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        // HINSTANCE wraps a raw pointer and is not Send; round-trip through
        // usize to move it into the spawned thread.
        let hmodule_addr = hmodule.0 as usize;
        std::thread::spawn(move || {
            let hmodule = HINSTANCE(hmodule_addr as *mut c_void);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(hmodule)));
        });
    }
    true
}
