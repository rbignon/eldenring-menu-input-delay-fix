//! EldenringMenufix: a standalone DLL that removes the Elden Ring 1.12+ menu
//! input-accept delay ("prevent accidental skips") by reverting the per-dialog
//! threshold setter to its inert 1.11 form. See `README.md`.
//!
//! The cross-platform pattern matching lives in [`aob`]; all Win32 work (the
//! `DllMain`, the module scan, and the memory write) is `#[cfg(windows)]`.

pub mod aob;
