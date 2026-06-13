# EldenringMenufix

A tiny standalone DLL that removes the menu "input accept delay" Elden Ring
added in patch **1.12** ("Adjusted the input speed in some menus, such as
conversation menus, to prevent accidental skips"). It restores the pre-1.12
behavior where yes/no confirmation boxes and conversation menus accept confirm
instantly.

The fix is a single 4-byte runtime patch (no per-frame work, no hooks). It is
**always on** and **build-agnostic**: it patches only builds that have the
delay and is a no-op everywhere else.

> Reverse-engineered by **Claude Fable 5** (Anthropic's agentic coding model).

## Install

1. Download `EldenringMenufix.dll` (from the GitHub Actions build artifacts /
   releases, or build it yourself, see below).
2. Load it with any Elden Ring DLL mod loader (Elden Mod Loader, ModEngine2,
   ...): drop it into the loader's mods folder.
3. EAC must be off (offline / Seamless), as for any exe-touching mod.

On launch the DLL writes `EldenringMenufix.log` next to itself, with a short
log saying whether the patch was applied.

## Supported builds

Validated on **1.13** and **1.16.2**. On a build without the delay (e.g. 1.10 /
ProductVersion 2.0.1.0) the signature does not match and the DLL does nothing,
by design.

## The mechanism (reverse-engineering writeup)

### TL;DR

Patch 1.12 added a per-dialog input-accept delay (~0.32 s) before a yes/no box
accepts confirm. The whole gate already existed in 1.10 but was **inert**: the
function that writes the delay into the dialog template was an empty stub
(`mov rax,rcx; ret`). 1.12 just **filled in the stub body** so it now sets the
threshold from a value returned by an Arxan-virtualised getter (~0.32, never a
visible constant).

Per-frame, the dialog accumulates `dt` into `+0x2300` capped at threshold
`+0x1278`; vtable **slot 18** releases input to the Scaleform movie once
`accum >= threshold`. Threshold 0 means accept on frame 1 (the 1.10 behaviour).

Removal = make the threshold stay 0. One AOB hits the setter on every
delay-active build:

```
40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? F3 0F 11 43 ?? 48 8B C3 48 83 C4 20 5B C3
```

Overwrite the setter's first 4 bytes with `48 8B C1 C3` (`mov rax,rcx; ret`,
the 1.10 form). That is exactly what this DLL does at startup.

### Mechanism (reconstructed)

`CS::MessageBoxDialog` (the yes/no box; also the path used by conversation
menus) carries two floats:

```
dialog + 0x1278   inputAcceptDelay   (threshold, seconds)   <- 0.32 on 1.12+, 0 on 1.10
dialog + 0x2300   elapsedSinceOpen   (accumulator, reset to 0 on open)
```

Per-frame, two virtuals on the dialog vtable:

```cpp
// slot 2  (shared dialog impl)
void update(float dt) {
    elapsedSinceOpen = min(elapsedSinceOpen + dt, inputAcceptDelay);  // saturates at threshold
}
// slot 18  (body runs only once accum reached threshold)
void tryReleaseInput() {
    if (elapsedSinceOpen < inputAcceptDelay) return;
    sendStateToMovie(/*ready=*/true);  // unblocks confirm on the Scaleform side
}
```

The throttle is C++-side: slot 18 pushes the "ready" state to the dialog's GFx
movie (`this+0x358`), which then lets the decide event through. That is why
this is exe-only despite the UI being ActionScript.

### Where the threshold comes from

The dialog copies it from a window descriptor (template) at creation:
`desc+0x18` -> `dialog+0x1278`. The descriptor field is set by a tiny setter,
called from two pre-existing sites: the message-box template init (all yes/no
popups), and the menu id 0xb open path (conversation menus).

### The actual 1.10 -> 1.12 change

```asm
; 1.10  eldenring.exe+77D560   (empty stub: writes nothing, threshold stays 0)
mov  rax, rcx
ret

; 1.12+  (1.12 +78DDE0, 1.13 +78DFD0, 1.16.2 +78E0C0; identical bar the call disp)
push rbx
sub  rsp, 0x20
mov  rbx, rcx                   ; self (window desc)
call <getMenuInputAcceptDelay>  ; -> xmm0  (~0.32; Arxan-virtualised, entry = jmp into stub region)
movss [rbx+0x18], xmm0          ; desc->inputAcceptDelay = ...
mov  rax, rbx
add  rsp, 0x20
pop  rbx
ret
```

That is the whole patch: a pre-shipped empty hook stub, filled in 1.12. The
mechanism (accumulator/threshold/slot18/copy) is byte-identical across versions
modulo offset shifts. The delay value is not a `.rdata` constant or an
immediate; it is produced by the virtualised getter, so it is invisible to
static constant scans.

### Per-version reference

| App ver | ProductVersion | Setter RVA | `movss` store RVA | Getter RVA |
|---|---|---|---|---|
| 1.10 | 2.0.1.0 | `+77D560` (stub, no delay) | - | - |
| 1.12 | 2.2.0.0 | `+78DDE0` | `+78DDEE` | `+E55C70` |
| 1.13 | 2.3.0.0 | `+78DFD0` | `+78DFDE` | `+E56180` |
| 1.16.2 | 2.6.2.0 | `+78E0C0` | `+78E0CE` | `+E56060` |

Other useful 1.13 anchors: `MessageBoxDialog` vtable `+2B03540`, slot2 override
`+927C40`, shared slot2 impl `+78E0D0`, slot18 `+78DF40` (body at `+78DF78`).
Dialog fields: threshold `+0x1278`, accumulator `+0x2300`. Desc field: `+0x18`.

## How this DLL applies it

`DllMain` spawns a worker thread (no work under the loader lock) that:

1. queries the live `eldenring.exe` module base and size;
2. AOB-scans the image for the setter, requiring exactly one match;
3. overwrites its 4-byte prologue with `48 8B C1 C3` (flip the page to RWX,
   write, restore protection, flush the instruction cache).

The setter runs at dialog-template creation, so a single startup patch affects
every dialog opened afterward. It fails safe: if the module info is
unavailable, the AOB is missing, the match is not unique, or the write fails,
it logs and the game runs unpatched.

## Build from source

Requires the stable Rust toolchain with the MSVC target (the DLL builds on
Windows only).

```
cargo build --lib --release
# -> target/release/EldenringMenufix.dll
```

The pure pattern-matching logic is testable on any platform:

```
cargo test --lib
```

## Re-deriving the signature after a game update

`SETTER_PATTERN` in `src/aob.rs` is a byte signature, so a game update that
recompiles the setter can break it. The symptom is `EldenringMenufix.log`
reporting that the setter was not found while the delay is clearly present in
game. Regenerate the pattern with the bundled tool:

```
uv run tools/find_menu_input_setter.py path/to/eldenring.exe
```

It prints a ready-to-paste `SETTER_PATTERN`; drop it into `src/aob.rs` and run
`cargo fmt`. The executable must be the decrypted / unpacked image (a memory
dump, or a build with the anti-tamper layer stripped); the live retail exe is
packed and will not scan correctly.

The tool finds the setter two independent ways and requires them to agree:

- Method A (AOB): the same byte signature the DLL embeds. It matches only builds
  that actually have the delay.
- Method B (semantic): scans small `.pdata` functions for the setter's shape, a
  `T* set(T* this) { this->field = getter(); return this; }` whose getter entry
  is an obfuscation `jmp` trampoline. Being register/offset/byte agnostic, it
  still finds the setter after the exact bytes drift, and rebuilds the AOB from
  what it found.

`--patch stub` (recommended) or `--patch nop` additionally writes a statically
patched copy of the exe, handy for isolating the behaviour outside the DLL.

## Credits and license

Reverse-engineered by **Claude Fable 5** (Anthropic), run via Claude Code.

Licensed under **AGPL-3.0**. See [`LICENSE`](LICENSE).
