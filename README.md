# MenuInputDelayFix

A tiny standalone DLL that removes the menu "input accept delay" Elden Ring
added in patch **1.12** ("Adjusted the input speed in some menus, such as
conversation menus, to prevent accidental skips"). It restores the pre-1.12
behavior where yes/no confirmation boxes and conversation menus accept confirm
instantly.

The fix is a single 5-byte runtime patch (no per-frame work, no hooks). It is
**always on** and **build-agnostic**: it patches only builds that have the
delay and is a no-op everywhere else.

> Reverse-engineered by **Claude Fable 5** (Anthropic's agentic coding model).

## Install

1. Download `MenuInputDelayFix.dll` (from the GitHub Actions build artifacts /
   releases, or build it yourself, see below).
2. Load it with any Elden Ring DLL mod loader (Elden Mod Loader, ModEngine2,
   ...): drop it into the loader's mods folder.
3. EAC must be off (offline / Seamless), as for any exe-touching mod.

On launch the DLL writes `MenuInputDelayFix.log` next to itself, with a short
log saying whether the patch was applied.

## Supported builds

Validated in-game on **1.13** and **1.16.2**; the AOB also matches **1.12**
statically. On a build without the delay (pre-1.12, ProductVersion 2.0.x) the
signature does not match and the DLL does nothing, by design.

## The mechanism (reverse-engineering writeup)

### TL;DR

Patch 1.12 added a per-dialog input-accept delay (~0.32 s) before a yes/no box
accepts confirm. The whole gate already existed pre-1.12 but was **inert**: the
function that writes the delay into the dialog template was an empty stub
(`mov rax,rcx; ret`). 1.12 just **filled in the stub body** so it now sets the
threshold from the debug property **`MenuMan.MenuOpenPadBlockTime`** (~0.32, via
its getter; the value lives in a `.data` global, not a `.rdata` constant). That
property's UTF-16 name string is new in 1.12, so a string-table diff against an
older build is the fastest way to find it.

Per-frame, the dialog accumulates `dt` into `+0x2300` capped at threshold
`+0x1278`; vtable **slot 18** releases input to the Scaleform movie once
`accum >= threshold`. Threshold 0 means accept on frame 1 (the pre-1.12
behaviour).

Removal = make the threshold stay 0. One AOB hits the setter's call+store core
on every delay-active build (and nothing on pre-1.12):

```
E8 ?? ?? ?? ?? F3 0F 11 43 18 48 8B C3
```

Overwrite the 5-byte `call <getter>` with `0F 57 C0 90 90`
(`xorps xmm0,xmm0; nop; nop`): xmm0 becomes 0, so the following
`movss [rbx+0x18],xmm0` writes 0 into the threshold. That is exactly what this
DLL does at startup.

The AOB deliberately anchors on the call + store, not the function prologue or
stack frame (those drift when the function's callers/callees change); the
literal field offset `0x18` is kept because it is what makes the pattern unique
and distinguishes a delay build from the pre-1.12 stub. (AOB hardening thanks to
thefifthmatt.)

### Mechanism (reconstructed)

`CS::MessageBoxDialog` (the yes/no box; also the path used by conversation
menus) carries two floats:

```
dialog + 0x1278   inputAcceptDelay   (threshold, seconds)   <- 0.32 on 1.12+, 0 pre-1.12
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

### The actual pre-1.12 -> 1.12 change

```asm
; pre-1.12  eldenring.exe+77D560   (empty stub: writes nothing, threshold stays 0)
mov  rax, rcx
ret

; 1.12+  (1.12 +78DDE0, 1.13 +78DFD0, 1.16.2 +78E0C0; identical bar the call disp)
push rbx
sub  rsp, 0x20
mov  rbx, rcx                   ; self (window desc)
call <MenuOpenPadBlockTime getter>  ; -> xmm0 (~0.32; debug-property getter, jmp thunk)
                                ; ^ the DLL overwrites this 5-byte call with
                                ;   `xorps xmm0,xmm0; nop; nop` so the store writes 0
movss [rbx+0x18], xmm0          ; desc->inputAcceptDelay = ...
mov  rax, rbx
add  rsp, 0x20
pop  rbx
ret
```

That is the whole patch: a pre-shipped empty hook stub, filled in 1.12. The
mechanism (accumulator/threshold/slot18/copy) is byte-identical across versions
modulo offset shifts. The delay value is not a `.rdata` constant or an
immediate; it is the `MenuMan.MenuOpenPadBlockTime` debug property, read from a
`.data` backing global via the getter (e.g. `eldenring.exe+4588BDC` on 1.16.2:
0 on disk, ~0.32 at runtime). That global is thread-local and lazily populated
(filled on first read) from the property's registered default, which lives in
the Arxan-scattered getter/registration code, hence no clean constant to scan
for. None of this matters for the fix: the setter patch keeps the desc threshold
at 0, so the property machinery never feeds a non-zero value into a dialog.

### Per-version reference

| App ver | ProductVersion | Setter RVA | `movss` store RVA | Getter RVA |
|---|---|---|---|---|
| 1.11 (pre-1.12) | 2.0.1.0 | `+77D560` (stub, no delay) | - | - |
| 1.12 | 2.2.0.0 | `+78DDE0` | `+78DDEE` | `+E55C70` |
| 1.13 | 2.3.0.0 | `+78DFD0` | `+78DFDE` | `+E56180` |
| 1.16.2 | 2.6.2.0 | `+78E0C0` | `+78E0CE` | `+E56060` |

Other useful 1.13 anchors: `MessageBoxDialog` vtable `+2B03540`, slot2 override
`+927C40`, shared slot2 impl `+78E0D0`, slot18 `+78DF40` (body at `+78DF78`).
Dialog fields: threshold `+0x1278`, accumulator `+0x2300`. Desc field: `+0x18`.

## How this DLL applies it

`DllMain` spawns a worker thread (no work under the loader lock) that:

1. queries the live `eldenring.exe` module base and size;
2. AOB-scans the executable sections for the setter's call+store core, requiring
   exactly one match;
3. overwrites the 5-byte `call <getter>` at the match with `0F 57 C0 90 90`
   (`xorps xmm0,xmm0; nop; nop`; flip the page to RWX, write, restore protection,
   flush the instruction cache).

The setter runs at dialog-template creation, so a single startup patch affects
every dialog opened afterward. It fails safe: if the module info is
unavailable, the AOB is missing, the match is not unique, or the write fails,
it logs and the game runs unpatched.

The menu code is plaintext in memory (not in the DRM-encrypted set) and is not
restored by the anti-tamper layer on the validated builds, so a one-shot byte
patch sticks. If a future build is observed reverting the patch, neutralize the
relevant Arxan code-restoration routine before writing.

## Build from source

Requires the stable Rust toolchain with the MSVC target (the DLL builds on
Windows only).

```
cargo build --lib --release
# -> target/release/MenuInputDelayFix.dll
```

The pure pattern-matching logic is testable on any platform:

```
cargo test --lib
```

## Re-deriving the signature after a game update

`SETTER_PATTERN` in `src/aob.rs` is a byte signature, so a game update that
recompiles the setter can break it. The symptom is `MenuInputDelayFix.log`
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
  is a `jmp` thunk into the obfuscated debug-property accessor. Being
  register/offset/byte agnostic, it still finds the setter after the exact bytes
  drift, and rebuilds the AOB from what it found.

Shortcut for a fresh version: the property name string `MenuOpenPadBlockTime`
(UTF-16) is new in 1.12, so diffing the string tables against a pre-1.12 build
points straight at it.

`--patch call` (the runtime patch: call -> `xorps xmm0,xmm0; nop; nop`) or
`--patch nop` (NOP the `movss` store) additionally writes a statically patched
copy of the exe, handy for isolating the behaviour outside the DLL.

## Credits and license

Reverse-engineered by **Claude Fable 5** (Anthropic), run via Claude Code, with
dynamic confirmation (Cheat Engine) and the runtime mod by the project author.
The debug-property name `MenuMan.MenuOpenPadBlockTime` was identified by the
Souls modding community; the more robust call+store AOB and the `xorps` patch
were suggested by thefifthmatt.

Licensed under **AGPL-3.0**. See [`LICENSE`](LICENSE).
