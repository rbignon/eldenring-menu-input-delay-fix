#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pefile", "capstone"]
# ///
"""Locate the Elden Ring "menu input-accept delay" setter on any game build, and
emit the Rust `SETTER_PATTERN` the mod needs.

Run it when a game update makes MenuInputDelayFix.log report that the setter was
not found (the runtime AOB in `src/aob.rs` no longer matches).
The tool finds the setter again, prints a ready-to-paste `SETTER_PATTERN`, and
can optionally produce a statically patched exe. Standalone: `uv run` pulls
`pefile` + `capstone` automatically.

WHAT THIS TARGETS (background: README.md)
  Patch 1.12 enabled a per-dialog "input accept delay" that suppresses confirm
  for ~0.32 s after a yes/no box opens. The gate existed in 1.11 but was inert:
  the function that writes the delay into the dialog template was an empty stub.
  1.12 filled in the body, which now looks like:

        push rbx
        sub  rsp, 0x20
        mov  rbx, rcx                ; rbx = this (the window-desc)
        call <getter>                ; MenuMan.MenuOpenPadBlockTime debug-property
                                     ; getter (jmp thunk), returns ~0.32 (s)
        movss [rbx+0x18], xmm0        ; writes the threshold into the desc
        mov  rax, rbx
        add  rsp, 0x20
        pop  rbx
        ret

  The mod neutralizes the getter `call` (bytes E8 ?? ?? ?? ??) with
  `xorps xmm0,xmm0; nop; nop` (0F 57 C0 90 90), so the following movss writes 0
  into the threshold for every dialog. The AOB anchors on that call+store core
  (not the prologue/stack frame, which drift); the literal field offset 0x18 is
  kept because it is what makes the pattern unique.
  Shortcut for a fresh version: the property name string `MenuOpenPadBlockTime`
  (UTF-16) is new in 1.12, so a string-table diff against a pre-1.12 build points
  straight at it.

HOW IT FINDS THE SETTER (two methods that cross-check)
  A. AOB (fast): the known byte signature of the active-delay setter (the same
     one the mod embeds). Matches only builds that HAVE the delay.
  B. Semantic (robust, register/offset/byte agnostic): scan small (<0x30) .pdata
     functions for the shape `T* setX(T* this){ this->field = getter(); return
     this; }` whose callee entry is a `jmp` thunk into the obfuscated debug-
     property accessor. On builds with the delay this yields exactly one
     function; on builds without it, zero.
     If the compiler changes the exact bytes (the AOB drifts), B still finds it,
     and `--emit-rust` rebuilds the AOB from the bytes it actually found.

  B is the authority, A is confirmation; they must agree.

USAGE
  uv run tools/find_menu_input_setter.py <eldenring.exe>            # locate + emit
  uv run tools/find_menu_input_setter.py <eldenring.exe> --patch call
  uv run tools/find_menu_input_setter.py <eldenring.exe> --patch nop -o out.exe
  uv run tools/find_menu_input_setter.py <eldenring.exe> --patch call --inplace
"""

import argparse
import struct
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_REG, Cs

_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True

# ---- method A: precise byte signature (kept in sync with the Rust mod) -------
# Core only: call <getter>; movss [rbx+0x18],xmm0; mov rax,rbx. Wildcards just
# the call rel32. Excludes the prologue/epilogue and stack-frame sizes (those
# drift when callers/callees change); keeps the literal 0x18 (load-bearing for
# uniqueness and for discriminating a delay build).
SIG = [
    0xE8,  # call <getter>
    None,
    None,
    None,
    None,
    0xF3,  # movss [rbx+0x18], xmm0
    0x0F,
    0x11,
    0x43,
    0x18,
    0x48,  # mov rax, rbx
    0x8B,
    0xC3,
]
SIG_MOVSS_OFF = 5  # movss store within the AOB match (call is 5 bytes)
CALL_PATCH = bytes([0x0F, 0x57, 0xC0, 0x90, 0x90])  # xorps xmm0,xmm0 ; nop ; nop


class PE:
    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)
        self.ib = self.pe.OPTIONAL_HEADER.ImageBase
        self.img = self.pe.get_memory_mapped_image()
        self.secs = []  # (vstart, vend, raw_ptr, name)
        for s in self.pe.sections:
            n = s.Name.rstrip(b"\x00").decode("latin1", "replace")
            self.secs.append(
                (
                    s.VirtualAddress,
                    s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData),
                    s.PointerToRawData,
                    n,
                )
            )
        self.text = [(a, b) for a, b, r, n in self.secs if n == ".text"]

    def in_text(self, rva):
        return any(a <= rva < b for a, b in self.text)

    def file_off(self, rva):
        for a, b, r, n in self.secs:
            if a <= rva < b:
                return rva - a + r
        return None

    def pdata(self):
        out = {}
        for a, b, r, n in self.secs:
            if n != ".pdata":
                continue
            for off in range(a, b - 11, 12):
                beg = struct.unpack_from("<I", self.img, off)[0]
                end = struct.unpack_from("<I", self.img, off + 4)[0]
                if beg or end:
                    out[beg] = end
        return out


# ---- method A ---------------------------------------------------------------
def find_aob(pe):
    hits = []
    img = pe.img
    for a, b in pe.text:
        for rva in range(a, b - len(SIG) + 1):
            if img[rva] != SIG[0]:
                continue
            if all(s is None or img[rva + i] == s for i, s in enumerate(SIG)):
                hits.append(rva)
    return hits


# ---- method B ---------------------------------------------------------------
def _callee_is_trampoline(pe, rva):
    if not pe.in_text(rva):
        return None  # straight into the protector region -> treat as obfuscated
    ins = next(_md.disasm(pe.img[rva : rva + 16], pe.ib + rva), None)
    return bool(ins and ins.mnemonic == "jmp")


def find_semantic(pe):
    """Return list of (setter_rva, movss_rva, base_reg, disp, getter_rva, obf)."""
    res = []
    for fs, fe in pe.pdata().items():
        if fe <= fs or fe - fs > 0x30 or not pe.in_text(fs):
            continue
        ins = list(_md.disasm(pe.img[fs:fe], pe.ib + fs))
        if not ins or ins[-1].mnemonic != "ret":
            continue
        for i, s in enumerate(ins):
            if s.mnemonic != "movss" or i < 1 or ins[i - 1].mnemonic != "call":
                continue
            ops = s.operands
            if not (
                len(ops) == 2 and ops[0].type == CS_OP_MEM and ops[1].type == CS_OP_REG
            ):
                continue
            if (
                s.reg_name(ops[1].reg) != "xmm0"
                or ops[0].mem.index != 0
                or not 0 < ops[0].mem.disp < 0x80
            ):
                continue
            base = s.reg_name(ops[0].mem.base)
            if not any(
                x.mnemonic == "mov" and x.op_str == f"{base}, rcx" for x in ins[:i]
            ):
                continue
            if not any(
                x.mnemonic == "mov" and x.op_str == f"rax, {base}" for x in ins[i:]
            ):
                continue
            cop = ins[i - 1].op_str
            gt = int(cop, 16) - pe.ib if cop.startswith("0x") else None
            obf = _callee_is_trampoline(pe, gt) if gt is not None else None
            res.append((fs, s.address - pe.ib, base, ops[0].mem.disp, gt, obf))
    return res


# ---- emit the Rust SETTER_PATTERN from the bytes actually found -------------
def emit_rust(pe, call_rva):
    """Build the core `SETTER_PATTERN` for the `call` at `call_rva`.

    Emits the semantic core `call <getter>; movss [reg+disp],xmm0; mov rax,reg`,
    wildcarding only the 4 call-rel32 bytes and keeping every other byte exact
    (opcode, register, and the literal field offset, which is load-bearing).
    Excludes the prologue/epilogue/stack frame. Returns the Rust source for the
    const, or None if the bytes do not disassemble to that shape.
    """
    code = bytes(pe.img[call_rva : call_rva + 0x20])
    ins = list(_md.disasm(code, pe.ib + call_rva))
    if len(ins) < 3 or ins[0].mnemonic != "call":
        return None
    movss, movr = ins[1], ins[2]
    store = (
        movss.mnemonic == "movss"
        and len(movss.operands) == 2
        and movss.operands[0].type == CS_OP_MEM
        and movss.operands[0].mem.base != 0
        and movss.operands[0].mem.index == 0
        and movss.reg_name(movss.operands[1].reg) == "xmm0"
    )
    base = movss.reg_name(movss.operands[0].mem.base) if store else None
    returns_this = (
        movr.mnemonic == "mov"
        and movr.op_str == f"rax, {base}"
        if store
        else False
    )
    if not (store and returns_this):
        return None
    end = (movr.address + movr.size) - (pe.ib + call_rva)
    wild = set(range(1, 5))  # the call's rel32 (E8 + 4 bytes)
    entries = ["None" if k in wild else f"Some(0x{code[k]:02X})" for k in range(end)]
    lines = ["const SETTER_PATTERN: &[Option<u8>] = &["]
    for k in range(0, len(entries), 6):
        lines.append("    " + ", ".join(entries[k : k + 6]) + ",")
    lines.append("];")
    return "\n".join(lines)


def locate(path):
    pe = PE(path)
    sem = find_semantic(pe)
    sem_obf = [h for h in sem if h[5]]  # callee is an obfuscation trampoline
    aob = find_aob(pe)
    return pe, sem, sem_obf, aob


def main():
    ap = argparse.ArgumentParser(
        description="Locate/patch the ER menu input-accept delay setter."
    )
    ap.add_argument("exe")
    ap.add_argument("--patch", choices=["call", "nop"])
    ap.add_argument("-o", "--out")
    ap.add_argument("--inplace", action="store_true")
    args = ap.parse_args()

    pe, sem, sem_obf, aob = locate(args.exe)

    # `chosen` is the setter function start (semantic, when known); `chosen_movss`
    # is the threshold store; the getter `call` is the 5 bytes right before it.
    chosen = None
    chosen_movss = None
    if len(sem_obf) == 1:
        chosen = sem_obf[0][0]
        chosen_movss = sem_obf[0][1]  # true RVA, exact even if the AOB drifted
    elif len(aob) == 1:
        chosen = aob[0]  # AOB now anchors on the call, not the function start
        chosen_movss = aob[0] + SIG_MOVSS_OFF

    print(
        f"semantic candidates (shape+returns-this): {len(sem)}, "
        f"of which obfuscated-getter: {len(sem_obf)}"
    )
    for fs, ms, base, disp, gt, obf in sem_obf:
        print(
            f"  setter @ {fs:#x}  movss[{base}+{disp:#x}],xmm0  "
            f"getter={gt:#x}  (obfuscated trampoline)"
        )
    print(f"AOB matches: {len(aob)}  {[hex(x) for x in aob]}")

    if chosen is None:
        if not sem_obf and not aob:
            print(
                "\nNOT FOUND. Either this build has the delay disabled "
                "(e.g. a pre-1.12 / 2.0.x exe),"
            )
            print("or the setter shape changed. Re-derive via the research doc recipe.")
            sys.exit(2)
        print(
            "\nAMBIGUOUS: methods disagree or multiple candidates. "
            "Inspect manually before patching."
        )
        sys.exit(3)

    if aob and (chosen_movss - SIG_MOVSS_OFF) not in aob:
        print(
            f"\nWARNING: AOB ({[hex(x) for x in aob]}) and semantic "
            f"(call {chosen_movss - SIG_MOVSS_OFF:#x}) disagree; using semantic. Verify."
        )

    movss = chosen_movss
    call_rva = movss - SIG_MOVSS_OFF  # the `call <getter>`, 5 bytes before movss
    fo_call = pe.file_off(call_rva)
    fo_movss = pe.file_off(movss)
    mb = bytes(pe.img[movss : movss + 5])
    movss_ok = mb[0:3] == b"\xf3\x0f\x11"
    cb = bytes(pe.img[call_rva : call_rva + 1])
    call_ok = cb == b"\xe8"
    setter_str = f"eldenring.exe+{chosen:X}" if chosen is not None else "(unknown)"
    print(
        f"\nSetter fn: {setter_str}   call: eldenring.exe+{call_rva:X}"
        f"   movss store: eldenring.exe+{movss:X}  bytes={mb.hex(' ')}"
        f"{'' if movss_ok and call_ok else '  (!! unexpected bytes)'}"
    )
    print(f"file offsets: call={fo_call:#x} movss={fo_movss:#x}")

    rust = emit_rust(pe, call_rva)
    if rust:
        print("\nReady-to-paste Rust pattern for src/aob.rs")
        print("(run `cargo fmt` after pasting):\n")
        print(rust)
    else:
        print(
            "\nCould not rebuild the Rust pattern automatically; "
            "inspect the setter bytes by hand."
        )

    if not args.patch:
        print(
            "\nNo --patch given. The mod patches at runtime; --patch only writes a static exe."
        )
        return

    with open(args.exe, "rb") as f:
        data = bytearray(f.read())
    if args.patch == "call":
        if not call_ok:
            print("Refusing --patch call: no E8 call where expected.")
            sys.exit(4)
        before = bytes(data[fo_call : fo_call + 5])
        data[fo_call : fo_call + 5] = CALL_PATCH
        what = f"call {before.hex(' ')} -> {CALL_PATCH.hex(' ')}  (xorps xmm0,xmm0; nop; nop)"
    else:  # nop the movss store
        if not movss_ok:
            print("Refusing --patch nop: movss bytes not where expected. Use --patch call.")
            sys.exit(4)
        before = bytes(data[fo_movss : fo_movss + 5])
        data[fo_movss : fo_movss + 5] = b"\x90" * 5
        what = f"movss store {before.hex(' ')} -> 90 90 90 90 90"

    out = args.exe if args.inplace else (args.out or args.exe + ".patched.exe")
    with open(out, "wb") as f:
        f.write(data)
    print(f"\nPatched ({args.patch}): {what}\n  written: {out}")


if __name__ == "__main__":
    main()
