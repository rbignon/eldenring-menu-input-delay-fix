#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pefile", "capstone"]
# ///
"""Locate the Elden Ring "menu input-accept delay" setter on any game build, and
emit the Rust `SETTER_PATTERN` the mod needs.

Run it when a game update makes EldenringMenufix.log report that the setter was
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
        call <delay_getter>          ; obfuscated trampoline, returns ~0.32 (s)
        movss [rbx+0x18], xmm0        ; writes the threshold into the desc
        mov  rax, rbx
        add  rsp, 0x20
        pop  rbx
        ret

  The mod restores the 1.11 stub (`mov rax,rcx; ret`, bytes 48 8B C1 C3) over the
  setter's first 4 bytes, which zeroes the threshold for every dialog.

HOW IT FINDS THE SETTER (two methods that cross-check)
  A. AOB (fast): the known byte signature of the active-delay setter (the same
     one the mod embeds). Matches only builds that HAVE the delay.
  B. Semantic (robust, register/offset/byte agnostic): scan small (<0x30) .pdata
     functions for the shape `T* setX(T* this){ this->field = getter(); return
     this; }` whose callee entry is a `jmp` (obfuscation trampoline). On builds
     with the delay this yields exactly one function; on builds without it, zero.
     If the compiler changes the exact bytes (the AOB drifts), B still finds it,
     and `--emit-rust` rebuilds the AOB from the bytes it actually found.

  B is the authority, A is confirmation; they must agree.

USAGE
  uv run tools/find_menu_input_setter.py <eldenring.exe>            # locate + emit
  uv run tools/find_menu_input_setter.py <eldenring.exe> --patch stub
  uv run tools/find_menu_input_setter.py <eldenring.exe> --patch nop -o out.exe
  uv run tools/find_menu_input_setter.py <eldenring.exe> --patch stub --inplace
"""

import argparse
import struct
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_REG, Cs

_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True

# ---- method A: precise byte signature (kept in sync with the Rust mod) -------
SIG = [
    0x40,
    0x53,
    0x48,
    0x83,
    0xEC,
    0x20,
    0x48,
    0x8B,
    0xD9,
    0xE8,
    None,
    None,
    None,
    None,
    0xF3,
    0x0F,
    0x11,
    0x43,
    None,
    0x48,
    0x8B,
    0xC3,
    0x48,
    0x83,
    0xC4,
    0x20,
    0x5B,
    0xC3,
]
SIG_MOVSS_OFF = 14  # movss store within the AOB match (5 bytes)
STUB = bytes([0x48, 0x8B, 0xC1, 0xC3])  # mov rax,rcx ; ret


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
def emit_rust(pe, rva):
    """Build a wildcarded `SETTER_PATTERN` for the setter at `rva`.

    Wildcards the call's rel32 displacement and the threshold `movss` field
    displacement (the two operands that move across builds), keeping every
    opcode/register byte exact. Returns the Rust source for the const, or None
    if the function does not disassemble to the expected `... call; movss
    [base+disp],xmm0 ...; ret` shape.
    """
    code = bytes(pe.img[rva : rva + 0x40])
    ins = list(_md.disasm(code, pe.ib + rva))
    wild = set()
    end = None
    saw_call_movss = False
    for i, x in enumerate(ins):
        rel = x.address - (pe.ib + rva)
        enc = x.encoding  # capstone reports the exact field offsets and sizes
        if x.mnemonic == "call" and enc.imm_size:
            wild.update(
                range(rel + enc.imm_offset, rel + enc.imm_offset + enc.imm_size)
            )
        if (
            x.mnemonic == "movss"
            and enc.disp_size
            and i >= 1
            and ins[i - 1].mnemonic == "call"
        ):
            ops = x.operands
            store = (
                len(ops) == 2
                and ops[0].type == CS_OP_MEM
                and ops[0].mem.base != 0
                and ops[0].mem.index == 0
            )
            if store:
                wild.update(
                    range(rel + enc.disp_offset, rel + enc.disp_offset + enc.disp_size)
                )
                saw_call_movss = True
        if x.mnemonic == "ret":
            end = rel + x.size
            break
    if end is None or not saw_call_movss:
        return None

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
    ap.add_argument("--patch", choices=["nop", "stub"])
    ap.add_argument("-o", "--out")
    ap.add_argument("--inplace", action="store_true")
    args = ap.parse_args()

    pe, sem, sem_obf, aob = locate(args.exe)

    chosen = None
    chosen_movss = None
    if len(sem_obf) == 1:
        chosen = sem_obf[0][0]
        chosen_movss = sem_obf[0][1]  # true RVA, exact even if the AOB drifted
    elif len(aob) == 1:
        chosen = aob[0]
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

    if aob and chosen not in aob:
        print(
            f"\nWARNING: AOB ({[hex(x) for x in aob]}) and semantic "
            f"({chosen:#x}) disagree; using semantic. Verify."
        )

    movss = chosen_movss
    fo_func = pe.file_off(chosen)
    fo_movss = pe.file_off(movss)
    mb = bytes(pe.img[movss : movss + 5])
    movss_ok = mb[0:3] == b"\xf3\x0f\x11"
    print(
        f"\nSetter: eldenring.exe+{chosen:X}   movss store: eldenring.exe+{movss:X}"
        f"  bytes={mb.hex(' ')}{'' if movss_ok else '  (!! unexpected, prefer --patch stub)'}"
    )
    print(f"file offsets: setter={fo_func:#x} movss={fo_movss:#x}")

    rust = emit_rust(pe, chosen)
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
    if args.patch == "stub":
        before = bytes(data[fo_func : fo_func + 4])
        data[fo_func : fo_func + 4] = STUB
        what = f"setter+0 {before.hex(' ')} -> {STUB.hex(' ')}  (mov rax,rcx; ret)"
    else:
        if not movss_ok:
            print(
                "Refusing --patch nop: movss bytes not where expected. Use --patch stub."
            )
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
