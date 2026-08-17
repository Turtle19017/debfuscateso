#!/usr/bin/env python3
"""Focused static analysis helper for ysm_inner.original_placement_v3.so.

No third-party Python modules are required.  The script intentionally focuses on
stable landmarks recovered from the current ARM64 sample:

* IL2CPP API resolver at 0x3016ac
* cached class resolver at 0x3011ac
* native method resolver at 0x301474
* field-offset resolver at 0x301590

It emits a JSON report that can be diffed across later samples.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

TEXT_START = 0x25E2E0
TEXT_END = 0x4D6810

RESOLVER_START = 0x3016AC
RESOLVER_END = 0x301914
CUSTOM_SYM = 0x357184

WRAPPERS = {
    0x3011AC: "find_class_cached",
    0x301474: "resolve_method_pointer",
    0x301590: "resolve_field_offset",
    0x3016AC: "init_il2cpp_api",
}

# Confirmed manually from call-site lazy-decrypt islands.  Keeping these
# annotations separate from the structural scanner makes provenance explicit: the
# xrefs/arguments are recovered algorithmically, while plaintext is only added
# after its initializer + XOR path has been verified.
KNOWN_CALLS = {
    0x25EA24: {
        "image": "mscorlib.dll",
        "namespace": "System",
        "class": "String",
        "member": "get_Chars",
        "argc": 1,
    },
    0x25EDE0: {
        "image": "UnityEngine.CoreModule.dll",
        "namespace": "UnityEngine",
        "class": "Transform",
        "member": "get_position",
        "argc": 0,
    },
    0x25F200: {
        "image": "UnityEngine.CoreModule.dll",
        "namespace": "UnityEngine",
        "class": "Component",
        "member": "get_gameObject",
        "argc": 0,
    },
    0x25F944: {
        "image": "Assembly-CSharp.dll",
        "namespace": "COW.GamePlay",
        "class": "Player",
        "member": "get_HeadCollider",
        "argc": 0,
    },
    0x25FAD8: {
        "image": "Assembly-CSharp.dll",
        "namespace": "COW.GamePlay",
        "class": "HPFKOGPDBBE",
        "member": "FOHHPOKDOND",
        "argc": 4,
    },
    0x26000C: {
        "image": "UnityEngine.dll",
        "namespace": "UnityEngine",
        "class": "Component",
        "member": "get_transform",
        "argc": 0,
    },
    0x2603C0: {
        "image": "UnityEngine.dll",
        "namespace": "UnityEngine",
        "class": "Camera",
        "member": "get_main",
        "argc": 0,
    },
    0x260768: {
        "image": "Assembly-CSharp.dll",
        "namespace": "COW.GamePlay",
        "class": "Player",
        "member": "get_IsDieing",
        "argc": 0,
    },
    0x260B0C: {
        "image": "Assembly-CSharp.dll",
        "namespace": "COW.GamePlay",
        "class": "Player",
        "member": "IsLocalTeammate",
        "argc": 1,
    },
    0x2615E8: {
        "image": "Assembly-CSharp.dll",
        "namespace": "COW.GamePlay",
        "class": "EMKJHAJNPDH",
        "member": "PDBGEOANOEP",
    },
    0x261768: {
        "image": "Assembly-CSharp.dll",
        "namespace": "COW.GamePlay",
        "class": "EMKJHAJNPDH",
        "member": "MMECELKLHFC",
    },
    0x2619E0: {
        "image": "Assembly-CSharp.dll",
        "namespace": "COW.GamePlay",
        "class": "Player",
        "member": "<NNFKGNCILNK>k__BackingField",
    },
}


@dataclass
class Section:
    name: str
    addr: int
    offset: int
    size: int


class Elf64:
    def __init__(self, data: bytes):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("expected ELF64 little-endian")
        self.machine = struct.unpack_from("<H", data, 18)[0]
        shoff = struct.unpack_from("<Q", data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
        headers = []
        for i in range(shnum):
            off = shoff + i * shentsize
            sh_name, sh_type = struct.unpack_from("<II", data, off)
            sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQQ", data, off + 8)
            headers.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size))
        n = headers[shstrndx]
        names = data[n[4] : n[4] + n[5]]
        self.sections: list[Section] = []
        for sh_name, _, _, addr, off, size in headers:
            end = names.find(b"\0", sh_name)
            name = names[sh_name:end].decode("ascii", "replace") if end >= 0 else ""
            self.sections.append(Section(name, addr, off, size))

    def va_to_off(self, va: int) -> int:
        for s in self.sections:
            if s.size and s.addr <= va < s.addr + s.size and s.offset:
                return s.offset + (va - s.addr)
        # This sample happens to have identity mapping in .text/.rodata, but do
        # not silently rely on that for future variants.
        raise KeyError(f"VA 0x{va:x} not backed by a file section")

    def cstr(self, va: int, max_len: int = 256) -> str:
        off = self.va_to_off(va)
        end = self.data.find(b"\0", off, off + max_len)
        if end < 0:
            end = min(len(self.data), off + max_len)
        return self.data[off:end].decode("utf-8", "replace")

    def u32(self, va: int) -> int:
        return struct.unpack_from("<I", self.data, self.va_to_off(va))[0]


def sign_extend(v: int, bits: int) -> int:
    top = 1 << (bits - 1)
    return (v ^ top) - top


def branch_target(pc: int, ins: int) -> tuple[str, int] | None:
    op = ins & 0xFC000000
    if op not in (0x14000000, 0x94000000):
        return None
    imm = sign_extend(ins & 0x03FFFFFF, 26) << 2
    return ("BL" if op == 0x94000000 else "B", pc + imm)


def decode_adrp(pc: int, ins: int) -> tuple[int, int] | None:
    if ins & 0x9F000000 != 0x90000000:
        return None
    rd = ins & 31
    immlo = (ins >> 29) & 3
    immhi = (ins >> 5) & 0x7FFFF
    imm = sign_extend((immhi << 2) | immlo, 21) << 12
    return rd, (pc & ~0xFFF) + imm


def decode_add_imm(ins: int) -> tuple[int, int, int] | None:
    # ADD (immediate), 64-bit, no flags.
    if ins & 0xFF000000 != 0x91000000:
        return None
    rd = ins & 31
    rn = (ins >> 5) & 31
    imm = (ins >> 10) & 0xFFF
    if (ins >> 22) & 1:
        imm <<= 12
    return rd, rn, imm


def decode_str_x_unsigned(ins: int) -> tuple[int, int, int] | None:
    # STR Xt, [Xn, #imm12*8]
    if ins & 0xFFC00000 != 0xF9000000:
        return None
    rt = ins & 31
    rn = (ins >> 5) & 31
    imm = ((ins >> 10) & 0xFFF) * 8
    return rt, rn, imm


def decode_movz_w(ins: int) -> tuple[int, int] | None:
    # MOV Wd,#imm is a MOVZ alias (hw=0 in all observed call sites).
    if ins & 0x7F800000 != 0x52800000:
        return None
    rd = ins & 31
    imm16 = (ins >> 5) & 0xFFFF
    hw = (ins >> 21) & 0x3
    return rd, imm16 << (16 * hw)


def decode_mov_x_reg(ins: int) -> tuple[int, int] | None:
    """Decode the common ``mov Xd, Xm`` alias of ORR Xd, XZR, Xm.

    This matters at lookup call sites where a BSS string address is kept in a
    callee-saved register (for example x20) and copied into x3 immediately
    before the resolver call.
    """
    if ins & 0xFFE0FFE0 != 0xAA0003E0:
        return None
    rd = ins & 31
    rm = (ins >> 16) & 31
    return rd, rm


def iter_text_words(elf: Elf64, start: int = TEXT_START, end: int = TEXT_END):
    for pc in range(start, end, 4):
        try:
            yield pc, elf.u32(pc)
        except KeyError:
            break


def recover_resolver(elf: Elf64) -> list[dict]:
    words = {pc: ins for pc, ins in iter_text_words(elf, RESOLVER_START, RESOLVER_END)}
    rows = []
    x1_page = None
    for pc in range(RESOLVER_START, RESOLVER_END, 4):
        ins = words.get(pc)
        if ins is None:
            continue
        a = decode_adrp(pc, ins)
        if a and a[0] == 1:
            x1_page = a[1]
        add = decode_add_imm(ins)
        if add and add[0] == 1 and add[1] == 1 and x1_page is not None:
            x1_page += add[2]
        br = branch_target(pc, ins)
        if not br or br != ("BL", CUSTOM_SYM):
            continue
        name_va = x1_page
        # Result store is within the next 5 instructions.  Track the ADRP base
        # register used by the store.
        pages: dict[int, int] = {}
        slot = None
        for q in range(pc + 4, min(pc + 28, RESOLVER_END), 4):
            qi = words[q]
            aa = decode_adrp(q, qi)
            if aa:
                pages[aa[0]] = aa[1]
            st = decode_str_x_unsigned(qi)
            if st and st[0] in (0, 8) and st[1] in pages:
                # Most stores use x0; the final object_new case moves x0->x8.
                slot = pages[st[1]] + st[2]
                break
        rows.append({
            "resolver_call": f"0x{pc:x}",
            "name_va": f"0x{name_va:x}" if name_va is not None else None,
            "name": elf.cstr(name_va) if name_va is not None else None,
            "slot": f"0x{slot:x}" if slot is not None else None,
        })
    return rows


def direct_xrefs(elf: Elf64, target: int) -> list[int]:
    out = []
    for pc, ins in iter_text_words(elf):
        br = branch_target(pc, ins)
        if br and br[1] == target:
            out.append(pc)
    return out


def recover_call_args(elf: Elf64, call_pc: int, lookback: int = 32) -> dict:
    """Recover constant pointer arguments immediately before a wrapper call.

    This is deliberately a tiny forward constant-propagation pass, not a full
    ARM64 emulator.  In addition to ADRP+ADD it follows MOV through
    callee-saved registers.  Direct calls invalidate volatile x0..x18 so stale
    constants are not accidentally propagated through an unrelated call.
    """
    regs: dict[int, int] = {}
    argc = None
    begin = max(TEXT_START, call_pc - lookback * 4)
    for pc in range(begin, call_pc, 4):
        ins = elf.u32(pc)

        br = branch_target(pc, ins)
        if br and br[0] == "BL":
            for r in range(19):
                regs.pop(r, None)
            continue

        a = decode_adrp(pc, ins)
        if a:
            regs[a[0]] = a[1]
            continue

        add = decode_add_imm(ins)
        if add:
            rd, rn, imm = add
            if rn in regs:
                regs[rd] = regs[rn] + imm
            else:
                regs.pop(rd, None)
            continue

        mov = decode_mov_x_reg(ins)
        if mov:
            rd, rm = mov
            if rm in regs:
                regs[rd] = regs[rm]
            else:
                regs.pop(rd, None)
            continue

        mz = decode_movz_w(ins)
        if mz and mz[0] == 4:
            argc = mz[1]
        # mov w4,wzr (ORR alias), exact mask on Rd only.
        if (ins & 0xFFFFFFE0) == 0x2A1F03E0 and (ins & 31) == 4:
            argc = 0

    return {
        "x0": f"0x{regs[0]:x}" if 0 in regs else None,
        "x1": f"0x{regs[1]:x}" if 1 in regs else None,
        "x2": f"0x{regs[2]:x}" if 2 in regs else None,
        "x3": f"0x{regs[3]:x}" if 3 in regs else None,
        "argc": argc,
    }


def build_report(path: Path) -> dict:
    data = path.read_bytes()
    elf = Elf64(data)
    if elf.machine != 183:  # EM_AARCH64
        raise ValueError(f"expected AArch64 (183), got e_machine={elf.machine}")
    wrapper_xrefs = {}
    for addr, name in WRAPPERS.items():
        xs = direct_xrefs(elf, addr)
        entries = []
        for pc in xs:
            ent = {"callsite": f"0x{pc:x}"}
            if addr in (0x301474, 0x301590):
                ent.update(recover_call_args(elf, pc))
            if pc in KNOWN_CALLS:
                ent["decoded"] = KNOWN_CALLS[pc]
            entries.append(ent)
        wrapper_xrefs[name] = {"address": f"0x{addr:x}", "xrefs": entries}
    managed_targets = []
    for wrapper_name, wrapper in wrapper_xrefs.items():
        for row in wrapper["xrefs"]:
            decoded = row.get("decoded")
            if not decoded:
                continue
            target = {"wrapper": wrapper_name, "callsite": row["callsite"], **decoded}
            if "member" in decoded:
                argc = decoded.get("argc")
                suffix = f"/{argc}" if argc is not None else ""
                target["signature"] = (
                    f"{decoded['image']}::{decoded['namespace']}.{decoded['class']}"
                    f"::{decoded['member']}{suffix}"
                )
            managed_targets.append(target)

    return {
        "file": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "machine": "AArch64",
        "resolver": recover_resolver(elf),
        "wrappers": wrapper_xrefs,
        "managed_targets": managed_targets,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", type=Path)
    ap.add_argument("-o", "--output", type=Path)
    ns = ap.parse_args()
    report = build_report(ns.binary)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if ns.output:
        ns.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
