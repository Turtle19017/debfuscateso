#!/usr/bin/env python3
"""Recover the first relocation-aware indirect targets in GLES3JNIView_init.

This is a static evaluator for the exact corrected v3 ELF. It does not execute
or patch the target. The final zero-valued pristine-snapshot target is reported
as evidence that later CFF evaluation requires runtime state/side effects.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA256 = "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1"
MASK = (1 << 64) - 1
RELA_OFF = 0x73B20
RELA_SIZE = 0x67638
DYNSYM_OFF = 0x2D0
NSYM = 6837

R_AARCH64_ABS64 = 0x101
R_AARCH64_GLOB_DAT = 0x401
R_AARCH64_JUMP_SLOT = 0x402
R_AARCH64_RELATIVE = 0x403


def make_runtime_image(image: bytes) -> bytearray:
    e_phoff = struct.unpack_from("<Q", image, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", image, 0x36)[0]
    e_phnum = struct.unpack_from("<H", image, 0x38)[0]
    loads = []
    max_end = 0
    for i in range(e_phnum):
        typ, flags, off, va, _pa, filesz, memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", image, e_phoff + i * e_phentsize
        )
        if typ == 1:
            loads.append((off, va, filesz, memsz, flags))
            max_end = max(max_end, va + memsz)
    mem = bytearray(max_end + 0x1000)
    for off, va, filesz, _memsz, _flags in loads:
        mem[va : va + filesz] = image[off : off + filesz]

    def qword(va: int) -> int:
        return struct.unpack_from("<Q", mem, va)[0]

    def sym_value(index: int) -> int:
        assert 0 <= index < NSYM
        return struct.unpack_from("<IBBHQQ", image, DYNSYM_OFF + index * 24)[4]

    for pos in range(RELA_OFF, RELA_OFF + RELA_SIZE, 24):
        target, info, addend = struct.unpack_from("<QQq", image, pos)
        rtype = info & 0xFFFFFFFF
        sym = info >> 32
        if rtype == R_AARCH64_RELATIVE:
            value = addend & MASK
        elif rtype == R_AARCH64_ABS64:
            value = (qword(target) + sym_value(sym) + addend) & MASK
        elif rtype in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT):
            value = (sym_value(sym) + addend) & MASK
        else:
            continue
        struct.pack_into("<Q", mem, target, value)
    return mem


def q(mem: bytearray, va: int) -> int:
    return struct.unpack_from("<Q", mem, va)[0]


def target_269460(mem: bytearray) -> int:
    x26 = 0x8127250E47E15DC0
    x19 = 0x516948
    x23 = 0x515EE8
    x10 = (-q(mem, x19 + 0x5D0)) & MASK
    x10 ^= x26
    x10 = (x10 * 0x115 + 0x115) & MASK
    x10 ^= x26
    x10 = (q(mem, x23 + 0x5D0) + x10) & MASK
    x10 = q(mem, x10 + 1)
    return (x10 + 0x628A7B5CA195C353) & MASK


def target_2db220(mem: bytearray) -> int:
    x22 = 0x526298
    x21 = 0x526240
    x8 = q(mem, x22 + 8)
    x8 = (-((x8 << 1) & MASK)) & MASK
    x8 ^= 0xF0AA4504C2DB616A
    x8 = (x8 + 2) & MASK
    x8 ^= 0x78552282616DB0B5
    x8 = (q(mem, x21 + 0x10) + x8) & MASK
    x8 = q(mem, x8 + 1)
    return (x8 + 0xC6D01D596152639D) & MASK


def target_2da720(mem: bytearray) -> int:
    x19 = 0x526170
    x20 = 0x526090
    x24 = 0x956F24E8FC5B14CC
    x10 = (-q(mem, x19 + 0x60)) & MASK
    x10 ^= x24
    x10 = (x10 * 0x0E + 0x0F) & MASK
    x10 ^= x24
    x10 = q(mem, (q(mem, x20 + 0x60) + x10) & MASK)
    return (x10 + 0x525E94F235D89C00) & MASK


def pristine_target_2694d0(mem: bytearray) -> int:
    x26 = 0x8127250E47E15DC0
    x25 = 0x628A7B5CA195C352
    x19 = 0x516948
    x23 = 0x515EE8

    x8 = (-q(mem, x19 + 0x1A0)) & MASK
    x8 ^= x26
    x8 = (x8 * 0x8F + 0x8F) & MASK

    x9 = (-q(mem, x19 + 0x5D0)) & MASK
    x9 ^= x26
    x9 = (x9 * 0x115 + 0x115) & MASK

    x8 ^= x26
    x8 = (q(mem, x23 + 0x1A0) + x8) & MASK
    x8 = q(mem, x8 + 0x31)
    x8 = (-x8) & MASK

    x9 ^= x26
    x8 ^= x25
    x8 = (x8 * 6 + 7) & MASK
    x9 = (q(mem, x23 + 0x5D0) + x9) & MASK
    x9 = q(mem, x9 + 0x31)
    x8 ^= x25
    return (x9 + x8) & MASK


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("--strict-hash", action="store_true")
    args = ap.parse_args()

    image = args.input.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != EXPECTED_SHA256:
        msg = f"SHA-256 {digest} != expected {EXPECTED_SHA256}"
        if args.strict_hash:
            raise SystemExit(msg)
        print("[!]", msg)

    mem = make_runtime_image(image)
    t1 = target_269460(mem)
    t2 = target_2db220(mem)
    t3 = target_2da720(mem)
    pristine = pristine_target_2694d0(mem)

    assert t1 == 0x2DB1A8
    assert t2 == 0x2DA5C0
    assert t3 == 0x2CEEDC
    assert pristine == 0

    print(f"[+] SHA-256                        {digest}")
    print(f"[+] init 0x269460 pristine target  0x{t1:X}")
    print(f"[+] 0x2DB220 pristine target        0x{t2:X}")
    print(f"[+] 0x2DA720 pristine target        0x{t3:X}")
    print("[+] 0x2CEEDC                       atomic 32-bit load helper (LDAR/LDR by order)")
    print(f"[+] init 0x2694D0 pristine target   0x{pristine:X}")
    print("[+] conclusion                     relocations alone are insufficient after the first state chain")
    print("[+] next                           emulate runtime-initialized/CFF state before evaluating later BLR targets")


if __name__ == "__main__":
    main()
