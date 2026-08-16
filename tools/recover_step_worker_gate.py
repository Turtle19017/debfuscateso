#!/usr/bin/env python3
"""Recover the step-triggered worker and early 0x2B2D04 CFF gates.

Sample-specific static evaluator for ysm_inner.original_placement_v3.so.
No runtime execution or patching is performed.
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

X21 = 0x402D93E7663678F1
X22 = 0x016C9F3B31B3C788
X28_GATE = 0xFD5CB0445B8BE495


def va_to_file(va: int) -> int:
    if 0 <= va < 0x4E29C0:
        return va
    if 0x4E69C0 <= va < 0x511798:
        return va - 0x4000
    if 0x5147A0 <= va < 0x537560:
        return va - 0x8000
    raise ValueError(f"VA 0x{va:x} is not file-backed")


def qword(image: bytes, va: int) -> int:
    return struct.unpack_from("<Q", image, va_to_file(va))[0]


def sym_value(image: bytes, index: int) -> int:
    if not 0 <= index < NSYM:
        raise ValueError(index)
    return struct.unpack_from("<IBBHQQ", image, DYNSYM_OFF + index * 24)[4]


def build_runtime_qwords(image: bytes) -> dict[int, int]:
    out: dict[int, int] = {}
    for pos in range(RELA_OFF, RELA_OFF + RELA_SIZE, 24):
        target, info, addend = struct.unpack_from("<QQq", image, pos)
        rtype = info & 0xFFFFFFFF
        sym = info >> 32
        if rtype == R_AARCH64_RELATIVE:
            out[target] = addend & MASK
        elif rtype == R_AARCH64_ABS64:
            out[target] = (qword(image, target) + sym_value(image, sym) + addend) & MASK
        elif rtype in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT):
            out[target] = (sym_value(image, sym) + addend) & MASK
    return out


def runtime_qword(image: bytes, rt: dict[int, int], va: int) -> int:
    return rt.get(va, qword(image, va))


def load_qword(image: bytes, rt: dict[int, int], va: int) -> int:
    # Only an exact aligned relocation target is rewritten by the linker.
    if va % 8 == 0 and va in rt:
        return rt[va]
    return qword(image, va)


def common_dispatch(image: bytes, rt: dict[int, int], state: int) -> int:
    """Dispatcher used after the first and second std::string::empty tests."""
    x8 = runtime_qword(image, rt, 0x51D098)
    x10 = runtime_qword(image, rt, 0x51D0F0)
    x11 = runtime_qword(image, rt, 0x51D008)
    sh = state << 3

    x8 = (-x8) & MASK
    x10 = (-x10) & MASK
    x8 ^= X21
    x8 = (x8 + 1) & MASK
    x10 ^= X21
    x8 ^= X21
    x8 = (x11 + x8 + sh) & MASK
    x8 = load_qword(image, rt, (x8 + 1) & MASK)

    x8 = (-x8) & MASK
    x8 ^= X28_GATE
    x8 = (state * x8 + state) & MASK

    x10 = (x10 * 12 + 12) & MASK
    x11 = runtime_qword(image, rt, 0x51D060)
    x9 = x10 ^ X21
    x9 = (x11 + x9 + sh) & MASK
    x9 = load_qword(image, rt, (x9 + 1) & MASK)
    x8 ^= X28_GATE
    return (x9 + x8 + 1) & MASK


def third_dispatch(image: bytes, rt: dict[int, int], empty: bool) -> int:
    state = 0x10 if empty else 0x20
    x9 = runtime_qword(image, rt, 0x51D098)
    x8 = runtime_qword(image, rt, 0x51D0F0)
    x12 = runtime_qword(image, rt, 0x51D008)

    x9 = (-x9) & MASK
    x8 = (-x8) & MASK
    x9 ^= X21
    x8 ^= X21
    x9 = (x9 + 1) & MASK
    x8 = (x8 * 12 + 12) & MASK
    x9 ^= X21
    x9 = (x12 + x9 + state) & MASK
    x9 = load_qword(image, rt, (x9 + 1) & MASK)

    x8 ^= X21
    x11 = runtime_qword(image, rt, 0x51D060)
    x9 = (-x9) & MASK
    x8 = (x11 + x8 + state) & MASK
    x9 ^= X28_GATE
    x9 = (x9 + 1) & MASK
    x8 = load_qword(image, rt, (x8 + 1) & MASK)
    x9 = (x9 << (1 if empty else 2)) & MASK
    x9 ^= X28_GATE
    return (x8 + x9 + 1) & MASK


def helper_result_dispatch(image: bytes, rt: dict[int, int], nonzero: bool) -> int:
    state = 6 if nonzero else 1
    x8 = runtime_qword(image, rt, 0x51D098)
    x10 = runtime_qword(image, rt, 0x51D008)
    x11 = runtime_qword(image, rt, 0x51D0F0)
    sh = state << 3

    x8 = (-x8) & MASK
    x8 ^= X21
    x8 = (x8 + 1) & MASK
    x8 ^= X21
    x8 = (x10 + x8 + sh) & MASK

    x10 = (-x11) & MASK
    x10 ^= X21
    x8 = load_qword(image, rt, (x8 + 1) & MASK)
    x10 = (x10 * 12 + 12) & MASK

    x11 = runtime_qword(image, rt, 0x51D060)
    x8 = (-x8) & MASK
    x8 ^= X28_GATE
    x8 = (state * x8 + state) & MASK
    x9 = x10 ^ X21
    x9 = (x11 + sh + x9) & MASK
    x9 = load_qword(image, rt, (x9 + 1) & MASK)
    x8 ^= X28_GATE
    return (x9 + x8 + 1) & MASK


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

    rt = build_runtime_qwords(image)

    print("[+] spawn site                  0x26FD30 (GLES3JNIView_step)")
    print("[+] pthread entry               0x297238")
    print("[+] worker payload              0x2B2D04")
    print("[+] std::string::empty helper   0x2A3F5C")
    print("[+] local string globals        0x539B18 0x539B30 0x539AE8")
    print(f"[+] first nonempty  state 0  -> 0x{common_dispatch(image, rt, 0):x}")
    print(f"[+] first empty     state 3  -> 0x{common_dispatch(image, rt, 3):x}")
    print(f"[+] second nonempty state 5  -> 0x{common_dispatch(image, rt, 5):x}")
    print(f"[+] second empty    state 7  -> 0x{common_dispatch(image, rt, 7):x}")
    print(f"[+] third nonempty  state 32 -> 0x{third_dispatch(image, rt, False):x}")
    print(f"[+] third empty     state 16 -> 0x{third_dispatch(image, rt, True):x}")
    print("[+] all nonempty continuation   0x2B3230")
    print("[+] three-string helper         0x2B3528")
    print(f"[+] helper nonzero state 6    -> 0x{helper_result_dispatch(image, rt, True):x}")
    print(f"[+] helper zero    state 1    -> 0x{helper_result_dispatch(image, rt, False):x}")
    print("[+] note: 0x2B322C is an early-return block, not the end of the full CFF routine")


if __name__ == "__main__":
    main()
