#!/usr/bin/env python3
"""Recover the five-string publication block produced by auth_core.

Sample-specific static evaluator for ysm_inner.original_placement_v3.so.
It evaluates relocation-backed constants only; it does not execute or patch the
sample and does not alter authentication behavior.
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
X19 = 0x585E2D84F3FC9F95


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


def runtime_qwords(image: bytes) -> dict[int, int]:
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


def recover_common_base(image: bytes, rt: dict[int, int]) -> int:
    """Evaluate 0x29F050..0x29F078, before the per-slot add immediate."""
    x8 = rt.get(0x51BBE8, qword(image, 0x51BBE8))
    x9 = rt.get(0x51B6C8, qword(image, 0x51B6C8))
    x8 = (-x8) & MASK
    x8 ^= X19
    x8 = (x8 * 0x45 + 0x45) & MASK
    x8 ^= X19
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

    rt = runtime_qwords(image)
    base = recover_common_base(image, rt)
    print(f"[+] common publication base    0x{base:x}")
    if base != 0x539ACF:
        raise SystemExit(f"unexpected base 0x{base:x}")

    slots = [
        (0, 0x01, 0x360, "auth UI status/result text"),
        (1, 0x19, 0x158, "step transition field"),
        (2, 0x31, 0x128, "UI-displayed field"),
        (3, 0x49, 0x050, "original auth input/key"),
        (4, 0x61, 0x198, "auth-core-produced field"),
    ]
    for idx, delta, src, role in slots:
        print(
            f"[+] g[{idx}] 0x{base + delta:x} <- "
            f"{'[sp+0x50] pointer' if idx == 3 else f'sp+0x{src:x}'}  {role}"
        )

    print("[+] auth_core entry preserves x0 at 0x298C04 (mov x23,x0)")
    print("[+] original x0 pointer saved at 0x299480 -> [sp+0x50]")
    print("[+] g[3] publication uses that pointer at 0x29F07C..0x29F08C")
    print("[+] manual worker passes key object at 0x2952BC -> auth_core")
    print("[+] auto worker passes key object at 0x294918 -> auth_core")
    print("[+] do not label g[1]/g[4] as protocol fields until their producers are traced")


if __name__ == "__main__":
    main()
