#!/usr/bin/env python3
"""Verify the YSM v3 IL2CPP resolver, consumer helpers, and nearby XZ loader code.

Sample-specific static analysis only. This tool does not patch hooks, bypass
licensing, or alter runtime validation.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA256 = "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1"
TEXT_END = 0x4E29C0


def u32(image: bytes, off: int) -> int:
    return struct.unpack_from("<I", image, off)[0]


def cstr(image: bytes, off: int) -> str:
    end = image.index(0, off)
    return image[off:end].decode("ascii")


def bl_target(image: bytes, pc: int) -> int | None:
    w = u32(image, pc)
    if (w & 0xFC000000) != 0x94000000:
        return None
    imm = w & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return pc + (imm << 2)


def b_target(image: bytes, pc: int) -> int | None:
    w = u32(image, pc)
    if (w & 0xFC000000) != 0x14000000:
        return None
    imm = w & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return pc + (imm << 2)


def adr_target(image: bytes, pc: int) -> int | None:
    w = u32(image, pc)
    if (w & 0x9F000000) != 0x10000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return pc + imm


def direct_callers(image: bytes, target: int) -> list[int]:
    return [pc for pc in range(0, TEXT_END, 4) if bl_target(image, pc) == target]


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

    assert bl_target(image, 0x3016C0) == 0x356FCC
    assert bl_target(image, 0x3016D8) == 0x356FCC
    for pc in range(0x3016FC, 0x3018F5, 0x1C):
        assert bl_target(image, pc) == 0x357184, hex(pc)
    assert b_target(image, 0x301910) == 0x357128

    exports = [
        (0x104E7E, 0x0E0, "il2cpp_assembly_get_image"),
        (0x1108CA, 0x0D8, "il2cpp_domain_get"),
        (0x0F9B35, 0x0D0, "il2cpp_domain_get_assemblies"),
        (0x11C38E, 0x0E8, "il2cpp_image_get_name"),
        (0x10F513, 0x110, "il2cpp_class_from_name"),
        (0x107281, 0x128, "il2cpp_class_get_field_from_name"),
        (0x1187F1, 0x140, "il2cpp_class_get_method_from_name"),
        (0x10E484, 0x168, "il2cpp_field_get_offset"),
        (0x11D5CC, 0x130, "il2cpp_field_static_get_value"),
        (0x1095DC, 0x138, "il2cpp_field_static_set_value"),
        (0x115409, 0x120, "il2cpp_array_new"),
        (0x0FBE16, 0x170, "il2cpp_string_chars"),
        (0x11415C, 0x0C0, "il2cpp_string_new"),
        (0x104E98, 0x0C8, "il2cpp_string_new_utf16"),
        (0x116303, 0x160, "il2cpp_type_get_name"),
        (0x0FDD8A, 0x158, "il2cpp_method_get_param"),
        (0x11AE01, 0x148, "il2cpp_class_get_methods"),
        (0x0F9B52, 0x150, "il2cpp_method_get_name"),
        (0x11541A, 0x118, "il2cpp_object_new"),
    ]
    for addr, _slot, expected in exports:
        assert cstr(image, addr) == expected

    assert u32(image, 0x3011A0) == 0xB00019E8
    assert u32(image, 0x3011A4) == 0xF9406101
    assert u32(image, 0x3011A8) == 0xD61F0020

    callers = {
        0x3011A0: direct_callers(image, 0x3011A0),
        0x301474: direct_callers(image, 0x301474),
        0x301590: direct_callers(image, 0x301590),
    }
    assert len(callers[0x3011A0]) == 14
    assert len(callers[0x301474]) == 27
    assert len(callers[0x301590]) == 8

    provider = 0x3016AC
    assert not direct_callers(image, provider)
    assert not [pc for pc in range(0, TEXT_END, 4) if b_target(image, pc) == provider]
    assert not [pc for pc in range(0, TEXT_END, 4) if adr_target(image, pc) == provider]

    xz_literals = {
        0x105071: "/system/lib64/liblzma.so",
        0x112E74: "CrcGenerateTable",
        0x11AFBF: "Crc64GenerateTable",
        0x11C434: "XzUnpacker_Construct",
        0x0F9C1C: "XzUnpacker_IsStreamWasFinished",
        0x0FF117: "XzUnpacker_Free",
        0x103D33: "XzUnpacker_Code",
        0x104E1E: ".symtab",
    }
    for addr, expected in xz_literals.items():
        assert cstr(image, addr) == expected
    assert bl_target(image, 0x358888) == 0x356FCC
    for pc in (0x3588A0, 0x3588BC, 0x3588D8, 0x3588F8, 0x358918, 0x358938):
        assert bl_target(image, pc) == 0x357184
    assert direct_callers(image, 0x358810) == [0x357C64]

    print(f"[+] SHA-256                   {digest}")
    print("[+] provider                  0x3016AC: polling custom module open + 19 IL2CPP exports")
    print("[+] provider tail             0x301910 -> 0x357128 (free wrapper; return underlying handle)")
    print("[+] corrected table map")
    for _addr, slot, name in exports:
        print(f"    0x63E000+0x{slot:03x}  {name}")
    print("[+] consumer 0x3011A0        il2cpp_string_new trampoline; direct callers = 14")
    print("[+] consumer 0x301474        method-pointer resolver; direct callers = 27")
    print("[+] consumer 0x301590        field-offset resolver; direct callers = 8")
    print("[+] provider direct BL/B/ADR  none; trigger remains indirect/obfuscated")
    print("[+] 0x358810                  XZ/liblzma decompression adapter, not proven game-hook init")
    print("[+] 0x357C04 cluster          custom ELF/loader machinery (.symtab aware)")
    print("[+] next                       resolve indirect trigger into 0x3016AC")


if __name__ == "__main__":
    main()
