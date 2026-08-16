#!/usr/bin/env python3
"""Regenerate symbolic .rela.dyn using the recovered inner PT_LOAD mapping.

The original custom relocation target is an inner virtual address. Earlier
normalization treated that value as a raw-file offset when reading the pre-
relocation qword for R_AARCH64_ABS64. That is only valid for PT_LOAD #1.
PT_LOAD #2 and #3 have VA-file deltas 0x4000 and 0x8000 respectively.

This helper reproduces the 3749 symbolic relocations directly from the outer
metadata and reads ABS64 source qwords through the recovered original inner
PT_LOAD mapping before emitting standard Elf64_Rela records.
"""
from __future__ import annotations
import argparse
import hashlib
import struct
from pathlib import Path

SAMPLE_SHA256 = "acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca"
OUTER_LOADS = (
    (0x000000, 0x000000, 0x390D84),
    (0x391780, 0x3A1780, 0x38B660),
    (0x71E000, 0xD73000, 0x29F4),
)
INNER_LOADS = (
    (0x000000, 0x000000, 0x4E29C0, 0x4E29C0),
    (0x4E29C0, 0x4E69C0, 0x029DD8, 0x02A640),
    (0x50C7A0, 0x5147A0, 0x022DC0, 0x12E1F1),
)
SEED_K_VA = 0x0B9760
SEED_TABLE_VA = 0x31E790
RELOC_RECORDS_VA = 0x3B29D0
RELOC_RECORD_BYTES_VA = 0x3D73A4
RELOC_RECORD_COUNT_VA = 0x72CD10
RELOC_SEED_INDEX = 7
RECORD_SIZE = 40
R_AARCH64_ABS64 = 0x101
R_AARCH64_GLOB_DAT = 0x401


def outer_va_to_off(va: int) -> int:
    for file_off, seg_va, file_size in OUTER_LOADS:
        if seg_va <= va < seg_va + file_size:
            return file_off + (va - seg_va)
    raise ValueError(f"outer VA 0x{va:x} outside known LOADs")


def read_outer(image: bytes, va: int, size: int) -> bytes:
    off = outer_va_to_off(va)
    return image[off : off + size]


def u32_outer(image: bytes, va: int) -> int:
    return struct.unpack("<I", read_outer(image, va, 4))[0]


def derive_seed16(image: bytes) -> bytes:
    k = read_outer(image, SEED_K_VA, 16)
    t = read_outer(image, SEED_TABLE_VA, 64)
    a, b, c, d = t[0::4], t[1::4], t[2::4], t[3::4]
    return bytes((d[i] + c[i] + k[i] * b[i] + k[i] * k[i] * a[i]) & 0xFF for i in range(16))


def cb1d8(data: bytes, seed: int) -> bytes:
    out = bytearray(data)
    state = seed & 0xFFFFFFFF
    prev = 0
    for i, old in enumerate(data):
        state = (state * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        state ^= (prev << 8) & 0xFFFFFFFF
        state ^= i & 0xFFFFFFFF
        out[i] = old ^ ((state >> 16) & 0xFF)
        prev = old
    return bytes(out)


def read_inner_qword(inner: bytes, va: int) -> int | None:
    for file_off, seg_va, file_size, mem_size in INNER_LOADS:
        if seg_va <= va and va + 8 <= seg_va + file_size:
            off = file_off + (va - seg_va)
            if off + 8 > len(inner):
                raise ValueError(f"inner file too short for VA 0x{va:x}")
            return struct.unpack_from("<Q", inner, off)[0]
        if seg_va + file_size <= va and va + 8 <= seg_va + mem_size:
            return 0  # zero-filled BSS before relocation
    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Fix YSM ABS64 RELA addends using recovered inner VA-to-file mapping"
    )
    ap.add_argument("outer_so", type=Path)
    ap.add_argument("inner_raw", type=Path)
    ap.add_argument("output", type=Path, help="corrected 3749-entry symbolic rela.dyn.bin")
    ap.add_argument("--compare", type=Path, help="optional previous rela.dyn.bin")
    ap.add_argument("--strict-hash", action="store_true")
    args = ap.parse_args()

    outer = args.outer_so.read_bytes()
    inner = args.inner_raw.read_bytes()
    digest = hashlib.sha256(outer).hexdigest()
    if digest != SAMPLE_SHA256:
        msg = f"outer SHA-256 differs from mapped sample: {digest}"
        if args.strict_hash:
            raise SystemExit("[!] " + msg)
        print("[!] warning:", msg)

    seed16 = derive_seed16(outer)
    record_bytes = u32_outer(outer, RELOC_RECORD_BYTES_VA)
    record_count = u32_outer(outer, RELOC_RECORD_COUNT_VA)
    if record_bytes != record_count * RECORD_SIZE:
        raise SystemExit("custom relocation byte/count mismatch")

    encrypted = read_outer(outer, RELOC_RECORDS_VA, record_bytes)
    decoded = cb1d8(encrypted, seed16[RELOC_SEED_INDEX])
    output = bytearray()
    abs64_count = glob_count = 0
    anchor = None

    for i in range(record_count):
        q0, q1, q2, q3, q4 = struct.unpack_from("<5Q", decoded, i * RECORD_SIZE)
        reloc_type = q0 & 0xFFFFFFFF
        direction = q3 & 0xFF
        if direction not in (0, 1):
            raise SystemExit(f"record {i}: invalid target direction {direction}")
        target = q1 - q2 if direction else q1 + q2

        if reloc_type == R_AARCH64_ABS64:
            original = read_inner_qword(inner, target)
            if original is None:
                raise SystemExit(f"ABS64 target 0x{target:x} outside recovered inner PT_LOAD memory")
            addend = (original + q4) & 0xFFFFFFFFFFFFFFFF
            abs64_count += 1
        elif reloc_type == R_AARCH64_GLOB_DAT:
            original = None
            addend = q4
            glob_count += 1
        else:
            raise SystemExit(f"record {i}: unexpected relocation type 0x{reloc_type:x}")

        signed = addend if addend < (1 << 63) else addend - (1 << 64)
        output += struct.pack("<QQq", target, q0, signed)
        if target == 0x5241C8:
            anchor = (i, original, q4, signed)

    args.output.write_bytes(output)
    print(
        f"[+] wrote {args.output}: {record_count} entries "
        f"({abs64_count} ABS64, {glob_count} GLOB_DAT)"
    )

    if args.compare:
        old = args.compare.read_bytes()
        if len(old) != len(output):
            print(f"[!] compare size differs: 0x{len(old):x} != 0x{len(output):x}")
        else:
            changed = sum(
                old[i * 24 : (i + 1) * 24] != output[i * 24 : (i + 1) * 24]
                for i in range(record_count)
            )
            print(f"[+] changed entries vs previous: {changed}/{record_count}")

    if anchor is not None:
        index, original, q4, signed = anchor
        expected = -0x73C92442917AACA3
        print(
            f"[+] crash anchor VA 0x5241c8: record={index} "
            f"original=0x{original:x} q4=0x{q4:x} addend={signed}"
        )
        if digest == SAMPLE_SHA256 and signed != expected:
            raise SystemExit(f"mapped-sample crash anchor mismatch: {signed} != {expected}")
        if signed == expected:
            print("[+] crash anchor matches the corrected dl_iterate_phdr addend")


if __name__ == "__main__":
    main()
