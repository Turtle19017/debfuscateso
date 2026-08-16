#!/usr/bin/env python3
"""Recover the protected inner module's compact program-header table.

The outer YSM loader stores nine 40-byte records at VA 0x414330. Each byte is
XOR-obfuscated with the seed byte recorded by FD140 (0x2d for the mapped sample).
The compact record preserves the fields needed by the custom loader:

    uint32 p_type
    uint32 p_flags
    uint64 p_vaddr
    uint64 p_memsz
    uint64 p_filesz
    uint64 p_offset

p_paddr and p_align are not present in this compact representation. This tool
emits the exact recovered fields plus clearly-marked inferred p_paddr/p_align
values useful for rebuilding an ELF header for analysis.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path

SAMPLE_SHA256 = "acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca"
LOADS = (
    (0x000000, 0x000000, 0x390D84),
    (0x391780, 0x3A1780, 0x38B660),
    (0x71E000, 0xD73000, 0x29F4),
)

PHDR_TABLE_VA = 0x414330
PHDR_COUNT_VA = 0x72CD70
PHDR_SEED_VA = 0x72CD88
COMPACT_PHDR_SIZE = 40
ELF64_PHDR_SIZE = 56

PT_NAMES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    4: "PT_NOTE",
    6: "PT_PHDR",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def va_to_offset(va: int) -> int:
    for file_off, seg_va, file_size in LOADS:
        if seg_va <= va < seg_va + file_size:
            return file_off + (va - seg_va)
    raise ValueError(f"VA 0x{va:x} outside known outer LOAD ranges")


def read_va(image: bytes, va: int, size: int) -> bytes:
    off = va_to_offset(va)
    if off + size > len(image):
        raise ValueError(f"read beyond image at VA 0x{va:x}")
    return image[off : off + size]


def infer_align(ptype: int, offset: int, vaddr: int) -> tuple[int, str]:
    """Return a conservative analysis alignment and why it is inferred.

    The compact records do not preserve p_align. For PT_LOAD the recovered
    offset/vaddr congruence is consistent with Android arm64 16 KiB pages.
    Other values follow normal ELF ABI conventions only for analysis.
    """
    if ptype == 1:
        return 0x4000, "inferred: all PT_LOAD offset/vaddr pairs are congruent mod 0x4000"
    if ptype in (6, 2):
        return 8, "inferred ABI-typical alignment"
    if ptype in (4, 0x6474E550):
        return 4, "inferred ABI-typical alignment"
    if ptype == 0x6474E551:
        return 0x10, "inferred ABI-typical GNU_STACK alignment"
    if ptype == 0x6474E552:
        return 1, "inferred; compact table does not preserve p_align"
    return 1, "inferred fallback"


def decode(image: bytes) -> tuple[int, int, list[dict]]:
    count = struct.unpack("<I", read_va(image, PHDR_COUNT_VA, 4))[0]
    seed = read_va(image, PHDR_SEED_VA, 1)[0]
    raw = read_va(image, PHDR_TABLE_VA, count * COMPACT_PHDR_SIZE)
    records = []
    for i in range(count):
        enc = raw[i * COMPACT_PHDR_SIZE : (i + 1) * COMPACT_PHDR_SIZE]
        dec = bytes(b ^ seed for b in enc)
        p_type, p_flags, p_vaddr, p_memsz, p_filesz, p_offset = struct.unpack(
            "<IIQQQQ", dec
        )
        p_align, align_note = infer_align(p_type, p_offset, p_vaddr)
        records.append(
            {
                "index": i,
                "p_type": p_type,
                "p_type_name": PT_NAMES.get(p_type, f"0x{p_type:x}"),
                "p_flags": p_flags,
                "p_offset": p_offset,
                "p_vaddr": p_vaddr,
                "p_filesz": p_filesz,
                "p_memsz": p_memsz,
                "p_paddr_inferred": p_vaddr,
                "p_align_inferred": p_align,
                "align_note": align_note,
            }
        )
    return count, seed, records


def pack_full_phdr(record: dict) -> bytes:
    return struct.pack(
        "<IIQQQQQQ",
        record["p_type"],
        record["p_flags"],
        record["p_offset"],
        record["p_vaddr"],
        record["p_paddr_inferred"],
        record["p_filesz"],
        record["p_memsz"],
        record["p_align_inferred"],
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Recover compact protected-inner program headers")
    ap.add_argument("outer_so", type=Path)
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--strict-hash", action="store_true")
    args = ap.parse_args()

    image = args.outer_so.read_bytes()
    digest = sha256(image)
    if digest != SAMPLE_SHA256:
        msg = f"input SHA-256 differs from mapped sample: {digest}"
        if args.strict_hash:
            raise SystemExit("[!] " + msg)
        print("[!] warning:", msg)

    count, seed, records = decode(image)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    with (args.output_dir / "phdrs.tsv").open("w", encoding="utf-8", newline="") as f:
        cols = [
            "index", "p_type_name", "p_type", "p_flags", "p_offset", "p_vaddr",
            "p_filesz", "p_memsz", "p_paddr_inferred", "p_align_inferred", "align_note",
        ]
        w = csv.DictWriter(f, fieldnames=cols, delimiter="\t")
        w.writeheader()
        for r in records:
            row = dict(r)
            for k in (
                "p_type", "p_flags", "p_offset", "p_vaddr", "p_filesz", "p_memsz",
                "p_paddr_inferred", "p_align_inferred",
            ):
                row[k] = f"0x{row[k]:x}"
            w.writerow(row)

    (args.output_dir / "phdrs.inferred.bin").write_bytes(
        b"".join(pack_full_phdr(r) for r in records)
    )

    phdr = next((r for r in records if r["p_type"] == 6), None)
    facts = {
        "input_sha256": digest,
        "source": {
            "table_va": PHDR_TABLE_VA,
            "count_va": PHDR_COUNT_VA,
            "seed_va": PHDR_SEED_VA,
            "count": count,
            "seed": seed,
            "compact_record_size": COMPACT_PHDR_SIZE,
        },
        "elf_header_facts": {
            "e_ehsize": 0x40,
            "e_phoff": phdr["p_offset"] if phdr else None,
            "e_phentsize": ELF64_PHDR_SIZE,
            "e_phnum": count,
            "phdr_table_size": count * ELF64_PHDR_SIZE,
            "phdr_end": (phdr["p_offset"] + count * ELF64_PHDR_SIZE) if phdr else None,
        },
        "notes": [
            "p_type/p_flags/p_offset/p_vaddr/p_filesz/p_memsz are recovered exactly from the compact table",
            "p_paddr and p_align are not present in the compact table and are inferred in phdrs.inferred.bin",
        ],
        "program_headers": records,
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(facts, indent=2), encoding="utf-8"
    )

    print(f"[+] count          {count}")
    print(f"[+] XOR seed       0x{seed:02x}")
    if phdr:
        print(f"[+] e_phoff        0x{phdr['p_offset']:x}")
        print(f"[+] e_phnum        {count}")
        print(f"[+] PHDR end       0x{phdr['p_offset'] + count * ELF64_PHDR_SIZE:x}")
    for r in records:
        print(
            f"    {r['index']:2d} {r['p_type_name']:<15} flags=0x{r['p_flags']:x} "
            f"off=0x{r['p_offset']:x} va=0x{r['p_vaddr']:x} "
            f"filesz=0x{r['p_filesz']:x} memsz=0x{r['p_memsz']:x}"
        )
    print(f"[+] wrote          {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
