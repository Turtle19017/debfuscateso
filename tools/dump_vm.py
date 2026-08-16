#!/usr/bin/env python3
"""Extract the six mapped VM bytecode streams from the sample SO."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

EXTRA_SEGMENT_VA = 0xD73000
EXTRA_SEGMENT_FILE_OFFSET = 0x71E000

PROGRAMS = [
    ("FD55C", 0xFD55C, 0xD736EC, 0xD73794, 0x827),
    ("FDDC4", 0xFDDC4, 0xD73708, 0xD73FBC, 0x21D),
    ("FD3E4", 0xFD3E4, 0xD73724, 0xD741DC, 0x5FB),
    ("FD33C", 0xFD33C, 0xD73740, 0xD747D8, 0x227),
    ("FD7C4", 0xFD7C4, 0xD7375C, 0xD74A00, 0x7B6),
    ("FDFFC", 0xFDFFC, 0xD73778, 0xD751B8, 0x83C),
]


def va_to_file_offset(va: int) -> int:
    if va < EXTRA_SEGMENT_VA:
        raise ValueError(f"VA 0x{va:X} is below extra segment")
    return EXTRA_SEGMENT_FILE_OFFSET + (va - EXTRA_SEGMENT_VA)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path, help="original or outer-decrypted SO")
    ap.add_argument("out_dir", type=Path)
    args = ap.parse_args()

    src = args.input.read_bytes()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "input": str(args.input),
        "input_sha256": hashlib.sha256(src).hexdigest(),
        "extra_segment": {
            "va": hex(EXTRA_SEGMENT_VA),
            "file_offset": hex(EXTRA_SEGMENT_FILE_OFFSET),
        },
        "programs": [],
    }

    for name, target_va, record_va, code_va, size in PROGRAMS:
        off = va_to_file_offset(code_va)
        end = off + size
        if end > len(src):
            raise SystemExit(f"{name}: bytecode exceeds input file")
        blob = src[off:end]
        out = args.out_dir / f"{name.lower()}.vm.bin"
        out.write_bytes(blob)
        item = {
            "name": name,
            "protected_function_va": hex(target_va),
            "record_va": hex(record_va),
            "bytecode_va": hex(code_va),
            "file_offset": hex(off),
            "size": hex(size),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "file": out.name,
        }
        manifest["programs"].append(item)
        print(f"{name:6s} VA=0x{code_va:X} off=0x{off:X} size=0x{size:X} -> {out}")

    manifest_path = args.out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"manifest -> {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
