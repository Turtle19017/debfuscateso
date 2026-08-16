#!/usr/bin/env python3
"""Restore an ELF64 header/program-header table onto the recovered inner raw file.

This intentionally restores only structures supported by recovered evidence. It
does not attempt to decrypt/rebuild PT_DYNAMIC; use this file to validate the
original program-header/file-to-VA layout with standard ELF tools.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

ET_DYN = 3
EM_AARCH64 = 183
EV_CURRENT = 1


def pack_ehdr(e_phoff: int, e_phnum: int) -> bytes:
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1
    return bytes(ident) + struct.pack(
        "<HHIQQQIHHHHHH",
        ET_DYN,
        EM_AARCH64,
        EV_CURRENT,
        0,
        e_phoff,
        0,
        0,
        64,
        56,
        e_phnum,
        64,
        0,
        0,
    )


def pack_phdr(r: dict) -> bytes:
    return struct.pack(
        "<IIQQQQQQ",
        r["p_type"],
        r["p_flags"],
        r["p_offset"],
        r["p_vaddr"],
        r["p_paddr_inferred"],
        r["p_filesz"],
        r["p_memsz"],
        r["p_align_inferred"],
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("inner_raw", type=Path)
    ap.add_argument("phdr_manifest", type=Path)
    ap.add_argument("output", type=Path)
    args = ap.parse_args()

    data = bytearray(args.inner_raw.read_bytes())
    manifest = json.loads(args.phdr_manifest.read_text(encoding="utf-8"))
    recs = manifest["program_headers"]
    facts = manifest["elf_header_facts"]
    phoff = facts["e_phoff"]
    phnum = facts["e_phnum"]
    phblob = b"".join(pack_phdr(r) for r in recs)
    if len(phblob) != phnum * 56:
        raise SystemExit("program-header length mismatch")
    end = phoff + len(phblob)
    if end != 0x238:
        print(f"[!] recovered PHDR end is 0x{end:x}, expected sample anchor 0x238")
    if len(data) < end:
        raise SystemExit("inner image too small")

    note_before = bytes(data[0x238:0x2D0]) if len(data) >= 0x2D0 else b""
    data[:64] = pack_ehdr(phoff, phnum)
    data[phoff:end] = phblob
    if note_before and bytes(data[0x238:0x2D0]) != note_before:
        raise SystemExit("PT_NOTE bytes unexpectedly changed")

    args.output.write_bytes(data)
    print(f"[+] wrote {args.output}")
    print(f"    e_phoff=0x{phoff:x} e_phnum={phnum} phdr_end=0x{end:x}")
    print("    PT_DYNAMIC bytes are still protected/raw and are NOT reconstructed by this tool")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
