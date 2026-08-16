#!/usr/bin/env python3
"""Map Android tombstone module-relative PCs back into a reconstructed inner ELF.

Pure-stdlib helper: validates SHA-256, maps virtual addresses through PT_LOAD,
prints instruction bytes, and reports the nearest dynamic symbol.  This is useful
for catching stale/wrong APK installs before interpreting a crash log.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

PT_LOAD = 1
SHT_DYNSYM = 11


def cstr(buf: bytes, off: int) -> str:
    if not 0 <= off < len(buf):
        return ""
    end = buf.find(b"\0", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("utf-8", errors="replace")


def parse_int(text: str) -> int:
    return int(text, 0)


def main() -> int:
    ap = argparse.ArgumentParser(description="Map crash PCs into an ELF and sanity-check the exact build")
    ap.add_argument("elf", type=Path)
    ap.add_argument("pc", nargs="+", type=parse_int, help="module-relative PC(s), e.g. 0x287410")
    ap.add_argument("--expected-sha256")
    args = ap.parse_args()

    b = args.elf.read_bytes()
    digest = hashlib.sha256(b).hexdigest()
    print(f"sha256 {digest}")
    if args.expected_sha256 and digest.lower() != args.expected_sha256.lower():
        print(f"[!] SHA mismatch: expected {args.expected_sha256.lower()}")

    if len(b) < 64 or b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        raise SystemExit("expected ELF64 little-endian")

    e_phoff = struct.unpack_from("<Q", b, 0x20)[0]
    e_shoff = struct.unpack_from("<Q", b, 0x28)[0]
    e_phentsize = struct.unpack_from("<H", b, 0x36)[0]
    e_phnum = struct.unpack_from("<H", b, 0x38)[0]
    e_shentsize = struct.unpack_from("<H", b, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", b, 0x3C)[0]

    loads = []
    for i in range(e_phnum):
        p = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", b, p)
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<QQQQQQ", b, p + 8)
        if p_type == PT_LOAD:
            loads.append((p_offset, p_vaddr, p_filesz, p_memsz, p_flags, p_align))

    sections = []
    for i in range(e_shnum):
        s = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from("<II", b, s)
        sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQQ", b, s + 8)
        sh_link, sh_info = struct.unpack_from("<II", b, s + 40)
        sh_addralign, sh_entsize = struct.unpack_from("<QQ", b, s + 48)
        sections.append({
            "index": i, "name": sh_name, "type": sh_type, "flags": sh_flags,
            "addr": sh_addr, "offset": sh_offset, "size": sh_size,
            "link": sh_link, "info": sh_info, "addralign": sh_addralign,
            "entsize": sh_entsize,
        })

    symbols = []
    for sec in sections:
        if sec["type"] != SHT_DYNSYM or not sec["entsize"]:
            continue
        if sec["link"] >= len(sections):
            continue
        strsec = sections[sec["link"]]
        dynstr = b[strsec["offset"]:strsec["offset"] + strsec["size"]]
        count = sec["size"] // sec["entsize"]
        for i in range(count):
            p = sec["offset"] + i * sec["entsize"]
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", b, p)
            name = cstr(dynstr, st_name) if st_name else ""
            if name:
                symbols.append((st_value, st_size, name))
    symbols.sort(key=lambda x: x[0])

    def va_to_off(va: int):
        for off, vaddr, filesz, memsz, flags, algn in loads:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        return None

    def nearest_symbol(va: int):
        best = None
        for value, size, name in symbols:
            if value > va:
                break
            best = (value, size, name)
        return best

    for pc in args.pc:
        off = va_to_off(pc)
        print(f"\npc 0x{pc:x}")
        if off is None:
            print("  file offset: <not file-backed by PT_LOAD>")
        else:
            print(f"  file offset: 0x{off:x}")
            print(f"  bytes[pc-4:pc+8]: {b[max(0, off-4):min(len(b), off+8)].hex()}")
        sym = nearest_symbol(pc)
        if sym:
            value, size, name = sym
            inside = size == 0 or pc < value + size
            print(f"  nearest dynsym: {name} @ 0x{value:x} size 0x{size:x} delta +0x{pc-value:x} inside={inside}")
        else:
            print("  nearest dynsym: <none>")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
