#!/usr/bin/env python3
"""Recover inner ELF symbol metadata embedded/encrypted in libysmteam.so.

This is sample-specific research tooling for the analyzed ARM64 YSM loader. It does
not execute the Android target. It reproduces the fixed metadata seed, applies the
CB1D8 byte-stream transform, parses Elf64_Sym entries, and maps the custom 40-byte
PLT records onto the inner image's 0x10-byte PLT stubs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Iterable

SAMPLE_SHA256 = "acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca"

LOADS = (
    (0x000000, 0x000000, 0x390D84),
    (0x391780, 0x3A1780, 0x38B660),
    (0x71E000, 0xD73000, 0x29F4),
)

SEED_K_VA = 0x0B9760
SEED_TABLE_VA = 0x31E790

DYNSTR_VA = 0x4144A0
DYNSTR_LEN_VA = 0x3D73A0
DYNSTR_SEED_INDEX = 8

DYNSYM_VA = 0x704C10
DYNSYM_LEN_VA = 0x704C00
DYNSYM_SEED_INDEX = 3
ELF64_SYM_SIZE = 24

PLT_RECORDS_VA = 0x4431A0
PLT_RECORD_BYTES_VA = 0x72CD14
PLT_RECORD_COUNT_VA = 0x704C04
PLT_RECORD_SEED_INDEX = 5
PLT_RECORD_SIZE = 40
INNER_PLT_FIRST = 0x4D6830
INNER_PLT_STRIDE = 0x10
AARCH64_JUMP_SLOT = 0x402

RELOC_RECORDS_VA = 0x3B29D0
RELOC_RECORD_BYTES_VA = 0x3D73A4
RELOC_RECORD_COUNT_VA = 0x72CD10
RELOC_RECORD_SEED_INDEX = 7

KNOWN_EXPECTATIONS = {
    "JNI_OnLoad": (0x27C444, 0x49C),
    "Java_com_ysmteam_imgui_GLES3JNIView_init": (0x26931C, 0x6774),
    "Java_com_ysmteam_imgui_GLES3JNIView_resize": (0x26FA90, 0x60),
    "Java_com_ysmteam_imgui_GLES3JNIView_step": (0x26FAF0, 0x380),
    "Java_com_ysmteam_imgui_GLES3JNIView_imgui_Shutdown": (0x26FE70, 0x3C),
    "Java_com_ysmteam_imgui_GLES3JNIView_getWindowRect": (0x26FEAC, 0x220),
    "Java_com_ysmteam_imgui_GLES3JNIView_onTouch": (0x2700CC, 0xAC),
    "DobbyHook": (0x358CE8, 0x158),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def va_to_offset(va: int) -> int:
    for file_off, seg_va, file_size in LOADS:
        if seg_va <= va < seg_va + file_size:
            return file_off + (va - seg_va)
    raise ValueError(f"VA 0x{va:x} is outside known file-backed LOAD ranges")


def read_va(image: bytes, va: int, size: int) -> bytes:
    off = va_to_offset(va)
    end = off + size
    if end > len(image):
        raise ValueError(f"read beyond image: VA=0x{va:x}, size=0x{size:x}")
    return image[off:end]


def u32_va(image: bytes, va: int) -> int:
    return struct.unpack("<I", read_va(image, va, 4))[0]


def derive_seed16(image: bytes) -> bytes:
    """Reproduce B96D0's fixed 16-byte metadata seed."""
    k = read_va(image, SEED_K_VA, 16)
    t = read_va(image, SEED_TABLE_VA, 64)
    a, b, c, d = t[0::4], t[1::4], t[2::4], t[3::4]
    return bytes((d[i] + c[i] + k[i] * b[i] + k[i] * k[i] * a[i]) & 0xFF for i in range(16))


def cb1d8(data: bytes, seed: int) -> bytes:
    """Reproduce the sample's CB1D8 metadata stream transform."""
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


def cstring(buf: bytes, off: int) -> str:
    if off < 0 or off >= len(buf):
        return f"<bad-st_name:0x{off:x}>"
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("utf-8", errors="replace")


def parse_dynsym(dynsym: bytes, dynstr: bytes) -> list[dict]:
    if len(dynsym) % ELF64_SYM_SIZE:
        raise ValueError(f"dynsym size 0x{len(dynsym):x} is not divisible by 24")
    result = []
    for i in range(len(dynsym) // ELF64_SYM_SIZE):
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", dynsym, i * ELF64_SYM_SIZE
        )
        result.append({
            "index": i,
            "name_offset": st_name,
            "name": cstring(dynstr, st_name) if st_name else "",
            "bind": st_info >> 4,
            "type": st_info & 0xF,
            "other": st_other,
            "shndx": st_shndx,
            "value": st_value,
            "size": st_size,
        })
    return result


def parse_custom_records(raw: bytes, count: int) -> list[dict]:
    if len(raw) != count * PLT_RECORD_SIZE:
        raise ValueError(
            f"custom record length mismatch: got 0x{len(raw):x}, expected 0x{count * PLT_RECORD_SIZE:x}"
        )
    records = []
    for i in range(count):
        rec = raw[i * PLT_RECORD_SIZE : (i + 1) * PLT_RECORD_SIZE]
        q = struct.unpack("<5Q", rec)
        r_info = q[0]
        records.append({
            "index": i,
            "r_info": r_info,
            "symbol_index": r_info >> 32,
            "reloc_type": r_info & 0xFFFFFFFF,
            "qwords": list(q),
        })
    return records


def attach_plt_names(records: list[dict], symbols: list[dict]) -> list[dict]:
    out = []
    for rec in records:
        idx = rec["symbol_index"]
        sym = symbols[idx] if 0 <= idx < len(symbols) else None
        out.append({
            **rec,
            "plt_address": INNER_PLT_FIRST + rec["index"] * INNER_PLT_STRIDE,
            "symbol_name": sym["name"] if sym else "<bad-symbol-index>",
            "symbol_value": sym["value"] if sym else 0,
            "symbol_size": sym["size"] if sym else 0,
        })
    return out


def write_tsv(path: Path, rows: Iterable[dict], columns: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        f.write("\t".join(columns) + "\n")
        for row in rows:
            vals = []
            for c in columns:
                v = row.get(c, "")
                if isinstance(v, int) and c in {
                    "value", "size", "plt_address", "r_info", "reloc_type",
                    "symbol_value", "symbol_size"
                }:
                    vals.append(f"0x{v:x}")
                else:
                    vals.append(str(v).replace("\t", " ").replace("\n", "\\n"))
            f.write("\t".join(vals) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Recover encrypted inner dynstr/dynsym and PLT mapping from libysmteam.so"
    )
    ap.add_argument("outer_so", type=Path)
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--strict-hash", action="store_true", help="require the known sample SHA-256")
    ap.add_argument("--dump-raw", action="store_true", help="also write decrypted metadata blobs")
    args = ap.parse_args()

    image = args.outer_so.read_bytes()
    digest = sha256(image)
    if digest != SAMPLE_SHA256:
        msg = f"input SHA-256 differs from mapped sample: {digest}"
        if args.strict_hash:
            raise SystemExit("[!] " + msg)
        print("[!] warning:", msg)

    seed16 = derive_seed16(image)
    expected_seed = bytes.fromhex("9a0d6d36ed21f793e953996ea264e885")
    if seed16 != expected_seed:
        raise SystemExit(f"[!] unexpected seed16 {seed16.hex()}")

    dynstr_len = u32_va(image, DYNSTR_LEN_VA)
    dynsym_len = u32_va(image, DYNSYM_LEN_VA)
    plt_bytes = u32_va(image, PLT_RECORD_BYTES_VA)
    plt_count = u32_va(image, PLT_RECORD_COUNT_VA)
    reloc_bytes = u32_va(image, RELOC_RECORD_BYTES_VA)
    reloc_count = u32_va(image, RELOC_RECORD_COUNT_VA)

    dynstr = cb1d8(read_va(image, DYNSTR_VA, dynstr_len), seed16[DYNSTR_SEED_INDEX])
    dynsym = cb1d8(read_va(image, DYNSYM_VA, dynsym_len), seed16[DYNSYM_SEED_INDEX])
    symbols = parse_dynsym(dynsym, dynstr)

    plt_raw = cb1d8(read_va(image, PLT_RECORDS_VA, plt_bytes), seed16[PLT_RECORD_SEED_INDEX])
    plt_records = attach_plt_names(parse_custom_records(plt_raw, plt_count), symbols)

    reloc_raw = cb1d8(read_va(image, RELOC_RECORDS_VA, reloc_bytes), seed16[RELOC_RECORD_SEED_INDEX])
    reloc_records = parse_custom_records(reloc_raw, reloc_count)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_tsv(args.output_dir / "dynsym.tsv", symbols,
              ["index", "name", "bind", "type", "shndx", "value", "size"])
    write_tsv(args.output_dir / "plt.tsv", plt_records,
              ["index", "plt_address", "symbol_index", "symbol_name", "reloc_type", "symbol_value", "symbol_size"])

    by_name = {s["name"]: s for s in symbols if s["name"]}
    known = {}
    for name, (expected_va, expected_size) in KNOWN_EXPECTATIONS.items():
        s = by_name.get(name)
        known[name] = None if s is None else {
            "index": s["index"], "value": s["value"], "size": s["size"],
            "expected_value": expected_va, "expected_size": expected_size,
            "matches": s["value"] == expected_va and s["size"] == expected_size,
        }

    manifest = {
        "input_sha256": digest,
        "seed16": seed16.hex(),
        "dynstr": {"va": DYNSTR_VA, "length": dynstr_len, "sha256": sha256(dynstr)},
        "dynsym": {"va": DYNSYM_VA, "length": dynsym_len, "entries": len(symbols), "sha256": sha256(dynsym)},
        "plt_records": {
            "va": PLT_RECORDS_VA, "bytes": plt_bytes, "count": plt_count,
            "record_size": PLT_RECORD_SIZE, "first_plt": INNER_PLT_FIRST,
            "all_jump_slot": all(r["reloc_type"] == AARCH64_JUMP_SLOT for r in plt_records),
            "sha256": sha256(plt_raw),
        },
        "other_reloc_records": {
            "va": RELOC_RECORDS_VA, "bytes": reloc_bytes, "count": reloc_count,
            "record_size": PLT_RECORD_SIZE, "sha256": sha256(reloc_raw),
        },
        "known_symbols": known,
    }
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    if args.dump_raw:
        (args.output_dir / "dynstr.bin").write_bytes(dynstr)
        (args.output_dir / "dynsym.bin").write_bytes(dynsym)
        (args.output_dir / "plt_records.bin").write_bytes(plt_raw)
        (args.output_dir / "reloc_records.bin").write_bytes(reloc_raw)

    jni = by_name.get("JNI_OnLoad")
    print(f"[+] seed16           {seed16.hex()}")
    print(f"[+] dynstr           0x{dynstr_len:x} bytes")
    print(f"[+] dynsym           {len(symbols)} entries / 0x{dynsym_len:x} bytes")
    print(f"[+] PLT records      {plt_count} x 0x{PLT_RECORD_SIZE:x}, all JUMP_SLOT={manifest['plt_records']['all_jump_slot']}")
    print(f"[+] other relocs     {reloc_count} x 0x{PLT_RECORD_SIZE:x}")
    if jni:
        print(f"[+] JNI_OnLoad       sym#{jni['index']} VA=0x{jni['value']:x} size=0x{jni['size']:x}")
    for n in [
        "Java_com_ysmteam_imgui_GLES3JNIView_init",
        "Java_com_ysmteam_imgui_GLES3JNIView_resize",
        "Java_com_ysmteam_imgui_GLES3JNIView_step",
        "Java_com_ysmteam_imgui_GLES3JNIView_imgui_Shutdown",
        "Java_com_ysmteam_imgui_GLES3JNIView_getWindowRect",
        "Java_com_ysmteam_imgui_GLES3JNIView_onTouch",
        "DobbyHook",
    ]:
        s = by_name.get(n)
        if s:
            print(f"    {n} = 0x{s['value']:x} (0x{s['size']:x})")
    print(f"[+] wrote            {args.output_dir}")


if __name__ == "__main__":
    main()
