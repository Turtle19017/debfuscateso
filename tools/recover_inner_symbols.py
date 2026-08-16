#!/usr/bin/env python3
"""Recover inner ELF symbols and normalize YSM custom relocation records.

Sample-specific static tooling for the analyzed ARM64 YSM loader. No Android
execution is required.

Besides decrypting dynstr/dynsym and naming PLT stubs, this version decodes the
40-byte custom relocation record consumed by outer function 0xFDA30:

    q0 = ELF r_info
    q1 = noisy target offset base
    q2 = 6-bit target delta
    q3 = direction flag (0 => q1+q2, 1 => q1-q2)
    q4 = relocation-side addend component

For the recovered non-PLT table the only types are R_AARCH64_ABS64 (0x101) and
R_AARCH64_GLOB_DAT (0x401). The outer loader's 0xFDA30 implementation applies:

    ABS64:     *P = *P + S + q4
    GLOB_DAT:  *P = S + q4
    JUMP_SLOT: *P = S + q4

Therefore a standard Elf64_Rela equivalent can be produced with effective
addend A = original_qword + q4 for ABS64, and A = q4 for GLOB_DAT/JUMP_SLOT.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path
from typing import Iterable

SAMPLE_SHA256 = "acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca"
INNER_SIZE = 0x530070
MEM_END = 0x643000

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

RELOC_RECORDS_VA = 0x3B29D0
RELOC_RECORD_BYTES_VA = 0x3D73A4
RELOC_RECORD_COUNT_VA = 0x72CD10
RELOC_RECORD_SEED_INDEX = 7

RECORD_SIZE = 40
INNER_PLT_FIRST = 0x4D6830
INNER_PLT_STRIDE = 0x10

R_AARCH64_ABS64 = 0x101
R_AARCH64_GLOB_DAT = 0x401
R_AARCH64_JUMP_SLOT = 0x402

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
    raise ValueError(f"VA 0x{va:x} outside known LOAD ranges")


def read_va(image: bytes, va: int, size: int) -> bytes:
    off = va_to_offset(va)
    end = off + size
    if end > len(image):
        raise ValueError(f"read beyond image VA=0x{va:x} size=0x{size:x}")
    return image[off:end]


def u32_va(image: bytes, va: int) -> int:
    return struct.unpack("<I", read_va(image, va, 4))[0]


def derive_seed16(image: bytes) -> bytes:
    k = read_va(image, SEED_K_VA, 16)
    t = read_va(image, SEED_TABLE_VA, 64)
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


def cstring(buf: bytes, off: int) -> str:
    if not 0 <= off < len(buf):
        return f"<bad-st_name:0x{off:x}>"
    end = buf.find(b"\0", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("utf-8", errors="replace")


def parse_dynsym(dynsym: bytes, dynstr: bytes) -> list[dict]:
    if len(dynsym) % ELF64_SYM_SIZE:
        raise ValueError("dynsym not divisible by 24")
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


def decode_custom_records(
    raw: bytes,
    count: int,
    symbols: list[dict],
    inner: bytes | None,
    kind: str,
) -> list[dict]:
    if len(raw) != count * RECORD_SIZE:
        raise ValueError("record length mismatch")

    result = []
    for i in range(count):
        q0, q1, q2, q3, q4 = struct.unpack_from("<5Q", raw, i * RECORD_SIZE)
        reloc_type = q0 & 0xFFFFFFFF
        symidx = q0 >> 32
        direction = q3 & 0xFF
        if direction not in (0, 1):
            raise ValueError(f"record {i}: unexpected direction flag {direction}")

        target = q1 - q2 if direction else q1 + q2
        sym = symbols[symidx] if 0 <= symidx < len(symbols) else None

        original = None
        if inner is not None:
            if target + 8 <= len(inner):
                original = struct.unpack_from("<Q", inner, target)[0]
            elif target < MEM_END:
                original = 0  # runtime BSS is zero-filled before relocation

        if reloc_type == R_AARCH64_ABS64:
            effective_addend = None if original is None else (original + q4) & 0xFFFFFFFFFFFFFFFF
        elif reloc_type in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT):
            effective_addend = q4
        else:
            effective_addend = None

        rec = {
            "index": i,
            "kind": kind,
            "r_info": q0,
            "symbol_index": symidx,
            "symbol_name": sym["name"] if sym else "<bad-symbol-index>",
            "reloc_type": reloc_type,
            "target_offset": target,
            "encoded_base": q1,
            "target_delta": q2,
            "direction": direction,
            "q4": q4,
            "original_qword": original,
            "effective_addend": effective_addend,
        }
        if kind == "plt":
            rec["plt_address"] = INNER_PLT_FIRST + i * INNER_PLT_STRIDE
        result.append(rec)
    return result


def pack_rela(records: list[dict]) -> bytes:
    out = bytearray()
    for rec in records:
        addend = rec["effective_addend"]
        if addend is None:
            raise ValueError(
                f"cannot normalize record {rec['index']} type 0x{rec['reloc_type']:x}"
            )
        signed = addend if addend < (1 << 63) else addend - (1 << 64)
        out += struct.pack("<QQq", rec["target_offset"], rec["r_info"], signed)
    return bytes(out)


def write_tsv(path: Path, rows: Iterable[dict], columns: list[str]) -> None:
    hex_columns = {
        "value", "size", "plt_address", "r_info", "reloc_type", "target_offset",
        "encoded_base", "target_delta", "q4", "original_qword", "effective_addend",
    }
    with path.open("w", encoding="utf-8", newline="") as f:
        f.write("\t".join(columns) + "\n")
        for row in rows:
            vals = []
            for c in columns:
                v = row.get(c, "")
                if v is None:
                    vals.append("")
                elif isinstance(v, int) and c in hex_columns:
                    vals.append(f"0x{v:x}")
                else:
                    vals.append(str(v).replace("\t", " ").replace("\n", "\\n"))
            f.write("\t".join(vals) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Recover inner symbols and normalize custom relocation tables"
    )
    ap.add_argument("outer_so", type=Path)
    ap.add_argument("output_dir", type=Path)
    ap.add_argument(
        "--inner", type=Path,
        help="recovered 0x530070-byte inner image; enables standard RELA addend recovery for ABS64",
    )
    ap.add_argument("--strict-hash", action="store_true")
    ap.add_argument("--dump-raw", action="store_true")
    args = ap.parse_args()

    image = args.outer_so.read_bytes()
    digest = sha256(image)
    if digest != SAMPLE_SHA256:
        msg = f"input SHA-256 differs from mapped sample: {digest}"
        if args.strict_hash:
            raise SystemExit("[!] " + msg)
        print("[!] warning:", msg)

    inner = args.inner.read_bytes() if args.inner else None
    if inner is not None and len(inner) != INNER_SIZE:
        print(f"[!] warning: inner size 0x{len(inner):x}, expected 0x{INNER_SIZE:x}")

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

    plt_raw = cb1d8(
        read_va(image, PLT_RECORDS_VA, plt_bytes), seed16[PLT_RECORD_SEED_INDEX]
    )
    reloc_raw = cb1d8(
        read_va(image, RELOC_RECORDS_VA, reloc_bytes), seed16[RELOC_RECORD_SEED_INDEX]
    )
    plt_records = decode_custom_records(plt_raw, plt_count, symbols, inner, "plt")
    reloc_records = decode_custom_records(reloc_raw, reloc_count, symbols, inner, "dyn")

    assert all(r["target_offset"] % 8 == 0 for r in plt_records + reloc_records)
    assert all(r["reloc_type"] == R_AARCH64_JUMP_SLOT for r in plt_records)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_tsv(
        args.output_dir / "dynsym.tsv", symbols,
        ["index", "name", "bind", "type", "shndx", "value", "size"],
    )
    write_tsv(
        args.output_dir / "plt.tsv", plt_records,
        ["index", "plt_address", "target_offset", "symbol_index", "symbol_name", "reloc_type", "q4", "effective_addend"],
    )
    write_tsv(
        args.output_dir / "relocs.tsv", reloc_records,
        ["index", "target_offset", "symbol_index", "symbol_name", "reloc_type", "encoded_base", "target_delta", "direction", "q4", "original_qword", "effective_addend"],
    )

    if inner is not None:
        (args.output_dir / "rela.plt.bin").write_bytes(pack_rela(plt_records))
        (args.output_dir / "rela.dyn.bin").write_bytes(pack_rela(reloc_records))

    by_name = {s["name"]: s for s in symbols if s["name"]}
    known = {}
    for name, (expected_va, expected_size) in KNOWN_EXPECTATIONS.items():
        s = by_name.get(name)
        known[name] = None if s is None else {
            "index": s["index"],
            "value": s["value"],
            "size": s["size"],
            "expected_value": expected_va,
            "expected_size": expected_size,
            "matches": s["value"] == expected_va and s["size"] == expected_size,
        }

    manifest = {
        "input_sha256": digest,
        "seed16": seed16.hex(),
        "dynstr": {"va": DYNSTR_VA, "length": dynstr_len, "sha256": sha256(dynstr)},
        "dynsym": {"va": DYNSYM_VA, "length": dynsym_len, "entries": len(symbols), "sha256": sha256(dynsym)},
        "plt_records": {
            "count": len(plt_records),
            "types": {f"0x{k:x}": v for k, v in Counter(r["reloc_type"] for r in plt_records).items()},
            "target_min": min(r["target_offset"] for r in plt_records),
            "target_max": max(r["target_offset"] for r in plt_records),
        },
        "other_reloc_records": {
            "count": len(reloc_records),
            "types": {f"0x{k:x}": v for k, v in Counter(r["reloc_type"] for r in reloc_records).items()},
            "target_min": min(r["target_offset"] for r in reloc_records),
            "target_max": max(r["target_offset"] for r in reloc_records),
        },
        "normalized_rela": inner is not None,
        "known_symbols": known,
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    if args.dump_raw:
        (args.output_dir / "dynstr.bin").write_bytes(dynstr)
        (args.output_dir / "dynsym.bin").write_bytes(dynsym)
        (args.output_dir / "plt_records.bin").write_bytes(plt_raw)
        (args.output_dir / "reloc_records.bin").write_bytes(reloc_raw)

    print(f"[+] seed16       {seed16.hex()}")
    print(f"[+] dynsym       {len(symbols)} entries")
    print(f"[+] non-PLT     {len(reloc_records)} records: {Counter(hex(r['reloc_type']) for r in reloc_records)}")
    print(
        f"[+] PLT         {len(plt_records)} JUMP_SLOT records, GOT slots "
        f"0x{min(r['target_offset'] for r in plt_records):x}..0x{max(r['target_offset'] for r in plt_records):x}"
    )
    if inner is not None:
        print(
            f"[+] normalized   rela.dyn.bin=0x{len(reloc_records) * 24:x} "
            f"rela.plt.bin=0x{len(plt_records) * 24:x}"
        )
    print(f"[+] wrote        {args.output_dir}")


if __name__ == "__main__":
    main()
