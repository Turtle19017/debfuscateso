#!/usr/bin/env python3
"""Extract the Base64-embedded DEX used by the reconstructed YSM inner module.

This is a static recovery helper for the mapped v3 image.  It validates the
known image hash when requested, locates the long Base64 literal whose decoded
bytes start with a Dalvik DEX magic, writes the DEX, and emits a small JSON
manifest with header/class facts.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import struct
from pathlib import Path

KNOWN_SHA256 = "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1"
EXPECTED_B64_OFF = 0x1016CA
EXPECTED_B64_LEN = 4892
EXPECTED_DEX_LEN = 3668
EXPECTED_DEX_SHA256 = "fdef253bbfbc40cff2de3f5e53fd3412f41a4912018978cd2f8a92f9e441a66b"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def uleb128(buf: bytes, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        value |= (b & 0x7F) << shift
        if b < 0x80:
            return value, off
        shift += 7


def dex_strings(dex: bytes) -> list[str]:
    count = u32(dex, 0x38)
    table = u32(dex, 0x3C)
    result = []
    for i in range(count):
        off = u32(dex, table + i * 4)
        _, p = uleb128(dex, off)
        end = dex.index(0, p)
        result.append(dex[p:end].decode("utf-8", errors="replace"))
    return result


def dex_types(dex: bytes, strings: list[str]) -> list[str]:
    count = u32(dex, 0x40)
    table = u32(dex, 0x44)
    return [strings[u32(dex, table + i * 4)] for i in range(count)]


def class_descriptors(dex: bytes, types: list[str]) -> list[str]:
    count = u32(dex, 0x60)
    table = u32(dex, 0x64)
    return [types[u32(dex, table + i * 32)] for i in range(count)]


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract the embedded Base64 DEX from reconstructed YSM inner ELF")
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--strict-hash", action="store_true")
    args = ap.parse_args()

    image = args.input.read_bytes()
    digest = sha256(image)
    if args.strict_hash and digest != KNOWN_SHA256:
        raise SystemExit(f"unexpected input SHA-256: {digest}")

    candidates = []
    for m in re.finditer(rb"[A-Za-z0-9+/=]{256,}", image):
        raw = m.group()
        try:
            decoded = base64.b64decode(raw, validate=True)
        except Exception:
            continue
        if decoded.startswith(b"dex\n"):
            candidates.append((m.start(), raw, decoded))

    if len(candidates) != 1:
        raise SystemExit(f"expected exactly one DEX Base64 candidate, got {len(candidates)}")

    off, encoded, dex = candidates[0]
    dex_digest = sha256(dex)
    if digest == KNOWN_SHA256:
        checks = {
            "offset": off == EXPECTED_B64_OFF,
            "base64_length": len(encoded) == EXPECTED_B64_LEN,
            "dex_length": len(dex) == EXPECTED_DEX_LEN,
            "dex_sha256": dex_digest == EXPECTED_DEX_SHA256,
        }
        if not all(checks.values()):
            raise SystemExit(f"mapped-sample DEX validation failed: {checks}")

    args.output.write_bytes(dex)

    strings = dex_strings(dex)
    types = dex_types(dex, strings)
    classes = class_descriptors(dex, types)
    manifest = {
        "input_sha256": digest,
        "base64_offset": off,
        "base64_length": len(encoded),
        "dex_magic": dex[:8].decode("latin1"),
        "dex_length": len(dex),
        "dex_sha256": dex_digest,
        "header": {
            "file_size": u32(dex, 0x20),
            "header_size": u32(dex, 0x24),
            "endian_tag": u32(dex, 0x28),
            "string_ids_size": u32(dex, 0x38),
            "type_ids_size": u32(dex, 0x40),
            "proto_ids_size": u32(dex, 0x48),
            "field_ids_size": u32(dex, 0x50),
            "method_ids_size": u32(dex, 0x58),
            "class_defs_size": u32(dex, 0x60),
        },
        "classes": classes,
    }
    if args.json:
        args.json.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"[+] Base64 offset  0x{off:x}")
    print(f"[+] Base64 length  {len(encoded)}")
    print(f"[+] DEX size       {len(dex)}")
    print(f"[+] DEX SHA-256    {dex_digest}")
    for cls in classes:
        print(f"[+] class          {cls}")
    print(f"[+] wrote          {args.output}")


if __name__ == "__main__":
    main()
