#!/usr/bin/env python3
"""Decrypt the sample's outer .main region with the recovered RC4 key.

This is a research helper for a local copy of libysmteam.so. It does not patch
or change authentication behavior; it only reproduces the loader's outer code
decryption step offline.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

DEFAULT_START = 0xFBBAC
DEFAULT_SIZE = 0x2680
DEFAULT_KEY = bytes.fromhex("baa707fe71ef4dc2240c15c0b2d907da")


def rc4(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key must not be empty")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray(len(data))
    for n, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = value ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path, help="original libysmteam.so")
    ap.add_argument("output", type=Path, help="output SO with plaintext .main")
    ap.add_argument("--start", type=lambda x: int(x, 0), default=DEFAULT_START)
    ap.add_argument("--size", type=lambda x: int(x, 0), default=DEFAULT_SIZE)
    ap.add_argument("--key", default=DEFAULT_KEY.hex(), help="RC4 key in hex")
    args = ap.parse_args()

    src = args.input.read_bytes()
    key = bytes.fromhex(args.key)
    end = args.start + args.size
    if end > len(src):
        raise SystemExit(
            f"range 0x{args.start:X}..0x{end:X} exceeds file size 0x{len(src):X}"
        )

    plain = rc4(src[args.start:end], key)
    if len(plain) >= 4:
        print(f"plaintext first dword: {plain[:4].hex()}")

    patched = bytearray(src)
    patched[args.start:end] = plain
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)

    print(f"input sha256 : {hashlib.sha256(src).hexdigest()}")
    print(f"output sha256: {hashlib.sha256(patched).hexdigest()}")
    print(f"decrypted    : 0x{args.start:X} + 0x{args.size:X}")
    print(f"key          : {key.hex()}")
    print(f"wrote        : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
