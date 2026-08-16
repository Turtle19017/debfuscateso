#!/usr/bin/env python3
"""Decrypt and inflate the reconstructed inner combined stream.

Input to this tool is the *combined ciphertext stream* after the sample-specific
small-blob pre-transform has already been reproduced. The first ChaCha20
plaintext bytes are expected to be:

    uint32_le uncompressed_size
    zlib_stream...

The tool deliberately separates the ChaCha20/zlib stage from the earlier
white-box/pre-transform stage so each part can be validated independently.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import zlib
from pathlib import Path

DEFAULT_KEY = bytes.fromhex(
    "5ced6a2489e3a61b72779a91e7ed5ab0"
    "ba7f446c8293e4787c91cb206d6a749d"
)
DEFAULT_NONCE = bytes.fromhex("1192c5524733ab4a89007731")
DEFAULT_COUNTER = 1


def rotl32(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] ^= s[a]
    s[d] = rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] ^= s[c]
    s[b] = rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] ^= s[a]
    s[d] = rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] ^= s[c]
    s[b] = rotl32(s[b], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("IETF ChaCha20 nonce must be 12 bytes")
    constants = b"expand 32-byte k"
    initial = list(struct.unpack("<4I", constants))
    initial += list(struct.unpack("<8I", key))
    initial += [counter & 0xFFFFFFFF]
    initial += list(struct.unpack("<3I", nonce))
    work = initial.copy()
    for _ in range(10):
        quarter_round(work, 0, 4, 8, 12)
        quarter_round(work, 1, 5, 9, 13)
        quarter_round(work, 2, 6, 10, 14)
        quarter_round(work, 3, 7, 11, 15)
        quarter_round(work, 0, 5, 10, 15)
        quarter_round(work, 1, 6, 11, 12)
        quarter_round(work, 2, 7, 8, 13)
        quarter_round(work, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(work, initial)])


def chacha20_xor(data: bytes, key: bytes, nonce: bytes, counter: int = 1) -> bytes:
    out = bytearray(len(data))
    for off in range(0, len(data), 64):
        stream = chacha20_block(key, counter, nonce)
        block = data[off : off + 64]
        out[off : off + len(block)] = bytes(a ^ b for a, b in zip(block, stream))
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(out)


def self_test() -> None:
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    got = chacha20_block(key, 1, nonce).hex()
    expected = (
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    if got != expected:
        raise AssertionError(f"ChaCha20 self-test failed: {got}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path, nargs="?", help="combined ChaCha20 ciphertext")
    ap.add_argument("output", type=Path, nargs="?", help="inflated inner memory image")
    ap.add_argument("--key", default=DEFAULT_KEY.hex())
    ap.add_argument("--nonce", default=DEFAULT_NONCE.hex())
    ap.add_argument("--counter", type=lambda x: int(x, 0), default=DEFAULT_COUNTER)
    ap.add_argument("--dump-plaintext", type=Path, help="optional ChaCha20 plaintext dump")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    self_test()
    if args.self_test and args.input is None:
        print("ChaCha20 self-test: OK")
        return 0
    if args.input is None or args.output is None:
        ap.error("input and output are required unless --self-test is used alone")

    cipher = args.input.read_bytes()
    key = bytes.fromhex(args.key)
    nonce = bytes.fromhex(args.nonce)
    plain = chacha20_xor(cipher, key, nonce, args.counter)
    if len(plain) < 6:
        raise SystemExit("plaintext is too short")

    expected_size = struct.unpack_from("<I", plain, 0)[0]
    compressed = plain[4:]
    if not compressed.startswith((b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")):
        raise SystemExit(
            f"unexpected zlib header {compressed[:2].hex()} after ChaCha20; "
            "check the pre-transform/input stream"
        )
    inflated = zlib.decompress(compressed)
    if len(inflated) != expected_size:
        raise SystemExit(
            f"size mismatch: header={expected_size} inflated={len(inflated)}"
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(inflated)
    if args.dump_plaintext:
        args.dump_plaintext.write_bytes(plain)

    print(f"cipher sha256 : {hashlib.sha256(cipher).hexdigest()}")
    print(f"plain prefix  : {plain[:16].hex()}")
    print(f"inner size    : {len(inflated)} (0x{len(inflated):X})")
    print(f"inner sha256  : {hashlib.sha256(inflated).hexdigest()}")
    print(f"wrote         : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
