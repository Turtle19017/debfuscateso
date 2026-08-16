#!/usr/bin/env python3
"""One-command offline extractor for the analyzed libysmteam.so sample.

Pipeline:
  original SO
    -> B1E90 decrypt 0x1010-byte small stage + PKCS#7 unpad
    -> append 0x2A2649-byte large stage
    -> ChaCha20 (IETF, counter 1)
    -> uint32_le expected size + zlib
    -> 0x530070-byte inner memory image

No target execution/runtime dump is required.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import zlib
from pathlib import Path

from emulate_b1e90 import B1E90Emulator
from decrypt_inner_combined import chacha20_xor, DEFAULT_COUNTER, DEFAULT_KEY, DEFAULT_NONCE


def chacha20_xor_fast(data: bytes, key: bytes, nonce: bytes, counter: int) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        full_nonce = counter.to_bytes(4, "little") + nonce
        enc = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None).encryptor()
        return enc.update(data) + enc.finalize()
    except Exception:
        return chacha20_xor(data, key, nonce, counter)


SMALL_OFF = 0x4515A0
SMALL_SIZE = 0x1010
LARGE_OFF = 0x4525B0
LARGE_SIZE = 0x2A2649
EXPECTED_SMALL_PLAIN = 0x1000
EXPECTED_INNER_SIZE = 0x530070
EXPECTED_INNER_SHA256 = "5a0ff6b4e1d3bf811dbd1f2b5db3e48ae14c12fb6da5f5662bf2e3c7bd66f168"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("so", type=Path, help="original libysmteam.so (or outer-main-decrypted copy)")
    ap.add_argument("output", type=Path, help="output inner memory image")
    ap.add_argument("--work-dir", type=Path, help="optionally dump intermediate stages")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    so = args.so.read_bytes()
    need = LARGE_OFF + LARGE_SIZE
    if len(so) < need:
        raise SystemExit(f"SO too small: need >=0x{need:x}, got 0x{len(so):x}")

    small_cipher = so[SMALL_OFF : SMALL_OFF + SMALL_SIZE]
    large_cipher = so[LARGE_OFF : LARGE_OFF + LARGE_SIZE]

    if not args.quiet:
        print("[1/4] emulating B1E90 over the 0x1010-byte small stage")
    emu = B1E90Emulator(args.so)
    small_plain = emu.decrypt_pkcs7(small_cipher, progress=not args.quiet)
    if len(small_plain) != EXPECTED_SMALL_PLAIN:
        raise SystemExit(f"unexpected small plaintext size: 0x{len(small_plain):x}")

    combined = small_plain + large_cipher
    if not args.quiet:
        print(f"[2/4] combined ciphertext: 0x{len(combined):x} bytes")
        print("[3/4] ChaCha20 decrypt")
    plain = chacha20_xor_fast(combined, DEFAULT_KEY, DEFAULT_NONCE, DEFAULT_COUNTER)
    if len(plain) < 6:
        raise SystemExit("ChaCha20 plaintext too short")

    expected_size = struct.unpack_from("<I", plain, 0)[0]
    if expected_size != EXPECTED_INNER_SIZE:
        raise SystemExit(
            f"unexpected size header 0x{expected_size:x}; expected 0x{EXPECTED_INNER_SIZE:x}"
        )
    compressed = plain[4:]
    if not compressed.startswith((b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")):
        raise SystemExit(f"unexpected zlib header: {compressed[:2].hex()}")

    if not args.quiet:
        print("[4/4] zlib inflate")
    inner = zlib.decompress(compressed)
    if len(inner) != expected_size:
        raise SystemExit(f"inflated size mismatch: {len(inner)} != {expected_size}")

    digest = sha256(inner)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(inner)

    if args.work_dir:
        args.work_dir.mkdir(parents=True, exist_ok=True)
        (args.work_dir / "small_cipher.bin").write_bytes(small_cipher)
        (args.work_dir / "small_plain.bin").write_bytes(small_plain)
        (args.work_dir / "combined_cipher.bin").write_bytes(combined)
        (args.work_dir / "chacha_plain.bin").write_bytes(plain)

    print(f"small plain : 0x{len(small_plain):x} sha256={sha256(small_plain)}")
    print(f"combined    : 0x{len(combined):x} sha256={sha256(combined)}")
    print(f"inner       : 0x{len(inner):x} sha256={digest}")
    if digest == EXPECTED_INNER_SHA256:
        print("validation  : exact known-sample hash match")
    else:
        print("validation  : size/format valid, hash differs from current checkpoint")
    print(f"wrote       : {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
