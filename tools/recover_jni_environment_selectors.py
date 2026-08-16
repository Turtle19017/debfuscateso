#!/usr/bin/env python3
"""Recover the plaintext /proc/self/maps selectors used by the mapped YSM inner JNI environment initializer.

This is static analysis tooling. It does not modify the target or bypass any runtime check.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

INNER_SIZE = 0x530070
KNOWN_SHA256 = {
    "5a0ff6b4e1d3bf811dbd1f2b5db3e48ae14c12fb6da5f5662bf2e3c7bd66f168",  # raw recovered inner
    "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1",  # corrected direct-load v3
}


def xorb(data: bytes, mask: bytes) -> bytes:
    return bytes(v ^ mask[i % len(mask)] for i, v in enumerate(data))


def ztrim(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("utf-8")


def decode_tail4(encoded: bytes, mask8: bytes) -> bytes:
    # Mirrors the USHLL/EOR/UZP1 tail decoders: the four source bytes are
    # widened into even byte lanes and therefore use mask bytes 0,2,4,6.
    return bytes(encoded[i] ^ mask8[i * 2] for i in range(4))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("inner", type=Path)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--strict-hash", action="store_true")
    args = ap.parse_args()

    b = args.inner.read_bytes()
    digest = hashlib.sha256(b).hexdigest()
    if len(b) != INNER_SIZE:
        raise SystemExit(f"unexpected inner size 0x{len(b):x}; expected 0x{INNER_SIZE:x}")
    if args.strict_hash and digest not in KNOWN_SHA256:
        raise SystemExit(f"unrecognized mapped-sample SHA-256: {digest}")

    maps = [
        ztrim(xorb(b[0xF6360:0xF6370], b[0xF6020:0xF6030])),
        ztrim(xorb(b[0xF6030:0xF6040], b[0xF60B0:0xF60C0])),
        ztrim(xorb(b[0xF6730:0xF6740], b[0xF6710:0xF6720])),
    ]

    # Helper 1 @ 0x2E9368: /data/app/ + /base.apk + package.
    h1mask = b[0xF7530:0xF7538]
    h1_a_enc = b[0xF7DD0:0xF7DD8] + b[0xF70D8:0xF70DC]
    h1_a = xorb(h1_a_enc[:8], h1mask) + bytes([
        h1_a_enc[8] ^ 0x77,
        h1_a_enc[9] ^ 0x3F,
        h1_a_enc[10] ^ 0xB5,
        0,
    ])
    h1_b_enc = b[0xF8828:0xF8830] + struct.pack("<H", 0x3F1C) + b"\x01"
    h1_b = xorb(h1_b_enc[:8], h1mask) + bytes([
        h1_b_enc[8] ^ 0x77,
        h1_b_enc[9] ^ 0x3F,
        0,
    ])
    h1_pkg_enc = b[0x1E60CD:0x1E60DD] + struct.pack("<I", 0x3DCD5E1A)
    h1_pkg = xorb(h1_pkg_enc[:16], b[0xF6850:0xF6860]) + decode_tail4(
        h1_pkg_enc[16:20], b[0xF7100:0xF7108]
    )

    # Helper 2 @ 0x2E9B90: /data/app/ + install-time asset-pack split + package.
    h2mask8 = b[0xF8290:0xF8298]
    h2_a_enc = b[0xF8038:0xF8040] + b[0xF7328:0xF732C]
    h2_a = xorb(h2_a_enc[:8], h2mask8) + bytes([
        h2_a_enc[8] ^ 0x1B,
        h2_a_enc[9] ^ 0x4D,
        h2_a_enc[10] ^ 0x21,
        0,
    ])
    h2_b_enc = bytearray(b[0x1E60FE:0x1E60FE + 35])
    h2_b_enc[31:35] = struct.pack("<I", 0x21266B00)
    h2_mask16 = b[0xF6A40:0xF6A50]
    h2_b = bytearray(35)
    for i in range(32):
        h2_b[i] = h2_b_enc[i] ^ h2_mask16[i % 16]
    h2_tail = b[0xF7CA0:0xF7CA8]
    h2_b[32] = h2_b_enc[32] ^ h2_tail[0]
    h2_b[33] = h2_b_enc[33] ^ h2_tail[4]
    h2_b[34] = h2_b_enc[34] ^ 0x21
    h2_pkg_enc = b[0x1E6121:0x1E6131] + struct.pack("<I", 0x87592C76)
    h2_pkg = xorb(h2_pkg_enc[:16], h2_mask16) + decode_tail4(
        h2_pkg_enc[16:20], b[0xF7A80:0xF7A88]
    )

    # Helper 3 @ 0x2EA420: /data/app/ + ABI split + package.
    h3mask8 = b[0xF8408:0xF8410]
    h3_a_enc = b[0xF77D0:0xF77D8] + b[0xF8830:0xF8834]
    h3_a = xorb(h3_a_enc[:8], h3mask8) + bytes([
        h3_a_enc[8] ^ 0x2B,
        h3_a_enc[9] ^ 0x6B,
        h3_a_enc[10] ^ 0x33,
        0,
    ])
    h3_b_enc = b[0x1E6152:0x1E6152 + 28]
    h3_b = bytearray(28)
    for i in range(24):
        h3_b[i] = h3_b_enc[i] ^ h3mask8[i % 8]
    for i, k in enumerate((0x2B, 0x6B, 0x33, 0x35), start=24):
        h3_b[i] = h3_b_enc[i] ^ k
    h3_pkg_enc = b[0x1E616E:0x1E617E] + struct.pack("<I", 0x354B0A46)
    h3_pkg = xorb(h3_pkg_enc[:16], b[0xF6220:0xF6230]) + decode_tail4(
        h3_pkg_enc[16:20], b[0xF8430:0xF8438]
    )

    selectors = [
        {
            "helper": "0x2E9368",
            "maps_path": maps[0],
            "must_contain": [ztrim(h1_a), ztrim(h1_b), ztrim(h1_pkg)],
        },
        {
            "helper": "0x2E9B90",
            "maps_path": maps[1],
            "must_contain": [ztrim(h2_a), ztrim(bytes(h2_b)), ztrim(h2_pkg)],
        },
        {
            "helper": "0x2EA420",
            "maps_path": maps[2],
            "must_contain": [ztrim(h3_a), ztrim(bytes(h3_b)), ztrim(h3_pkg)],
        },
    ]

    expected = [
        ["/data/app/", "/base.apk", "com.dts.freefiremax"],
        ["/data/app/", "/split_asset_pack_install_time.apk", "com.dts.freefiremax"],
        ["/data/app/", "/split_config.arm64_v8a.apk", "com.dts.freefiremax"],
    ]
    if maps != ["/proc/self/maps"] * 3:
        raise SystemExit(f"unexpected maps paths: {maps}")
    if [x["must_contain"] for x in selectors] != expected:
        raise SystemExit("decoded selector validation failed")

    out = {
        "input_sha256": digest,
        "selectors": selectors,
        "orchestrator": "0x2EE670",
        "failure_behavior": "each empty helper result is checked by 0x2EE670 and leads to exit(0)",
    }
    print(f"[+] input sha256 {digest}")
    for x in selectors:
        print(f"[+] {x['helper']} reads {x['maps_path']}")
        for s in x["must_contain"]:
            print(f"      contains: {s}")
    if args.json:
        args.json.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"[+] wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
