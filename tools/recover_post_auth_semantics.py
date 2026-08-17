#!/usr/bin/env python3
"""Recover published auth-state and post-auth request field semantics.

Sample-specific static verifier for ysm_inner.original_placement_v3.so.
It only reads the reconstructed image; it does not send requests or modify auth flow.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA256 = "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1"
XOR = 0x3F


def xor3f(data: bytes) -> str:
    out = bytes(x ^ XOR for x in data)
    return out.split(b"\0", 1)[0].decode("ascii")


def u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def movwide_imm16(b: bytes, off: int) -> int:
    """Extract imm16 from a MOVZ/MOVK-style wide-immediate instruction."""
    return (u32(b, off) >> 5) & 0xFFFF


def cstr(b: bytes, off: int) -> str:
    end = b.index(0, off)
    return b[off:end].decode("ascii")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("--strict-hash", action="store_true")
    args = ap.parse_args()

    image = args.input.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != EXPECTED_SHA256:
        msg = f"SHA-256 {digest} != expected {EXPECTED_SHA256}"
        if args.strict_hash:
            raise SystemExit(msg)
        print("[!]", msg)

    # Auth response keys/defaults.
    token = xor3f(image[0xF8818:0xF881C] + struct.pack("<H", movwide_imm16(image, 0x2B0914)))
    message = xor3f(image[0xF8350:0xF8358])
    unknown_error = xor3f(
        image[0xF7520:0xF7528]
        + image[0xF7A50:0xF7A54]
        + struct.pack("<H", movwide_imm16(image, 0x2B06B4))
    )
    expire = xor3f(
        image[0xF7A58:0xF7A5C]
        + struct.pack("<H", movwide_imm16(image, 0x2B09E8))
        + bytes([movwide_imm16(image, 0x2B09F8) & 0xFF])
    )
    chk = xor3f(image[0xF7DC8:0xF7DCC] + bytes([movwide_imm16(image, 0x2B0984) & 0xFF]))
    nonce_reply = xor3f(
        struct.pack("<H", movwide_imm16(image, 0x2AFF88))
        + bytes([movwide_imm16(image, 0x2AFF8C) & 0xFF])
    )

    # App/device fingerprint input to 0x2A7C34.
    package_enc = image[0x1E51BF:0x1E51CF]
    package_tail = struct.pack("<I", 0x3F475E52)
    package = xor3f(package_enc + package_tail)
    build_prop = cstr(image, 0x11E820)
    model_prop = cstr(image, 0x10F4DC)

    # Post-auth request keys from 0x2B3528 lazy strings.
    key = xor3f(image[0xF8340:0xF8344])
    hwid = xor3f(image[0xF77B0:0xF77B4] + bytes([movwide_imm16(image, 0x2B8288) & 0xFF]))
    nonce = xor3f(image[0xF7320:0xF7324] + struct.pack("<H", movwide_imm16(image, 0x2B8360)))
    ts = xor3f(
        struct.pack("<H", movwide_imm16(image, 0x2B83C4))
        + bytes([movwide_imm16(image, 0x2B83C8) & 0xFF])
    )
    encrypt_failed = xor3f(
        image[0xF80E0:0xF80E8]
        + image[0xF7880:0xF7884]
        + struct.pack("<H", movwide_imm16(image, 0x2B843C))
        + bytes([movwide_imm16(image, 0x2B8440) & 0xFF])
    )

    assert token == "token"
    assert message == "message"
    assert unknown_error == "Unknown error"
    assert expire == "expire"
    assert chk == "_chk"
    assert nonce_reply == "_n"
    assert package == "com.dts.freefiremax"
    assert build_prop == "ro.build.id"
    assert model_prop == "ro.product.model"
    assert [key, hwid, token, nonce, ts] == ["key", "hwid", "token", "nonce", "ts"]
    assert encrypt_failed == "Encrypt failed"

    print(f"[+] SHA-256                         {digest}")
    print("[+] 0x2AD220 ABI                    json value/lookup helper, hidden sret in x8")
    print(f"[+] response key                    {message!r} (default {unknown_error!r}) -> g[0] 0x539AD0")
    print(f"[+] response key                    {token!r} -> g[1] 0x539AE8")
    print(f"[+] response key                    {expire!r} -> g[2] 0x539B00")
    print("[+] g[3]                            original login key -> 0x539B18")
    print(f"[+] fingerprint prefix              {package!r}")
    print(f"[+] fingerprint properties          {build_prop!r}, {model_prop!r}, {model_prop!r}")
    print("[+] 0x2A7C34                        byte string -> zero-padded 2-digit hex text")
    print("[+] g[4]                            hex-encoded HWID/fingerprint -> 0x539B30")
    print(f"[+] internal response keys          {nonce_reply!r}, {chk!r}")
    print(f"[+] 0x2B3528 request keys            {key!r}, {hwid!r}, {token!r}, {nonce!r}, {ts!r}")
    print(f"[+] packaging error literal         {encrypt_failed!r}")
    print("[+] interpretation                  0x2B3528 is post-auth request/transport stage, not proven IL2CPP hook init")


if __name__ == "__main__":
    main()
