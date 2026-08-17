#!/usr/bin/env python3
"""Verify non-secret config-selector and response-parser roles in YSM v3.

Static checks only. This tool does not recover or output cryptographic key
material and does not construct or send network requests.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA256 = "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1"


def has_bl(image: bytes, pc: int, target: int) -> bool:
    word = struct.unpack_from("<I", image, pc)[0]
    if (word & 0xFC000000) != 0x94000000:
        return False
    imm = word & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return pc + (imm << 2) == target


def verification_literal(image: bytes) -> str:
    raw = image[0x1E5517:0x1E5517 + 16] + struct.pack("<I", 0x00003F5B)
    dec = bytes(x ^ 0x3F for x in raw[:18])
    return dec.split(b"\0", 1)[0].decode("ascii")


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

    # Four selector wrappers all feed the same five-output config loader.
    for pc in (0x2AB6D4, 0x2BF454, 0x2C4A70, 0x2C4ED4):
        assert has_bl(image, pc, 0x2BF5E0), hex(pc)

    # Primary-auth URL selector -> curl.
    assert has_bl(image, 0x29BCCC, 0x2AB558)
    assert has_bl(image, 0x29BCF0, 0x2A9F70)

    # Post-auth URL selector -> curl.
    assert has_bl(image, 0x2B5954, 0x2C4C84)
    assert has_bl(image, 0x2B5964, 0x2A9F70)

    # AES-GCM decrypt anchors inside the config loader.
    for pc, target in {
        0x2C029C: 0x4D6FD0,  # EVP_CIPHER_CTX_new
        0x2C02A4: 0x4D6FE0,  # EVP_aes_256_gcm
        0x2C02BC: 0x4D71F0,  # EVP_DecryptInit_ex
        0x2C03C4: 0x4D7000,  # EVP_CIPHER_CTX_ctrl
        0x2C049C: 0x4D71F0,  # second EVP_DecryptInit_ex
        0x2C05A4: 0x4D70A0,  # EVP_DecryptUpdate
        0x2C06A8: 0x4D7000,  # EVP_CIPHER_CTX_ctrl
        0x2C0738: 0x4D70B0,  # EVP_DecryptFinal_ex
        0x2C0744: 0x4D7030,  # EVP_CIPHER_CTX_free
        0x2C0874: 0x4D7200,  # OPENSSL_cleanse
    }.items():
        assert has_bl(image, pc, target), (hex(pc), hex(target))

    # Response-side anchors.
    assert has_bl(image, 0x2B5B18, 0x2C8530)
    assert has_bl(image, 0x2B5EA8, 0x2C8530)
    assert has_bl(image, 0x2B5F98, 0x2CAED4)
    assert has_bl(image, 0x2B6024, 0x2ACDD8)

    literal = verification_literal(image)
    assert literal == "Verification faid", repr(literal)

    print(f"[+] SHA-256                  {digest}")
    print("[+] config loader            0x2BF5E0 (five std::string outputs)")
    print("[+] config output #1         primary-auth URL via getter 0x2AB558")
    print("[+] config output #2         post-auth URL via getter 0x2C4C84")
    print("[+] config crypto            AES-256-GCM decrypt via EVP API")
    print("[+] decrypt final            0x2C0738 (not 0x2C049C)")
    print(f"[+] validation literal       {literal}")
    print("[+] 0x2C8530                 lazy XOR-0x3F literal decoder")
    print("[+] 0x2CAED4                 in-memory input-adapter constructor")
    print("[+] 0x2ACDD8                 parser/deserializer stage")
    print("[+] note                     no secret config key material is output")


if __name__ == "__main__":
    main()
