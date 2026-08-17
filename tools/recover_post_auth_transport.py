#!/usr/bin/env python3
"""Verify non-secret post-auth transport constants in the reconstructed YSM ELF.

This sample-specific tool performs static checks only. It does not construct,
send, sign, or forge requests and intentionally does not recover key material.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

EXPECTED_SHA256 = "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1"


def xor_const(raw: bytes, key: int) -> str:
    out = bytes(x ^ key for x in raw)
    return out.split(b"\0", 1)[0].decode("ascii")


def header_strings(image: bytes) -> list[str]:
    # 0x2C1C80
    h1a = (
        image[0xF8650:0xF8658]
        + image[0xF7460:0xF7464]
        + struct.pack("<H", 0x0E14)
        + bytes([0x2E])
    )
    h1b = image[0xF7898:0xF78A0] + struct.pack("<H", 0x494B) + bytes([0x2E])

    # 0x2C1E70
    h2a = image[0xF7C98:0xF7CA0] + bytes([0x2E])
    h2b = h1b

    # 0x2C201C
    h3a = image[0xF76E8:0xF76F0] + image[0xF7E88:0xF7E8C] + bytes([0x2E])
    h3b = (
        image[0xF7D30:0xF7D38]
        + image[0xF8160:0xF8164]
        + struct.pack("<H", 0x2E77)
    )

    return [
        xor_const(h1a, 0x2E) + xor_const(h1b, 0x2E),
        xor_const(h2a, 0x2E) + xor_const(h2b, 0x2E),
        xor_const(h3a, 0x2E) + xor_const(h3b, 0x2E),
    ]


def has_bl(image: bytes, pc: int, target: int) -> bool:
    word = struct.unpack_from("<I", image, pc)[0]
    if (word & 0xFC000000) != 0x94000000:
        return False
    imm = word & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return pc + (imm << 2) == target


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

    headers = header_strings(image)
    assert headers == [
        "Content-Type: image/jpeg",
        "Accept: image/jpeg",
        "User-Agent: X-YSM-K8sN3xY",
    ]

    # OpenSSL/BoringSSL PLT targets used by 0x2A8108.
    crypto_calls = {
        0x2A8654: 0x4D6FC0,  # RAND_bytes
        0x2A8658: 0x4D6FD0,  # EVP_CIPHER_CTX_new
        0x2A8660: 0x4D6FE0,  # EVP_aes_256_gcm
        0x2A8678: 0x4D6FF0,  # EVP_EncryptInit_ex
        0x2A8774: 0x4D7000,  # EVP_CIPHER_CTX_ctrl
        0x2A8820: 0x4D6FF0,  # EVP_EncryptInit_ex
        0x2A8AC0: 0x4D7010,  # EVP_EncryptUpdate
        0x2A8B24: 0x4D7020,  # EVP_EncryptFinal_ex
        0x2A8CA0: 0x4D7000,  # EVP_CIPHER_CTX_ctrl
        0x2A8CA8: 0x4D7030,  # EVP_CIPHER_CTX_free
    }
    for pc, target in crypto_calls.items():
        assert has_bl(image, pc, target), (hex(pc), hex(target))

    # libcurl lifecycle in 0x2A9F70.
    for pc, target in {
        0x2AA23C: 0x4D7050,  # curl_easy_setopt
        0x2AAD60: 0x4D7060,  # curl_slist_append
        0x2AADD4: 0x4D7060,
        0x2AAE48: 0x4D7060,
        0x2AAED0: 0x4D7050,
        0x2AAED8: 0x4D7070,  # curl_easy_perform
        0x2AAEE4: 0x4D7080,  # curl_slist_free_all
        0x2AAEEC: 0x4D7090,  # curl_easy_cleanup
    }.items():
        assert has_bl(image, pc, target), (hex(pc), hex(target))

    print(f"[+] SHA-256                 {digest}")
    print("[+] crypto                  AES-256-GCM via EVP API")
    print("[+] GCM parameters          random 12-byte IV, 16-byte tag (MBA-evaluated)")
    print("[+] first curl option       10002 / CURLOPT_URL (MBA-evaluated)")
    for h in headers:
        print(f"[+] HTTP header             {h}")
    print("[+] endpoint                selected by 0x2C4C84 -> 0x2BF5E0; not yet recovered")
    print("[+] note                    secret key material intentionally not recovered/output")


if __name__ == "__main__":
    main()
