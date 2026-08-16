#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

V3_SHA256 = "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1"

# Second init-array constructor and the package selector it initializes.
CTOR_VA = 0x29734C
PACKAGE_OBJECT_VA = 0x538680
PACKAGE_POINTER_VA = 0x5376D8

# At 0x297520 the constructor copies 16 bytes from this literal to the stack,
# then appends the immediate dword below before calling 0x2853E0.
SOURCE16_VA = 0x1E4821
SOURCE4 = struct.pack("<I", 0x03A3C87E)

# 0x296C90 decoder constants.
KEY16_VA = 0x0F5F30
KEY8_VA = 0x0F7F50

# Original-placement .rela.dyn and exact relative relocation count.
RELA_DYN_OFF = 0x073B20
RELATIVE_COUNT = 13896
R_AARCH64_RELATIVE = 0x403
INIT_ARRAY_SLOT_2 = 0x509548


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_tail(src4: bytes, key8: bytes) -> bytes:
    """Model ldr s0; ushll; eor d; uzp1; str s0 in 0x296C90.

    Loading four source bytes into s0 followed by USHLL places them in the even
    byte positions of four zero-extended halfwords. UZP1 then extracts those
    even bytes after XOR, so the effective four-byte key is key8[0::2].
    """
    if len(src4) != 4 or len(key8) != 8:
        raise ValueError("bad tail/key length")
    return bytes(src4[i] ^ key8[2 * i] for i in range(4))


def find_relative_addend(image: bytes, target: int) -> int | None:
    for i in range(RELATIVE_COUNT):
        off = RELA_DYN_OFF + i * 24
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", image, off)
        if (r_info & 0xFFFFFFFF) == R_AARCH64_RELATIVE and r_offset == target:
            return r_addend & 0xFFFFFFFFFFFFFFFF
    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Recover the package-name substring used by core init at 0x270AC4."
    )
    ap.add_argument("inner_so", type=Path)
    ap.add_argument("--strict-hash", action="store_true")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    image = args.inner_so.read_bytes()
    digest = sha256(image)
    if digest != V3_SHA256:
        msg = f"input SHA-256 differs from mapped v3: {digest}"
        if args.strict_hash:
            raise SystemExit("[!] " + msg)
        print("[!] warning:", msg)

    src16 = image[SOURCE16_VA : SOURCE16_VA + 16]
    key16 = image[KEY16_VA : KEY16_VA + 16]
    key8 = image[KEY8_VA : KEY8_VA + 8]
    if len(src16) != 16 or len(key16) != 16 or len(key8) != 8:
        raise SystemExit("[!] truncated input")

    plain16 = bytes(a ^ b for a, b in zip(src16, key16))
    plain4 = decode_tail(SOURCE4, key8)
    plain = plain16 + plain4
    expected = b"com.dts.freefiremax\0"
    if plain != expected:
        raise SystemExit(f"[!] unexpected decode: {plain!r}")

    ctor_addend = find_relative_addend(image, INIT_ARRAY_SLOT_2)
    if ctor_addend != CTOR_VA:
        raise SystemExit(
            f"[!] second init-array slot mismatch: {ctor_addend!r}, expected 0x{CTOR_VA:x}"
        )

    result = {
        "input_sha256": digest,
        "constructor": {
            "va": CTOR_VA,
            "init_array_slot": INIT_ARRAY_SLOT_2,
            "relative_addend": ctor_addend,
        },
        "lazy_object": {
            "object_va": PACKAGE_OBJECT_VA,
            "published_pointer_va": PACKAGE_POINTER_VA,
            "copy_helper": 0x2853E0,
            "decode_helper": 0x296C90,
        },
        "encoded_source": {
            "source16_va": SOURCE16_VA,
            "source16_hex": src16.hex(),
            "source4_hex": SOURCE4.hex(),
            "key16_va": KEY16_VA,
            "key16_hex": key16.hex(),
            "key8_va": KEY8_VA,
            "key8_hex": key8.hex(),
        },
        "decoded": plain.rstrip(b"\0").decode("ascii"),
        "consumer": {
            "core_init_va": 0x270184,
            "strstr_callsite": 0x270AC4,
            "needle_pointer_global_va": PACKAGE_POINTER_VA,
            "semantic": "strstr(package_name_utf8, com.dts.freefiremax)",
        },
    }

    print(f"[+] constructor      0x{CTOR_VA:x} via init-array slot 0x{INIT_ARRAY_SLOT_2:x}")
    print(f"[+] object/pointer   0x{PACKAGE_OBJECT_VA:x} / 0x{PACKAGE_POINTER_VA:x}")
    print(f"[+] decoded needle   {result['decoded']}")
    print("[+] consumer         strstr(package_name_utf8, needle) @ 0x270ac4")

    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"[+] wrote            {args.json}")


if __name__ == "__main__":
    main()
