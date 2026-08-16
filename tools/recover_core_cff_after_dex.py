#!/usr/bin/env python3
"""Recover the natural post-DexLoader CFF path in the corrected YSM inner ELF.

This is sample-specific static tooling. It evaluates the relocation-backed CFF
jump tables in the reconstructed inner image and decodes the Java class/method
strings used after DexLoader returns successfully.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED_SHA256 = "5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1"
MASK = (1 << 64) - 1
R_AARCH64_RELATIVE = 0x403
RELA_OFF = 0x73B20
RELA_SIZE = 0x67638

X28 = 0xF1CAE710C7E84E81
C19 = 0x2F18BD1410303E39
CSTATE = 0xBC4571CAF5BE1039
CINDEX = 0xF1CAE710C7E84E82
TABLE_A = 0x517300
TABLE_B = 0x5170D0


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def va_to_file(va: int) -> int:
    if 0 <= va < 0x4E29C0:
        return va
    if 0x4E69C0 <= va < 0x511798:
        return va - 0x4000
    if 0x5147A0 <= va < 0x537560:
        return va - 0x8000
    raise ValueError(f"VA 0x{va:x} not file-backed")


def u64_file(image: bytes, va: int) -> int:
    return struct.unpack_from("<Q", image, va_to_file(va))[0]


def build_relative_map(image: bytes) -> dict[int, int]:
    out: dict[int, int] = {}
    for pos in range(RELA_OFF, RELA_OFF + RELA_SIZE, 24):
        target, info, addend = struct.unpack_from("<QQq", image, pos)
        if (info & 0xFFFFFFFF) == R_AARCH64_RELATIVE:
            out[target] = addend & MASK
    return out


def runtime_qword(image: bytes, rel: dict[int, int], va: int) -> int:
    if va in rel:
        return rel[va]
    return u64_file(image, va)


def load_qword(image: bytes, rel: dict[int, int], va: int) -> int:
    # The obfuscated tables sometimes use unaligned LDURs. Only exact aligned
    # relocation targets are rewritten by the Android linker.
    if va % 8 == 0 and va in rel:
        return rel[va]
    return u64_file(image, va)


def dispatch_after_dex(image: bytes, rel: dict[int, int], state: int) -> int:
    # 0x270FF8..0x271068. At this point x24 == 22 and x26 == CINDEX.
    x24 = 22
    x26 = CINDEX
    x20 = TABLE_B
    x21_base = 0x517278

    x8 = runtime_qword(image, rel, x21_base + 0x88)
    x8 = (-x8) & MASK
    x8 ^= X28
    x8 = (x8 * 22 + x24) & MASK
    x10 = runtime_qword(image, rel, x20 + 0xB0)
    x11 = state << 3
    x8 ^= X28
    x8 = (x10 + x8 + x11) & MASK
    x8 = load_qword(image, rel, (x8 + 1) & MASK)
    x8 = (-x8) & MASK
    x8 ^= CSTATE
    x8 = (state * x8 + state) & MASK
    x9 = runtime_qword(image, rel, x20)
    x9 = (x9 + x11) & MASK
    x9 = load_qword(image, rel, (x9 + x26) & MASK)
    x8 ^= CSTATE
    return (x9 + x8 + 1) & MASK


def resolve_call_271104(image: bytes, rel: dict[int, int]) -> int:
    # 0x27106C success block. Stack locals restored from the core prologue:
    # [x29-0x48] = 38, [x29-0x40] = 40.
    a = TABLE_A
    b = TABLE_B
    x8 = runtime_qword(image, rel, a + 0x80)
    x11 = runtime_qword(image, rel, b + 0x130)
    x9 = runtime_qword(image, rel, a + 0x90)
    x8 = (-x8) & MASK
    x8 ^= X28
    x8 = (x8 * 38 + 38) & MASK
    x9 = (-x9) & MASK
    x9 ^= X28
    x9 = (x9 * 40 + 40) & MASK
    x10 = runtime_qword(image, rel, b + 0x140)
    x8 ^= X28
    v1 = load_qword(image, rel, (x11 + x8 + 0x41) & MASK)
    x8 = (-((v1 << 3) & MASK)) & MASK
    x8 ^= 0x78C5E8A08181F1C8
    x8 = (x8 + 8) & MASK
    x8 ^= C19
    x9 ^= X28
    v2 = load_qword(image, rel, (x10 + x9 + 0x41) & MASK)
    return (v2 + x8 + 1) & MASK


def dispatch_after_268808(image: bytes, rel: dict[int, int], state: int) -> int:
    # 0x271108..0x271168. x24 is still 22 here.
    x8 = runtime_qword(image, rel, TABLE_A)
    x8 = (-x8) & MASK
    x8 ^= X28
    x8 = (x8 * 22 + 22) & MASK
    x10 = runtime_qword(image, rel, TABLE_B + 0xB0)
    x11 = state << 3
    x8 ^= X28
    x8 = (x10 + x8 + x11) & MASK
    x8 = load_qword(image, rel, (x8 + 1) & MASK)
    x8 = (-x8) & MASK
    x8 ^= CSTATE
    x8 = (state * x8 + state) & MASK
    x9 = runtime_qword(image, rel, TABLE_B)
    x9 = (x9 + x11) & MASK
    x9 = load_qword(image, rel, (x9 + CINDEX) & MASK)
    x8 ^= CSTATE
    return (x9 + x8 + 1) & MASK


def common_pair(image: bytes, rel: dict[int, int], off: int) -> tuple[int, int]:
    x8 = runtime_qword(image, rel, TABLE_A + 0x80)
    x9 = runtime_qword(image, rel, TABLE_A + 0x90)
    x10 = runtime_qword(image, rel, TABLE_B + 0x130)
    x8 = (-x8) & MASK
    x9 = (-x9) & MASK
    x8 ^= X28
    x9 ^= X28
    x8 = (x8 * 38 + 38) & MASK
    x9 = (x9 * 40 + 40) & MASK
    x8 ^= X28
    v1 = load_qword(image, rel, (x10 + x8 + off) & MASK)
    x10 = runtime_qword(image, rel, TABLE_B + 0x140)
    x9 ^= X28
    v2 = load_qword(image, rel, (x10 + x9 + off) & MASK)
    return v1, v2


def resolve_post_class_calls(image: bytes, rel: dict[int, int]) -> dict[str, int]:
    # 0x2713F4 lazy getter
    v1, v2 = common_pair(image, rel, 0xD1)
    x = ((-v1) & MASK) ^ C19
    x = (x * 26 + 26) & MASK
    x ^= C19
    c1 = (v2 + x + 1) & MASK

    # 0x271470 decoder
    v1, v2 = common_pair(image, rel, 0x101)
    x = (-((v1 << 5) & MASK)) & MASK
    x ^= 0xE317A2820607C720
    x = (x + 0x20) & MASK
    x ^= C19
    c2 = (v2 + x + 1) & MASK

    # 0x2714E4 second lazy getter
    v1, v2 = common_pair(image, rel, 0xE1)
    x = ((-v1) & MASK) ^ C19
    x = (x * 28 + 28) & MASK
    x ^= C19
    c3 = (v2 + x + 1) & MASK

    # 0x271548 second decoder
    v1, v2 = common_pair(image, rel, 0x29)
    x = ((-v1) & MASK) ^ C19
    x = (x * 5 + 5) & MASK
    x ^= C19
    c4 = (v2 + x + 1) & MASK

    # 0x2715D4 JNIEnv trampoline
    v1, v2 = common_pair(image, rel, 0x21)
    x = (-((v1 << 2) & MASK)) & MASK
    x ^= 0xBC62F45040C0F8E4
    x = (x + 4) & MASK
    x ^= C19
    c5 = (v2 + x + 1) & MASK

    # 0x2716C8 JNIEnv varargs trampoline
    v1, v2 = common_pair(image, rel, 0xB9)
    x = ((-v1) & MASK) ^ C19
    x = (x * 23 + 23) & MASK
    x ^= C19
    c6 = (v2 + x + 1) & MASK

    return {
        "getter_method_name": c1,
        "decoder_method_name": c2,
        "getter_signature": c3,
        "decoder_signature": c4,
        "get_method_id_trampoline": c5,
        "new_object_v_trampoline": c6,
    }


def dispatch_after_load_class(image: bytes, rel: dict[int, int], state: int) -> int:
    # 0x271300..0x27135C. x25 has been reloaded from [x29-0x38] == 22.
    x8 = runtime_qword(image, rel, TABLE_A)
    x8 = (-x8) & MASK
    x8 ^= X28
    x8 = (x8 * 22 + 22) & MASK
    x10 = runtime_qword(image, rel, TABLE_B + 0xB0)
    x11 = state << 3
    x8 ^= X28
    x8 = (x10 + x8 + x11) & MASK
    x8 = load_qword(image, rel, (x8 + 1) & MASK)
    x8 = (-x8) & MASK
    x8 ^= CSTATE
    x8 = (state * x8 + state) & MASK
    x9 = runtime_qword(image, rel, TABLE_B)
    x9 = (x9 + x11) & MASK
    x9 = load_qword(image, rel, (x9 + CINDEX) & MASK)
    x8 ^= CSTATE
    return (x9 + x8 + 1) & MASK


def decode_class_name(image: bytes) -> str:
    enc = bytearray(image[0x1E4869:0x1E4869 + 31])
    key = image[0x0F7160:0x0F7168]
    out = bytearray(enc)
    for i in range(24):
        out[i] ^= key[i % 8]
    for i, k in enumerate([0x45, 0xF9, 0x8B, 0x91, 0x45, 0xB3, 0xC3], 24):
        out[i] ^= k
    return bytes(out).rstrip(b"\0").decode("ascii")


def decode_method_name(image: bytes) -> str:
    enc = bytearray(image[0x0F76A0:0x0F76A8])
    key = image[0x0F7E40:0x0F7E48]
    out = bytearray(enc[:7])
    even = key[0::2][:4]
    for i in range(4):
        out[i] ^= even[i]
    out[4] ^= 0x57
    out[5] ^= 0x83
    out[6] ^= 0xA3
    return bytes(out).rstrip(b"\0").decode("ascii")


def decode_signature(image: bytes) -> str:
    enc = bytearray(image[0x1E4888:0x1E4888 + 29])
    key = image[0x0F7FE8:0x0F7FF0]
    out = bytearray(enc)
    for i in range(24):
        out[i] ^= key[i % 8]
    for i, k in enumerate([0xC7, 0x29, 0xA3, 0x7D, 0x57], 24):
        out[i] ^= k
    return bytes(out).rstrip(b"\0").decode("ascii")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("--strict-hash", action="store_true")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    image = args.input.read_bytes()
    digest = sha256(image)
    if digest != EXPECTED_SHA256:
        msg = f"SHA-256 {digest} != expected {EXPECTED_SHA256}"
        if args.strict_hash:
            raise SystemExit(msg)
        print("[!]", msg)

    rel = build_relative_map(image)
    calls = resolve_post_class_calls(image, rel)
    result = {
        "sha256": digest,
        "dexloader_result_dispatch": {
            "state_6_nonzero_success_bit": dispatch_after_dex(image, rel, 6),
            "state_15_zero_success_bit": dispatch_after_dex(image, rel, 15),
        },
        "success_block_call_0x271104": resolve_call_271104(image, rel),
        "initializer_result_dispatch": {
            "state_26_nonzero": dispatch_after_268808(image, rel, 26),
            "state_19_zero": dispatch_after_268808(image, rel, 19),
        },
        "class_name": decode_class_name(image),
        "load_class_result_dispatch": {
            "state_7_nonnull": dispatch_after_load_class(image, rel, 7),
            "state_27_null": dispatch_after_load_class(image, rel, 27),
        },
        "post_class_calls": calls,
        "constructor_method_name": decode_method_name(image),
        "constructor_signature": decode_signature(image),
    }

    print(f"[+] DexLoader success state 6 -> 0x{result['dexloader_result_dispatch']['state_6_nonzero_success_bit']:x}")
    print(f"[+] DexLoader zero state 15   -> 0x{result['dexloader_result_dispatch']['state_15_zero_success_bit']:x}")
    print(f"[+] 0x271104 indirect call    -> 0x{result['success_block_call_0x271104']:x}")
    print(f"[+] initializer nonzero       -> 0x{result['initializer_result_dispatch']['state_26_nonzero']:x}")
    print(f"[+] initializer zero          -> 0x{result['initializer_result_dispatch']['state_19_zero']:x}")
    print(f"[+] class                     {result['class_name']}")
    print(f"[+] loadClass nonnull state 7 -> 0x{result['load_class_result_dispatch']['state_7_nonnull']:x}")
    print(f"[+] loadClass null state 27   -> 0x{result['load_class_result_dispatch']['state_27_null']:x}")
    for name, va in calls.items():
        print(f"[+] {name:28s} -> 0x{va:x}")
    print(f"[+] ctor method               {result['constructor_method_name']}{result['constructor_signature']}")

    if args.json:
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
