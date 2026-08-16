#!/usr/bin/env python3
"""Verify the embedded YSM overlay DEX and recover its core Java behavior.

Sample-specific, dependency-free verifier for the extracted 3668-byte DEX.
It validates the exact ViewAdder and GLES3JNIView code items used by the
post-Dex native path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED_SHA256 = "fdef253bbfbc40cff2de3f5e53fd3412f41a4912018978cd2f8a92f9e441a66b"


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def uleb(data: bytes, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    pos = off
    while True:
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7


def sleb(data: bytes, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    pos = off
    while True:
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if shift < 32 and (b & 0x40):
                value |= -(1 << shift)
            return value, pos


def strings(data: bytes) -> list[str]:
    size = u32(data, 0x38)
    off = u32(data, 0x3C)
    out = []
    for i in range(size):
        s_off = u32(data, off + 4 * i)
        _, pos = uleb(data, s_off)
        end = data.index(0, pos)
        out.append(data[pos:end].decode("utf-8", errors="replace"))
    return out


def types(data: bytes, ss: list[str]) -> list[str]:
    size = u32(data, 0x40)
    off = u32(data, 0x44)
    return [ss[u32(data, off + 4 * i)] for i in range(size)]


def methods(data: bytes, ss: list[str], ts: list[str]):
    proto_size = u32(data, 0x48)
    proto_off = u32(data, 0x4C)
    protos = []
    for i in range(proto_size):
        p = proto_off + 12 * i
        shorty, ret, params = struct.unpack_from("<III", data, p)
        args = []
        if params:
            n = u32(data, params)
            args = [ts[u16(data, params + 4 + 2 * j)] for j in range(n)]
        protos.append((ss[shorty], ts[ret], args))

    size = u32(data, 0x58)
    off = u32(data, 0x5C)
    out = []
    for i in range(size):
        cls, proto, name = struct.unpack_from("<HHI", data, off + 8 * i)
        out.append((ts[cls], ss[name], protos[proto]))
    return out


def code_units(data: bytes, off: int):
    registers, ins, outs, tries = struct.unpack_from("<HHHH", data, off)
    insns_size = u32(data, off + 12)
    units = list(struct.unpack_from("<" + "H" * insns_size, data, off + 16))
    return registers, ins, outs, tries, units


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("--strict-hash", action="store_true")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    data = args.input.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        msg = f"SHA-256 {digest} != expected {EXPECTED_SHA256}"
        if args.strict_hash:
            raise SystemExit(msg)
        print("[!]", msg)

    if data[:8] != b"dex\n037\0":
        raise SystemExit(f"unexpected DEX magic: {data[:8]!r}")

    ss = strings(data)
    ts = types(data, ss)
    ms = methods(data, ss, ts)

    expected_classes = {
        "Lcom/ysmteam/imgui/GLES3JNIView;",
        "Lcom/ysmteam/imgui/MainActivity;",
        "Lcom/ysmteam/imgui/ViewAdder;",
    }
    if not expected_classes.issubset(set(ts)):
        raise SystemExit("expected overlay classes not found")

    # Exact ViewAdder constructor at code_off 0x67C:
    # Object.<init>; iput activity; iput view; return-void.
    va_ctor = code_units(data, 0x67C)
    expected_ctor = [0x1070, 0x0026, 0x0000, 0x015B, 0x0002, 0x025B, 0x0003, 0x000E]
    if va_ctor[4] != expected_ctor:
        raise SystemExit("ViewAdder.<init> code mismatch")

    # Exact ViewAdder.run at code_off 0x69C.
    va_run = code_units(data, 0x69C)
    expected_run = [
        0x0022, 0x000A, 0xF112, 0x3070, 0x000A, 0x0110,
        0x3154, 0x0002, 0x106E, 0x0001, 0x0001, 0x010C,
        0x3254, 0x0003, 0x306E, 0x000B, 0x0021, 0x0528,
        0x000D, 0x106E, 0x0025, 0x0000, 0x000E,
    ]
    if va_run[4] != expected_run:
        raise SystemExit("ViewAdder.run code mismatch")

    # Decode the one typed catch handler: java.lang.Exception -> code-unit 18.
    insns_size = len(va_run[4])
    tries_off = 0x69C + 16 + 2 * insns_size + (2 if insns_size & 1 else 0)
    start, count, handler_off = struct.unpack_from("<IHH", data, tries_off)
    handlers_base = tries_off + 8
    hsize, pos = sleb(data, handlers_base + handler_off)
    type_idx, pos = uleb(data, pos)
    handler_addr, pos = uleb(data, pos)
    catch_type = ts[type_idx]
    if (start, count, hsize, catch_type, handler_addr) != (0, 17, 1, "Ljava/lang/Exception;", 18):
        raise SystemExit("unexpected ViewAdder.run catch handler")

    # Verify method references used by ViewAdder.run.
    refs = {
        1: "getWindow",
        10: "<init>",
        11: "addContentView",
        37: "printStackTrace",
        38: "<init>",
    }
    for idx, name in refs.items():
        if ms[idx][1] != name:
            raise SystemExit(f"method@{idx} expected {name}, got {ms[idx][1]}")

    gles_ctor = code_units(data, 0x52C)
    if len(gles_ctor[4]) != 41:
        raise SystemExit("unexpected GLES3JNIView.<init> size")

    result = {
        "sha256": digest,
        "dex_size": len(data),
        "method_ids": u32(data, 0x58),
        "class_defs": u32(data, 0x60),
        "classes": sorted(expected_classes),
        "viewadder": {
            "constructor_code_off": "0x67c",
            "run_code_off": "0x69c",
            "constructor": "this.activity = activity; this.view = view",
            "run": "activity.getWindow().addContentView(view, new ViewGroup.LayoutParams(-1, -1))",
            "catch": "java.lang.Exception -> printStackTrace()",
        },
        "gles3jniview": {
            "constructor_code_off": "0x52c",
            "setup": [
                "setEGLConfigChooser(8,8,8,8,16,0)",
                "getHolder().setFormat(-3)",
                "setZOrderOnTop(true)",
                "setEGLContextClientVersion(3)",
                "setRenderer(this)",
                "setRenderMode(1)",
            ],
        },
    }

    print(f"[+] DEX SHA-256 {digest}")
    print(f"[+] classes={result['class_defs']} methods={result['method_ids']}")
    print("[+] ViewAdder.run:", result["viewadder"]["run"])
    print("[+] catch:", result["viewadder"]["catch"])
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"[+] wrote {args.json}")


if __name__ == "__main__":
    main()
