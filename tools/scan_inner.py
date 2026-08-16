#!/usr/bin/env python3
"""Report research markers and known offsets in an extracted inner memory image."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

MARKERS = [
    b"Dear ImGui",
    b"imgui.ini",
    b"ImGui_ImplOpenGL3",
    b"Dobby",
    b"libEGL.so",
    b"libGLESv2.so",
    b"curl",
    b"OpenSSL",
    b"Login",
]

KNOWN = {
    "arm64_text_start": 0x25E2E0,
    "menu_renderer_region": 0x27CAEC,
    "input_text_call": 0x27CFFC,
    "paste_key_button": 0x27D490,
    "login_button": 0x27DBE8,
    "auto_login_worker": 0x2948DC,
    "manual_login_worker": 0x29527C,
    "auth_core": 0x298B94,
}


def all_offsets(data: bytes, needle: bytes, limit: int = 16) -> list[int]:
    out: list[int] = []
    pos = 0
    while len(out) < limit:
        pos = data.find(needle, pos)
        if pos < 0:
            break
        out.append(pos)
        pos += 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    args = ap.parse_args()

    data = args.input.read_bytes()
    print(f"file   : {args.input}")
    print(f"size   : {len(data)} (0x{len(data):X})")
    print(f"sha256 : {hashlib.sha256(data).hexdigest()}")
    print("\nmarkers:")
    for marker in MARKERS:
        offs = all_offsets(data, marker)
        rendered = ", ".join(f"0x{x:X}" for x in offs) if offs else "not found"
        print(f"  {marker.decode('ascii', 'replace')!r:24s} {rendered}")

    print("\nknown sample offsets:")
    for name, off in KNOWN.items():
        status = "inside" if off < len(data) else "outside"
        print(f"  {name:24s} 0x{off:X}  [{status}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
