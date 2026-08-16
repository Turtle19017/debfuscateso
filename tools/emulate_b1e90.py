#!/usr/bin/env python3
"""Offline B1E90 emulator for the analyzed ARM64 libysmteam.so sample.

Requires: pip install unicorn
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

B1E90_START = 0xB1E90
B1E90_END = 0xB9690
MEMCPY_PLT = 0xA8DF0
STACK_FAIL_PLT = 0xA8F30
RELA_DYN_OFF = 0x9EBB8
RELA_DYN_SIZE = 0x9D98
R_AARCH64_RELATIVE = 0x403

RX_FILE_OFF = 0x0
RX_VA = 0x0
RX_FILE_SIZE = 0x390D84
RW_FILE_OFF = 0x391780
RW_VA = 0x3A1780
RW_FILE_SIZE = 0x38B660
RW_MEM_SIZE = 0x9D0B68

PAGE = 0x1000
STACK_BASE = 0x20000000
STACK_SIZE = 0x20000
SP = STACK_BASE + 0x10000
INPUT = STACK_BASE + 0x18000
OUTPUT = STACK_BASE + 0x18100
GUARD = 0x30000000
RETURN_SENTINEL = 0x40000000


def align_down(v: int, a: int = PAGE) -> int:
    return v & ~(a - 1)


def align_up(v: int, a: int = PAGE) -> int:
    return (v + a - 1) & ~(a - 1)


class B1E90Emulator:
    def __init__(self, so_path: Path):
        try:
            from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
            from unicorn.arm64_const import (
                UC_ARM64_REG_LR,
                UC_ARM64_REG_SP,
                UC_ARM64_REG_X0,
                UC_ARM64_REG_X1,
                UC_ARM64_REG_X2,
                UC_ARM64_REG_PC,
            )
        except ImportError as exc:
            raise RuntimeError("Unicorn is required: pip install unicorn") from exc

        self.UC_HOOK_CODE = UC_HOOK_CODE
        self.REG_LR = UC_ARM64_REG_LR
        self.REG_SP = UC_ARM64_REG_SP
        self.REG_X0 = UC_ARM64_REG_X0
        self.REG_X1 = UC_ARM64_REG_X1
        self.REG_X2 = UC_ARM64_REG_X2
        self.REG_PC = UC_ARM64_REG_PC
        self.so = Path(so_path).read_bytes()
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self._map_image()
        self._apply_relative_relocs()
        self._install_hooks()

    def _map_image(self) -> None:
        from unicorn import UC_PROT_ALL

        # Do not map page zero; none of the transform's valid accesses require it.
        rx_start = PAGE
        rx_end = align_up(RX_VA + RX_FILE_SIZE)
        self.mu.mem_map(rx_start, rx_end - rx_start, UC_PROT_ALL)
        self.mu.mem_write(rx_start, self.so[rx_start:RX_FILE_SIZE])

        rw_start = align_down(RW_VA)
        rw_end = align_up(RW_VA + RW_MEM_SIZE)
        self.mu.mem_map(rw_start, rw_end - rw_start, UC_PROT_ALL)
        self.mu.mem_write(RW_VA, self.so[RW_FILE_OFF : RW_FILE_OFF + RW_FILE_SIZE])

        self.mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        self.mu.mem_map(GUARD, PAGE, UC_PROT_ALL)
        self.mu.mem_map(RETURN_SENTINEL, PAGE, UC_PROT_ALL)

        # Imported __stack_chk_guard GOT slot.
        self.mu.mem_write(0x3A4F60, struct.pack("<Q", GUARD))
        self.mu.mem_write(GUARD, struct.pack("<Q", 0x1122334455667788))

    def _apply_relative_relocs(self) -> None:
        end = RELA_DYN_OFF + RELA_DYN_SIZE
        for off in range(RELA_DYN_OFF, end, 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.so, off)
            if (r_info & 0xFFFFFFFF) == R_AARCH64_RELATIVE:
                self.mu.mem_write(r_offset, struct.pack("<Q", r_addend & 0xFFFFFFFFFFFFFFFF))

        # Restore the imported guard slot after RELATIVE processing.
        self.mu.mem_write(0x3A4F60, struct.pack("<Q", GUARD))

    def _install_hooks(self) -> None:
        self.mu.hook_add(
            self.UC_HOOK_CODE,
            self._hook_memcpy,
            begin=MEMCPY_PLT,
            end=MEMCPY_PLT,
        )
        self.mu.hook_add(
            self.UC_HOOK_CODE,
            self._hook_stack_fail,
            begin=STACK_FAIL_PLT,
            end=STACK_FAIL_PLT,
        )

    def _hook_memcpy(self, uc, address, size, user_data) -> None:
        dst = uc.reg_read(self.REG_X0)
        src = uc.reg_read(self.REG_X1)
        n = uc.reg_read(self.REG_X2)
        uc.mem_write(dst, bytes(uc.mem_read(src, n)))
        uc.reg_write(self.REG_X0, dst)
        uc.reg_write(self.REG_PC, uc.reg_read(self.REG_LR))

    def _hook_stack_fail(self, uc, address, size, user_data) -> None:
        raise RuntimeError("B1E90 hit __stack_chk_fail")

    def transform(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("B1E90 accepts exactly 16 bytes")
        self.mu.mem_write(INPUT, block)
        self.mu.mem_write(OUTPUT, b"\0" * 16)
        self.mu.reg_write(self.REG_X0, INPUT)
        self.mu.reg_write(self.REG_X1, OUTPUT)
        self.mu.reg_write(self.REG_SP, SP)
        self.mu.reg_write(self.REG_LR, RETURN_SENTINEL)
        self.mu.emu_start(B1E90_START, RETURN_SENTINEL)
        return bytes(self.mu.mem_read(OUTPUT, 16))

    def decrypt_pkcs7(self, ciphertext: bytes, progress: bool = False) -> bytes:
        if not ciphertext or len(ciphertext) % 16:
            raise ValueError("ciphertext length must be a non-zero multiple of 16")
        total = len(ciphertext) // 16
        out = bytearray()
        for i in range(total):
            out += self.transform(ciphertext[i * 16 : i * 16 + 16])
            if progress and (i + 1) % 64 == 0:
                print(f"  B1E90: {i + 1}/{total} blocks")
        pad = out[-1]
        if not 1 <= pad <= 16 or out[-pad:] != bytes([pad]) * pad:
            raise ValueError(f"invalid PKCS#7 padding after B1E90 (last byte=0x{pad:02x})")
        return bytes(out[:-pad])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("so", type=Path)
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--raw-blocks", action="store_true")
    args = ap.parse_args()

    data = args.input.read_bytes()
    emu = B1E90Emulator(args.so)
    if args.raw_blocks:
        if len(data) % 16:
            raise SystemExit("input length must be a multiple of 16")
        out = b"".join(emu.transform(data[i : i + 16]) for i in range(0, len(data), 16))
    else:
        out = emu.decrypt_pkcs7(data, progress=True)
    args.output.write_bytes(out)
    print(f"wrote {len(out)} bytes -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
