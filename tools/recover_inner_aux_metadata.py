#!/usr/bin/env python3
"""Recover auxiliary inner-loader metadata: exact custom SysV hash and ctor arrays.

The protected loader keeps two 6837-entry uint32 arrays used directly by the
symbol resolver at 0xC8920.  C8920 implements the classic SysV ELF hash and
walks bucket[h % nbucket] followed by chain[symbol_index].  The arrays are
CB1D8-encrypted separately in the outer SO.

A third CB1D8 table contains the six constructor addends used for the inner
.init_array.  The .fini_array base/count are stored as scalar metadata; its two
addends are already present in the separately recovered runtime-relative fixups.

Important distinction: the exact buckets/chains recovered here are the custom
protector-side resolver tables.  The surviving inner .shstrtab names a
`.gnu.hash` section, not `.hash`, so these tables are not claimed to be the
producer's original GNU-hash bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

SAMPLE_SHA256 = "acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca"
LOADS = (
    (0x000000, 0x000000, 0x390D84),
    (0x391780, 0x3A1780, 0x38B660),
    (0x71E000, 0xD73000, 0x29F4),
)

SEED_K_VA = 0x0B9760
SEED_TABLE_VA = 0x31E790

BUCKETS_VA = 0x40D850
BUCKETS_LEN_VA = 0x3D73A8
BUCKETS_SEED_INDEX = 0

CHAINS_VA = 0x3A5410
CHAINS_LEN_VA = 0x72CD78
CHAINS_SEED_INDEX = 1

NBUCKET_VA = 0x3D73AC
NCHAIN_VA = 0x41449C

INIT_VALUES_VA = 0x443170
INIT_VALUES_LEN_VA = 0x72CD94
INIT_SEED_INDEX = 2
INIT_ARRAY_VA_PTR = 0x3D73B8
INIT_COUNT_VA = 0x72CD8C

FINI_ARRAY_VA_PTR = 0x72CD80
FINI_COUNT_VA = 0x72CD18


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def va_to_offset(va: int) -> int:
    for file_off, seg_va, file_size in LOADS:
        if seg_va <= va < seg_va + file_size:
            return file_off + (va - seg_va)
    raise ValueError(f"VA 0x{va:x} outside known file-backed LOAD ranges")


def read_va(image: bytes, va: int, size: int) -> bytes:
    off = va_to_offset(va)
    return image[off : off + size]


def u32_va(image: bytes, va: int) -> int:
    return struct.unpack("<I", read_va(image, va, 4))[0]


def u64_va(image: bytes, va: int) -> int:
    return struct.unpack("<Q", read_va(image, va, 8))[0]


def derive_seed16(image: bytes) -> bytes:
    k = read_va(image, SEED_K_VA, 16)
    table = read_va(image, SEED_TABLE_VA, 64)
    a, b, c, d = table[0::4], table[1::4], table[2::4], table[3::4]
    return bytes(
        (d[i] + c[i] + k[i] * b[i] + k[i] * k[i] * a[i]) & 0xFF
        for i in range(16)
    )


def cb1d8(data: bytes, seed: int) -> bytes:
    out = bytearray(data)
    state = seed & 0xFFFFFFFF
    prev = 0
    for i, old in enumerate(data):
        state = (state * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        state ^= (prev << 8) & 0xFFFFFFFF
        state ^= i & 0xFFFFFFFF
        out[i] = old ^ ((state >> 16) & 0xFF)
        prev = old
    return bytes(out)


def elf_hash(name: bytes) -> int:
    h = 0
    for c in name:
        h = (h << 4) + c
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g
    return h & 0xFFFFFFFF


def parse_names(dynstr: bytes, dynsym: bytes) -> list[bytes]:
    if len(dynsym) % 24:
        raise ValueError("dynsym length is not divisible by 24")
    names = []
    for i in range(len(dynsym) // 24):
        st_name = struct.unpack_from("<I", dynsym, i * 24)[0]
        if st_name == 0:
            names.append(b"")
            continue
        if st_name >= len(dynstr):
            raise ValueError(f"bad st_name 0x{st_name:x} at symbol {i}")
        end = dynstr.find(b"\0", st_name)
        if end < 0:
            raise ValueError(f"unterminated dynstr name at 0x{st_name:x}")
        names.append(dynstr[st_name:end])
    return names


def validate_resolver_hash(
    dynstr: bytes,
    dynsym: bytes,
    nbucket: int,
    buckets: list[int],
    chains: list[int],
) -> dict:
    names = parse_names(dynstr, dynsym)
    rebuilt_buckets = [0] * nbucket
    rebuilt_chains = [0] * len(names)

    # C8920 walks a linked list beginning at buckets[h % nbucket].
    # The stored tables correspond exactly to prepending each symbol.
    for index, name in enumerate(names):
        if index == 0 or not name:
            continue
        bucket = elf_hash(name) % nbucket
        rebuilt_chains[index] = rebuilt_buckets[bucket]
        rebuilt_buckets[bucket] = index

    return {
        "symbols": len(names),
        "buckets_exact": rebuilt_buckets == buckets,
        "chains_exact": rebuilt_chains == chains,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Recover exact custom SysV hash tables and constructor-array metadata"
    )
    ap.add_argument("outer_so", type=Path)
    ap.add_argument("output_dir", type=Path)
    ap.add_argument(
        "--metadata-dir",
        type=Path,
        help="directory containing recovered dynstr.bin/dynsym.bin; enables exact C8920 validation",
    )
    ap.add_argument("--strict-hash", action="store_true")
    args = ap.parse_args()

    image = args.outer_so.read_bytes()
    digest = sha256(image)
    if digest != SAMPLE_SHA256:
        msg = f"input SHA-256 differs from mapped sample: {digest}"
        if args.strict_hash:
            raise SystemExit("[!] " + msg)
        print("[!] warning:", msg)

    seed16 = derive_seed16(image)
    if seed16.hex() != "9a0d6d36ed21f793e953996ea264e885":
        raise SystemExit(f"[!] unexpected seed16 {seed16.hex()}")

    nbucket = u32_va(image, NBUCKET_VA)
    nchain = u32_va(image, NCHAIN_VA)
    buckets_len = u32_va(image, BUCKETS_LEN_VA)
    chains_len = u32_va(image, CHAINS_LEN_VA)

    buckets_raw = cb1d8(
        read_va(image, BUCKETS_VA, buckets_len), seed16[BUCKETS_SEED_INDEX]
    )
    chains_raw = cb1d8(
        read_va(image, CHAINS_VA, chains_len), seed16[CHAINS_SEED_INDEX]
    )

    if buckets_len != nbucket * 4 or chains_len != nchain * 4:
        raise SystemExit("[!] recovered hash-array sizes do not match counts")

    buckets = list(struct.unpack(f"<{nbucket}I", buckets_raw))
    chains = list(struct.unpack(f"<{nchain}I", chains_raw))

    init_values_len = u32_va(image, INIT_VALUES_LEN_VA)
    init_values_raw = cb1d8(
        read_va(image, INIT_VALUES_VA, init_values_len), seed16[INIT_SEED_INDEX]
    )
    if init_values_len % 8:
        raise SystemExit("[!] init-value table is not qword aligned")
    init_values = list(
        struct.unpack(f"<{init_values_len // 8}Q", init_values_raw)
    )

    init_array_va = u64_va(image, INIT_ARRAY_VA_PTR)
    init_count = u32_va(image, INIT_COUNT_VA)
    fini_array_va = u64_va(image, FINI_ARRAY_VA_PTR)
    fini_count = u32_va(image, FINI_COUNT_VA)
    if len(init_values) != init_count:
        raise SystemExit("[!] init-array count does not match decrypted value table")

    validation = None
    if args.metadata_dir:
        dynstr = (args.metadata_dir / "dynstr.bin").read_bytes()
        dynsym = (args.metadata_dir / "dynsym.bin").read_bytes()
        validation = validate_resolver_hash(
            dynstr, dynsym, nbucket, buckets, chains
        )
        if not validation["buckets_exact"] or not validation["chains_exact"]:
            raise SystemExit("[!] recovered hash tables do not match C8920 semantics")

    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)

    hash_blob = struct.pack("<II", nbucket, nchain) + buckets_raw + chains_raw
    (output / "hash.sysv.bin").write_bytes(hash_blob)
    (output / "hash.buckets.bin").write_bytes(buckets_raw)
    (output / "hash.chains.bin").write_bytes(chains_raw)

    with (output / "init_array.tsv").open("w", encoding="utf-8") as f:
        f.write("index\tarray_va\tfunction_addend\n")
        for i, value in enumerate(init_values):
            f.write(f"{i}\t0x{init_array_va + i * 8:x}\t0x{value:x}\n")

    manifest = {
        "input_sha256": digest,
        "seed16": seed16.hex(),
        "sysv_hash": {
            "nbucket": nbucket,
            "nchain": nchain,
            "buckets_va": BUCKETS_VA,
            "chains_va": CHAINS_VA,
            "bucket_seed_index": BUCKETS_SEED_INDEX,
            "chain_seed_index": CHAINS_SEED_INDEX,
            "hash_blob_size": len(hash_blob),
            "hash_blob_sha256": sha256(hash_blob),
            "validation": validation,
        },
        "init_array": {
            "va": init_array_va,
            "count": init_count,
            "byte_size": init_count * 8,
            "values": init_values,
            "encrypted_table_va": INIT_VALUES_VA,
            "seed_index": INIT_SEED_INDEX,
        },
        "fini_array": {
            "va": fini_array_va,
            "count": fini_count,
            "byte_size": fini_count * 8,
            "note": "entries are supplied by the recovered runtime relative-fixup table",
        },
        "resolver_evidence": {
            "function": "0xC8920",
            "algorithm": "SysV ELF hash",
            "lookup": "bucket[h % nbucket] then chain[symbol_index]",
            "chain_build_semantics": "prepending (chain[i] = old_bucket; bucket = i)",
        },
    }
    (output / "aux_metadata.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    print(
        f"[+] SysV hash    nbucket={nbucket} nchain={nchain} "
        f"size=0x{len(hash_blob):x} sha256={sha256(hash_blob)}"
    )
    print(
        f"[+] init_array   VA=0x{init_array_va:x} count={init_count} "
        + " ".join(f"0x{x:x}" for x in init_values)
    )
    print(f"[+] fini_array   VA=0x{fini_array_va:x} count={fini_count}")
    if validation:
        print(
            f"[+] validation   buckets={validation['buckets_exact']} "
            f"chains={validation['chains_exact']}"
        )
    print(f"[+] wrote        {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
