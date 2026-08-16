# Outer ELF parser and dynamic reconstruction

This note records the normal ELF parser in the outer loader and how it now lines up with the separately recovered protected-inner program-header table.

## Normal ELF parsing path

`0xC6F10` scans the first `0x80` bytes of a supplied image for ELF magic `7F 45 4C 46`.
When found it stores the header pointer and the byte offset of that header inside the supplied buffer.

`0xC7294` then reads standard `Elf64_Ehdr` fields:

```text
Ehdr + 0x20 = e_phoff
Ehdr + 0x38 = e_phnum
```

and computes the program-header pointer. The parser uses normal 64-bit program headers with `sizeof(Elf64_Phdr) == 0x38`.

## PT_LOAD scan at `0xC6F90`

`0xC6F90` walks the program headers in `0x38`-byte steps and recognizes `PT_LOAD`.
It counts load segments, finds the minimum `p_vaddr`, page-aligns that value and computes the load bias from the mapped image base.

Recovered context fields include:

```text
ctx + 0xC0 = load_bias
ctx + 0xC8 = number_of_PT_LOAD_segments
```

## PT_DYNAMIC parser at `0xC7028`

`0xC7028` finds `PT_DYNAMIC` and consumes ordinary `Elf64_Dyn` entries until `DT_NULL`.

High-confidence tag mapping:

| Tag | Meaning | Loader action |
|---:|---|---|
| `2` | `DT_PLTRELSZ` | divide by 24 and store PLT RELA count |
| `4` | `DT_HASH` | parse SysV hash |
| `5` | `DT_STRTAB` | `load_bias + d_ptr` |
| `6` | `DT_SYMTAB` | `load_bias + d_ptr` |
| `7` | `DT_RELA` | `load_bias + d_ptr` |
| `8` | `DT_RELASZ` | divide by 24 and store RELA count |
| `10` | `DT_STRSZ` | store dynstr size |
| `14` | `DT_SONAME` | store dynstr offset |
| `23` | `DT_JMPREL` | `load_bias + d_ptr` |
| `0x6FFFFEF5` | `DT_GNU_HASH` | parse GNU hash |

The 24-byte divisor confirms `Elf64_Rela`, not REL.

Useful context fields:

```text
ctx + 0x48 = DT_STRTAB pointer
ctx + 0x50 = DT_STRSZ
ctx + 0x58 = DT_SYMTAB pointer
ctx + 0xD0 = DT_JMPREL pointer
ctx + 0xD8 = DT_PLTRELSZ / 24
ctx + 0xE0 = DT_RELA pointer
ctx + 0xE8 = DT_RELASZ / 24
```

## Program-header status: now recovered

An earlier checkpoint correctly observed that reversing `C6F10..C7294` alone did not reveal the protected inner module's producer-side program headers.
That gap is now closed independently by the compact protected PHDR table used by `FD55C`.

For the mapped sample, `tools/recover_inner_phdrs.py` recovers:

```text
e_phoff      0x40
e_phentsize  0x38
e_phnum      9
PHDR end     0x238
```

and nine records containing exact `p_type`, `p_flags`, `p_offset`, `p_vaddr`, `p_filesz` and `p_memsz` values.
The compact records omit only `p_paddr` and `p_align`.

The three recovered `PT_LOAD` mappings are:

```text
#1 off 0x000000  VA 0x000000  filesz 0x4E29C0  memsz 0x4E29C0  R-X
#2 off 0x4E29C0  VA 0x4E69C0  filesz 0x029DD8  memsz 0x02A640  RW-
#3 off 0x50C7A0  VA 0x5147A0  filesz 0x022DC0  memsz 0x12E1F1  RW-
```

The recovered original `PT_DYNAMIC` location is:

```text
file offset 0x505570
VA          0x509570
size        0x230
```

See `research/PROGRAM_HEADERS.md` for the complete table and validation.

## Preserved Android note

The PHDR table ends exactly at `0x238`, where the raw recovered file already contains a valid `PT_NOTE` payload.
After restoring only the ELF header and PHDRs, standard tools decode that note as:

```text
Android API level 21
NDK r25c
build 9519653
```

This is an independent structural consistency check for the recovered header layout.

## Dynamic metadata status

The bytes currently present at the original `PT_DYNAMIC` file offset are not a plaintext standard dynamic table.
The protector stores inner dynstr/dynsym/relocation/dependency information separately in encrypted outer tables, all of which are now recoverable offline.

Recovered semantics include:

```text
6837 dynamic symbols
13896 R_AARCH64_RELATIVE fixups
3272 R_AARCH64_ABS64 relocations
477 R_AARCH64_GLOB_DAT relocations
3097 R_AARCH64_JUMP_SLOT relocations
10 exact dependency names/order
SONAME libysmteam.so
```

So the original dynamic-table **location and capacity** are recovered exactly, while its contents are reconstructed semantically rather than byte-for-byte.

## Reconstruction tools

Conservative header restoration:

```bash
python tools/recover_inner_phdrs.py libysmteam.so phdr_meta --strict-hash
python tools/restore_inner_header.py \
  ysm_inner_payload.bin phdr_meta/manifest.json ysm_inner.header_restored.so
```

The header-restored file preserves raw `PT_DYNAMIC` bytes and is useful for `readelf -h -l -n`.

Near-original-layout semantic reconstruction:

```bash
python tools/build_inner_near_original_elf.py \
  ysm_inner_payload.bin \
  ysm_inner.near_original.so \
  --metadata-dir inner_meta \
  --phdr-manifest phdr_meta/manifest.json
```

This keeps the recovered original three-LOAD VA mapping and nine-entry PHDR shape. Recovered dynamic metadata is placed inside unused capacity of the original third LOAD's BSS range, so no synthetic fourth PT_LOAD is needed. The third LOAD `p_filesz` is extended, but its `p_memsz` and recovered virtual range are preserved.

The result is still a semantic reconstruction rather than a byte-perfect producer ELF because `p_align`, `p_paddr`, original hash layout and exact dynamic-metadata placement were not retained by the protector.
