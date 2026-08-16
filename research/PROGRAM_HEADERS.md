# Recovered inner program-header layout

This checkpoint closes a major gap between the extracted `0x530070`-byte inner raw file and the producer-side ELF layout.

## Protected compact PHDR table

`FD55C` builds 16-byte wrapper objects around a source table referenced by the descriptor initialized at `FD140`.
The source records are 40 bytes each and are decoded by helpers `CA468`, `CA4D0`, `CA538`, `CA598`, `CA5F8` and `CA658`.

For the mapped sample:

```text
compact table VA   0x414330
record count       9
record size        40
XOR seed           0x2D
```

Each decoded record is:

```c
struct CompactPhdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_vaddr;
    uint64_t p_memsz;
    uint64_t p_filesz;
    uint64_t p_offset;
};
```

`p_paddr` and `p_align` were discarded by this protected representation, so they remain inferred rather than exact.

## Exact recovered fields

| # | Type | Flags | p_offset | p_vaddr | p_filesz | p_memsz |
|---:|---|---:|---:|---:|---:|---:|
| 0 | `PT_PHDR` | R | `0x40` | `0x40` | `0x1F8` | `0x1F8` |
| 1 | `PT_LOAD` | R-X | `0x0` | `0x0` | `0x4E29C0` | `0x4E29C0` |
| 2 | `PT_LOAD` | RW- | `0x4E29C0` | `0x4E69C0` | `0x29DD8` | `0x2A640` |
| 3 | `PT_LOAD` | RW- | `0x50C7A0` | `0x5147A0` | `0x22DC0` | `0x12E1F1` |
| 4 | `PT_DYNAMIC` | RW- | `0x505570` | `0x509570` | `0x230` | `0x230` |
| 5 | `PT_GNU_RELRO` | R | `0x4E29C0` | `0x4E69C0` | `0x29DD8` | `0x2A640` |
| 6 | `PT_GNU_EH_FRAME` | R | `0x1FFafc` | `0x1FFafc` | `0x12AF4` | `0x12AF4` |
| 7 | `PT_GNU_STACK` | RW- | `0x0` | `0x0` | `0x0` | `0x0` |
| 8 | `PT_NOTE` | R | `0x238` | `0x238` | `0x98` | `0x98` |

The `PT_PHDR` record gives a particularly strong consistency check:

```text
e_phoff      = 0x40
sizeof Phdr  = 0x38
phnum        = 9
PHDR bytes   = 9 * 0x38 = 0x1F8
PHDR end     = 0x40 + 0x1F8 = 0x238
```

`0x238` is exactly where the preserved `PT_NOTE` begins in the recovered raw file.

Therefore the original-shape ELF header facts are now high confidence:

```text
e_ehsize     0x40
e_phoff      0x40
e_phentsize  0x38
e_phnum      9
```

## Preserved Android note

Restoring only the ELF header and nine program headers, without touching bytes from `0x238` onward, lets `readelf -n` parse the existing note directly.

The note identifies:

```text
Android API level  21
NDK revision       r25c
build              9519653
```

`file` correspondingly identifies the restored sample as an AArch64 Android shared object built by NDK r25c.

## Important correction: raw offsets are not always virtual addresses

The first load has `p_offset == p_vaddr`, which is why previously recovered code addresses below `0x4E29C0` were unaffected.

The writable loads use biases:

```text
LOAD #2: p_vaddr - p_offset = 0x4000
LOAD #3: p_vaddr - p_offset = 0x8000
```

So after file offset `0x4E29C0`, treating raw-file offsets as VAs is incorrect.

For example, the previously mapped `key_buffer @ VA 0x53912C` belongs to LOAD #3. Its corresponding file offset would be:

```text
0x53912C - 0x8000 = 0x53112C
```

which is beyond the recovered raw file end `0x530070`, correctly placing that object in BSS rather than file-backed data.

LOAD #3 boundaries are:

```text
file start              0x50C7A0
original file-backed end 0x52F560
VA start                0x5147A0
original file-backed end 0x537560
memory end              0x642991
```

The recovered raw file continues another `0xB10` bytes after `0x52F560`; those bytes include compiler-comment strings and are outside the original third PT_LOAD file extent.

## Original PT_DYNAMIC location

The compact table also recovers the exact dynamic-segment location:

```text
file offset  0x505570
VA           0x509570
size         0x230
entries      35 Elf64_Dyn-sized slots
```

The bytes currently present there in the recovered payload are not a plaintext `Elf64_Dyn` table. The custom loader instead uses separately protected symbol/relocation metadata already recovered elsewhere in this repository.

Therefore the location and capacity of the original dynamic segment are exact, while its reconstructed contents remain semantic rather than byte-for-byte original.

## Tools

Recover the compact table:

```bash
python tools/recover_inner_phdrs.py libysmteam.so phdr_meta --strict-hash
```

Restore only the original-shape ELF header/program headers:

```bash
python tools/restore_inner_header.py \
  ysm_inner_payload.bin \
  phdr_meta/manifest.json \
  ysm_inner.header_restored.so
```

This output is intentionally useful for `readelf -h -l -n`; its `PT_DYNAMIC` bytes remain protected.

## Near-original-layout semantic reconstruction

`tools/build_inner_near_original_elf.py` goes one step further.

Rather than adding a fourth synthetic PT_LOAD, it preserves the recovered three-load VA mapping and the original nine-entry PHDR shape. Recovered dynamic metadata is stored inside unused capacity of LOAD #3's original BSS range, and only that segment's `p_filesz` is extended.

The dynamic table is rebuilt at its exact recovered location `0x505570 / VA 0x509570` with:

```text
DT_NEEDED x10
DT_HASH
DT_STRTAB
DT_SYMTAB
DT_STRSZ
DT_SYMENT
DT_RELA
DT_RELASZ
DT_RELAENT
DT_RELACOUNT = 13896
DT_PLTGOT
DT_PLTRELSZ
DT_PLTREL = DT_RELA
DT_JMPREL
DT_SONAME
DT_NULL
```

Validation on the mapped sample:

```text
original PHDR count         9
DT_RELA entries             17645
  R_AARCH64_RELATIVE        13896
  symbol .rela.dyn           3749
DT_JMPREL entries            3097
```

The generated file is recognized as:

```text
ELF 64-bit LSB shared object, ARM aarch64
for Android 21, built by NDK r25c (9519653)
```

and `readelf -d` / `readelf -r --use-dynamic` can walk the reconstructed dynamic metadata using the corrected original VA mapping.

Caveat: this remains a semantic reconstruction, not a byte-perfect producer ELF, because the original `p_align`, `p_paddr`, hash layout and exact dynamic-metadata placement were not retained by the protector.
