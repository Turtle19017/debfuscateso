# Outer ELF parser and dynamic reconstruction

This checkpoint separates two concepts that were previously easy to conflate:

1. the outer library contains a normal ELF parser used for already-formed ELF images;
2. the protected inner module stores its symbol/relocation metadata separately, so the recovered `0x530070` inner image is not itself the producer's original ELF file.

The parser is still useful because it reveals exactly which ELF structures the loader expects and provides a template for a loader-shaped reconstruction.

## ELF magic and program headers

`0xC6F10` scans the first `0x80` bytes of a supplied image for the four-byte ELF magic `7F 45 4C 46`.

When found it stores:

```text
ctx + 0x18 = pointer to located Elf64_Ehdr
ctx + 0x38 = byte offset of the ELF header within the supplied buffer
```

`0xC7294` then reads the standard `Elf64_Ehdr` fields:

```text
Ehdr + 0x20 = e_phoff
Ehdr + 0x38 = e_phnum
```

and computes:

```text
ctx + 0x28 = e_phnum
ctx + 0x20 = image_base + elf_header_offset + e_phoff
```

So the code is using normal 64-bit ELF program headers with `sizeof(Elf64_Phdr) == 0x38`.

## PT_LOAD scan at `0xC6F90`

The function walks all program headers in `0x38`-byte steps and recognizes `p_type == PT_LOAD (1)`.

For every load segment it:

- increments the load-segment count;
- finds the minimum `p_vaddr`;
- page-aligns that minimum down to `0x1000`;
- computes the load bias from the supplied mapped image base.

Recovered context fields:

```text
ctx + 0xC0 = load_bias
ctx + 0xC8 = number_of_PT_LOAD_segments
```

The resulting formula is equivalent to:

```c
load_bias = mapped_base - page_align_down(min_load_p_vaddr);
```

## PT_DYNAMIC and dynamic tags at `0xC7028`

`0xC7028` finds `PT_DYNAMIC (2)` and walks normal `Elf64_Dyn` entries until `DT_NULL`.

High-confidence tag mapping from direct comparisons in the routine:

| Tag | Meaning | Loader action |
|---:|---|---|
| `2` | `DT_PLTRELSZ` | divides by 24 and stores PLT relocation count |
| `4` | `DT_HASH` | parses SysV hash header/buckets/chains |
| `5` | `DT_STRTAB` | `load_bias + d_ptr` |
| `6` | `DT_SYMTAB` | `load_bias + d_ptr` |
| `7` | `DT_RELA` | `load_bias + d_ptr` |
| `8` | `DT_RELASZ` | divides by 24 and stores RELA count |
| `10` | `DT_STRSZ` | stores string-table size |
| `14` | `DT_SONAME` | stores string-table offset and a present flag |
| `23` | `DT_JMPREL` | `load_bias + d_ptr` |
| `0x6FFFFEF5` | `DT_GNU_HASH` | parses GNU-hash header/bloom/buckets/chains |

The division used for `DT_PLTRELSZ`/`DT_RELASZ` is by `sizeof(Elf64_Rela) == 24`, confirming RELA rather than REL.

Useful recovered context fields include:

```text
ctx + 0x48 = DT_STRTAB pointer
ctx + 0x50 = DT_STRSZ
ctx + 0x58 = DT_SYMTAB pointer
ctx + 0xD0 = DT_JMPREL pointer
ctx + 0xD8 = DT_PLTRELSZ / 24
ctx + 0xE0 = DT_RELA pointer
ctx + 0xE8 = DT_RELASZ / 24
```

`0xC7360` resolves the SONAME by returning:

```text
strtab + soname_offset
```

when `DT_SONAME` was present.

## What this does and does not prove for the inner module

The normal parser above is used on complete ELF images (the outer loader also uses it when inspecting other loaded libraries).

The protected inner module is different: its `dynstr`, `dynsym`, relocation arrays and dependency metadata are stored separately/encrypted by the outer library, while the recovered `0x530070` payload contains the mapped code/data image.

Therefore the exact producer-side original `e_phoff`, program-header file offsets and dynamic-section virtual address are **not yet recovered** merely by reversing `C6F10..C7294`.

What is recovered exactly from the protected metadata is already sufficient to rebuild the important dynamic semantics:

```text
6837 dynamic symbols
3749 .rela.dyn entries
3097 .rela.plt entries
10 external shared-library dependencies
SONAME libysmteam.so
```

The ten dependency names appear contiguously in recovered dynstr before the SONAME:

```text
libdl.so
libc.so
libm.so
liblog.so
libandroid.so
libEGL.so
libGLESv2.so
libGLESv3.so
libGLESv1_CM.so
libz.so
```

The original `DT_NEEDED` ordering is strongly suggested by this ordering but should still be treated as reconstructed metadata rather than byte-for-byte original dynamic-section evidence.

## Loader-shaped synthetic reconstruction

`tools/build_inner_reconstructed_elf.py` takes the exact recovered inner image and metadata and adds a fourth synthetic metadata `PT_LOAD` above the recovered BSS range.

It emits allocated:

```text
.dynstr
.dynsym
.hash
.rela.dyn
.rela.plt
.dynamic
```

plus `PT_DYNAMIC` containing:

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
DT_PLTGOT
DT_PLTRELSZ
DT_PLTREL = DT_RELA
DT_JMPREL
DT_SONAME
DT_NULL
```

The SysV `.hash` is regenerated from the recovered 6837-symbol dynsym table, allowing standard ELF tooling to perform symbol lookup without requiring the original stripped hash layout.

Example:

```bash
python tools/build_inner_reconstructed_elf.py \
  ysm_inner_payload.bin \
  ysm_inner.reconstructed.so \
  --metadata-dir inner_meta
```

Validation on the current sample:

```text
file -> ELF 64-bit LSB shared object, ARM aarch64, dynamically linked
readelf -d -> 10 DT_NEEDED entries + SONAME libysmteam.so
readelf -r -> 3749 .rela.dyn + 3097 .rela.plt entries
```

Synthetic metadata mapping used by the current tool:

```text
metadata PT_LOAD VA = 0x650000
```

This VA and the generated program headers are explicitly analyst reconstruction. The original file layout remains an open reconstruction problem.
