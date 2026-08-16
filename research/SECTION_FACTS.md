# Recovered inner section facts

This checkpoint recovers high-confidence original section boundaries without pretending that the destroyed `Elf64_Shdr` entries themselves have been decoded.

The evidence comes from the recovered original-shape PHDRs, surviving EH-frame metadata, recovered relocations and constructor arrays, and the plaintext section-name table at the end of the raw inner image.

## Exact / high-confidence allocated-section boundaries

```text
.note.android.ident  VA 0x000238  file 0x000238  size 0x000098
.eh_frame_hdr        VA 0x1FF AFC file 0x1FF AFC size 0x012AF4
.eh_frame            VA 0x2125F0  file 0x2125F0  size 0x04BCE4
.text                VA 0x25E2E0  file 0x25E2E0  size 0x278530
.plt                 VA 0x4D6810  file 0x4D6810  size 0x00C1B0
.data.rel.ro         VA 0x4E69C0  file 0x4E29C0  size 0x022B70
.fini_array          VA 0x509530  file 0x505530  size 0x000010
.init_array          VA 0x509540  file 0x505540  size 0x000030
.dynamic             VA 0x509570  file 0x505570  size 0x000230
.got                 VA 0x5097A0  file 0x5057A0  size 0x000F18
.got.plt             VA 0x50A6B8  file 0x5066B8  size 0x0060E0
.relro_padding       VA 0x510798               size 0x000868
.data                VA 0x5147A0  file 0x50C7A0  size 0x022DC0
.bss                 VA 0x537560               size 0x10B431
.comment                           file 0x52F560  size 0x00034A
.shstrtab                          file 0x52F8AA  size 0x000100
```

(`0x1FF AFC` above is `0x1FFAFC`; spacing is only for readability.)

## Why these boundaries are strong

### `.eh_frame_hdr` -> `.eh_frame`

The recovered `PT_GNU_EH_FRAME` starts at `0x1FFAFC` and has size `0x12AF4`.
Its first bytes use the standard encoding:

```text
01 1B 03 3B
```

The encoded `eh_frame_ptr` resolves to `0x2125F0`.
The header advertises 9,565 FDE search-table entries, and:

```text
12 + 9565 * 8 = 0x12AF4
```

exactly equals the recovered PHDR size.

Parsing the `.eh_frame` CIE/FDE records reaches its zero terminator at `0x25E2D4`; 12 bytes of alignment then place the first code at `0x25E2E0`.

### `.text` -> `.plt`

The first regular PLT entry is `0x4D6830`. AArch64 PLT0 occupies the preceding `0x20` bytes, so:

```text
.plt start = 0x4D6810
```

The recovered 3,097 regular PLT records are `0x10` bytes each:

```text
0x20 + 3097 * 0x10 = 0xC1B0
```

which ends exactly at `0x4E29C0`, the recovered first PT_LOAD file/memory end.

### writable RELRO layout

The second PT_LOAD begins at file `0x4E29C0`, VA `0x4E69C0`.
The exact constructor metadata gives:

```text
.fini_array  0x509530..0x509540
.init_array  0x509540..0x509570
.dynamic     0x509570..0x5097A0
```

Therefore `.data.rel.ro` is the contiguous region from the second LOAD start through the beginning of `.fini_array`.

### Correct `.got.plt` start

An earlier scratch boundary treated the first `R_AARCH64_JUMP_SLOT` target (`0x50A6D0`) as the start of `.got.plt`. That omitted the three reserved AArch64 GOT.PLT qwords.

The actual file-backed bytes at `0x50A6B8` are:

```text
qword 0 = 0
qword 1 = 0
qword 2 = 0
qword 3 = 0x4D6810   # first regular lazy-binding slot value
```

Thus:

```text
.got.plt start = 0x50A6D0 - 3*8 = 0x50A6B8
```

and the second PT_LOAD file-backed end is `0x510798`, giving:

```text
.got.plt size = 0x60E0 = (3 + 3097) * 8
```

The zero-filled tail to the second LOAD memory end (`0x511000`) is `0x868`, matching `.relro_padding`.

### `.data` / `.bss`

The recovered third PT_LOAD is:

```text
file 0x50C7A0, VA 0x5147A0
filesz 0x22DC0
memsz  0x12E1F1
```

So its original file-backed end is:

```text
VA 0x537560
```

This directly gives the `.data` / `.bss` boundary.

## Surviving `.shstrtab`

Immediately after the original third PT_LOAD file data is `.comment`:

```text
.comment  file 0x52F560..0x52F8AA
```

The following `0x100` bytes are a plaintext section-name table:

```text
.shstrtab file 0x52F8AA..0x52F9AA
```

It contains 24 standalone section-name strings:

```text
.init_array
.fini_array
.text
.got
.comment
.note.android.ident
.got.plt
.rela.plt
.bss
.dynstr
.eh_frame_hdr
.gnu.version_r
.data.rel.ro
.rela.dyn
.gnu.version
.dynsym
.gnu.hash
.relro_padding
.eh_frame
.gcc_except_table
.dynamic
.shstrtab
.rodata
.data
```

ELF `sh_name` is an offset into a byte string table; it does not need to point at the start of a standalone C string. Two additional valid names are encoded as suffix aliases:

```text
.plt   -> suffix inside ".got.plt"
.hash  -> suffix inside ".gnu.hash"
```

Therefore the table can name:

```text
24 standalone names
+ 2 suffix aliases
+ 1 NULL section
= 27 section slots
```

## Candidate original section-header shape

The bytes after `.shstrtab` are padded to `0x52F9B0`.
The remaining raw-image tail is:

```text
0x52F9B0 .. 0x530070
size = 0x6C0
```

Since `sizeof(Elf64_Shdr) == 0x40`:

```text
0x6C0 / 0x40 = 27
```

This exactly matches the 27 names/slots above.

The strongest current section-header shape is therefore:

```text
candidate e_shoff     = 0x52F9B0
e_shentsize           = 0x40
candidate e_shnum     = 27
```

The 27 trailing entries themselves remain scrambled/destroyed, so individual original `Elf64_Shdr` fields and `e_shstrndx` are **not yet claimed recovered**.

## Hash correction

A previous note said the surviving section-name table contained `.gnu.hash` but not `.hash`. That was too strict: `.hash` exists as a valid suffix-name alias beginning inside the `.gnu.hash` string.

Combined with the exact 6,837-bucket custom SysV resolver table recovered from the outer loader, this is now strong evidence for a SysV `.hash` section in the original section namespace as well. The original `.gnu.hash` bytes are still not recovered.

## Tool

```bash
python tools/recover_inner_section_facts.py \
  ysm_inner_payload.bin \
  section_facts \
  --phdr-manifest phdr_meta/manifest.json \
  --metadata-dir inner_meta \
  --aux-dir inner_aux
```

Outputs:

```text
section_facts/section_facts.json
section_facts/sections.tsv
```

Next target: determine whether the destroyed `0x6C0` section-header tail has a recoverable transform. If not, reconstruct a coherent 27-entry section table from these direct boundaries plus the recovered dynamic tables, while keeping reconstructed fields explicitly distinguished from original bytes.
