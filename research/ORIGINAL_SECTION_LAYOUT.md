# Original dynamic-section placement and 27-section reconstruction

The low file range between the surviving Android note and `.gcc_except_table` can now be laid out almost completely from independent size, header and alignment constraints.

## Exact low-file chain

The first recovered PT_LOAD begins at file/VA zero. `PT_NOTE` ends at `0x2D0`, and the recovered dynsym has exactly 6,837 `Elf64_Sym` entries (`0x280F8` bytes). This fixes the start of the original dynamic metadata chain:

```text
.note.android.ident  0x000238 .. 0x0002D0  size 0x000098
.dynsym              0x0002D0 .. 0x0283C8  size 0x0280F8
.gnu.version         0x0283C8 .. 0x02B932  size 0x00356A
padding              0x02B932 .. 0x02B934
.gnu.version_r       0x02B934 .. 0x02B994  size 0x000060
padding              0x02B994 .. 0x02B998
.gnu.hash            0x02B998 .. 0x0378A0  size 0x00BF08
.hash                0x0378A0 .. 0x044E50  size 0x00D5B0
.dynstr              0x044E50 .. 0x073B1D  size 0x02ECCD
padding              0x073B1D .. 0x073B20
.rela.dyn            0x073B20 .. 0x0DB158  size 0x067638
.rela.plt            0x0DB158 .. 0x0ED3B0  size 0x012258
.gcc_except_table    0x0ED3B0 .. 0x0F5EB0  size 0x008B00
.rodata              0x0F5EB0 .. 0x1FFAFC  size 0x109C4C
```

The chain is not based on one heuristic. Each boundary is constrained by a different recovered artifact:

- `.dynsym`: exact recovered byte length, 6,837 × 24.
- `.gnu.version`: exactly one `Elf64_Half` per dynamic symbol; the original bytes survive plaintext and parse correctly.
- `.gnu.version_r`: parses as three `Elf64_Verneed` records with their Vernaux records and valid offsets into the recovered dynstr.
- `.gnu.hash`: the original 16-byte header survives plaintext and is `nbuckets=1625`, `symoffset=336`, `bloom_size=2048`, `bloom_shift=26`. Those values plus dynsym count determine the section size exactly: `0xBF08`.
- `.hash`: starts immediately after `.gnu.hash`; its surviving header is `nbucket=6837`, `nchain=6837`, giving exact size `8 + 6837*4 + 6837*4 = 0xD5B0`.
- `.dynstr`: exact recovered size `0x2ECCD`; its dependency/version tail is deliberately left plaintext in the raw image and lands exactly at `0x73B1D`.
- `.rela.dyn`: `13,896 R_AARCH64_RELATIVE + 3,272 ABS64 + 477 GLOB_DAT = 17,645` standard Rela records = `0x67638` bytes.
- `.rela.plt`: `3,097 R_AARCH64_JUMP_SLOT` Rela records = `0x12258` bytes.
- the byte at `0xED3B0` is already the beginning of valid LSDA-style `.gcc_except_table` data.

## Correction to the earlier exception-table checkpoint

`0xED59C` was the minimum LSDA address referenced by the earlier FDE walk. It is **not** the true section start.

The exact low-layout chain above forces `.rela.plt` to end at `0xED3B0`, and the bytes at `0xED3B0` already decode like the same LSDA format seen throughout the exception table. The corrected section is:

```text
.gcc_except_table  0xED3B0 .. 0xF5EB0  size 0x8B00
```

## GNU hash can be reconstructed semantically at the original location

Although the protector scrambles the body of the original `.gnu.hash`, its header survives. The recovered dynsym order from symbol index 336 onward is already GNU-hash bucket-contiguous for the header's `1625` buckets.

Therefore a standard GNU hash table can be regenerated from the recovered dynsym/dynstr using exactly:

```text
nbuckets    = 1625
symoffset   = 336
bloom_size  = 2048
bloom_shift = 26
```

The regenerated table is exactly `0xBF08` bytes and occupies the recovered original placement `0x2B998..0x378A0`.

The custom SysV resolver table recovered from the outer SO similarly produces a valid original-placement `.hash` at `0x378A0..0x44E50`.

## 27 section headers

The surviving `.shstrtab` and the exact `0x6C0` tail now support a complete 27-entry semantic section table:

```text
 0  NULL
 1  .note.android.ident
 2  .dynsym
 3  .gnu.version
 4  .gnu.version_r
 5  .gnu.hash
 6  .hash
 7  .dynstr
 8  .rela.dyn
 9  .rela.plt
10  .gcc_except_table
11  .rodata
12  .eh_frame_hdr
13  .eh_frame
14  .text
15  .plt
16  .data.rel.ro
17  .fini_array
18  .init_array
19  .dynamic
20  .got
21  .got.plt
22  .relro_padding
23  .data
24  .bss
25  .comment
26  .shstrtab
```

This order follows the recovered file/VA layout and uses `.plt` and `.hash` as valid suffix offsets inside the surviving `.got.plt` and `.gnu.hash` strings.

Thus the ELF header can now be reconstructed with:

```text
e_phoff     = 0x40
e_phnum     = 9
e_shoff     = 0x52F9B0
e_shentsize = 0x40
e_shnum     = 27
e_shstrndx  = 26
```

The original section-header bytes were destroyed/scrambled, so exact producer values such as every alignment/flag field are still not claimed byte-for-byte. The reconstructed table is semantic and layout-compatible.

## Original-placement builder

`tools/build_inner_original_placement_elf.py` no longer appends recovered dynamic metadata into BSS. It writes the recovered/regenerated tables back into the original low-file slots and keeps the output size exactly `0x530070`.

It reconstructs at original addresses:

```text
.dynsym      0x0002D0
.gnu.version 0x0283C8  (surviving bytes preserved)
.gnu.version_r 0x02B934 (surviving bytes preserved)
.gnu.hash    0x02B998  (regenerated using recovered header + dynsym/dynstr)
.hash        0x0378A0  (exact recovered custom SysV table)
.dynstr      0x044E50
.rela.dyn    0x073B20
.rela.plt    0x0DB158
.dynamic     VA 0x509570 / file 0x505570
section headers file 0x52F9B0
```

The reconstructed `.dynamic` now includes both hash families, symbol versioning, RELA counts, exact dependency order and constructor arrays:

```text
DT_NEEDED x10
DT_SONAME
DT_HASH
DT_GNU_HASH
DT_STRTAB / DT_STRSZ
DT_SYMTAB / DT_SYMENT
DT_VERSYM
DT_VERNEED / DT_VERNEEDNUM
DT_RELA / DT_RELASZ / DT_RELAENT / DT_RELACOUNT
DT_PLTGOT / DT_PLTRELSZ / DT_PLTREL / DT_JMPREL
DT_FINI_ARRAY / DT_FINI_ARRAYSZ
DT_INIT_ARRAY / DT_INIT_ARRAYSZ
```

Validation on the mapped sample:

```text
file    -> ELF64 AArch64 shared object, Android 21, NDK r25c
readelf -h -> 9 PHDRs, 27 SHDRs, e_shoff 0x52F9B0
readelf -S -> coherent 27-section layout
readelf -V -> 6837 version symbols + 3 version-needed records
readelf -I -> valid SysV and GNU hash histograms
readelf -d -> 33 reconstructed dynamic entries at the original PT_DYNAMIC location
readelf -r --use-dynamic -> 17,645 Rela.dyn + 3,097 Rela.plt
```

The current reconstruction is now much closer to the producer's original file than the earlier BSS-extended near-original wrapper: the output file size, low metadata placement, PHDR shape, PT_DYNAMIC location, `.comment`, `.shstrtab`, and section-header location all match the recovered original layout. Remaining uncertainty is primarily byte-perfect reconstruction of metadata bytes the protector destroyed and exact original SHDR flags/alignment fields.
