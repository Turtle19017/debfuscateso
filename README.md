# debfuscateso

Static reverse-engineering notes and reproducible helpers for the analyzed ARM64 Android `libysmteam.so` sample.

The repository does **not** include the original APK/SO or extracted payload binaries. Tools operate on researcher-supplied local files. It documents unpacking/devirtualization and loader reconstruction; it does not contain an authentication-bypass patch.

## Current checkpoint

For the mapped sample, the important stages are reproducible offline:

- outer `.main` decrypt and VM stream extraction;
- `B1E90` white-box block stage + ChaCha20 + zlib -> exact `0x530070` inner image;
- 6,837 recovered dynamic symbols and exact JNI exports;
- 13,896 `R_AARCH64_RELATIVE`, 3,272 `R_AARCH64_ABS64`, 477 `R_AARCH64_GLOB_DAT`, 3,097 `R_AARCH64_JUMP_SLOT` relocations;
- exact ten-library custom-loader dependency order;
- exact custom resolver SysV bucket/chain tables (`6837/6837`);
- exact `.init_array` / `.fini_array` metadata;
- protected original-shape program headers: `e_phoff=0x40`, `e_phnum=9`, three original PT_LOAD mappings and original PT_DYNAMIC/PT_NOTE/GNU_RELRO/EH_FRAME/STACK roles;
- high-confidence original 27-section layout and original low dynamic-section placements;
- proof that stripped ELF metadata regions are destructive high-entropy 7-bit filler rather than ordinary reversible ciphertext;
- original GNU-hash header + complete 2048-word bloom filter survive byte-for-byte, with the final 336 chain entries also surviving;
- a canonical NDK/LLD-shaped `PT_DYNAMIC` reconstruction that fills the recovered original `0x230` segment exactly with 35 `Elf64_Dyn` records, including eager-binding flags required by full RELRO.

Known inner image:

```text
size   = 0x530070
sha256 = 5a0ff6b4e1d3bf811dbd1f2b5db3e48ae14c12fb6da5f5662bf2e3c7bd66f168
```

## Quick workflow

```bash
pip install unicorn

python tools/extract_inner.py \
  libysmteam.so \
  ysm_inner_payload.bin

python tools/recover_inner_symbols.py \
  libysmteam.so \
  inner_meta \
  --inner ysm_inner_payload.bin \
  --strict-hash \
  --dump-raw

python tools/recover_inner_runtime_metadata.py \
  libysmteam.so \
  inner_runtime \
  --strict-hash

cp inner_runtime/rela.relative.bin inner_meta/
cp inner_runtime/needed.txt inner_meta/

python tools/recover_inner_phdrs.py \
  libysmteam.so \
  phdr_meta \
  --strict-hash

python tools/recover_inner_aux_metadata.py \
  libysmteam.so \
  inner_aux \
  --metadata-dir inner_meta \
  --strict-hash

python tools/recover_inner_original_layout.py \
  ysm_inner_payload.bin \
  original_layout \
  --metadata-dir inner_meta \
  --aux-dir inner_aux

python tools/audit_inner_randomization.py \
  ysm_inner_payload.bin \
  --metadata-dir inner_meta \
  --aux-dir inner_aux \
  --json randomization_audit.json

python tools/recover_inner_dynamic_table.py \
  ysm_inner_payload.bin \
  dynamic_meta \
  --metadata-dir inner_meta \
  --aux-dir inner_aux \
  --layout-manifest original_layout/original_layout.json

python tools/build_inner_original_placement_elf.py \
  ysm_inner_payload.bin \
  ysm_inner.original_placement.so \
  --metadata-dir inner_meta \
  --aux-dir inner_aux \
  --phdr-manifest phdr_meta/manifest.json \
  --layout-manifest original_layout/original_layout.json
```

## Important recovered layout

```text
.note.android.ident  0x000238 .. 0x0002D0
.dynsym              0x0002D0 .. 0x0283C8
.gnu.version         0x0283C8 .. 0x02B932
.gnu.version_r       0x02B934 .. 0x02B994
.gnu.hash            0x02B998 .. 0x0378A0
.hash                0x0378A0 .. 0x044E50
.dynstr              0x044E50 .. 0x073B1D
.rela.dyn            0x073B20 .. 0x0DB158
.rela.plt            0x0DB158 .. 0x0ED3B0
.gcc_except_table    0x0ED3B0 .. 0x0F5EB0
.rodata              0x0F5EB0 .. 0x1FFAFC
.eh_frame_hdr        0x1FFAFC .. 0x2125F0
.eh_frame            0x2125F0 .. 0x25E2D4
.text                0x25E2E0 .. 0x4D6810
.plt                 0x4D6810 .. 0x4E29C0

.data.rel.ro         0x4E69C0 .. 0x509530
.fini_array          0x509530 .. 0x509540
.init_array          0x509540 .. 0x509570
.dynamic             0x509570 .. 0x5097A0
.got                 0x5097A0 .. 0x50A6B8
.got.plt             0x50A6B8 .. 0x510798
.relro_padding       0x510798 .. 0x511000
.data                0x5147A0 .. 0x537560
.bss                 0x537560 .. 0x642991

.comment        file 0x52F560 .. 0x52F8AA
.shstrtab       file 0x52F8AA .. 0x52F9AA
section headers file 0x52F9B0 .. 0x530070 = 27 * 0x40
```

Recovered ELF-header shape:

```text
e_phoff     = 0x40
e_phnum     = 9
e_shoff     = 0x52F9B0
e_shentsize = 0x40
e_shnum     = 27
e_shstrndx  = 26
```

## Destructive stripping result

The randomized raw ranges for `dynsym`, `rela.dyn`, `rela.plt`, `PT_DYNAMIC`, the ELF/PHDR header area and the section-header tail contain only values `0x00..0x7f` and have near-7-bit-maximal entropy. Exact recovered metadata contains many high-bit bytes that are absent from those raw ranges. These regions are therefore treated as destructively replaced data, not as a generic reversible stream cipher.

The GNU hash is a useful exception: its original 16-byte header and entire `0x4000`-byte bloom filter survive exactly. Rebuilding buckets/chains from recovered dynsym order also matches the surviving final 336 chain entries (symbols `6501..6836`).

## PT_DYNAMIC shape

Recovered `PT_DYNAMIC` is exactly `0x230` bytes = 35 `Elf64_Dyn` records. The canonical NDK/LLD-shaped reconstruction uses ten `DT_NEEDED` records plus:

```text
DT_SONAME
DT_FLAGS = DF_BIND_NOW
DT_FLAGS_1 = DF_1_NOW
DT_RELA / DT_RELASZ / DT_RELAENT / DT_RELACOUNT
DT_JMPREL / DT_PLTRELSZ / DT_PLTGOT / DT_PLTREL
DT_SYMTAB / DT_SYMENT / DT_STRTAB / DT_STRSZ
DT_GNU_HASH / DT_HASH
DT_INIT_ARRAY / DT_INIT_ARRAYSZ
DT_FINI_ARRAY / DT_FINI_ARRAYSZ
DT_VERSYM / DT_VERNEED / DT_VERNEEDNUM
DT_NULL
```

This fills the recovered segment exactly with no padding entries. The ordering is a high-confidence canonical reconstruction; the stripped raw `.dynamic` bytes do not directly retain original ordering.

## Exact inner entry points

```text
JNI_OnLoad                                         0x27C444  size 0x49C
Java_com_ysmteam_imgui_GLES3JNIView_init           0x26931C  size 0x6774
Java_com_ysmteam_imgui_GLES3JNIView_resize         0x26FA90  size 0x60
Java_com_ysmteam_imgui_GLES3JNIView_step           0x26FAF0  size 0x380
Java_com_ysmteam_imgui_GLES3JNIView_imgui_Shutdown 0x26FE70  size 0x3C
Java_com_ysmteam_imgui_GLES3JNIView_getWindowRect  0x26FEAC  size 0x220
Java_com_ysmteam_imgui_GLES3JNIView_onTouch        0x2700CC  size 0xAC
DobbyHook                                          0x358CE8  size 0x158
```

`GLES3JNIView_step` calls the custom menu renderer at `0x27CAEC`.

## Research notes

- `research/CHECKPOINT.md`
- `research/ADDRESS_MAP.md`
- `research/VM.md`
- `research/INNER_LOADER.md`
- `research/B1E90.md`
- `research/INNER_METADATA.md`
- `research/RELOCATIONS.md`
- `research/RUNTIME_FIXUPS.md`
- `research/ELF_PARSER.md`
- `research/PROGRAM_HEADERS.md`
- `research/HASH_AND_ARRAYS.md`
- `research/SECTION_FACTS.md`
- `research/EXCEPTION_SECTIONS.md`
- `research/DESTRUCTIVE_STRIPPING.md`
- `research/DYNAMIC_TABLE.md`
- `research/AUTH_FLOW.md`

Original analyzed `libysmteam.so` SHA-256:

```text
acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca
```

Most addresses are sample-specific; use the hash together with the maps and validation checks.
