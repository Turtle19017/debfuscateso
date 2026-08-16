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
- original low dynamic-section placement recovered from `.dynsym` through `.rela.plt`;
- GNU-version tables survive parseably, and the original GNU-hash header is recovered as `nbuckets=1625`, `symoffset=336`, `bloom_size=2048`, `bloom_shift=26`;
- corrected `.gcc_except_table` start `0xED3B0` and exact following `.rodata`/EH/text/PLT layout;
- full 27-entry semantic section-table reconstruction at `e_shoff=0x52F9B0`, `e_shnum=27`, `e_shstrndx=26`;
- original-placement semantic ELF reconstruction that stays exactly `0x530070` bytes instead of appending metadata into BSS.

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

python tools/build_inner_original_placement_elf.py \
  ysm_inner_payload.bin \
  ysm_inner.original_placement.so \
  --metadata-dir inner_meta \
  --aux-dir inner_aux \
  --phdr-manifest phdr_meta/manifest.json \
  --layout-manifest original_layout/original_layout.json
```

The older analysis/near-original builders are still useful when experimenting, but `build_inner_original_placement_elf.py` is now the preferred reconstruction for this mapped sample.

## Recovered original section layout

```text
.note.android.ident  0x000238 .. 0x0002D0
.dynsym              0x0002D0 .. 0x0283C8  size 0x280F8
.gnu.version         0x0283C8 .. 0x02B932  size 0x356A
.gnu.version_r       0x02B934 .. 0x02B994  size 0x60
.gnu.hash            0x02B998 .. 0x0378A0  size 0xBF08
.hash                0x0378A0 .. 0x044E50  size 0xD5B0
.dynstr              0x044E50 .. 0x073B1D  size 0x2ECCD
.rela.dyn            0x073B20 .. 0x0DB158  size 0x67638
.rela.plt            0x0DB158 .. 0x0ED3B0  size 0x12258
.gcc_except_table    0x0ED3B0 .. 0x0F5EB0  size 0x8B00
.rodata              0x0F5EB0 .. 0x1FFAFC  size 0x109C4C
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

The earlier `0xED59C` value is retained only as the **minimum LSDA referenced by an FDE**. It is not the section start; the true `.gcc_except_table` begins at `0xED3B0`, immediately after the recovered `.rela.plt` extent.

The surviving `.shstrtab` stores `.gnu.hash` and `.got.plt`; ELF section names can point into the middle of another string, so `.hash` and `.plt` are valid suffix names. The 24 standalone names + `.hash` + `.plt` + NULL give exactly 27 sections, matching the surviving `0x6C0` section-header tail.

## Original-placement reconstruction validation

The current builder restores/regenerates dynamic metadata at the recovered original file positions instead of extending BSS:

```text
.dynsym      file/VA 0x0002D0
.gnu.version file/VA 0x0283C8  (surviving bytes preserved)
.gnu.version_r       0x02B934  (surviving bytes preserved)
.gnu.hash            0x02B998  (regenerated from recovered header + dynsym/dynstr)
.hash                0x0378A0  (exact recovered SysV resolver table)
.dynstr              0x044E50
.rela.dyn            0x073B20
.rela.plt            0x0DB158
.dynamic       file  0x505570 / VA 0x509570
section headers file 0x52F9B0
```

On the mapped sample:

```text
file       -> ELF64 AArch64 shared object, Android 21, NDK r25c
readelf -h -> 9 program headers, 27 section headers
readelf -S -> coherent recovered section map
readelf -V -> 6837 version symbols + 3 version-needed records
readelf -I -> valid SysV and GNU hash histograms
readelf -d -> 33 reconstructed dynamic entries at original PT_DYNAMIC
readelf -r --use-dynamic -> 17645 .rela.dyn + 3097 .rela.plt
```

This is still called a **semantic reconstruction**, not a byte-perfect producer file: protected bytes such as original hash bodies/dynamic entries/SHDR fields were destroyed or scrambled, so those are regenerated from recovered semantics where necessary.

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
- `research/ORIGINAL_SECTION_LAYOUT.md`
- `research/AUTH_FLOW.md`

Original analyzed `libysmteam.so` SHA-256:

```text
acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca
```

Most addresses are sample-specific; use the hash together with the maps and validation checks.
