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
- high-confidence original section boundaries, including `.gcc_except_table`, `.rodata`, `.eh_frame_hdr`, `.eh_frame`, `.text`, `.plt`, `.data.rel.ro`, constructor arrays, `.dynamic`, `.got`, `.got.plt`, `.data`, `.bss`, `.comment` and `.shstrtab`;
- strong original section-table shape evidence: candidate `e_shoff=0x52F9B0`, `e_shentsize=0x40`, candidate `e_shnum=27`.

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

python tools/recover_inner_section_facts.py \
  ysm_inner_payload.bin \
  section_facts \
  --phdr-manifest phdr_meta/manifest.json \
  --metadata-dir inner_meta \
  --aux-dir inner_aux

python tools/recover_exception_sections.py \
  ysm_inner_payload.bin \
  --json exception_sections.json

python tools/build_inner_near_original_elf.py \
  ysm_inner_payload.bin \
  ysm_inner.near_original.so \
  --metadata-dir inner_meta \
  --phdr-manifest phdr_meta/manifest.json \
  --aux-dir inner_aux
```

## Important recovered layout

```text
.gcc_except_table  0x0ED59C .. 0x0F5EB0  size 0x008914
.rodata             0x0F5EB0 .. 0x1FFAFC  size 0x109C4C
.eh_frame_hdr       0x1FFAFC .. 0x2125F0  size 0x012AF4
.eh_frame           0x2125F0 .. 0x25E2D4  size 0x04BCE4
.text               0x25E2E0 .. 0x4D6810
.plt                0x4D6810 .. 0x4E29C0

.data.rel.ro        0x4E69C0 .. 0x509530
.fini_array         0x509530 .. 0x509540
.init_array         0x509540 .. 0x509570
.dynamic            0x509570 .. 0x5097A0
.got                0x5097A0 .. 0x50A6B8
.got.plt            0x50A6B8 .. 0x510798
.relro_padding      0x510798 .. 0x511000
.data               0x5147A0 .. 0x537560
.bss                0x537560 .. 0x642991

.comment        file 0x52F560 .. 0x52F8AA
.shstrtab       file 0x52F8AA .. 0x52F9AA
Shdr-tail       file 0x52F9B0 .. 0x530070 = 0x6C0 = 27 * 0x40
```

A correction from an earlier checkpoint: the surviving `.shstrtab` stores `.gnu.hash`, but ELF section names can point into the middle of another string. The suffix `.hash` is therefore a valid name at an interior string-table offset, just as `.plt` is encoded as a suffix of `.got.plt`. The 24 standalone names + `.plt` + `.hash` + NULL give exactly 27 section-name slots, matching the `0x6C0` destroyed section-header tail.

The exact custom SysV hash table recovered from the outer resolver is therefore strong evidence for original `.hash` semantics as well; the producer's original `.gnu.hash` bytes are still not recovered.

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
- `research/AUTH_FLOW.md`

Original analyzed `libysmteam.so` SHA-256:

```text
acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca
```

Most addresses are sample-specific; use the hash together with the maps and validation checks.
