# debfuscateso

Static reverse-engineering notes and reproducible helpers for the analyzed ARM64 Android `libysmteam.so` sample.

This repository intentionally does **not** include the original APK/SO binaries or extracted payloads. The tools operate on local researcher-supplied files.

## Current checkpoint

The important protection, metadata and loader stages are now reproducible offline:

1. `base.apk` reaches `System.loadLibrary("ysmteam")` from the application's startup path.
2. The native constructor decrypts outer `.main` at `VA 0xFBBAC`, size `0x2680`.
3. The outer VM layer and its six protected streams are mapped.
4. The exact `0x530070`-byte inner raw file/image is recovered offline through `B1E90`, ChaCha20 and zlib.
5. Encrypted inner `.dynstr`, `.dynsym`, PLT records and symbol-based relocation records are recoverable offline.
6. Relocations normalize to 13,896 `R_AARCH64_RELATIVE`, 3,272 `R_AARCH64_ABS64`, 477 `R_AARCH64_GLOB_DAT` and 3,097 `R_AARCH64_JUMP_SLOT` entries.
7. The exact ten-library custom-loader dependency order is recovered.
8. The custom symbol resolver's exact 6,837-bucket/6,837-chain SysV hash tables are recovered and validated byte-for-byte against recovered dynstr/dynsym.
9. Exact constructor metadata is recovered: `.fini_array @ 0x509530` (2 entries) and `.init_array @ 0x509540` (6 entries).
10. Exact inner JNI exports are known, including `JNI_OnLoad @ 0x27C444` and `Java_com_ysmteam_imgui_GLES3JNIView_step @ 0x26FAF0`.
11. `GLES3JNIView_step` calls the custom menu renderer at `0x27CAEC`.
12. The protected compact inner program-header table is recovered: `e_phoff=0x40`, `e_phnum=9`, three original PT_LOAD mappings, PT_DYNAMIC, PT_PHDR, PT_NOTE, GNU_RELRO/EH_FRAME/STACK.
13. Restoring only the header/PHDR region makes the preserved note identify Android API 21, NDK r25c, build 9519653.

The repository is for reverse-engineering research and documentation. It does not contain an authentication-bypass patch.

## Quick path

### 1. Extract the inner image

```bash
pip install unicorn
python tools/extract_inner.py libysmteam.so ysm_inner_payload.bin
```

Known-sample output:

```text
size   = 0x530070
sha256 = 5a0ff6b4e1d3bf811dbd1f2b5db3e48ae14c12fb6da5f5662bf2e3c7bd66f168
```

### 2. Recover dynsym and symbol-based relocations

```bash
python tools/recover_inner_symbols.py \
  libysmteam.so \
  inner_meta \
  --inner ysm_inner_payload.bin \
  --strict-hash \
  --dump-raw
```

### 3. Recover runtime relative fixups and dependency order

```bash
python tools/recover_inner_runtime_metadata.py \
  libysmteam.so \
  inner_runtime \
  --strict-hash

cp inner_runtime/rela.relative.bin inner_meta/
cp inner_runtime/needed.txt inner_meta/
```

This recovers 13,896 runtime relative fixups and the exact custom-loader dependency order:

```text
liblog.so
libandroid.so
libEGL.so
libGLESv2.so
libGLESv3.so
libGLESv1_CM.so
libz.so
libdl.so
libc.so
libm.so
```

### 4. Recover the protected original-shape program headers

```bash
python tools/recover_inner_phdrs.py \
  libysmteam.so \
  phdr_meta \
  --strict-hash
```

Recovered high-confidence ELF-header facts:

```text
e_phoff      0x40
e_phentsize  0x38
e_phnum      9
PHDR end     0x238
```

Original load mappings:

```text
PT_LOAD  off 0x000000  VA 0x000000  filesz 0x4E29C0  memsz 0x4E29C0  R-X
PT_LOAD  off 0x4E29C0  VA 0x4E69C0  filesz 0x029DD8  memsz 0x02A640  RW-
PT_LOAD  off 0x50C7A0  VA 0x5147A0  filesz 0x022DC0  memsz 0x12E1F1  RW-
```

Original `PT_DYNAMIC` location:

```text
file offset 0x505570
VA          0x509570
size        0x230
```

### 5. Recover exact custom resolver hash + constructor arrays

```bash
python tools/recover_inner_aux_metadata.py \
  libysmteam.so \
  inner_aux \
  --metadata-dir inner_meta \
  --strict-hash
```

This recovers the exact lookup tables used by outer resolver `0xC8920`:

```text
nbucket = 6837
nchain  = 6837
hash blob size = 0xD5B0
SHA-256 = b1b7604e37c57fb53edd78a3db620ef4fd4bdb34b34d57784670cf0e2a195380
```

It also recovers:

```text
.fini_array VA    0x509530  count 2
.init_array VA    0x509540  count 6
```

The recovered SysV table is exact **custom-loader resolver metadata**. The surviving original section-name table names `.gnu.hash` rather than `.hash`, so `DT_HASH` in the reconstructed ELF is a semantic replacement and is not claimed to be the producer's original hash section.

### 6A. Header-only restoration

```bash
python tools/restore_inner_header.py \
  ysm_inner_payload.bin \
  phdr_meta/manifest.json \
  ysm_inner.header_restored.so
```

This is useful for `readelf -h -l -n` and deliberately leaves the raw/protected `PT_DYNAMIC` bytes untouched.

### 6B. Near-original-layout semantic reconstruction

```bash
python tools/build_inner_near_original_elf.py \
  ysm_inner_payload.bin \
  ysm_inner.near_original.so \
  --metadata-dir inner_meta \
  --phdr-manifest phdr_meta/manifest.json \
  --aux-dir inner_aux
```

This keeps the recovered original three-LOAD file-to-VA mapping and original nine-entry PHDR shape. Recovered dynamic metadata is placed in unused capacity of the original third LOAD's BSS range, so no synthetic fourth PT_LOAD is needed. Only that segment's `p_filesz` is extended; its recovered `p_memsz` and VA range are preserved.

With `--aux-dir`, the builder uses the exact custom SysV resolver table instead of regenerating one and emits the recovered constructor tags:

```text
DT_FINI_ARRAY   0x509530
DT_FINI_ARRAYSZ 0x10
DT_INIT_ARRAY   0x509540
DT_INIT_ARRAYSZ 0x30
```

Validation on the mapped sample:

```text
file -> ELF 64-bit LSB shared object, ARM aarch64,
        for Android 21, built by NDK r25c (9519653)

readelf -d -> 10 DT_NEEDED + SONAME + exact init/fini array tags + reconstructed dynamic metadata
readelf -r --use-dynamic -> 17,645 .rela.dyn + 3,097 .rela.plt entries
readelf -I -> valid 6,837-bucket SysV hash histogram
```

The result is a semantic reconstruction, not a byte-perfect producer ELF. The protected compact PHDR records do not retain `p_paddr`/`p_align`; original `.gnu.hash`/GNU-version bytes and the original section-header contents are still not recovered.

### Other analysis wrappers

```bash
python tools/build_inner_analysis_elf.py \
  ysm_inner_payload.bin ysm_inner.analysis.so \
  --metadata-dir inner_meta

python tools/build_inner_reconstructed_elf.py \
  ysm_inner_payload.bin ysm_inner.reconstructed.so \
  --metadata-dir inner_meta
```

The first is the conservative analysis wrapper; the second is the older loader-shaped synthetic reconstruction. `build_inner_near_original_elf.py` is preferred when preserving the recovered original file-to-VA layout matters.

## Other tools

```text
tools/decrypt_outer_main.py
tools/dump_vm.py
tools/emulate_b1e90.py
tools/decrypt_inner_combined.py
tools/scan_inner.py
```

## Exact inner entry points recovered so far

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

## Research notes

- `research/CHECKPOINT.md` — high-level checkpoint.
- `research/ADDRESS_MAP.md` — outer, VM and inner-image address map.
- `research/VM.md` — dispatcher/register/opcode checkpoint.
- `research/INNER_LOADER.md` — descriptor, loader object and unpack path.
- `research/B1E90.md` — white-box block transform and extraction validation.
- `research/INNER_LAYOUT.md` — earlier synthetic analysis layout.
- `research/INNER_METADATA.md` — recovered dynstr/dynsym and exact JNI/PLT mapping.
- `research/RELOCATIONS.md` — 40-byte custom symbol-relocation semantics.
- `research/RUNTIME_FIXUPS.md` — 13,896 relative fixups, mapping-base/load-bias semantics and exact dependency order.
- `research/ELF_PARSER.md` — normal outer ELF parser and corrected reconstruction status.
- `research/PROGRAM_HEADERS.md` — recovered protected-inner PHDR table and corrected file-to-VA mappings.
- `research/HASH_AND_ARRAYS.md` — exact custom SysV hash tables, init/fini arrays and section-tail status.
- `research/AUTH_FLOW.md` — menu/login data flow and remaining protocol questions.

## Sample hash

```text
acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca
```

Use hashes and address maps together: most offsets in this repository are sample-specific.
