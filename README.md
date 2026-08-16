# debfuscateso

Static reverse-engineering notes and reproducible helpers for the analyzed ARM64 Android `libysmteam.so` sample.

This repository intentionally does **not** include the original APK/SO binaries or extracted payloads. The tools operate on local researcher-supplied files.

## Current checkpoint

The important protection and metadata stages are now reproducible offline:

1. `base.apk` reaches `System.loadLibrary("ysmteam")` from the application's startup path.
2. The native constructor decrypts outer `.main` at `VA 0xFBBAC`, size `0x2680`.
3. The outer VM layer and its six protected streams are mapped.
4. The inner payload is recovered offline through the `B1E90` white-box block stage, ChaCha20 and zlib.
5. The exact `0x530070`-byte inner memory image is reproducible from the original SO without running Android.
6. Encrypted inner `.dynstr`, `.dynsym`, PLT records and non-PLT relocation records are recoverable offline.
7. Custom relocations normalize to 3,272 `R_AARCH64_ABS64`, 477 `R_AARCH64_GLOB_DAT` and 3,097 `R_AARCH64_JUMP_SLOT` entries.
8. Exact inner JNI exports are known, including `JNI_OnLoad @ 0x27C444` and `Java_com_ysmteam_imgui_GLES3JNIView_step @ 0x26FAF0`.
9. `GLES3JNIView_step` calls the custom menu renderer at `0x27CAEC`.
10. The outer normal-ELF parser (`C6F10/C6F90/C7028`) is mapped through program headers and the relevant `DT_*` tags.

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

### 2. Recover symbols and relocations

```bash
python tools/recover_inner_symbols.py \
  libysmteam.so \
  inner_meta \
  --inner ysm_inner_payload.bin \
  --strict-hash \
  --dump-raw
```

Important outputs:

```text
inner_meta/dynstr.bin
inner_meta/dynsym.bin
inner_meta/dynsym.tsv
inner_meta/plt.tsv
inner_meta/relocs.tsv
inner_meta/rela.dyn.bin
inner_meta/rela.plt.bin
inner_meta/manifest.json
```

### 3A. Build the conservative analysis ELF

```bash
python tools/build_inner_analysis_elf.py \
  ysm_inner_payload.bin \
  ysm_inner.analysis.so \
  --metadata-dir inner_meta
```

This keeps the reconstructed metadata mostly as analysis sections and makes Ghidra/IDA/llvm-objdump much easier to use.

### 3B. Build the loader-shaped reconstruction

```bash
python tools/build_inner_reconstructed_elf.py \
  ysm_inner_payload.bin \
  ysm_inner.reconstructed.so \
  --metadata-dir inner_meta
```

This second wrapper additionally emits an allocated synthetic metadata `PT_LOAD`, SysV `.hash`, `.dynamic` and `PT_DYNAMIC`, including reconstructed:

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
DT_SONAME = libysmteam.so
```

The generated metadata VA/program headers are explicitly synthetic analysis reconstruction; they are not claimed to be the producer's original ELF file layout.

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
- `research/INNER_LAYOUT.md` — recovered memory-image boundaries and synthetic layout.
- `research/INNER_METADATA.md` — recovered dynstr/dynsym and exact JNI/PLT mapping.
- `research/RELOCATIONS.md` — custom relocation semantics and normalization to ELF RELA.
- `research/ELF_PARSER.md` — normal ELF parser, PT_LOAD/PT_DYNAMIC and recovered `DT_*` semantics.
- `research/AUTH_FLOW.md` — menu/login data flow and remaining protocol questions.

## Sample hash

```text
acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca
```

Use hashes and address maps together: most offsets in this repository are sample-specific.
