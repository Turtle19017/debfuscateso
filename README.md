# debfuscateso

Static reverse-engineering notes and reproducible helpers for the analyzed ARM64 Android `libysmteam.so` sample.

This repository intentionally does **not** include the original APK/SO binaries or extracted payloads. The tools operate on local researcher-supplied files.

## Current checkpoint

The protection stack has been mapped far enough to reproduce the important static stages offline:

1. `base.apk` reaches `System.loadLibrary("ysmteam")` from the application's startup path.
2. The native constructor reads a `.ced` descriptor and decrypts `.main` at `VA 0xFBBAC`, size `0x2680`.
3. Plaintext `.main` exposes the outer `JNI_OnLoad @ 0xFD214` and a second VM-based protection layer.
4. Six virtualized functions and their VM streams have been mapped.
5. The inner payload path is reproduced offline through the white-box block stage, ChaCha20 and zlib.
6. The exact `0x530070`-byte inner memory image is reproducible from the original SO without running the Android target.
7. The outer loader's encrypted inner `.dynstr`, `.dynsym` and PLT relocation records are now recoverable offline.
8. Exact inner JNI exports are known, including `JNI_OnLoad @ 0x27C444` and `Java_com_ysmteam_imgui_GLES3JNIView_step @ 0x26FAF0`.
9. `GLES3JNIView_step` calls the mapped custom menu renderer at `0x27CAEC` and its OpenGL imports can be named from the recovered PLT records.

The repository is for reverse-engineering research and documentation. It does not contain an authentication-bypass patch.

## Tools

### Extract the inner image from the original SO

```bash
pip install unicorn
python tools/extract_inner.py libysmteam.so ysm_inner_payload.bin
```

For the mapped sample, the recovered inner image is `0x530070` bytes with SHA-256:

```text
5a0ff6b4e1d3bf811dbd1f2b5db3e48ae14c12fb6da5f5662bf2e3c7bd66f168
```

### Recover inner symbols and PLT names

```bash
python tools/recover_inner_symbols.py libysmteam.so inner_meta --strict-hash --dump-raw
```

This reproduces the fixed metadata seed, decrypts the embedded inner dynstr/dynsym and the custom PLT record array, and writes:

```text
inner_meta/manifest.json
inner_meta/dynsym.tsv
inner_meta/plt.tsv
```

The mapped sample yields 6,837 dynamic symbols and 3,097 `R_AARCH64_JUMP_SLOT` PLT records.

### Build an analysis-friendly inner ELF

The extracted payload is a raw reconstructed memory/container image rather than the producer's original ELF file. Wrap it in a synthetic `ET_DYN` for Ghidra/IDA/llvm-objdump:

```bash
python tools/build_inner_analysis_elf.py \
  ysm_inner_payload.bin \
  ysm_inner.analysis.so \
  --metadata-dir inner_meta
```

With `--metadata-dir`, the wrapper adds recovered inner dynsym names and exact PLT labels. The generated section/program-header layout is analyst metadata and must not be confused with the original ELF layout.

### Decrypt outer `.main`

```bash
python tools/decrypt_outer_main.py libysmteam.so libysmteam.main_decrypted.so
```

### Extract VM bytecode

```bash
python tools/dump_vm.py libysmteam.so vm_dump
```

### Run the white-box block emulator directly

```bash
python tools/emulate_b1e90.py libysmteam.so input.bin output.bin
```

### Decrypt a reconstructed inner combined stream

```bash
python tools/decrypt_inner_combined.py combined.bin inner_payload.bin
```

### Scan an extracted inner image

```bash
python tools/scan_inner.py inner_payload.bin
```

## Exact inner entry points recovered so far

```text
JNI_OnLoad                                      0x27C444  size 0x49C
Java_com_ysmteam_imgui_GLES3JNIView_init        0x26931C  size 0x6774
Java_com_ysmteam_imgui_GLES3JNIView_resize      0x26FA90  size 0x60
Java_com_ysmteam_imgui_GLES3JNIView_step        0x26FAF0  size 0x380
Java_com_ysmteam_imgui_GLES3JNIView_imgui_Shutdown 0x26FE70 size 0x3C
Java_com_ysmteam_imgui_GLES3JNIView_getWindowRect  0x26FEAC size 0x220
Java_com_ysmteam_imgui_GLES3JNIView_onTouch     0x2700CC  size 0xAC
DobbyHook                                       0x358CE8  size 0x158
```

## Research notes

- `research/CHECKPOINT.md` — high-level checkpoint.
- `research/ADDRESS_MAP.md` — outer, VM and inner-image address map.
- `research/VM.md` — dispatcher, register encoding and opcode checkpoint.
- `research/INNER_LOADER.md` — descriptor, loader object and unpack path.
- `research/B1E90.md` — white-box block transform and end-to-end extraction validation.
- `research/INNER_LAYOUT.md` — synthetic analysis layout for the recovered memory image.
- `research/INNER_METADATA.md` — recovered dynstr/dynsym, exact JNI exports and PLT mapping.
- `research/AUTH_FLOW.md` — menu/login data flow and remaining protocol questions.

## Sample hashes

The original analyzed `libysmteam.so` has SHA-256:

```text
acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca
```

Use hashes and address maps together: most offsets in this repository are sample-specific.
