# debfuscateso

Static reverse-engineering notes and reproducible helpers for the analyzed ARM64 Android `libysmteam.so` sample.

This repository intentionally does **not** include the original APK/SO binaries or extracted payloads. The tools operate on local researcher-supplied files.

## Current checkpoint

The protection stack has been mapped far enough to reproduce several stages offline:

1. `base.apk` reaches `System.loadLibrary("ysmteam")` from the application's startup path.
2. The native constructor reads a `.ced` descriptor and decrypts `.main` at `VA 0xFBBAC`, size `0x2680`.
3. The recovered outer RC4 key for this sample is `baa707fe71ef4dc2240c15c0b2d907da`.
4. Plaintext `.main` exposes `JNI_OnLoad @ 0xFD214` and a second VM-based protection layer.
5. Six virtualized functions and their VM streams have been mapped.
6. The inner payload path uses a sample-specific pre-transform followed by ChaCha20 and zlib.
7. The extracted `0x530070`-byte inner memory image contains Dear ImGui, OpenGL/EGL, Dobby, curl/OpenSSL and the custom login/menu implementation.
8. The login data flow has been mapped through key input, worker creation, device-fingerprint/request construction and nonce validation.

The repository is for reverse-engineering research and documentation. It does not contain an authentication-bypass patch.

## Tools

### Decrypt outer `.main`

```bash
python tools/decrypt_outer_main.py libysmteam.so libysmteam.main_decrypted.so
```

The script patches only the encrypted `.main` range in a copy of the input file.

### Extract VM bytecode

```bash
python tools/dump_vm.py libysmteam.so vm_dump
```

This writes the six mapped bytecode blobs plus `manifest.json`.

### Extract the inner payload directly from the original SO

The white-box `B1E90` stage is now reproduced offline, so the complete inner
payload can be extracted without running Android or dumping process memory:

```bash
python tools/extract_inner.py libysmteam.so ysm_inner_payload.bin
```

Optional intermediate dumps:

```bash
python tools/extract_inner.py libysmteam.so ysm_inner_payload.bin --work-dir work
```

The `B1E90` emulator uses the Python `unicorn` package (`pip install unicorn`).
The ChaCha20 stage uses `cryptography` when available and falls back to the bundled
pure-Python implementation.

For the checkpoint sample the final inner image is `0x530070` bytes with SHA-256
`5a0ff6b4e1d3bf811dbd1f2b5db3e48ae14c12fb6da5f5662bf2e3c7bd66f168`.

### Run the B1E90 stage separately

```bash
python tools/emulate_b1e90.py libysmteam.so small_cipher.bin small_plain.bin
```

See `research/B1E90.md` for the emulated instruction subset and validation hashes.

### Decrypt the reconstructed inner combined stream

After reproducing the earlier sample-specific small-blob pre-transform and assembling the combined ChaCha20 ciphertext:

```bash
python tools/decrypt_inner_combined.py combined.bin inner_payload.bin
```

The script includes an RFC 8439 ChaCha20 self-test and validates the expected `uint32_le size + zlib stream` framing.

### Scan an extracted inner image

```bash
python tools/scan_inner.py inner_payload.bin
```

This reports known framework markers and sample offsets used by the research notes.

## Research notes

- `research/CHECKPOINT.md` — high-level checkpoint.
- `research/ADDRESS_MAP.md` — outer, VM and inner-image address map.
- `research/VM.md` — dispatcher, register encoding and opcode checkpoint.
- `research/B1E90.md` — concrete emulation of the white-box block transform and end-to-end validation.
- `research/AUTH_FLOW.md` — menu/login data flow and remaining protocol questions.

## Sample hashes

The original analyzed `libysmteam.so` has SHA-256:

```text
acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca
```

Use hashes and address maps together: most offsets in this repository are sample-specific.
