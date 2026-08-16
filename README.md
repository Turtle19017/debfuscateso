# debfuscateso

Static reverse-engineering notes and small reproducible tools for the analyzed `libysmteam.so` ARM64 Android library.

This repository intentionally does **not** include the original APK/SO binaries. Tools operate on a local copy supplied by the researcher.

## Current checkpoint

The outer library has been mapped far enough to reproduce several protection layers offline:

1. `base.apk` loads `libysmteam.so` through `System.loadLibrary("ysmteam")` from `FFAPI.load_lib()`.
2. The library constructor reads a `.ced` descriptor and decrypts `.main` at `VA 0xFBBAC`, size `0x2680`.
3. The recovered RC4 key for this sample is `baa707fe71ef4dc2240c15c0b2d907da`.
4. Decrypted `.main` exposes `JNI_OnLoad @ 0xFD214` and a second VM-based protection layer.
5. Six virtualized functions and their bytecode streams have been mapped.
6. The inner payload path uses a small pre-transform, ChaCha20 and zlib. The recovered ChaCha20 parameters are documented in `research/CHECKPOINT.md`.
7. The extracted inner memory image contains Dear ImGui, OpenGL/EGL, Dobby, curl/OpenSSL and the custom login/menu code.

The work here is for analysis and documentation. It does not include an authentication-bypass patch.

## Tools

- `tools/decrypt_outer_main.py` — patch the encrypted `.main` range in a local copy of the original SO.
- `tools/dump_vm.py` — extract the six VM bytecode programs from the original SO.
- `tools/decrypt_inner_combined.py` — ChaCha20 + zlib stage for a reconstructed combined inner stream.
- `tools/scan_inner.py` — sanity-check an extracted inner payload and report known markers/offsets.

See `research/CHECKPOINT.md` for the current address map and corrections discovered during analysis.
