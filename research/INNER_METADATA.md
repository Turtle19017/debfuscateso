# Recovered inner ELF metadata

The outer loader keeps key pieces of the inner module's ELF metadata in encrypted static buffers, separate from the recovered `0x530070`-byte memory image. This explains why the raw inner image contains executable AArch64 and data but no literal ELF header/dynamic table.

This note records the metadata path that is now reproducible offline by `tools/recover_inner_symbols.py`.

## Construction path

`JNI_OnLoad` creates a static-source object with `FCF08`, reshapes it through VM-protected `FD3E4`, then writes a fixed 16-byte seed into the metadata object through:

```text
FD3E4
  |
  `-- CA6B8
        `-- B96D0
```

`B96D0` computes its 16-byte result entirely from constants embedded in the outer SO. For this sample:

```text
K @ 0xB9760
5d6e7f90a1b2c3d4e5f60718293a4b5c

T @ 0x31E790 (64 bytes)
a9e55b5d20804548d0b2b09f73b51d49
9b881feb8d13c334a5bab6464165e679
980295b2f5d0398649af696e5ea1c313
606493ab97f340da43f59561aae2e2cb
```

Writing `T` as four interleaved vectors `A=T[0::4]`, `B=T[1::4]`, `C=T[2::4]`, `D=T[3::4]`, the recovered byte relation is:

```python
seed[i] = (D[i] + C[i] + K[i]*B[i] + K[i]*K[i]*A[i]) & 0xff
```

Result:

```text
seed16 = 9a0d6d36ed21f793e953996ea264e885
```

## `CB1D8` stream transform

Multiple metadata helpers call the same byte-stream deobfuscator. Exact recovered behavior:

```python
def cb1d8(data, seed):
    out = bytearray(data)
    state = seed & 0xffffffff
    prev = 0
    for i, old in enumerate(data):
        state = (state * 0x41C64E6D + 0x3039) & 0xffffffff
        state ^= (prev << 8) & 0xffffffff
        state ^= i
        out[i] = old ^ ((state >> 16) & 0xff)
        prev = old
    return bytes(out)
```

The persistent `state ^= i` is important: it mutates the state used by the next iteration.

## Recovered `.dynstr`

```text
encrypted VA      0x4144A0
length field VA   0x3D73A0
length            0x2ECCD = 191693
seed byte          seed16[8] = 0xE9
```

The decrypted table begins with normal dynamic-symbol names:

```text
\0__cxa_finalize\0__cxa_atexit\0syscall\0getpid\0__stack_chk_fail\0strlen...
```

`JNI_OnLoad` appears at dynstr offset 3054.

## Recovered `.dynsym`

```text
encrypted VA      0x704C10
length field VA   0x704C00
byte length        0x280F8 = 164088
seed byte          seed16[3] = 0x36
entry size         24 (Elf64_Sym)
entry count        6837
```

Parsing each entry as normal `Elf64_Sym` recovers exact names and addresses.

### Exact native entry points

```text
JNI_OnLoad
  symbol index 980
  VA           0x27C444
  size         0x49C

Java_com_ysmteam_imgui_GLES3JNIView_init        0x26931C  size 0x6774
Java_com_ysmteam_imgui_GLES3JNIView_resize      0x26FA90  size 0x60
Java_com_ysmteam_imgui_GLES3JNIView_step        0x26FAF0  size 0x380
Java_com_ysmteam_imgui_GLES3JNIView_imgui_Shutdown 0x26FE70 size 0x3C
Java_com_ysmteam_imgui_GLES3JNIView_getWindowRect  0x26FEAC size 0x220
Java_com_ysmteam_imgui_GLES3JNIView_onTouch     0x2700CC  size 0xAC
DobbyHook                                       0x358CE8  size 0x158
```

This corrects the earlier generic label around `0x26FAF0`: it is exactly the JNI export `GLES3JNIView_step`.

## Menu/render call chain

With the exact dynamic symbol table recovered, the native UI path is now:

```text
Java GLES3JNIView.step()
        |
        v
Java_com_ysmteam_imgui_GLES3JNIView_step @ 0x26FAF0
        |
        +-- clock_gettime@plt
        +-- glClearColor@plt
        +-- glClear@plt
        |
        +-- BL 0x27CAEC  # analyst label: menu_renderer
        |
        +-- glEnable@plt
        +-- glBlendFunc@plt
        +-- glDisable@plt
        `-- ImGui/frame cleanup helpers
```

The call to `0x27CAEC` occurs at `0x26FBE8`. This ties the previously mapped key/login UI to the exported GLES view step without requiring an `eglSwapBuffers` hypothesis.

## PLT record table

The outer loader stores a custom 40-byte record for every regular PLT entry.

```text
encrypted records VA  0x4431A0
byte-length field VA  0x72CD14
byte length            0x1E3E8 = 123880
count field VA         0x704C04
record count           0xC19 = 3097
record size            40
seed byte              seed16[5] = 0x21
first inner PLT stub   0x4D6830
PLT stride             0x10
```

For these records, the first qword behaves like standard ELF `r_info`:

```text
symbol index = r_info >> 32
reloc type   = r_info & 0xffffffff
```

All 3097 recovered PLT records use:

```text
0x402 = R_AARCH64_JUMP_SLOT
```

The record order maps directly to the contiguous PLT stub order:

```text
plt_addr(i) = 0x4D6830 + i * 0x10
```

Examples:

```text
0x4D6830  __cxa_finalize
0x4D6840  __cxa_atexit
0x4D6850  syscall
0x4D6860  getpid
0x4D6870  __stack_chk_fail
0x4D6880  strlen
0x4D6890  _Znwm
0x4D68A0  memcpy
```

A useful confirmation in `GLES3JNIView_step` is:

```text
0x4D6B50  clock_gettime
0x4D6B60  glClearColor
0x4D6B70  glClear
0x4D6B80  glEnable
0x4D6B90  glBlendFunc
0x4D6BA0  glDisable
0x4D6BD0  pthread_create
0x4D6BE0  _ZNSt6__ndk16thread6detachEv
```

## Second relocation table

A second encrypted 40-byte-record array is also recoverable:

```text
encrypted VA      0x3B29D0
length field VA   0x3D73A4
byte length        0x249C8 = 149960
count field VA    0x72CD10
count              0xEA5 = 3749
seed byte          seed16[7] = 0x93
```

Its first qword also looks like `r_info`, but the remaining fields are part of the outer loader's custom representation. Exact target relocation reconstruction remains a separate task; `FDA30` is the next useful routine to map for this array.

## Outer symbol lookup

`C8920(loader, name, out, flag)` is the loader's inner-symbol resolver. Current field mapping:

```text
loader+0xA8  dynstr
loader+0xB0  dynsym
loader+0xB8  dynsym byte-size boundary for linear scan
loader+0xC0  hash-mode flag
loader+0xC8  bucket count
loader+0xD8  hash buckets
loader+0xE0  hash chains
```

It uses classic ELF hash for the hashed lookup path and can fall back to a linear symbol scan. The outer call `C8FA8(..., "JNI_OnLoad")` therefore resolves the now-known inner symbol `0x27C444` from this reconstructed metadata.

## Tooling

```bash
python tools/recover_inner_symbols.py libysmteam.so inner_meta --strict-hash --dump-raw
```

Outputs:

```text
inner_meta/manifest.json
inner_meta/dynsym.tsv
inner_meta/plt.tsv

# with --dump-raw:
inner_meta/dynstr.bin
inner_meta/dynsym.bin
inner_meta/plt_records.bin
inner_meta/reloc_records.bin
```

The recovered TSV files can be supplied to the synthetic analysis-ELF builder so Ghidra/IDA/llvm-objdump see real function and PLT names.
