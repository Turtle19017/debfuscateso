# Inner analysis layout

The recovered `0x530070`-byte inner image is a memory/container image, not a recovered copy of the producer's original ELF file. It contains executable AArch64, PLT-like stubs, file-backed data and references to zero-filled runtime globals beyond the recovered bytes.

To make Ghidra/IDA/llvm-objdump analysis practical, `tools/build_inner_analysis_elf.py` wraps the raw image in a **synthetic** AArch64 `ET_DYN` whose virtual addresses match offsets in the recovered image. Do not treat its section table or program headers as original metadata.

## Recovered boundaries

High-confidence sample boundaries are:

```text
raw image size             0x530070
AArch64 code start         0x25E2E0
PLT0                       0x4D6810
first regular PLT entry    0x4D6830
end of contiguous PLT      0x4E29C0
file-backed image end      0x530070
inferred zero-fill end     0x643000
```

The regular PLT range contains 3,097 contiguous AArch64 stubs with the expected `adrp x16 / ldr x17 / add x16 / br x17` shape.

The synthetic layout is therefore:

```text
.blob  0x000000..0x25E2E0  R
.text  0x25E2E0..0x4D6810  RX
.plt   0x4D6810..0x4E29C0  RX
.data  0x4E29C0..0x530070  RW
.bss   0x530070..0x643000  RW, NOBITS
```

`0x643000` is an inferred analysis boundary, chosen because decoded AArch64 references zero-filled globals into the `0x642xxx` page. It is not claimed to be the original ELF `p_memsz`.

## Known symbols inserted by the wrapper

The analysis ELF adds symbols only for already mapped anchors:

```text
0x25E2E0  inner_code_start
0x27CAEC  menu_renderer
0x27CFFC  key_input_callsite
0x2948DC  auto_login_worker
0x29527C  login_worker
0x298B94  auth_core
0x4D6810  plt0
0x4D6830  plt_entries

0x537730  login_status
0x5390F8  save_key_flag
0x5390F9  auto_login_flag
0x539100  saved_key
0x53912C  key_buffer
0x5392A0  auth_busy
```

These names are analyst labels rather than symbols recovered from the original dynamic symbol table.

## Build

After extracting the raw inner image:

```bash
python tools/build_inner_analysis_elf.py ysm_inner_payload.bin ysm_inner.analysis.so
```

Validation examples:

```bash
file ysm_inner.analysis.so
readelf -h -l -S ysm_inner.analysis.so
readelf -s ysm_inner.analysis.so
llvm-objdump -d --start-address=0x27caec --stop-address=0x27d040 ysm_inner.analysis.so
```

The generated ELF intentionally remains separate from `extract_inner.py`: extraction reproduces bytes, while this wrapper adds analyst metadata that is partly inferred.

## Custom outer loader implication

The outer loader still matters. Its normal ELF parser (`C6F90..C7290`) handles program headers/dynamic tags, while `C8920` resolves symbols and `C8FA8(..., "JNI_OnLoad")` requests the inner entry point. Several metadata buffers are lazily deobfuscated by `CB1D8`-based helpers before being stored into loader fields.

Since the raw `0x530070`-byte image itself contains no literal ELF magic, the original inner ELF metadata is likely reconstructed/decrypted separately by the outer loader. The synthetic ELF is therefore a bridge for static analysis, not proof that original ELF reconstruction is complete.
