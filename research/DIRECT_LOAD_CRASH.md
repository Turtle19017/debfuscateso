# Direct-load SIGBUS: ABS64 addend normalization bug

A direct Android load test of the reconstructed inner ELF reached `linker64::soinfo::call_constructors`, proving that the linker accepted the recovered ELF/program-header/dynamic layout far enough to run `.init_array`.

The observed crash was:

```text
signal 7 (SIGBUS), code 1 (BUS_ADRALN)
#00 pc 0x125d   libdl.so
#01 pc 0x2ddb64 libysmteam.so
#02 linker64 soinfo::call_constructors
```

## Exact crash instruction

Inner VA `0x2DDB64` is:

```asm
blr x8
```

Therefore `libdl.so + 0x125d` is the branch target itself. Because `0x125d` is not instruction-aligned on AArch64, the fault is an invalid/unaligned indirect call target, not evidence that a correctly-entered libdl routine later performed an unaligned data access.

The surrounding block derives `x8` from two relocated data values. One relevant relocation target is:

```text
VA 0x5241C8
symbol: dl_iterate_phdr@LIBC
relocation type: R_AARCH64_ABS64
```

## Root cause

The first `recover_inner_symbols.py` RELA normalization read the pre-relocation qword with:

```python
struct.unpack_from("<Q", inner, target)
```

where `target` is an **inner virtual address**. That only works for the first original PT_LOAD because only that segment has `p_vaddr == p_offset`.

Recovered original mappings are:

```text
PT_LOAD #1  file 0x000000  VA 0x000000  delta 0x0000
PT_LOAD #2  file 0x4E29C0  VA 0x4E69C0  delta 0x4000
PT_LOAD #3  file 0x50C7A0  VA 0x5147A0  delta 0x8000
```

For target VA `0x5241C8`, the correct raw-file offset is therefore:

```text
0x5241C8 - 0x8000 = 0x51C1C8
```

The qword at that original file location is zero. The buggy direct-index read instead took the qword at raw offset `0x5241C8`, which is unrelated data (`0x181` in the mapped image).

The custom relocation's exact `q4` is:

```text
0x8c36dbbd6e85535d
signed = -0x73c92442917aaca3
```

Thus the correct standard RELA addend is exactly `q4`, while the buggy build added `0x181` and emitted:

```text
buggy   -0x73c92442917aab22
correct -0x73c92442917aaca3
```

The constructor code then combines the relocation result with the complementary obfuscated constant so that the correct final `blr x8` target is exactly `dl_iterate_phdr`. With the extra `0x181`, the indirect target becomes `dl_iterate_phdr + 0x181`, an odd address, matching `BUS_ADRALN`.

## Scope

Recomputing all 3,272 ABS64 records through the original PT_LOAD VA-to-file mapping changes:

```text
891 / 3749 symbolic relocation records
```

The GLOB_DAT records are unaffected because their standard addend is just `q4`.

This is a reconstruction-tool bug, not evidence that the inner module necessarily requires secret outer-loader state before its constructors can execute.

## Repair helper

Use:

```bash
python tools/fix_inner_abs64_addends.py \
  libysmteam.so \
  ysm_inner_payload.bin \
  inner_meta/rela.dyn.bin \
  --strict-hash
```

Then rebuild the original-placement ELF with the existing builder. For the mapped sample the helper validates the `0x5241C8` crash anchor and should produce the corrected `dl_iterate_phdr` addend shown above.
