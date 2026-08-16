# Inner relocation reconstruction

This note records the recovered semantics of the outer loader's 40-byte custom relocation records and how they are normalized back into standard AArch64 `Elf64_Rela` entries for analysis.

## Runtime handler

The relocation loop is native outer function `0xFDA30`. It receives the loader context, a pointer to the custom records, and a record count. Each record is `0x28` bytes:

```text
+0x00  q0 = ELF-style r_info
+0x08  q1 = noisy target-offset base
+0x10  q2 = small target delta (0..63)
+0x18  q3 = direction flag
+0x20  q4 = relocation-side addend component
```

The real target offset is reconstructed exactly as:

```text
q3 == 0  -> target = q1 + q2
q3 == 1  -> target = q1 - q2
```

For the current sample every recovered target is 8-byte aligned. The `q1/q2/q3` split is therefore an obfuscated representation of `r_offset`, not three independent ELF fields.

## Recovered relocation classes

The separate PLT table contains:

```text
3097 x R_AARCH64_JUMP_SLOT (0x402)
```

The non-PLT table contains exactly:

```text
3272 x R_AARCH64_ABS64    (0x101)
 477 x R_AARCH64_GLOB_DAT (0x401)
--------------------------------
3749 total
```

All current non-PLT records have a non-zero dynamic-symbol index.

## `0xFDA30` write semantics

After resolving the symbol through `0xC8920`, the loader computes `P = load_bias + target` and applies the current sample's relevant types as follows:

```text
R_AARCH64_JUMP_SLOT:
    *P = S + q4

R_AARCH64_GLOB_DAT:
    *P = S + q4

R_AARCH64_ABS64:
    *P = *P + S + q4
```

This means the custom ABS64 representation is equivalent to standard RELA with:

```text
A = original_qword_at_target + q4
```

while GLOB_DAT/JUMP_SLOT use:

```text
A = q4
```

The effective ABS64 addend may look intentionally nonsensical for some slots. That is still the exact arithmetic performed by the loader; the normalizer preserves the full 64-bit value rather than trying to reinterpret it heuristically.

## GOT / PLT-GOT ranges

Decoded relocation targets expose useful high-confidence boundaries:

```text
non-PLT GLOB_DAT targets : 0x5097A0 .. 0x50A6B0
PLT JUMP_SLOT targets    : 0x50A6D0 .. 0x510790
```

The synthetic analysis ELF therefore splits the writable image around:

```text
.got      0x5097A0 .. 0x50A6D0
.got.plt  0x50A6D0 .. 0x510798
```

These names are analysis labels inferred from relocation usage. They are not claimed to be the producer's original section headers.

## Tool output

`tools/recover_inner_symbols.py` now accepts the recovered inner image:

```bash
python tools/recover_inner_symbols.py \
  libysmteam.so \
  inner_meta \
  --inner ysm_inner_payload.bin \
  --strict-hash \
  --dump-raw
```

In addition to dynsym/PLT data it writes:

```text
inner_meta/relocs.tsv
inner_meta/rela.dyn.bin
inner_meta/rela.plt.bin
```

`rela.dyn.bin` contains 3749 normalized `Elf64_Rela` entries and `rela.plt.bin` contains 3097 normalized entries.

`tools/build_inner_analysis_elf.py` consumes those files and emits real `SHT_DYNSYM`, `SHT_RELA`, `.got` and `.got.plt` analysis sections. `readelf -r` can therefore display the recovered relocation targets and symbol names directly.

## Current status

This closes the previous "3749 unknown non-PLT relocation records" gap. The remaining ELF reconstruction work is primarily the producer's separated program-header/dynamic-tag metadata and exact original section boundaries; the symbol and relocation semantics needed for static analysis are now substantially recovered.
