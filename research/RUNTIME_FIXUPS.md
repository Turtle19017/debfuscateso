# Runtime relative fixups and exact dependency order

This checkpoint closes another relocation path that is separate from the previously normalized 40-byte `ABS64/GLOB_DAT/JUMP_SLOT` records.

## FD3E4 remap explains the metadata object

The VM-protected `FD3E4` function is a field-remapping constructor. It copies values from the `FCF08` source descriptor into the runtime metadata object and then calls `CA6B8`, which writes the 16-byte metadata seed at destination `+0xA8`.

The mappings relevant to the newly recovered table are:

```text
source +0xA8 -> metadata +0xA0    encrypted table pointer
source +0x14 -> metadata +0x40    encrypted table byte size
source +0x18 -> metadata +0x44    record count
seed16[10]   -> metadata +0xB2
```

For the checkpoint sample:

```text
source +0xA8 = VA 0x3D73D0
source +0x14 = 0x36480 bytes
source +0x18 = 0x3648 records = 13,896
seed16[10]   = 0x99
```

`CA93C` calls the already recovered `CB1D8` stream transform over that `0x36480`-byte buffer and returns the decrypted pointer.

Decrypted-table SHA-256:

```text
2986baafbd977d1c6263a044146e254cf4ad2da95fca9140d9f1689ea002c4c2
```

The table consists of exactly 13,896 records of two little-endian qwords:

```c
struct RuntimeFixup {
    uint64_t target_offset;
    uint64_t value_offset;
};
```

All target offsets are 8-byte aligned and strictly increasing.

Observed target range:

```text
0x4E69C0 .. 0x537558
```

## Mapping base versus load bias

`JNI_OnLoad` creates a temporary mapping object at `sp+0x38`. `C9010` initializes it and `C92A8/C9158/C9208/C92EC` populate/map the inner PT_LOAD span.

The object fields are:

```text
mapping +0x08 = actual mapped base
mapping +0x10 = mapped span size
mapping +0x18 = load bias
```

The key relation comes from `C9028`, which computes the page-aligned minimum and maximum PT_LOAD virtual addresses. In the mmap path (`C9208`):

```text
mapped_base = mmap(min_load_vaddr, span, ...)
load_bias   = mapped_base - min_load_vaddr
```

`JNI_OnLoad` copies these fields into the runtime loader object:

```text
FDCD4: loader +0x090 = mapped_base
FDCDC: loader +0x098 = mapped_span
FDCE8: loader +0x180 = load_bias
```

## Exact C8DBC fixup semantics

`C8AD4` stores the decrypted `CA93C` table at loader `+0x108` and its count at `+0x110`.

`C8DBC` applies every 16-byte record before the symbolic relocation passes:

```text
record.q0 = target_offset
record.q1 = value_offset

P = load_bias + target_offset
V = mapped_base + value_offset
*P = V
```

Equivalent pseudocode:

```c
for (size_t i = 0; i < loader->relative_count; ++i) {
    uint64_t target = loader->load_bias + table[i].target_offset;
    uint64_t value  = loader->mapped_base + table[i].value_offset;
    *(uint64_t *)target = value;
}
```

This is a custom relative-fixup family. It is distinct from `FDA30`, which handles the 40-byte symbol-based relocation records.

Some `value_offset` qwords in the `0x514xxx..0x527xxx` target area look high-entropy/opaque. They are intentionally retained: `C8DBC` applies them unconditionally, so filtering only values that look like canonical pointers would no longer reproduce the loader's exact behavior.

## Zero-based synthetic ELF equivalence

The reconstructed analysis ELF uses a zero-based first PT_LOAD. In that synthetic mapping:

```text
mapped_base == load_bias == B
```

Therefore each custom record can be represented exactly for the synthetic layout as:

```text
R_AARCH64_RELATIVE
r_offset = target_offset
r_addend = value_offset
```

which performs:

```text
*(B + r_offset) = B + r_addend
```

`tools/recover_inner_runtime_metadata.py` emits this zero-based equivalent as:

```text
rela.relative.bin
```

This is explicitly a reconstruction equivalence. It is not a claim that the producer's original minimum PT_LOAD virtual address has already been recovered byte-for-byte.

## Exact custom-loader dependency order

`FCF08` sets source `+0xF0` to the pointer table at outer VA `0x72CD20` and source `+0xF8` to count `10`. `FD3E4` remaps those fields to metadata `+0xF8/+0x100`, and `C8D20` walks the ten pointers and calls `dlopen` in order.

The pointer slots are zero in the outer file and are populated by the outer SO's own `R_AARCH64_RELATIVE` relocations. Their relocation addends point to the actual dependency strings.

Exact recovered custom-loader order:

```text
0  liblog.so
1  libandroid.so
2  libEGL.so
3  libGLESv2.so
4  libGLESv3.so
5  libGLESv1_CM.so
6  libz.so
7  libdl.so
8  libc.so
9  libm.so
```

String VAs in the outer image:

```text
0x31E7D0 liblog.so
0x31E7E0 libandroid.so
0x31E7F0 libEGL.so
0x31E800 libGLESv2.so
0x31E810 libGLESv3.so
0x31E820 libGLESv1_CM.so
0x31E830 libz.so
0x31E838 libdl.so
0x31E848 libc.so
0x31E850 libm.so
```

This is stronger evidence than the earlier inference from `.dynstr` string order. The list is still described as the **custom-loader dependency order**; a byte-for-byte original `DT_NEEDED` array is not claimed until the producer-side dynamic table itself is recovered.

## Updated reconstructed ELF

When `rela.relative.bin` and `needed.txt` are present in the metadata directory, `tools/build_inner_reconstructed_elf.py` now prepends the 13,896 zero-based RELATIVE entries to the previously normalized 3,749 symbol-based `.rela.dyn` entries.

Current generated table sizes:

```text
R_AARCH64_RELATIVE  13,896
ABS64/GLOB_DAT       3,749
--------------------------------
.rela.dyn total     17,645

.rela.plt            3,097 JUMP_SLOT
```

The synthetic `.dynamic` also emits:

```text
DT_RELACOUNT = 13896
```

Validation with standard tooling:

```text
readelf -r -> .rela.dyn contains 17,645 entries
readelf -d -> RELACOUNT 13896
readelf -d -> exact ten-library custom-loader ordering above
```

The remaining major reconstruction gap is no longer relocation behavior. It is recovery of the producer's original ELF file/program-header placement and exact original dynamic/hash layout rather than the equivalent synthetic layout used by the current rebuilder.
