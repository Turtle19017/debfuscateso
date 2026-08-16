# PT_DYNAMIC reconstruction

The protected raw bytes at the original `PT_DYNAMIC` range are destructively replaced, but the original table shape and tag set can be constrained much more tightly than before.

## Exact container size

Recovered program headers give:

```text
PT_DYNAMIC file offset = 0x505570
PT_DYNAMIC VA          = 0x509570
PT_DYNAMIC size        = 0x230
Elf64_Dyn size         = 0x10
```

Therefore the original dynamic segment contains exactly:

```text
0x230 / 0x10 = 35 entries
```

The raw `0x230` bytes are all in `0x00..0x7f`, consistent with destructive stripping.

## Toolchain fingerprint

The surviving `.comment` section identifies the primary build toolchain as:

```text
Android clang 14.0.7
r450784d1 / Android build 9352603
```

The low section order is also LLD-shaped:

```text
.dynsym
.gnu.version
.gnu.version_r
.gnu.hash
.hash
.dynstr
.rela.dyn
.rela.plt
```

The recovered GNU_RELRO range covers `.got.plt`. Since `.got.plt` becomes read-only after relocation, eager PLT binding is required.

## 35-entry LLD-shaped table

The ten dependency names plus known dynamic metadata fit the recovered segment exactly when bind-now flags are included:

```text
10 x DT_NEEDED
DT_SONAME
DT_FLAGS      = DF_BIND_NOW
DT_FLAGS_1    = DF_1_NOW
DT_RELA
DT_RELASZ
DT_RELAENT
DT_RELACOUNT
DT_JMPREL
DT_PLTRELSZ
DT_PLTGOT
DT_PLTREL     = DT_RELA
DT_SYMTAB
DT_SYMENT
DT_STRTAB
DT_STRSZ
DT_GNU_HASH
DT_HASH
DT_INIT_ARRAY
DT_INIT_ARRAYSZ
DT_FINI_ARRAY
DT_FINI_ARRAYSZ
DT_VERSYM
DT_VERNEED
DT_VERNEEDNUM
DT_NULL
```

With ten `DT_NEEDED` records this is exactly 35 `Elf64_Dyn` entries, or exactly `0x230` bytes. No padding records are needed.

The current ordering is a high-confidence canonical NDK/LLD reconstruction. The stripped raw bytes do not preserve enough information to label ordering itself as direct byte-for-byte plaintext recovery.

## Exact values

```text
DT_RELA      = 0x073B20
DT_RELASZ    = 0x067638
DT_RELACOUNT = 13896

DT_JMPREL    = 0x0DB158
DT_PLTRELSZ  = 0x012258
DT_PLTGOT    = 0x50A6B8

DT_SYMTAB    = 0x0002D0
DT_STRTAB    = 0x044E50
DT_GNU_HASH  = 0x02B998
DT_HASH      = 0x0378A0

DT_INIT_ARRAY   = 0x509540
DT_INIT_ARRAYSZ = 0x30
DT_FINI_ARRAY   = 0x509530
DT_FINI_ARRAYSZ = 0x10

DT_VERSYM     = 0x0283C8
DT_VERNEED    = 0x02B934
DT_VERNEEDNUM = 3
```

## Tool

```bash
python tools/recover_inner_dynamic_table.py \
  ysm_inner_payload.bin \
  dynamic_meta \
  --metadata-dir inner_meta \
  --aux-dir inner_aux \
  --layout-manifest original_layout/original_layout.json
```

Outputs:

```text
dynamic_meta/dynamic.bin   # exactly 0x230 bytes
dynamic_meta/dynamic.tsv
dynamic_meta/dynamic.json
```

`tools/build_inner_original_placement_elf.py` now uses the same 35-entry shape and refuses to write a dynamic table that does not exactly fill the recovered original `PT_DYNAMIC` size.
