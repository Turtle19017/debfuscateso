# `.gcc_except_table` / `.rodata` recovery

The surviving ARM64 unwind metadata recovers the exception-table end and the first LSDA referenced by an FDE. A later independent reconstruction of the low dynamic-section chain also recovers the **true section start**.

## CIE/FDE evidence

The recovered `.eh_frame` starts at `0x2125F0` and contains two CIE families:

```text
CIE @ 0x2125F0  augmentation = zR
CIE @ 0x252FB0  augmentation = zPLR
```

For the exception-enabled `zPLR` CIE:

```text
P encoding = 0x9C
L encoding = 0x1C  # pcrel | sdata8
R encoding = 0x1B  # pcrel | sdata4
```

The `.eh_frame_hdr` advertises 9,565 FDEs, and parsing `.eh_frame` produces exactly 9,565 FDE records. 858 distinct FDEs carry LSDA pointers.

The minimum LSDA actually referenced by those FDEs is:

```text
minimum referenced LSDA = 0x0ED59C
```

This value was previously mistaken for the start of `.gcc_except_table`.

The LSDA format's `ttype_offset` is relative to the byte immediately following the encoded offset. The maximum decoded type-table base is:

```text
maximum ttype_base = 0x0F5EB0
```

so `0xF5EB0` remains the exact exception-table end.

## Corrected section start

The separately recovered original low-file chain gives:

```text
.rela.dyn  0x073B20 .. 0x0DB158
.rela.plt  0x0DB158 .. 0x0ED3B0
```

`0xED3B0` immediately begins LSDA-formatted data (`ff 9c ...`), with no intervening named section. Therefore the corrected section is:

```text
.gcc_except_table
  start 0x0ED3B0
  end   0x0F5EB0
  size  0x008B00
```

The earlier `0xED59C` value should now be described only as the **minimum FDE-referenced LSDA**, not a section boundary.

The following read-only section remains:

```text
.rodata
  start 0x0F5EB0
  end   0x1FFAFC
  size  0x109C4C
```

## Tool

```bash
python tools/recover_exception_sections.py \
  ysm_inner_payload.bin \
  --json exception_sections.json
```

Expected mapped-sample result now includes both facts:

```text
FDEs                 9565
distinct LSDAs       858
min referenced LSDA  0xed59c
.gcc_except_table    0xed3b0..0xf5eb0 size=0x8b00
.rodata              0xf5eb0..0x1ffafc size=0x109c4c
```

## Current first-LOAD layout

The reconstructed consecutive region is now:

```text
.note.android.ident  0x000238 .. 0x0002D0
.dynsym              0x0002D0 .. 0x0283C8
.gnu.version         0x0283C8 .. 0x02B932
.gnu.version_r       0x02B934 .. 0x02B994
.gnu.hash            0x02B998 .. 0x0378A0
.hash                0x0378A0 .. 0x044E50
.dynstr              0x044E50 .. 0x073B1D
.rela.dyn            0x073B20 .. 0x0DB158
.rela.plt            0x0DB158 .. 0x0ED3B0
.gcc_except_table    0x0ED3B0 .. 0x0F5EB0
.rodata              0x0F5EB0 .. 0x1FFAFC
.eh_frame_hdr        0x1FFAFC .. 0x2125F0
.eh_frame            0x2125F0 .. 0x25E2D4
alignment padding    0x25E2D4 .. 0x25E2E0
.text                0x25E2E0 .. 0x4D6810
.plt                 0x4D6810 .. 0x4E29C0
```

See `research/ORIGINAL_SECTION_LAYOUT.md` for the low metadata derivation and the 27-entry section-table reconstruction.
