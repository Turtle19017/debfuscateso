# `.gcc_except_table` / `.rodata` recovery

The surviving ARM64 unwind metadata is sufficient to recover another exact section boundary in the first original PT_LOAD.

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

The `.eh_frame_hdr` advertises 9,565 FDEs, and parsing `.eh_frame` produces exactly 9,565 FDE records.

858 distinct FDEs carry LSDA pointers. Decoding those pcrel pointers gives:

```text
minimum LSDA = 0x0ED59C
maximum LSDA start = 0x0F5E94
```

The LSDA format's `ttype_offset` is relative to the byte immediately following the encoded offset. The type table grows backward from that base, so the maximum decoded type-table base is an exact end boundary for the exception table:

```text
maximum ttype_base = 0x0F5EB0
```

Therefore:

```text
.gcc_except_table
  start 0x0ED59C
  end   0x0F5EB0
  size  0x008914
```

The next bytes contain the already-observed ImGui/OpenGL/curl/OpenSSL strings and other read-only data, and continue until the exact `PT_GNU_EH_FRAME` start:

```text
.rodata
  start 0x0F5EB0
  end   0x1FFAFC
  size  0x109C4C
```

This fills two more entries from the surviving original section-name table without decoding the destroyed section-header tail.

## Tool

```bash
python tools/recover_exception_sections.py \
  ysm_inner_payload.bin \
  --json exception_sections.json
```

Expected mapped-sample result:

```text
FDEs              9565
distinct LSDAs    858
.gcc_except_table 0xed59c..0xf5eb0 size=0x8914
.rodata           0xf5eb0..0x1ffafc size=0x109c4c
```

## Current first-LOAD tail layout

The high-confidence consecutive region is now:

```text
.gcc_except_table  0x0ED59C .. 0x0F5EB0
.rodata             0x0F5EB0 .. 0x1FFAFC
.eh_frame_hdr       0x1FFAFC .. 0x2125F0
.eh_frame           0x2125F0 .. 0x25E2D4
alignment padding   0x25E2D4 .. 0x25E2E0
.text               0x25E2E0 .. 0x4D6810
.plt                0x4D6810 .. 0x4E29C0
```

The remaining large open question in the first LOAD is the protected/removed dynamic metadata region before `0x0ED59C`: original `.dynsym`, version tables, `.gnu.hash`/`.hash`, `.dynstr`, `.rela.dyn` and `.rela.plt` placement. Their semantics are recovered separately, but their original byte placement is not yet fully reconstructed.
