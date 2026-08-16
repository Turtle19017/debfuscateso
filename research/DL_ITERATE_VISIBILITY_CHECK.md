# dl_iterate_phdr visibility check around 0x2DDB64

The direct-load investigation around the CFF routine beginning at `0x2DB3F4` has a stronger interpretation than the earlier generic "base consistency" label.

## Callback setup

The parent passes:

```asm
0x2DDADC  adr  x0, 0x2DE034       ; callback
0x2DDAF4  adr  x11,0x2DB3F4       ; runtime anchor inside this routine
0x2DDB00  str  x11,[sp,#0x70]     ; ctx.anchor
...
0x2DDB64  blr  x8                  ; resolved dl_iterate_phdr
```

`ADR` is runtime-PC-relative, so the stored anchor is `B + 0x2DB3F4`, not the literal file VA alone.

The callback writes a 24-byte context:

```c
struct FindSegmentCtx {
    uintptr_t anchor;       // +0x00
    uintptr_t seg_start;    // +0x08
    uint64_t  seg_memsz;    // +0x10
};
```

The core callback block is:

```asm
0x2DE8C8  ldp  x12,x14,[sp,#0x30] ; info, data
0x2DE8CC  ldr  x16,[sp,#0x40]     ; current Elf64_Phdr *
0x2DE8D0  ldr  x13,[x16,#0x10]    ; p_vaddr
0x2DE8D4  ldr  x12,[x12]          ; info->dlpi_addr
0x2DE8D8  ldr  x14,[x14]          ; ctx->anchor
0x2DE8DC  add  x10,x13,x12        ; start = dlpi_addr + p_vaddr
0x2DE8E0  ldr  x12,[x16,#0x28]    ; p_memsz
0x2DE8E4  cmp  x14,x10
0x2DE8E8  str  x10,[sp,#0x20]
0x2DE8EC  add  x10,x10,x12        ; end = start + p_memsz
0x2DE8F4  str  x10,[sp,#0x10]
```

On the match path it copies the discovered values back to caller data:

```asm
0x2DE550  ldr  x12,[sp,#0x38]     ; data
0x2DE554  ldr  x8,[sp,#0x20]      ; segment start
0x2DE568  str  x8,[x12,#0x08]
0x2DE56C  ldr  x8,[sp,#0x40]      ; phdr
0x2DE584  ldr  x8,[x8,#0x28]      ; p_memsz
0x2DE590  str  x8,[x12,#0x10]
```

Therefore `ctx+8` remains zero if no enumerated load segment contains the runtime anchor, and becomes the segment start if one is found.

## Parent comparison is actually against zero

After `dl_iterate_phdr`, the parent loads:

```asm
0x2DDC30  ldr x10,[sp,#0x78]      ; ctx.seg_start
...
0x2DDCA4  cmp x10,x8
0x2DDCBC  csel x8,x4,x8,eq
```

Static evaluation of the MBA expression producing `x8` proves the expected value is exactly zero.

Relevant constants from the reconstructed image:

```text
x27 = 0xBA0429331C2343EA

[0x5266A0] = 0x51A076DA5272E008
[0x5266A8] = 0x33FFADE78E97A452

R_AARCH64_RELATIVE @ 0x526480 addend = 0x67675250F5080161
R_AARCH64_RELATIVE @ 0x526488 addend = 0x2B16A93143A2ABEC
```

With zero load bias, the pointer MBA resolves to the two original-data qwords:

```text
0x51F190 -> 0xC9BA1FF8031975F1
0x51F198 -> 0x647C1402726931F3
```

The final arithmetic is:

```text
m1 = 0xC9BA1FF8031975F1
m2 = 0x647C1402726931F3
C  = 0xE9B4F2DF663671FD
K  = 0x164B0D2099C98E03

-m2                         = 0x9B83EBFD8D96CE0D
m1 ^ (-m2)                  = 0x5239F4058E8FBBFC
(m1 ^ (-m2)) * C            = 0x200EED27652F040C
((...) * C) ^ m1            = 0xE9B4F2DF663671FD
(((...) * C) ^ m1) + K      = 0x0000000000000000
```

So the parent condition is semantically:

```c
ctx.seg_start == 0
```

or equivalently a test of whether `dl_iterate_phdr` found a linker-visible PT_LOAD containing the current routine's runtime address.

## Important correction

Do not label `eq` as PASS or FAIL from the `csel` alone. `csel x8,x4,x8,eq` only chooses the next flattened state. The final meaning of the two states must be traced through the CFF dispatcher.

The direct-load v3 run reached `JNI_OnLoad`, so this routine did not terminate that run. That runtime fact must be used when assigning semantic PASS/FAIL labels to the two CFF states.

This stage is therefore best described as a **linker-visibility / containing-segment presence check**, not a byte hash check and not merely an arithmetic comparison against an independently reconstructed load base.
