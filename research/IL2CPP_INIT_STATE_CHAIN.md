# Initial GLES init state chain toward the hidden IL2CPP trigger

This checkpoint follows the first indirect calls in `Java_com_ysmteam_imgui_GLES3JNIView_init @ 0x26931C` using a relocation-applied virtual image. It is a static control-flow recovery step only; no runtime patching is involved.

## 1. First indirect call in `GLES3JNIView_init`

The MBA expression ending at:

```asm
0x269460  blr x10
```

resolves exactly to:

```text
0x2DB1A8
```

This target is stable when arbitrary unaligned reads are taken from a PT_LOAD image after RELA writes have been applied.

## 2. First nested target inside `0x2DB1A8`

`0x2DB1A8` contains another obfuscated indirect call:

```asm
0x2DB220  blr x8
```

The same relocation-aware evaluation resolves it to:

```text
0x2DA5C0
```

## 3. `0x2DA5C0` immediately enters runtime-state machinery

The first indirect call inside `0x2DA5C0` is:

```asm
0x2DA6D0  adrp x0,0x51E000
0x2DA6D4  add  x0,x0,#0x780
...
0x2DA720  blr  x10
```

Its target resolves exactly to:

```text
0x2CEEDC
```

`0x2CEEDC` is a tiny atomic/plain 32-bit load helper:

```asm
0x2CEEDC  sub w8,w1,#1
0x2CEEE0  cmp w8,#2
0x2CEEE4  b.lo 0x2CEEF0
0x2CEEE8  cmp w1,#5
0x2CEEEC  b.ne 0x2CEEF8
0x2CEEF0  ldar w0,[x0]
0x2CEEF4  ret
0x2CEEF8  ldr  w0,[x0]
0x2CEEFC  ret
```

The object being sampled on this path is based at:

```text
0x51E780
```

Thus the first init chain is already consulting runtime state rather than merely traversing immutable relocation tables.

## 4. Why the next `BLR` cannot be read from the pristine relocated snapshot

The next indirect call in `GLES3JNIView_init` is:

```asm
0x2694D0  blr x8
```

If its MBA expression is evaluated against the relocated image **before accounting for the runtime state/call chain above**, the resulting value is:

```text
0x0
```

That is not a plausible executed call target. It demonstrates that relocation application alone is no longer a sufficient machine-state model at this point. Some combination of runtime-initialized state and side effects in the preceding CFF chain must be represented before later indirect targets can be trusted.

This is an important methodological correction: do not interpret a zero result here as a real null call or as evidence that the block is dead.

## 5. Consequence for the hidden `0x3016AC` trigger

The IL2CPP provider at `0x3016AC` has no ordinary direct `BL`, `B`, or `ADR` xref in the exact v3 text. `GLES3JNIView_init` contains dozens of later `BLR` sites, making it a plausible place for an indirect provider trigger, but none of those later edges should be labelled until the runtime state is carried forward correctly.

The current proven prefix is:

```text
GLES3JNIView_init @ 0x26931C
  -> BLR 0x269460
       -> 0x2DB1A8
          -> BLR 0x2DB220
               -> 0x2DA5C0
                  -> BLR 0x2DA720
                       -> 0x2CEEDC
                          -> atomic/plain load of runtime state @ 0x51E780
  -> later CFF/BLR targets require state-aware evaluation
```

No edge to `0x3016AC` is claimed yet.

## Next target

Extend the evaluator from a relocated-memory evaluator into a state-aware CFF evaluator for `0x2DA5C0` and the following `GLES3JNIView_init` blocks. The immediate goal is to reproduce the state value read through `0x2CEEDC`, propagate the resulting branch/CFF effects, and obtain a nonzero trustworthy target for `0x2694D0` and subsequent `BLR`s. Once a later target equals `0x3016AC`, the provider lifecycle edge will be proven rather than inferred.
