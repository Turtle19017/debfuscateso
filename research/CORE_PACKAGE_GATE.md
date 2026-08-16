# Core package-name gate after JNI worker startup

The `JNI_OnLoad` worker at `0x2970EC` attaches the native thread, sleeps five seconds, calls `0x270184(JNIEnv*)`, and detaches. Static analysis of the corrected v3 image now resolves the first application/package gate inside `0x270184` without patching any branch.

## Worker handoff

```asm
0x297128  ldr x0,[x20,#0x6c0]     ; global JavaVM *
0x297130  ldr x8,[x0]
0x297134  ldr x8,[x8,#0x20]       ; AttachCurrentThread
0x297138  add x1,sp,#0x10          ; &env
0x29713C  mov x2,xzr
0x297140  blr x8
0x297144  mov w0,#5
0x297148  bl  sleep@plt
0x29714C  ldr x0,[sp,#0x10]       ; JNIEnv *
0x297150  bl  0x270184
0x297154  ldr x0,[x20,#0x6c0]
0x297158  ldr x8,[x0]
0x29715C  ldr x8,[x8,#0x28]       ; DetachCurrentThread
0x297160  blr x8
```

## Natural JNI path in 0x270184

The early success path resolves to:

1. call local helper `0x2DB1A8(0)`;
2. pass its result to `sleep`;
3. call `0x356584(env)` to obtain Unity's `currentActivity` through `ActivityThread`, the application ClassLoader and `com.unity3d.player.UnityPlayer`;
4. call `0x3569F4(env, activity)` to obtain the activity package name as a `jstring`;
5. call the JNIEnv `GetStringUTFChars` slot through trampoline `0x272724`;
6. compare the resulting UTF-8 package name with a lazily decoded process-global substring by calling the `strstr` trampoline at `0x272730` from callsite `0x270AC4`.

The package substring was previously only represented by a pointer global at `0x5376D8`. Its exact plaintext is now recovered.

## Exact package selector

The pointer global is initialized by constructor `0x29734C`, which is the second recovered `.init_array` entry:

```text
R_AARCH64_RELATIVE @ 0x509548 -> 0x29734C
```

At `0x297520`, that constructor creates a 20-byte encoded source on the stack:

```asm
0x297520  adr  x10,0x1E4821
0x297524  ldr  q0,[x10]           ; encoded bytes 0..15
...
0x29752C  mov/movk w8,0x03A3C87E
0x297534  str  q0,[sp]
0x297538  str  w8,[sp,#0x10]      ; encoded bytes 16..19
```

The exact source bytes are:

```text
70 c6 b6 2d 0d 75 5c 5b 75 db be 66 0f 68 5d 10
7e c8 a3 03
```

The lazy initializer `0x2853E0` copies those 20 bytes into the object at `0x538680` and sets marker byte `object+0x14 = 1`.

`0x296C90` then decodes it in place. For the first 16 bytes the XOR key at `0x0F5F30` is:

```text
13 a9 db 03 69 01 2f 75 13 a9 db 03 69 01 2f 75
```

which gives:

```text
70c6b62d0d755c5b75dbbe660f685d10
XOR
13a9db0369012f7513a9db0369012f75
=
636f6d2e6474732e6672656566697265
= "com.dts.freefire"
```

The final four bytes use `ldr s0; ushll; eor d1; uzp1; str s0`. The eight-byte key at `0x0F7F50` is:

```text
13 00 a9 00 db 00 03 00
```

After the zero-extension/interleave and `uzp1`, the effective tail key is the even bytes:

```text
13 a9 db 03
```

therefore:

```text
7e c8 a3 03 XOR 13 a9 db 03 = 6d 61 78 00 = "max\0"
```

The complete decoded object is exactly:

```text
com.dts.freefiremax\0
```

After decoding, constructor `0x29734C` publishes the object through:

```asm
0x29754C  ... x19 = 0x538680
0x297554  mov x0,x19
0x297558  bl  0x296C90
0x297560  str x19,[0x5376D8]
```

Thus the consumer at `0x270AC4` is semantically:

```c
const char *package_utf = env->GetStringUTFChars(package_jstring, nullptr);
const char *required = *(const char **)0x5376D8;  // "com.dts.freefiremax"
void *match = strstr(package_utf, required);
```

This independently agrees with the earlier `/proc/self/maps` environment bootstrap, whose three selectors all require `com.dts.freefiremax` paths.

## Cleanup

The local trampolines around this path are consistent with ordinary JNI cleanup:

```asm
0x272724  JNIEnv table +0x548   ; GetStringUTFChars
0x272730  b strstr@plt
0x272734  JNIEnv table +0x550   ; ReleaseStringUTFChars
0x270178  JNIEnv table +0x0B8   ; DeleteLocalRef
```

The natural package gate should be analyzed as an environment expectation, not bypassed. The next useful target is to map the CFF successor after a non-null `strstr` result and follow it into the IL2CPP resolver/hook initialization.

## Reproduce

```bash
python tools/recover_core_package_gate.py \
  ysm_inner.original_placement_v3.so \
  --strict-hash \
  --json core_package_gate.json
```
