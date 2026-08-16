# Post-Dex core CFF: Java overlay class construction

This note resolves the first natural CFF successors after `DexLoader @ 0x355944` in the corrected v3 inner ELF. The result corrects an earlier architectural shortcut: the immediate success path does **not** jump directly into the IL2CPP resolver at `0x3016AC`. It first performs Java-side overlay-class initialization and construction.

## DexLoader result dispatch

After:

```asm
0x270F7C  bl 0x355944
...
0x271000  tst  w22,#1
0x271004  mov  w10,#6
0x271020  mov  w9,#15
0x271028  csel x9,x10,x9,ne
...
0x271068  br x8
```

the relocation-backed CFF table evaluates exactly to:

```text
state 6  -> 0x27106C
state 15 -> 0x272684
```

`0x272684` is the ordinary stack-canary epilogue/return block. Therefore the nonzero result path from DexLoader continues at `0x27106C`.

## First success-stage call

The indirect call at:

```asm
0x271104  blr x8
```

resolves statically to:

```text
0x268808
```

This helper receives `JNIEnv *`. It lazily decodes the same class name later used by the main path:

```text
com.ysmteam.imgui.GLES3JNIView
```

and invokes the class-loader helper at `0x35643C`. It performs additional Java-side initialization and returns a boolean-like low bit. The next CFF dispatch resolves to:

```text
state 26 (nonzero) -> 0x27116C
state 19 (zero)    -> 0x272684
```

Thus a zero result stops this initialization path cleanly; a nonzero result continues.

## Exact class-loader chain at 0x27116C

The next indirect calls resolve as follows:

```text
0x2711FC -> 0x272744   lazy encoded-string getter
0x271268 -> 0x272828   in-place string decoder
0x2712FC -> 0x35643C   ClassLoader.loadClass helper
```

The encoded object used by `0x272744` is 31 bytes from `0x1E4869`. Its decoder at `0x272828` yields exactly:

```text
com.ysmteam.imgui.GLES3JNIView\0
```

`0x35643C` is not a raw `FindClass` wrapper. It operates through the previously captured application `ClassLoader` and invokes Java `loadClass(String)`; its plaintext method metadata includes:

```text
loadClass
(Ljava/lang/String;)Ljava/lang/Class;
```

After the call, `0x271308` tests the returned class object. The CFF dispatch evaluates to:

```text
state 7  (class != NULL) -> 0x271360
state 27 (class == NULL) -> 0x272684
```

## Constructor lookup for GLES3JNIView

On the non-null class path, the indirect calls resolve to:

```text
0x2713F4 -> 0x2728D0   lazy method-name getter
0x271470 -> 0x272940   method-name decoder
0x2714E4 -> 0x27299C   lazy signature getter
0x271548 -> 0x272A80   signature decoder
0x2715D4 -> 0x2728C4   JNIEnv table +0x108
0x2716C8 -> 0x272B04   JNIEnv table +0x0E8 varargs wrapper
```

The decoded method metadata is exact:

```text
method name: <init>
signature:   (Landroid/content/Context;)V
```

`JNIEnv + 0x108` is `GetMethodID`, so the path is semantically:

```c
jclass view_cls = app_class_loader.loadClass(
    "com.ysmteam.imgui.GLES3JNIView"
);

jmethodID ctor = env->GetMethodID(
    view_cls,
    "<init>",
    "(Landroid/content/Context;)V"
);
```

The trampoline at `0x272B04` loads `JNIEnv` slot `+0xE8`, which is the `NewObjectV` slot. The continuation therefore constructs a Java `GLES3JNIView` instance using an Android `Context` argument before later overlay/window integration.

## Architectural consequence

The natural post-Dex path now has a stronger shape:

```text
DexLoader 0x355944
  -> success state 6
  -> 0x268808 Java-side initialization
  -> loadClass("com.ysmteam.imgui.GLES3JNIView")
  -> GetMethodID("<init>", "(Landroid/content/Context;)V")
  -> NewObjectV(...)
  -> later Java overlay integration
```

This means `0x3016AC` (the polling/custom-hash IL2CPP resolver) remains a separate subsystem whose **exact incoming edge is still unresolved**. A scan found no direct `BL 0x3016AC` and no plain 64-bit function pointer equal to that VA in the reconstructed file. It may be reached through another flattened/indirect state or another worker later in initialization.

Do not collapse the Java DEX/class-loader path and IL2CPP resolver into one direct call chain until that edge is recovered.

## Reproduce

```bash
python tools/recover_core_cff_after_dex.py \
  ysm_inner.original_placement_v3.so \
  --strict-hash \
  --json core_cff_after_dex.json
```

Expected highlights:

```text
DexLoader state 6        -> 0x27106C
DexLoader state 15       -> 0x272684
0x271104 indirect call   -> 0x268808
initializer state 26     -> 0x27116C
initializer state 19     -> 0x272684
class                    -> com.ysmteam.imgui.GLES3JNIView
loadClass state 7        -> 0x271360
loadClass state 27       -> 0x272684
GetMethodID trampoline   -> 0x2728C4
NewObjectV trampoline    -> 0x272B04
constructor              -> <init>(Landroid/content/Context;)V
```
