# JNI_OnLoad environment bootstrap

The corrected direct-load reconstruction exposes the natural JNI bootstrap clearly enough to separate ELF/linker reconstruction from application-environment expectations.

## JNI_OnLoad skeleton

Recovered dynamic symbol metadata places:

```text
JNI_OnLoad = 0x27C444
size       = 0x49C
```

Static evaluation of its obfuscated indirect calls gives the following natural skeleton:

```c
jint JNI_OnLoad(JavaVM *vm, void *) {
    store_global_vm(vm);

    init_environment_2EE670();

    JNIEnv *env = nullptr;
    jint rc = vm->GetEnv((void **)&env, JNI_VERSION_1_6);

    if (rc == JNI_OK) {
        std::thread t(thread_entry_0x2970EC /* captured context omitted */);
        t.detach();
    }

    return JNI_VERSION_1_6;
}
```

The exact constants simplify to:

```text
GetEnv requested version = 0x00010006 = JNI_VERSION_1_6
expected GetEnv status   = 0          = JNI_OK
JNI_OnLoad return value  = 0x00010006 = JNI_VERSION_1_6
```

The indirect call used for `GetEnv` resolves to a local trampoline at `0x27C8E0`:

```asm
0x27C8E0  ldr x8,[x0]
0x27C8E4  ldr x3,[x8,#0x30]
0x27C8E8  br  x3
```

The C++ thread wrapper resolves to `0x27C8EC`, which ultimately invokes `pthread_create` with entry `0x2970EC`, followed by `std::__ndk1::thread::detach()`.

## Environment initializer 0x2EE670

Before `GetEnv`, `JNI_OnLoad` calls `0x2EE670`. This routine invokes three near-clone helpers:

```text
0x2E9368
0x2E9B90
0x2EA420
```

All three decode and read the exact path:

```text
/proc/self/maps
```

They parse mappings with the format:

```text
%lx-%lx %4s %lx %x:%x %lu %s
```

and select mapping paths with `strstr` predicates.

### Helper 1 — base APK

`0x2E9368` requires one mapping path to contain all of:

```text
/data/app/
/base.apk
com.dts.freefiremax
```

### Helper 2 — install-time asset pack

`0x2E9B90` requires:

```text
/data/app/
/split_asset_pack_install_time.apk
com.dts.freefiremax
```

### Helper 3 — ARM64 configuration split

The previously unresolved helper `0x2EA420` is now fully decoded. It requires:

```text
/data/app/
/split_config.arm64_v8a.apk
com.dts.freefiremax
```

The third selector is independently recovered from three encrypted static strings:

- `/data/app/` from the lazy global at `0x63C2C8`;
- `/split_config.arm64_v8a.apk` from the encoded 28-byte source beginning at inner VA `0x1E6152`;
- `com.dts.freefiremax` from the encoded 20-byte source beginning at inner VA `0x1E616E`.

## Failure semantics in 0x2EE670

The orchestrator treats every helper result as required. Immediately after each helper, it computes the `std::string` length and branches to a dedicated failure block if the result is empty:

```text
helper 0x2E9368 empty -> 0x2EEF88 -> exit(0)
helper 0x2E9B90 empty -> 0x2EEFA0 -> exit(0)
helper 0x2EA420 empty -> 0x2EEFB8 -> exit(0)
```

There is another `exit(0)` path at `0x2EEF70` for failure to obtain a usable own-library directory through `dladdr`/`strrchr`.

Therefore a minimal standalone harness whose package is `com.test.harness` does **not** satisfy the natural environment expected by this initializer: its `/proc/self/maps` does not contain the three required Free Fire Max APK mappings. The expected natural result for this exact code path is process termination through `exit(0)`, not a successful continuation to the later JNI thread startup.

This is an environment/layout dependency. This note does not prescribe patching or bypassing the checks.

## Important crash-log caveat

An earlier reported tombstone contained PCs labelled roughly as:

```text
strlen
libysmteam.so + 0x287410
libysmteam.so + 0x287F34 (reported as JNI_OnLoad+180)
```

Those PCs do not match the exact corrected v3 image whose `JNI_OnLoad` is `0x27C444`. The known maps-helper `strlen` calls also operate on explicit stack/static buffers and do not explain a `strlen(NULL)` at those reported PCs.

Until the SHA-256 of the actually installed `libysmteam.so` is matched to the analyzed image, that tombstone should not be used to assign source-level semantics to exact-v3 addresses.

## Reproducible selector recovery

```bash
python tools/recover_jni_environment_selectors.py \
  ysm_inner.original_placement_v3.so \
  --strict-hash \
  --json jni_environment.json
```

Expected selectors:

```text
0x2E9368: /data/app/ + /base.apk + com.dts.freefiremax
0x2E9B90: /data/app/ + /split_asset_pack_install_time.apk + com.dts.freefiremax
0x2EA420: /data/app/ + /split_config.arm64_v8a.apk + com.dts.freefiremax
```
