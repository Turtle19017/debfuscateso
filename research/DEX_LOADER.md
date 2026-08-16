# Embedded DEX loader reached from the core package gate

The corrected v3 image establishes the natural call edge:

```text
0x270184 core JNI worker path
  -> package-name gate using strstr(..., "com.dts.freefiremax")
  -> CFF successor
  -> 0x270F7C: bl 0x355944
```

`0x355944` is indeed a DEX loader, but two earlier labels needed correction:

1. `JNIEnv` table offset `+0x6D8` is **GetJavaVM**, not RegisterNatives.
2. The loader is not purely in-memory: it Base64-decodes an embedded DEX, writes it to a temporary `.dex` file below `/data/data/<process>/`, marks the file read-only, constructs a `DexClassLoader`, then deletes the temporary DEX after loader creation.

## Function arguments

At entry:

```asm
0x355968  mov x21,x1
0x35596C  mov x19,x0
```

so:

```c
bool load_embedded_dex(JNIEnv *env, const std::string &base64_dex);
```

The second argument is converted with `NewStringUTF` and passed to `android/util/Base64.decode(String,int)`.

## GetJavaVM correction

The opening JNI call is:

```asm
0x355990  ldr x8,[x19]             ; JNINativeInterface **
0x355994  adrp/add x1,0x63E220     ; JavaVM ** output global
0x35599C  mov x0,x19               ; JNIEnv *
0x3559A0  ldr x8,[x8,#0x6D8]
0x3559A4  blr x8
0x3559A8  cbz w0,0x3559CC
```

The accompanying failure string is `"Failed to get JavaVM"`, which confirms `+0x6D8 = GetJavaVM` in this table layout.

## Temporary path construction

Helper `0x356A88` reads `/proc/self/cmdline` and returns it as a C++ string. `0x355944` builds:

```text
base directory = /data/data/<proc-self-cmdline>/
```

It calls `0x356BB0(8)` twice to generate random eight-character names, producing logical paths of the form:

```text
/data/data/<process>/<random>.dex
/data/data/<process>/<random>_opt
```

The first is the temporary DEX file. The second is the optimized-output directory supplied to `DexClassLoader`.

## JNI load sequence

The main Java/JNI sequence resolves to:

```text
FindClass("android/util/Base64")
GetStaticMethodID("decode", "(Ljava/lang/String;I)[B")
NewStringUTF(base64_dex)
CallStaticObjectMethod(Base64.decode, ..., 0)

FindClass("java/io/File")
GetMethodID("<init>", "(Ljava/lang/String;)V")
NewObject(File, dex_path)
NewObject(File, opt_path)

FindClass("java/io/FileOutputStream")
GetMethodID("<init>", "(Ljava/io/File;)V")
NewObject(FileOutputStream, dex_file)
GetMethodID("write", "([B)V")
GetMethodID("close", "()V")
CallVoidMethod(write, decoded_byte_array)
CallVoidMethod(close)

GetMethodID(File,"setReadOnly","()Z")
CallBooleanMethod(dex_file,setReadOnly)
GetMethodID(File,"mkdirs","()Z")
CallBooleanMethod(opt_dir,mkdirs)

FindClass("java/lang/ClassLoader")
GetStaticMethodID("getSystemClassLoader","()Ljava/lang/ClassLoader;")
CallStaticObjectMethod(...)

FindClass("dalvik/system/DexClassLoader")
GetMethodID("<init>",
  "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V")
NewObject(DexClassLoader, dex_path, opt_path, NULL, system_loader)
NewGlobalRef(dex_loader)

GetMethodID(File,"exists","()Z")
GetMethodID(File,"delete","()Z")
if (dex_file.exists()) dex_file.delete()
```

The loader logs `"DEX loaded successfully"` and returns `true` on the success path. Failure strings include:

```text
Failed to get JavaVM
Failed to find Base64 class
Failed to decode base64 DEX data
Failed to set DEX file to read-only
Failed to create DexClassLoader
Failed to create global reference
```

The many calls through JNIEnv table offset `+0xB8` at function exit are `DeleteLocalRef` cleanup.

## Exact embedded DEX

The v3 image contains one long literal Base64 payload at:

```text
inner VA/file offset 0x1016CA
Base64 length        4892 bytes
```

It decodes directly to:

```text
magic       dex\n037\0
size        3668 (0xE54)
SHA-256     fdef253bbfbc40cff2de3f5e53fd3412f41a4912018978cd2f8a92f9e441a66b
class defs  3
method ids  40
```

The three classes are:

```text
Lcom/ysmteam/imgui/GLES3JNIView;
Lcom/ysmteam/imgui/MainActivity;
Lcom/ysmteam/imgui/ViewAdder;
```

A recovered `R_AARCH64_RELATIVE` record also preserves a direct pointer to the Base64 literal:

```text
target 0x5147A0 -> addend 0x1016CA
```

This gives an independent static anchor for the payload.

## DEX behavior

The small DEX is an overlay/UI bootstrap, not an IL2CPP resolver blob.

`MainActivity.<clinit>` is exactly:

```java
System.loadLibrary("ysmteam");
```

`MainActivity.onCreate` creates a `GLES3JNIView` and sets it as content view.

`GLES3JNIView` declares native methods matching the recovered ELF JNI exports:

```text
init()
resize(int,int)
step()
imgui_Shutdown()
getWindowRect()
onTouch(int,float,float)
```

Its renderer callbacks forward directly to those native methods. `ViewAdder.run()` constructs full-screen layout parameters and calls `Window.addContentView(view, params)`.

Because the DEX uses standard name-based native declarations matching exported `Java_com_ysmteam_imgui_GLES3JNIView_*` symbols, no RegisterNatives call is required for this bootstrap.

## Reproduce

```bash
python tools/extract_embedded_dex.py \
  ysm_inner.original_placement_v3.so \
  ysm_embedded.dex \
  --strict-hash \
  --json ysm_embedded.dex.json
```

The next native target should be kept separate from this loader: the IL2CPP API resolver is visible around `0x3016AC`, where custom ELF symbol lookup resolves names such as `il2cpp_domain_get`, `il2cpp_class_from_name`, `il2cpp_field_get_offset`, and related APIs into globals around `0x63E0C0..0x63E170`. A direct CFF edge from the post-DEX success state to that resolver still needs to be proven.
