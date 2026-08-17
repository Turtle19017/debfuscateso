# IL2CPP resolver consumers and nearby loader infrastructure

This checkpoint separates three previously conflated areas in the corrected v3 inner ELF:

1. the IL2CPP export-table provider at `0x3016AC`;
2. the actual IL2CPP consumer helpers around `0x3011A0..0x3016A8` and their lower-text callers;
3. the custom ELF/XZ loader machinery around `0x356xxx..0x358xxx`.

The analysis is static and documents natural control/data flow only. It does not patch hooks, bypass licensing, or alter runtime validation.

## 1. `0x3016AC` is the IL2CPP export-table provider

The function preserves its input pointer in `x20` and repeatedly calls the custom module opener `0x356FCC` until it obtains a non-null module wrapper:

```asm
0x3016B8  mov w1,wzr
0x3016BC  mov x20,x0
0x3016C0  bl  0x356FCC
0x3016C4  cbz x0,0x3016D0
...
0x3016D0  mov x0,x20
0x3016D4  mov w1,wzr
0x3016D8  bl  0x356FCC
0x3016E0  mov w0,#1
0x3016E4  bl  sleep@plt
0x3016E8  cbz x19,0x3016D0
```

Once the wrapper is available, `0x357184` resolves 19 IL2CPP exports and stores them into the global dispatch table under page `0x63E000`.

The exact recovered map is:

```text
+0x0E0  il2cpp_assembly_get_image
+0x0D8  il2cpp_domain_get
+0x0D0  il2cpp_domain_get_assemblies
+0x0E8  il2cpp_image_get_name
+0x110  il2cpp_class_from_name
+0x128  il2cpp_class_get_field_from_name
+0x140  il2cpp_class_get_method_from_name
+0x168  il2cpp_field_get_offset
+0x130  il2cpp_field_static_get_value
+0x138  il2cpp_field_static_set_value
+0x120  il2cpp_array_new
+0x170  il2cpp_string_chars
+0x0C0  il2cpp_string_new
+0x0C8  il2cpp_string_new_utf16
+0x160  il2cpp_type_get_name
+0x158  il2cpp_method_get_param
+0x148  il2cpp_class_get_methods
+0x150  il2cpp_method_get_name
+0x118  il2cpp_object_new
```

This corrects the earlier shifted map. In particular:

```text
+0x0C0 = il2cpp_string_new
+0x0C8 = il2cpp_string_new_utf16
```

not the reverse.

At the end of the provider:

```asm
0x3018F8  mov x8,x0
0x3018FC  adrp x9,0x63E000
0x301904  str x8,[x9,#0x118]
...
0x301910  b   0x357128
```

`0x357128` frees the custom wrapper metadata, preserves `[wrapper+0x28]`, and returns that value:

```asm
0x357160  ldr x20,[x19,#0x28]
0x357164  mov x0,x19
0x357168  bl  free@plt
...
0x357174  mov x0,x20
```

So `0x3016AC` both populates the IL2CPP dispatch table and returns the wrapper's underlying module handle.

No plaintext `libil2cpp.so` literal has been found in the v3 image. The input to `0x3016AC` must identify a module exporting the listed IL2CPP API, but the exact caller-produced module string remains to be recovered rather than assumed.

## 2. Actual IL2CPP consumer helpers

### `0x3011A0`: `il2cpp_string_new` trampoline

The function is only three instructions:

```asm
0x3011A0  adrp x8,0x63E000
0x3011A4  ldr  x1,[x8,#0xC0]
0x3011A8  br   x1
```

Because table slot `+0xC0` is now proven to be `il2cpp_string_new`, this is a direct tail trampoline to that API.

There are 14 direct `BL` callers in the sample, all in the `0x274xxx..0x275xxx` region:

```text
0x274788 0x2747D8 0x274824 0x274870
0x2753EC 0x275438 0x275484 0x2754D0
0x275860 0x2758AC 0x2758F8 0x275944
0x275E20 0x275E8C
```

### `0x3011AC`: image/class finder with cache

This helper accepts three string-like C arguments and constructs a cache key. On a cache miss it uses:

```text
+0xD8  il2cpp_domain_get
+0xD0  il2cpp_domain_get_assemblies
+0xE0  il2cpp_assembly_get_image
+0xE8  il2cpp_image_get_name
+0x110 il2cpp_class_from_name
```

It iterates loaded assemblies, compares image names with `strcmp`, resolves the class by namespace/class name, caches the result, and returns the `Il2CppClass *`.

A useful semantic description is therefore:

```text
find_class(image_name, namespace_name, class_name)
```

### `0x301474`: method-pointer resolver

This helper takes image/namespace/class/method arguments plus an argument count. It walks the same domain/assembly/image path, resolves the class, then calls slot `+0x140` (`il2cpp_class_get_method_from_name`). When the returned MethodInfo is non-null, the helper returns its leading method pointer; otherwise it returns null.

A useful semantic description is:

```text
resolve_method_pointer(image, namespace, class, method, argc)
```

There are 27 direct callers, mostly in the lower text region:

```text
0x25EA24 0x25EDE0 0x25F200 0x25F944 0x25FAD8
0x26000C 0x2603C0 0x260768 0x260B0C 0x260E90
0x261238 0x2626F0 0x262A90 0x262CA4 0x262E9C
0x263584 0x263920 0x263CB4 0x264544 0x26489C
0x26533C 0x266020 0x267C80 0x268020 0x2684F8
0x274C04 0x274FE8
```

For example, the call at `0x25EA24` is followed by an indirect branch through the resolved result, which is the expected shape of a lazy IL2CPP method trampoline.

### `0x301590`: field-offset resolver

This helper reaches `0x3011AC`, resolves a field through table slot `+0x128` (`il2cpp_class_get_field_from_name`), then calls `+0x168` (`il2cpp_field_get_offset`). It returns `-1` on failure.

A useful semantic description is:

```text
resolve_field_offset(image, namespace, class, field)
```

Its 8 direct callers are:

```text
0x2615E8 0x261768 0x2619E0 0x261E30
0x264C50 0x265718 0x2659B4 0x268368
```

These xrefs show that the strongest concrete IL2CPP consumers are concentrated in `0x25Exxx..0x268xxx` and `0x274xxx..0x275xxx`, rather than being uniquely associated with the `0x358000..0x360000` range.

## 3. No ordinary direct incoming edge to `0x3016AC`

A text-wide scan of the exact v3 image finds no:

```text
direct BL -> 0x3016AC
direct B  -> 0x3016AC
ADR        -> 0x3016AC
```

An exact-pointer/relocation scan likewise has not produced a simple static function pointer to the provider.

Therefore the provider trigger is genuinely indirect/obfuscated: likely a CFF/MBA-derived `BLR`/`BR`, or a function pointer assembled at runtime. This is consistent with why a conventional xref search misses the initialization edge.

## 4. Correction: `0x358810` is XZ/liblzma loader support

The `0x358810` cluster should not currently be labelled a game-hook initializer.

At `0x358878` it passes the exact plaintext path:

```text
/system/lib64/liblzma.so
```

to `0x356FCC`, then resolves the following symbols with `0x357184`:

```text
CrcGenerateTable
Crc64GenerateTable
XzUnpacker_Construct
XzUnpacker_IsStreamWasFinished
XzUnpacker_Free
XzUnpacker_Code
```

The resolved XZ functions are stored around `0x63E260..0x63E278`. The code immediately calls `CrcGenerateTable` and `Crc64GenerateTable`, constructs an XZ unpacker, and drives decompression over a caller-supplied buffer.

The only direct caller of `0x358810` is:

```text
0x357C64
```

which lies inside the surrounding custom loader/parser machinery.

The nearby loader area also contains exact literals such as:

```text
.symtab
linker64
/system/bin/linker64
[vdso]
app_process64
/system/bin/app_process64
```

and `0x357C04` participates in ELF parsing/section handling. Together this makes the `0x356xxx..0x358xxx` area best described as custom module/ELF/symbol/decompression infrastructure, not a proven game-feature subsystem.

## 5. Best current lead into the hidden provider trigger

`Java_com_ysmteam_imgui_GLES3JNIView_init @ 0x26931C` contains a long MBA/CFF sequence with multiple indirect calls.

Relocation-applied evaluation of the first indirect call at:

```text
0x269460  blr x10
```

resolves its initial target to:

```text
0x2DB1A8
```

The next indirect call at `0x2694D0` cannot be evaluated correctly from the pristine relocated image alone because the preceding call may mutate the state/table bytes consumed by the following MBA expression. A side-effect-aware evaluator is therefore required before claiming any edge from `GLES3JNIView_init` to `0x3016AC`.

This is currently a lead, not a proven provider trigger.

## Current architecture

```text
custom module/ELF loader
  0x356FCC / 0x357184 / 0x357C04 / 0x358810
                 |
                 | supplies module/symbol infrastructure
                 v
IL2CPP provider 0x3016AC
  -> wait for target module wrapper
  -> resolve 19 IL2CPP exports
  -> populate 0x63E0C0..0x63E170
  -> return underlying module handle
                 |
                 v
IL2CPP consumer helpers
  0x3011A0  string_new trampoline
  0x3011AC  class finder/cache
  0x301474  method-pointer resolver
  0x301590  field-offset resolver
                 |
                 v
many callers in 0x25Exxx..0x268xxx and 0x274xxx..0x275xxx
```

The missing piece is the **incoming indirect edge to `0x3016AC`**. Recovering that edge is now more valuable than treating the XZ loader cluster as the engine-hook entrypoint.

## Next target

1. Build a side-effect-aware evaluator for the indirect calls in `GLES3JNIView_init` and nearby CFF routines.
2. Search for runtime-produced module-name/path objects passed as `x0` to candidate calls.
3. Confirm the exact indirect `BLR`/`BR` that lands at `0x3016AC` before assigning a lifecycle label such as `init_il2cpp` to its caller.
