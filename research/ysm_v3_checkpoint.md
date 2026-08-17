# ysm v3 static deobfuscation checkpoint

Sample: `ysm_inner.original_placement_v3(1).so`

- SHA-256: `5bb1dc65600331fee38e11a1815054a1b14ace93c206ce19521b42abb5560ba1`
- ELF64, little-endian, AArch64, stripped
- `.text`: `0x25e2e0..0x4d6810`
- Analysis is static/offline. The target does not need to be loaded or executed.

This checkpoint records three pieces of work: reconstruction of the IL2CPP API
resolver, semantic recovery of the managed lookup wrappers, and recovery of a
first set of lazy-decrypted managed names.

## 1. IL2CPP API resolver

`0x3016ac` is the API-table initializer. It obtains a custom linker/parser
object through `0x356fcc`, resolves plaintext export names through `0x357184`,
stores the resulting function pointers in globals around `0x63e000`, then ends
through `0x357128`.

Working semantic names:

| VA | semantic name | evidence |
|---:|---|---|
| `0x356fcc` | `custom_linker_open` | parser/open path with fallback to `dlopen`; saved real handle at object `+0x28` |
| `0x357184` | `custom_linker_sym` | ELF symbol lookup using GNU/SysV hash data and runtime symbol address calculation |
| `0x357128` | `custom_linker_free_return_handle` | frees parser object and returns saved handle |
| `0x3016ac` | `init_il2cpp_api` | resolves the 19 exports below |

Recovered table:

| global slot | export |
|---:|---|
| `0x63e0e0` | `il2cpp_assembly_get_image` |
| `0x63e0d8` | `il2cpp_domain_get` |
| `0x63e0d0` | `il2cpp_domain_get_assemblies` |
| `0x63e0e8` | `il2cpp_image_get_name` |
| `0x63e110` | `il2cpp_class_from_name` |
| `0x63e128` | `il2cpp_class_get_field_from_name` |
| `0x63e140` | `il2cpp_class_get_method_from_name` |
| `0x63e168` | `il2cpp_field_get_offset` |
| `0x63e130` | `il2cpp_field_static_get_value` |
| `0x63e138` | `il2cpp_field_static_set_value` |
| `0x63e120` | `il2cpp_array_new` |
| `0x63e170` | `il2cpp_string_chars` |
| `0x63e0c0` | `il2cpp_string_new` |
| `0x63e0c8` | `il2cpp_string_new_utf16` |
| `0x63e160` | `il2cpp_type_get_name` |
| `0x63e158` | `il2cpp_method_get_param` |
| `0x63e148` | `il2cpp_class_get_methods` |
| `0x63e150` | `il2cpp_method_get_name` |
| `0x63e118` | `il2cpp_object_new` |

No direct `B`/`BL` xref to `0x3016ac` was found in `.text`; its use is likely
indirect/constructor-driven and remains open.

## 2. Managed lookup wrappers

Three nearby wrappers now have stable semantics:

### `0x3011ac` — `find_class_cached(image, namespace, class)`

The routine enumerates domain assemblies, maps each assembly to an image,
compares `il2cpp_image_get_name()` with the requested image, calls
`il2cpp_class_from_name()`, and caches the resulting class pointer in the tree
rooted around `0x63e0f0`.

Direct xrefs: **2**, both from the method/field wrappers below.

### `0x301474` — `resolve_method_pointer(...)`

Inputs are `(image, namespace, class, method, parameter_count)`. After class
resolution it calls `il2cpp_class_get_method_from_name`; the returned
`MethodInfo*` is dereferenced at offset zero, so the wrapper returns the native
`methodPointer`, not the `MethodInfo*` itself.

Direct callsites found: **27**.

### `0x301590` — `resolve_field_offset(...)`

Inputs are `(image, namespace, class, field)`. It resolves a `FieldInfo*` via
`il2cpp_class_get_field_from_name` and returns `il2cpp_field_get_offset`.
Failure returns `-1`.

Direct callsites found: **8**.

The analyzer now follows `ADRP + ADD` constants through simple `mov Xd, Xm`
chains and invalidates volatile register constants across `BL`. This fixes the
previously missing `x3` at `0x25f944`: `x20 = 0x537a68`, followed by
`mov x3, x20` immediately before the resolver call.

## 3. Confirmed lazy-decrypted managed targets

The callsite strings live in BSS and are initialized on first use under
`__cxa_guard_*`. Their encrypted bytes come from `.rodata` and are transformed
by small XOR helpers/inline NEON XOR sequences. Only names whose initializer
and decrypt path were checked are marked as decoded.

### Method lookups

| callsite | recovered target |
|---:|---|
| `0x25ea24` | `mscorlib.dll::System.String::get_Chars/1` |
| `0x25ede0` | `UnityEngine.CoreModule.dll::UnityEngine.Transform::get_position/0` |
| `0x25f200` | `UnityEngine.CoreModule.dll::UnityEngine.Component::get_gameObject/0` |
| `0x25f944` | `Assembly-CSharp.dll::COW.GamePlay.Player::get_HeadCollider/0` |
| `0x25fad8` | `Assembly-CSharp.dll::COW.GamePlay.HPFKOGPDBBE::FOHHPOKDOND/4` |
| `0x26000c` | `UnityEngine.dll::UnityEngine.Component::get_transform/0` |
| `0x2603c0` | `UnityEngine.dll::UnityEngine.Camera::get_main/0` |
| `0x260768` | `Assembly-CSharp.dll::COW.GamePlay.Player::get_IsDieing/0` |
| `0x260b0c` | `Assembly-CSharp.dll::COW.GamePlay.Player::IsLocalTeammate/1` |

### Field-offset lookups

| callsite | recovered target |
|---:|---|
| `0x2615e8` | `Assembly-CSharp.dll::COW.GamePlay.EMKJHAJNPDH::PDBGEOANOEP` |
| `0x261768` | `Assembly-CSharp.dll::COW.GamePlay.EMKJHAJNPDH::MMECELKLHFC` |
| `0x2619e0` | `Assembly-CSharp.dll::COW.GamePlay.Player::<NNFKGNCILNK>k__BackingField` |

The last field is especially useful evidence that the plaintext recovery is
correct: its decrypted bytes form the compiler-style auto-property backing
field name exactly, including `<...>k__BackingField`.

### String-obfuscation pattern observed

The repeated family is:

1. A guard byte / C++ static guard controls one-time initialization.
2. Encrypted constants are copied from `.rodata` into a BSS buffer.
3. A flag byte marks the buffer as still encrypted.
4. On first read, code XORs one or more `q`/`d`/`s` chunks with constants from
   `.rodata`; tail bytes are often XORed with immediate constants.
5. The decrypt flag is cleared and a null terminator is written.

For 4-byte tails the compiler often emits `USHLL -> EOR v?.8b -> UZP1`. The
actual four-byte XOR key is therefore the even bytes of the loaded 8-byte key
vector. Treating the first four contiguous bytes as the key gives wrong
plaintext.

## Reproducible tooling

Generate the report:

```text
python3 tools/analyze_ysm_v3.py /path/to/ysm_inner.original_placement_v3.so \
  -o research/ysm_v3_analysis.json
```

Verify the exact current sample and recovered landmarks:

```text
python3 tools/verify_ysm_v3.py /path/to/ysm_inner.original_placement_v3.so
```

The verifier checks the sample fingerprint, all 19 IL2CPP resolver slots,
wrapper xref counts (2 / 27 / 8), MOV propagation at `0x25f944`, and the 12
currently confirmed managed targets.

## Open next steps

- Generalize the lazy-BSS string decoder instead of adding plaintext only after
  manual confirmation.
- Continue the unresolved method callsites beginning at `0x260e90` and field
  callsites beginning at `0x261e30`.
- Find the indirect initialization edge into `0x3016ac`.
- Use recovered managed names to cluster higher-level native routines before
  assigning stronger semantic names to them.
