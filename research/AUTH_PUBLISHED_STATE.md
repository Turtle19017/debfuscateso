# Auth-core published five-string state

Static analysis of the corrected v3 inner ELF shows that `0x298B94` publishes five libc++ `std::string` objects into the contiguous global block at `0x539AD0..0x539B47`.

This note documents natural data flow only. It does not describe changing the authentication decision or forging protocol state.

## Global layout

The block is five consecutive 24-byte libc++ strings:

```text
g[0]  0x539AD0
g[1]  0x539AE8
g[2]  0x539B00
g[3]  0x539B18
g[4]  0x539B30
```

The common obfuscated base used by the publication block resolves to `0x539ACF`; the individual destinations are obtained by adding `+1,+0x19,+0x31,+0x49,+0x61`.

The writes use `std::__ndk1::basic_string<...>::operator=(const basic_string&) @ 0x4D6BB0`:

```asm
0x29F07C  ldr x1,[sp,#0x50]
0x29F080  add x0,x8,#0x49       ; g[3]
0x29F08C  bl  0x4D6BB0

0x29F0B0  add x0,x8,#0x61       ; g[4]
0x29F0B4  add x1,sp,#0x198
0x29F0B8  bl  0x4D6BB0

0x29F0DC  add x0,x8,#0x19       ; g[1]
0x29F0E0  add x1,sp,#0x158
0x29F0E4  bl  0x4D6BB0

0x29F118  add x0,x8,#0x31       ; g[2]
0x29F11C  add x1,sp,#0x128
0x29F120  bl  0x4D6BB0

0x29F17C  add x0,x8,#0x1        ; g[0]
0x29F180  add x1,sp,#0x360
0x29F18C  bl  0x4D6BB0
```

## Important ABI correction: `0x2AD220` uses hidden sret `x8`

`0x2AD220` is a JSON string lookup/value helper with AArch64 hidden structure-return semantics. Its effective calling convention is:

```text
x0 = JSON object
x1 = key std::string
x2 = default std::string
x8 = destination std::string (hidden sret)
```

It calls `0x2CB2D4` for object/string-key lookup and returns either the found string or a copy of the supplied default.

This matters because the earlier call at `0x29CDC8` is **not** the producer of `sp+0x158`:

```asm
0x29CDB8  add x8,sp,#0x170       ; return destination
0x29CDBC  add x0,sp,#0x100       ; JSON
0x29CDC0  add x1,sp,#0x360       ; key
0x29CDC4  add x2,sp,#0x158       ; default
0x29CDC8  bl  0x2AD220
```

Here `sp+0x158` is an input/default object. The stack slot is reused in several flattened states, so producer claims must be tied to the final success-path lifetime.

## `g[1]` is the response `token`

The final success-path assignment to `sp+0x158` occurs at `0x29E9F0`.

Lazy string initialization at `0x2B08D4`, followed by decoder `0x2A7E9C`, yields exactly:

```text
token\0
```

The call is:

```asm
0x29E9E0  add x8,sp,#0x158       ; return destination
0x29E9E4  add x0,sp,#0xD0        ; parsed JSON object
0x29E9E8  add x1,sp,#0x140       ; "token"
0x29E9EC  add x2,sp,#0x128       ; default
0x29E9F0  bl  0x2AD220
```

No later success-path assignment to `sp+0x158` occurs before publication at `0x29F0E4`; later references validate/use the value. Therefore:

```text
g[1] @ 0x539AE8 = response "token" string
```

This explains why `GLES3JNIView_step` watches `g[1]`: a token transition is the natural trigger for the later detached worker.

## `g[2]` is the response `expire`

Lazy initializer `0x2B09B4` plus the same XOR-style decoding yields:

```text
expire\0
```

At `0x29ED88`, `0x2AD220` returns the corresponding JSON string via hidden sret into `sp+0x128`, which is later published to `g[2]` at `0x29F120`.

Therefore:

```text
g[2] @ 0x539B00 = response "expire" string
```

This also matches the earlier observation that getter `0x2BC884` feeds a UI-displayed string.

## `g[0]` is response message/status text

The response-message key decodes exactly to:

```text
message\0
```

and its default value decodes to:

```text
Unknown error\0
```

Around `0x29E700`, the code calls `0x2AD220` with key `"message"`, default `"Unknown error"`, and hidden return destination `sp+0x360`.

That same `sp+0x360` object is published into `g[0]`, and both login workers subsequently copy `g[0]` into process-global status/error string `0x537730`.

Therefore:

```text
g[0] @ 0x539AD0 = response message/status text
```

## `g[3]` is the original login key

Both login workers call `0x298B94` with the key string object as `x0`:

```asm
manual worker 0x29527C:
0x2952BC  add x0,x19,#0x8
0x2952C0  bl  0x298B94

auto worker 0x2948DC:
0x294918  add x0,x19,#0x8
0x29491C  bl  0x298B94
```

At auth-core entry the argument is preserved and later saved:

```asm
0x298C04  mov x23,x0
...
0x299480  str x23,[sp,#0x50]
```

The publication block loads that exact pointer and copies it into `g[3]`:

```text
g[3] @ 0x539B18 = original login key input
```

## `g[4]` is the hex-encoded app/device fingerprint (HWID)

The source object for `sp+0x198` is built before `0x299CC8`.

The lazy 20-byte package prefix decodes to:

```text
com.dts.freefiremax\0
```

The code then reads Android properties:

```text
ro.build.id
ro.product.model
ro.product.model
```

and constructs the source string in this observed order:

```text
"com.dts.freefiremax"
+ ro.build.id
+ ro.product.model
+ ro.product.model
```

The duplicate model append is present in the sample: `__system_property_get("ro.product.model", ...)` is called at both `0x299830` and `0x2998EC`, and each result is appended.

The final source is moved into `sp+0x1B0`, then:

```asm
0x299CC0  add x8,sp,#0x198       ; hidden return destination
0x299CC4  add x0,sp,#0x1B0       ; source byte string
0x299CC8  bl  0x2A7C34
```

`0x2A7C34` constructs a string stream and loops over every source byte. For each byte it sets hexadecimal formatting, width `2`, fill character `'0'`, and inserts the byte as an integer. It then returns the stream string through hidden sret.

Thus `sp+0x198` is a fixed-width hexadecimal serialization of the app/device fingerprint, and publication gives:

```text
g[4] @ 0x539B30 = hex-encoded HWID/fingerprint string
```

This is consistent with the previously recovered request field name `hwid`.

## Other response keys observed in the same path

Additional exact decoded keys include:

```text
_n
_chk
```

`_n` participates in the nonce/anti-replay path. `_chk` is extracted and used internally during response validation. These are separate stack-object lifetimes and are not the final published `g[1]` or `g[2]` values.

## Final five-slot map

```text
g[0]  0x539AD0  response "message" (default "Unknown error")
g[1]  0x539AE8  response "token"
g[2]  0x539B00  response "expire"
g[3]  0x539B18  original login key
g[4]  0x539B30  hex-encoded app/device fingerprint (HWID)
```

## Consequence for the step-triggered worker

The natural chain is now:

```text
auth_core 0x298B94
  -> publish message/token/expire/key/hwid

GLES3JNIView_step 0x26FAF0
  -> copy token g[1] through getter 0x2BC804
  -> compare with previous token @ 0x537750
  -> on transition, spawn worker 0x297238
       -> 0x2B2D04
          -> require key, hwid, token nonempty
          -> 0x2B3528(key, hwid, token)
```

The next stage is therefore not an unidentified three-string consumer anymore. Its arguments are known exactly enough to analyze the natural post-auth request path without guessing.
