# Multi-output config bundle and post-auth response parser

This checkpoint corrects two over-broad labels in the post-auth transport analysis. It documents natural data flow only and intentionally does not expose cryptographic key material or describe authentication bypasses.

## 1. `0x2C4C84` is a selector wrapper, not the AES-GCM engine

`0x2C4C84` returns a `std::string` through the AArch64 hidden-sret register `x8`. Before calling `0x2BF5E0`, it zero-initializes five libc++ string objects with the tiny helper at `0x2AD43C`:

```asm
0x2AD43C  stp xzr,xzr,[x0]
0x2AD440  str xzr,[x0,#0x10]
0x2AD444  ret
```

The five destinations used by `0x2C4C84` are:

```text
output[0] -> [x29-0x20]
output[1] -> [sp+0x38]
output[2] -> hidden-sret destination saved in x19
output[3] -> [sp+0x20]
output[4] -> [sp+0x08]
```

It then calls:

```asm
0x2C4EC0  sub x0,x29,#0x20
0x2C4EC4  add x1,sp,#0x38
0x2C4EC8  add x3,sp,#0x20
0x2C4ECC  add x4,sp,#0x08
0x2C4ED0  mov x2,x19
0x2C4ED4  bl  0x2BF5E0
```

Thus `0x2C4C84` specifically selects/returns **config output #2** from a five-output loader.

Three other wrappers prove the same architecture:

```text
0x2C4A10 -> passes its hidden-sret destination as x0 -> config output #0
0x2AB558 -> passes its hidden-sret destination as x1 -> config output #1
0x2C4C84 -> passes its hidden-sret destination as x2 -> config output #2
0x2BF3F8 -> passes its hidden-sret destination as x4 -> config output #4
```

There is no separate directly-called wrapper for output #3 in the currently mapped call graph.

## 2. Two config outputs are proven URLs

The wrapper at `0x2AB558` is called from the primary auth path:

```asm
0x29BCCC  bl 0x2AB558         ; hidden-sret -> [sp+0x360]
...
0x29BCD8  add x0,sp,#0x360    ; URL
0x29BCE0  add x1,sp,#0x320    ; body
0x29BCF0  bl 0x2A9F70         ; libcurl wrapper
```

Therefore:

```text
config output #1 = primary-auth transport URL
```

The post-auth path uses `0x2C4C84` in the same way:

```asm
0x2B5950  add x8,sp,#0x240
0x2B5954  bl  0x2C4C84
0x2B595C  add x0,sp,#0x240    ; URL
0x2B5960  add x1,sp,#0x2D8    ; encrypted body
0x2B5964  bl  0x2A9F70
```

Therefore:

```text
config output #2 = post-auth transport URL
```

This is stronger than describing `0x2C4C84` generically as a URL decryptor: it is a selector for one field of a larger encrypted configuration bundle.

## 3. `0x2BF5E0` is the five-output encrypted-config loader

`0x2BF5E0` receives five `std::string *` outputs in `x0..x4`. Its first repeated indirect helper resolves to `0x2BB59C`, a libc++ string-clear operation, confirming that the arguments are writable output strings rather than five ciphertext/key inputs.

The routine later executes an AES-256-GCM decrypt sequence:

```text
0x2C029C  EVP_CIPHER_CTX_new
0x2C02A4  EVP_aes_256_gcm
0x2C02BC  EVP_DecryptInit_ex      (cipher setup)
0x2C03C4  EVP_CIPHER_CTX_ctrl
0x2C049C  EVP_DecryptInit_ex      (key/IV setup)
0x2C05A4  EVP_DecryptUpdate
0x2C06A8  EVP_CIPHER_CTX_ctrl
0x2C0738  EVP_DecryptFinal_ex
0x2C0744  EVP_CIPHER_CTX_free
0x2C0874  OPENSSL_cleanse
```

Important correction: `0x2C049C` is a **second `EVP_DecryptInit_ex`**, not `EVP_DecryptFinal_ex`. The actual final authentication/decrypt check is at `0x2C0738`.

The exact config ciphertext/key material is intentionally not reproduced here. The useful architectural fact is that the routine decrypts/parses an internal bundle and publishes several string fields, two of which are independently proven to be transport URLs.

## 4. `0x2C8530` is not response decryption

The calls at `0x2B5B18` and `0x2B5EA8` target `0x2C8530`. Its complete body is only a 20-byte lazy XOR decoder:

```asm
0x2C8530  ldrb w8,[x0,#0x13]
0x2C8534  cbz  w8,0x2C8574
0x2C8538  movi v0.16b,#0x3f
...
0x2C8564  eor  v0.16b,v1.16b,v0.16b
...
0x2C8574  ret
```

The static bytes staged for these calls decode with XOR `0x3F` to the exact sample literal:

```text
Verification faid
```

(the misspelling `faid` is present in the sample).

Therefore these calls prepare a validation/error literal. They do **not** decrypt the HTTP response payload.

## 5. `0x2CAED4` is an input-adapter constructor

After transport/validation staging, `0x2B5F98` calls `0x2CAED4` with a begin/end range derived from a libc++ string:

```asm
0x2B5F8C  add x0,sp,#0xB8
0x2B5F90  add x2,x1,x8
0x2B5F98  bl  0x2CAED4
```

`0x2CAED4` allocates a small polymorphic object, stores the input begin/end pointers, and explicitly recognizes/skips an optional UTF-8 BOM (`EF BB BF`). This is characteristic of an in-memory text/JSON input adapter, not a decryption primitive.

The following call at `0x2B6024` enters `0x2ACDD8`, which consumes that adapter and additional parser/callback state. `0x2ACDD8` does contain reference-counted object management, but its role in this chain is broader parser/deserializer machinery rather than merely `shared_ptr` lifetime handling.

## Corrected post-auth response shape

The currently justified architecture is:

```text
post-auth request
  -> AES-256-GCM encrypt
  -> libcurl
  -> response string
  -> validation/error-string setup
       `Verification faid`
  -> in-memory input adapter (`0x2CAED4`)
  -> parser/deserializer (`0x2ACDD8`)
  -> field validation / success continuation (next target)
```

No response-decryption function has yet been proven at `0x2C8530` or `0x2CAED4`.

## Next target

Follow the parsed object produced after `0x2ACDD8`, recover the exact response-field lookups and natural success/failure dispatch, then trace the successful continuation to determine whether it eventually reaches the separate IL2CPP resolver at `0x3016AC`.
