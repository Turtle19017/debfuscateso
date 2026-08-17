# Post-auth transport: AES-256-GCM + libcurl

This note continues the natural `0x2B3528(key, hwid, token)` path after JSON assembly. It documents static data flow and transport structure only; it does not expose secret key material, construct a valid request, or alter authentication/response validation.

## High-confidence chain

The post-auth worker is now resolved to the following architecture:

```text
0x2B3528(key, hwid, token)
  -> build JSON-like request fields
       key
       hwid
       token
       nonce
       ts
  -> serialize request
  -> 0x2A8108  encryption/packaging helper
  -> 0x2A9F70  libcurl transport helper
  -> response/validation path (next target)
```

Direct call anchors in `0x2B3528` include:

```text
0x2B5678 -> 0x2A9C4C   serialization-side helper
0x2B5728 -> 0x2A8108   encryption helper
0x2B5964 -> 0x2A9F70   transport helper
```

At the encryption call site, the serialized request is passed as input and the encrypted result is returned through the AArch64 hidden-sret register `x8`. The key-material argument is deliberately not reproduced here.

## `0x2A8108` is AES-256-GCM

The imported crypto calls are explicit:

```text
0x2A8654  RAND_bytes
0x2A8658  EVP_CIPHER_CTX_new
0x2A8660  EVP_aes_256_gcm
0x2A8678  EVP_EncryptInit_ex
0x2A8774  EVP_CIPHER_CTX_ctrl
0x2A8820  EVP_EncryptInit_ex
0x2A8AC0  EVP_EncryptUpdate
0x2A8B24  EVP_EncryptFinal_ex
0x2A8CA0  EVP_CIPHER_CTX_ctrl
0x2A8CA8  EVP_CIPHER_CTX_free
```

Concrete evaluation of the obfuscated arguments against a relocation-applied v3 image resolves the important GCM parameters:

```text
RAND_bytes length              = 12 bytes
EVP_CTRL_GCM_SET_IVLEN         = 0x09
configured IV length           = 12 bytes
EVP_CTRL_GCM_GET_TAG           = 0x10
requested authentication tag   = 16 bytes
```

The second `EVP_EncryptInit_ex` receives the supplied key material and the same 12-byte random IV generated earlier.

Therefore the cryptographic primitive is unambiguously:

```text
AES-256-GCM
random 12-byte IV
16-byte GCM authentication tag
```

The exact output-container byte ordering (for example, whether IV/tag are prefixed or suffixed to ciphertext) is not yet documented here because that layout has not been independently closed to the same confidence level.

## Relocation-aware evaluator requirement

A useful reverse-engineering correction emerged while resolving these MBA blocks: arbitrary unaligned loads must be evaluated from a byte image **after relocations have been applied**.

It is not sufficient to say that an unaligned load uses the original file bytes merely because its address is not itself an exact relocation target. An unaligned read may overlap one or more bytes written by a nearby relocation. The reliable procedure is:

```text
1. map PT_LOAD segments by virtual address;
2. apply RELA writes into a mutable runtime image;
3. perform arbitrary aligned or unaligned reads from that relocated image.
```

This is relevant to several indirect-target and option-value MBA expressions in the transport/configuration code.

## `0x2A9F70` is the libcurl request wrapper

The transport helper contains the expected libcurl lifecycle:

```text
curl_easy_init-like indirect call near 0x2AA05C
curl_easy_setopt     @ 0x4D7050
curl_slist_append    @ 0x4D7060
curl_easy_perform    @ 0x4D7070
curl_slist_free_all  @ 0x4D7080
curl_easy_cleanup    @ 0x4D7090
```

There are repeated `curl_easy_setopt` calls between `0x2AA23C` and `0x2AAED0`.

The first option has been concretely evaluated as:

```text
10002 = CURLOPT_URL
```

and its value is derived from function argument `x0`. Thus the effective transport signature is structurally:

```text
0x2A9F70(url, encrypted_body) -> response_string
```

with the response returned through hidden sret. The exact endpoint/domain is produced by the separate configuration getter `0x2C4C84 -> 0x2BF5E0` and remains under analysis.

## Exact HTTP header strings

Three string constructors immediately before the header-list append sequence decode exactly. The static fragments use XOR `0x2E` and are concatenated into:

```text
Content-Type: image/jpeg
Accept: image/jpeg
User-Agent: X-YSM-K8sN3xY
```

The constructors are:

```text
0x2C1C80 -> "Content-Type: " + "image/jpeg"
0x2C1E70 -> "Accept: "       + "image/jpeg"
0x2C201C -> "User-Agent: "   + "X-YSM-K8sN3xY"
```

They are appended to a `curl_slist` at:

```text
0x2AAD60
0x2AADD4
0x2AAE48
```

and the completed list is supplied through a later `curl_easy_setopt` before `curl_easy_perform`.

The `image/jpeg` content type is therefore protocol camouflage/typing at the HTTP layer; it does not change the fact that the body originates from the JSON -> AES-GCM path above.

## Current architecture

```text
auth_core
  -> publishes token / expire / key / HWID

GLES3JNIView_step
  -> token transition
  -> worker 0x297238
  -> 0x2B2D04
  -> 0x2B3528(key, hwid, token)
       -> JSON request
       -> serialize
       -> AES-256-GCM (12-byte IV, 16-byte tag)
       -> libcurl
          URL from 0x2C4C84 / 0x2BF5E0
          Content-Type: image/jpeg
          Accept: image/jpeg
          User-Agent: X-YSM-K8sN3xY
       -> response validation
       -> downstream success continuation not yet closed
```

This further strengthens the correction that `0x2B3528` is a post-auth network/validation stage, not the IL2CPP hook engine itself.

## Next targets

1. Recover the URL output selected by `0x2C4C84` from the five-string configuration constructor `0x2BF5E0`.
2. Resolve the remaining `curl_easy_setopt` numeric options and their values to document method/body/callback/timeout/TLS behavior.
3. Close the encryption output-container layout without exposing secret key material.
4. Follow the natural response-success continuation and test whether it eventually reaches the separate IL2CPP resolver at `0x3016AC`.
