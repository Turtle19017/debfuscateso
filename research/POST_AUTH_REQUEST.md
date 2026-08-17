# Post-auth worker: secondary JSON request stage

The step-triggered worker path is now sufficiently resolved to correct the earlier tentative label that `0x2B2D04` / `0x2B3528` might directly be the game-engine or IL2CPP hook initializer.

This note documents the natural request/data flow only. It does not describe forging tokens, bypassing authentication, or altering verification decisions.

## Incoming path

After successful auth-core processing, the five published strings are:

```text
g[0]  message/status
g[1]  token
g[2]  expire
g[3]  original login key
g[4]  hex-encoded HWID/fingerprint
```

`GLES3JNIView_step @ 0x26FAF0` watches `g[1]` and starts detached worker `0x297238` when the token value changes. The worker calls `0x2B2D04`, which requires the following three strings to be nonempty:

```text
g[3] = key
g[4] = hwid
g[1] = token
```

The all-nonempty path calls:

```text
0x2B3528(key, hwid, token)
```

## Function argument preservation

At entry to `0x2B3528`:

```asm
0x2B3548  str x1,[sp,#0x58]      ; hwid
0x2B3554  stp x8,x2,[sp,#0x60]  ; token saved at sp+0x68
...
0x2B3594  mov x26,x0             ; key
```

Later string copies confirm the three values are consumed in that order:

```asm
0x2B3A34  mov x1,x26             ; copy key
0x2B3A40  bl  basic_string copy

0x2B3C74  ldr x1,[sp,#0x58]     ; copy hwid
0x2B3C7C  bl  basic_string copy

0x2B3EC0  ldr x1,[sp,#0x68]     ; copy token
0x2B3ECC  bl  basic_string copy
```

## Exact request field names

The function lazily initializes and decodes several short strings. All use the same XOR-`0x3f` style seen elsewhere in the sample.

The first five request keys decode exactly to:

```text
key
hwid
token
nonce
ts
```

Evidence:

```text
0x53A110 <- encoded bytes at 0x0F8340 -> "key"
0x53A120 <- encoded bytes at 0x0F77B0 -> "hwid"
0x53A130 <- encoded bytes at 0x0F8818 -> "token"
0x53A140 <- encoded bytes at 0x0F7320 -> "nonce"
0x53A150 <- immediate bytes 0x4B 0x4C 0x3F -> "ts"
```

Each key/value element is packed through repeated calls to `0x2A7ED4`, a nlohmann-JSON aggregate/initializer helper. The exact C++ template spelling is not needed to establish the data semantics: the blocks construct JSON-like key/value elements and aggregate them into a request object.

## Timestamp

`0x2B3528` calls:

```asm
0x2B3890  mov x0,xzr
0x2B3894  bl  time@plt
```

The returned timestamp is preserved and later used while building request state, matching the decoded `ts` field.

## Encryption/packaging stage

A later lazy static string decodes exactly to:

```text
Encrypt failed
```

Its initializer is reached from the `0x2B84xx` fallback area and combines:

```text
0x0F80E0: encoded "Encrypt "
0x0F7880: encoded "fail"
immediate tail: encoded "ed\0"
```

This confirms that the routine contains an encryption/packaging stage after the JSON request is assembled. The exact crypto helper and transport endpoint remain separate analysis targets.

## Correct architectural interpretation

At this checkpoint, the high-confidence chain is:

```text
auth_core
  -> publish token / expire / key / hwid / message

render loop
  -> token changed
  -> worker 0x297238
  -> 0x2B2D04
  -> require key, hwid, token nonempty
  -> 0x2B3528(key,hwid,token)
       -> build JSON request fields
          key
          hwid
          token
          nonce
          ts
       -> encryption/packaging stage
       -> transport/response handling still under analysis
```

Therefore `0x2B3528` should currently be described as a **post-auth request/transport routine**, not as the IL2CPP hook engine itself.

The previously identified polling/custom-hash IL2CPP resolver at `0x3016AC` remains a distinct downstream subsystem. Its exact incoming edge is still unproven; a reasonable next target is the successful completion path of this post-auth request.

## Next targets

1. Resolve the helper reached after JSON assembly and identify the encryption/packaging primitive.
2. Follow the network wrapper and recover the endpoint/domain descriptively.
3. Map the secondary response fields and validation sequence.
4. Trace only the natural successful continuation to determine whether and where it reaches the engine/IL2CPP initialization subsystem.
