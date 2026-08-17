# Post-auth response validation flow

This checkpoint closes the natural response-validation tail of `0x2B3528(key, hwid, token)` in the corrected v3 inner ELF.

It documents the sample's existing validation logic only. It does **not** describe bypassing nonce/freshness/status checks, forging responses, or constructing valid protocol state.

## 1. Root response object: exact fields `d` and `s`

After `0x2A9F70` returns the HTTP response, the string is adapted by `0x2CAED4` and parsed by `0x2ACDD8`.

The first two lazy key objects decode exactly to:

```text
0x53A1D8 -> "d"
0x53A1E8 -> "s"
```

The corresponding string lookups use `0x2AD220`, whose hidden-sret ABI was recovered previously:

```text
x0 = JSON object
x1 = key std::string
x2 = default std::string
x8 = destination std::string
```

The call sites are:

```text
0x2B65A8 -> lookup root["d"] -> result at sp+0x200
0x2B67A4 -> lookup root["s"] -> result at sp+0x1C0
```

Thus the outer response shape contains the exact top-level string fields `d` and `s`.

## 2. Paired `d` / `s` verification and nested `d` parsing

The validation sequence then calls:

```text
0x2B6A74 -> 0x2AD448      helper on `s`
0x2B6B24 -> 0x2AEB74      paired helper receiving `d` and `s`
```

The second helper returns a boolean-like result used by the flattened control flow. The current static evidence is sufficient to call it a paired `d`/`s` verification helper, but **not** sufficient to name its exact cryptographic/signature primitive.

The `d` string is then turned into an input range and parsed as a nested JSON document:

```text
0x2B6C48 -> 0x2AD0D0      build input adapter from `d`
0x2B6CE4 -> 0x2ACDD8      parse nested `d`
```

## 3. Exact nonce field `_n`

The lazy initializer at `0x2C537C` prepares the encoded bytes for the nested key object at `0x53A238`. The runtime XOR step yields exactly:

```text
_n
```

The lookup at:

```text
0x2B6F5C -> 0x2AD220
```

returns nested `d["_n"]` into the local string at `sp+0x120`.

The following obfuscated indirect call at `0x2B6FDC` resolves statically to:

```text
0x2AFE9C
```

`0x2AFE9C` is a libc++ `std::string` inequality-style comparator. It handles SSO and long strings, compares lengths, uses `memcmp` for long equal-length strings, and returns:

```text
0 -> strings equal
1 -> strings unequal
```

Its arguments on this path are:

```text
x0 = response nested `_n`  (sp+0x120)
x1 = request nonce         (sp+0x148)
```

Therefore this is the exact anti-replay nonce comparison.

Relocation-aware CFF evaluation gives:

```text
state 0x41  nonce equal     -> 0x2B7854
state 0x43  nonce mismatch  -> 0x2B71A0
```

The mismatch block prepares the sample's exact misspelled literal:

```text
Verification faid
```

and publishes it through the auth/result message path. This is the natural failure behavior; no branch modification is described here.

## 4. Exact freshness field `_ts` and 30-second window

On the nonce-equal path, `0x2C54C8` initializes the key object at `0x53A268`. Its decoded plaintext is exactly:

```text
_ts
```

The call at `0x2B7954` reaches `0x2B0040`, a nlohmann-style numeric field getter, and reads the nested timestamp value.

The code then calls:

```asm
0x2B79CC  ... time(NULL)
```

and computes the elapsed time between the current time and the response `_ts` value.

The MBA threshold evaluates exactly to:

```text
30 seconds (0x1E)
```

The corresponding CFF states resolve to:

```text
state 0x0E  elapsed <= 30 s  -> 0x2B7C9C
state 0x10  elapsed >  30 s  -> 0x2B7B74
```

The stale-response block again publishes `Verification faid`.

## 5. Nested `status` and `message`

After nonce and freshness validation pass, the next lazy key objects decode exactly to:

```text
0x53A298 -> "status"
0x53A2A8 -> "message"
```

The `status` lookup uses `0x2B0324`, a JSON boolean getter. Its low bit becomes the routine's eventual success result.

The first status dispatch is:

```text
state 0x20  status == true   -> 0x2B7E80
state 0x2F  status == false  -> 0x2B7ECC
```

Those blocks initialize the defaults used for the subsequent `message` lookup:

```text
0x53A2B8 -> "OK"
0x53A2C8 -> "Invalid"
```

Both paths converge and look up:

```text
nested_d["message"]
```

with the corresponding default. The resulting text is assigned to:

```text
g[0] @ 0x539AD0
```

which is the already-recovered auth/status message shown by the UI.

Therefore the natural message behavior is:

```text
status=true  -> default message "OK"
status=false -> default message "Invalid"
```

while an explicit response `message` overrides the default.

## 6. Final success publication and return value

After publishing the message, the final status dispatch evaluates to:

```text
state 0x48  status == true   -> 0x2B8158
state 0x02  status == false  -> 0x2B8190
```

At `0x2B8158`, the obfuscated destination used by the following `std::string::operator=` resolves exactly to:

```text
0x539AE8 = g[1]
```

The source is the original token argument saved by `0x2B3528` at `sp+0x68`.

Thus the success path re-publishes/reaffirms the original token:

```text
g[1] @ 0x539AE8 = original token argument
```

The failure path skips this assignment.

Cleanup eventually reaches the return block where:

```text
w0 = status & 1
```

So, after all earlier `d`/`s`, nonce and timestamp checks, `0x2B3528` naturally returns the nested response `status` boolean.

## 7. Correction: `0x53A2xx` is not feature storage

The region around `0x53A000` referenced throughout this tail is **not proven feature/config storage**.

The concrete objects resolved here are lazy key/default/error strings and initialization guards:

```text
0x53A1D8  "d"
0x53A1E8  "s"
0x53A238  "_n"
0x53A248  "Verification faid"
0x53A268  "_ts"
0x53A278  "Verification faid"
0x53A298  "status"
0x53A2A8  "message"
0x53A2B8  "OK"
0x53A2C8  "Invalid"
```

In this response tail, the meaningful process-global publications are instead:

```text
g[0] @ 0x539AD0  <- response/error message
g[1] @ 0x539AE8  <- original token, only on status=true
```

No direct feature-state publication or engine-hook initialization has been proven here.

## 8. Closed response semantics

The high-confidence natural flow is now:

```text
HTTP response string
  -> parse root JSON
  -> d = root["d"]
  -> s = root["s"]
  -> paired d/s verification
  -> parse `d` as nested JSON
  -> nested["_n"] == request nonce
       mismatch -> "Verification faid"
  -> now - nested["_ts"] <= 30 seconds
       stale -> "Verification faid"
  -> status = nested["status"]
  -> message = nested["message"]
       default "OK" / "Invalid" by status
  -> publish message to g[0]
  -> if status=true, re-publish original token to g[1]
  -> return status
```

This makes `0x2B3528` a complete secondary post-auth **request + response-validation transaction**. It still does not prove an incoming edge to the separate IL2CPP resolver at `0x3016AC`.

## 9. CFF constants used for the static evaluation

The relocation-applied evaluator used the following sample constants in this region:

```text
X21 = 0x3A0BFFBE8C453BE3
X27 = 0xA04AD19231273355
CFF = 0x9CC9447F5FF634B2
```

Known stack constants carried by `0x2B3528` include:

```text
[sp+0x70] = 6
[sp+0x78] = 20
[sp+0x80] = 47
[sp+0x88] = 98
[sp+0x90] = 99
```

All arbitrary table reads were performed from a mutable virtual image **after applying RELA writes**, including unaligned loads that overlap relocated bytes.

## Next target

The useful next target is no longer the response schema. It is the caller-side continuation after `0x2B3528`/`0x2B2D04` finishes successfully, plus independent xrefs into `0x3016AC`. The goal is to prove an actual edge into the engine/IL2CPP subsystem rather than infer one from the successful network transaction.
