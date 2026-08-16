# Login/authentication flow notes

This document records the static control/data flow recovered from the extracted inner image. It intentionally stops at protocol analysis and does not describe a patch that forces authentication to succeed.

## Menu side

The menu is implemented with Dear ImGui in the inner payload.

Recovered flow:

```text
InputText("##key", key_buffer, 0x100)
              |
              +-- Paste Key -> Android clipboard path
              |
              v
          Login button
              |
              v
      copy key to std::string
              |
              v
       spawn worker thread
              |
              v
           Auth(key)
```

Sample offsets in the extracted inner image:

```text
0x27CFFC  key InputText call
0x27D490  Paste Key button
0x27DBE8  Login button
0x29527C  manual-login worker
0x298B94  auth core
```

The input buffer is 256 bytes at reconstructed runtime address `0x53912C`.

## Login state

Recovered state objects/flags:

```text
0x5390F8  Save Key
0x5390F9  Auto Login
0x539100  saved key string
0x5392A0  auth busy
0x537730  status/error string
```

An additional worker at inner offset `0x2948DC` uses the saved-key path for auto-login.

The manual worker treats integer return value `1` from the auth core as success. That observation is useful for documenting control flow, not for replacing the check.

## Request construction

Recovered request-related field names include:

```text
game
key
hwid
nonce
ts
```

Device fingerprint construction reads Android properties including:

```text
ro.build.id
ro.product.model
```

The request is serialized and passed through an encryption/packaging stage before network transport.

## Response handling

Recovered strings/field names include:

```text
Encrypt failed
Bad response
Nonce mismatch

d
s
_n
```

The response nonce (`_n`) is compared against request state; a mismatch reaches the `Nonce mismatch` error path. This is consistent with an anti-replay check.

The exact semantic roles of response fields `d` and `s`, the transport endpoint, and the final response-verification sequence remain open items.

## Next analysis targets

1. Resolve the network wrapper reached by `0x298B94` and identify the transport library call chain.
2. Recover the endpoint/domain without assuming that plaintext strings survive in the image.
3. Map how `d`, `s`, and `_n` are decoded/verified.
4. Document the success-state side effects and menu state transition without altering the authentication decision.
