# Current reverse-engineering checkpoint

## Outer layer

- Target: Android ARM64 `libysmteam.so`
- `.main` encrypted region was identified and recovered offline.
- Constructor flow:
  - `FFAPI.load_lib()` loads the native library.
  - Constructor reads descriptor data.
  - `.main` is decrypted before the VM layer is entered.

## VM layer

Mapped virtualized functions:

- `FD55C`
- `FDDC4`
- `FD3E4`
- `FD33C`
- `FD7C4`
- `FDFFC`

The dispatcher and opcode table were reconstructed sufficiently to follow calls and object setup.

## Inner payload

The inner stage was recovered through:

```
small encrypted blob
    -> transform
    -> ChaCha20
    -> zlib
    -> extracted memory image
```

Recovered markers in the inner image:

- Dear ImGui
- ImGui OpenGL backend
- EGL/GLES imports
- Dobby hooking framework
- curl/OpenSSL dependencies
- custom login/menu implementation

## Login analysis checkpoint

Recovered high-level flow:

```
ImGui InputText
      |
      v
key buffer
      |
      v
Auth routine
      |
      +-- collect device information
      +-- create nonce
      +-- serialize request
      +-- encrypt request
      +-- network exchange
      +-- verify response nonce
```

Known response-related strings include:

- `Encrypt failed`
- `Bad response`
- `Nonce mismatch`

The next research step is mapping the request/response transport and documenting the protocol behavior.
