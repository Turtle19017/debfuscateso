# Address map

This map is for the currently analyzed ARM64 sample of `libysmteam.so`.
Addresses are sample-specific unless stated otherwise.

## Outer ELF

| Item | Address / range | Notes |
|---|---:|---|
| `.text` | `0xA90A0` | normal/protector code |
| constructor | `0xA90AC` | enters the outer decrypt path |
| outer decrypt driver | `0xC7384` | reads `.ced`, changes page protection and decrypts `.main` |
| `.main` | `0xFBBAC..0xFE22B` | encrypted on disk, `0x2680` bytes |
| `JNI_OnLoad` | `0xFD214` | readable after outer `.main` decryption |
| VM dispatcher | `0xFBE94` | dispatches opcodes `0x00..0x29` |
| extra RX segment VA | `0xD73000` | VM trampolines, records and bytecode |
| extra RX segment file offset | `0x71E000` | sample file mapping |

Outer `.main` RC4 key recovered for this sample:

```text
baa707fe71ef4dc2240c15c0b2d907da
```

## Virtualized functions

| Protected function | Record | VM bytecode | Size |
|---:|---:|---:|---:|
| `0xFD55C` | `0xD736EC` | `0xD73794` | `0x827` |
| `0xFDDC4` | `0xD73708` | `0xD73FBC` | `0x21D` |
| `0xFD3E4` | `0xD73724` | `0xD741DC` | `0x5FB` |
| `0xFD33C` | `0xD73740` | `0xD747D8` | `0x227` |
| `0xFD7C4` | `0xD7375C` | `0xD74A00` | `0x7B6` |
| `0xFDFFC` | `0xD73778` | `0xD751B8` | `0x83C` |

A record is consistent with the shape:

```c
struct VMRecord {
    void *self;
    void *protected_function;
    uint32_t type;            // observed: 3
    uint32_t bytecode_length;
    uint32_t bytecode_offset;
};
```

## Inner unpack path

The inner stage seen while following the VM-protected loader is:

```text
small encrypted/pre-transform stage
        + large ciphertext stage
                  |
                  v
              ChaCha20
                  |
                  v
          uint32_le size
          zlib stream
                  |
                  v
       inner memory image
```

Recovered ChaCha20 parameters for the sample:

```text
key     = 5ced6a2489e3a61b72779a91e7ed5ab0
          ba7f446c8293e4787c91cb206d6a749d
nonce   = 1192c5524733ab4a89007731
counter = 1
```

Observed inflated inner image size:

```text
5,439,600 bytes = 0x530070
```

The inflated image is a loader-oriented memory image rather than a standalone ELF file with its original header intact.

## Inner image research offsets

These are offsets inside the extracted `0x530070`-byte inner image, not outer SO virtual addresses.

| Item | Inner offset |
|---|---:|
| start of clean ARM64 code region observed | `0x25E2E0` |
| custom menu-renderer region | `0x27CAEC` |
| ImGui key `InputText` call | `0x27CFFC` |
| Paste Key button | `0x27D490` |
| Login button | `0x27DBE8` |
| auto-login worker | `0x2948DC` |
| manual-login worker | `0x29527C` |
| auth core | `0x298B94` |

Recovered runtime globals from the same image analysis:

```text
0x5390F8  Save Key flag
0x5390F9  Auto Login flag
0x539100  saved-key std::string
0x53912C  key input buffer (256 bytes)
0x5392A0  auth-busy state
0x537730  status/error string object
```

These runtime addresses are based on the reconstructed in-memory layout and should not be confused with raw offsets in the original outer SO.
