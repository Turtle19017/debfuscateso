# Inner loader / unpack path

This note records the current high-confidence mapping from the decrypted outer `.main` code into the inner payload unpacker.

## Descriptor creation at `0xFD140`

`JNI_OnLoad` creates a local descriptor and calls `FD140(descriptor)` before entering virtualized `FD55C`.

`FD140` makes the two embedded input ranges explicit:

```text
descriptor + 0x00 = 0x4615A0
descriptor + 0x08 = 0x1010

descriptor + 0x10 = 0x4625B0
descriptor + 0x18 = 0x2A2649
```

The outer SO's second LOAD segment has `VA - file_offset = 0x10000`, therefore the corresponding file offsets are:

```text
VA 0x4615A0 -> file offset 0x4515A0, length 0x1010
VA 0x4625B0 -> file offset 0x4525B0, length 0x2A2649
```

This corrects an earlier scratch-note offset that treated these VAs as if they were raw file offsets.

## `FDDC4` loader-object flow

The VM stream for protected function `FDDC4` takes a loader/context pointer and an unpacker object.

The first native helper of interest is:

```c
bool C781C(Object *obj, void *source, size_t source_size)
{
    if (!source || !source_size)
        return false;
    obj->source = source;       // +0x08
    obj->source_size = source_size; // +0x10
    return true;
}
```

This matches the call recovered from VM code:

```text
C781C(unpacker, loader[0x00], loader[0x08])
```

The unpacker vtable located at reconstructed outer address `0x3A3EF0` has these recovered entries:

```text
+0x00 -> 0xC785C
+0x08 -> 0xC788C
+0x10 -> 0xC7840
+0x18 -> 0xFD7C4   # virtualized unpack routine
+0x20 -> 0xC7848
```

`C7848` stores a second pointer/size pair at object offsets `+0x28/+0x30`. `FDDC4` invokes the virtual methods and, after successful unpacking, propagates the produced output pointer/size back into the loader context before the custom in-memory ELF loader continues.

## PKCS#7 wrapper at `0xB1D68`

`FD7C4` calls native function `0xB1D68`. Its behavior is now mapped directly from ARM64:

```c
int decrypt_blocks(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t *output_len)
```

Observed behavior:

1. Reject null pointers.
2. Reject zero length and lengths that are not multiples of 16.
3. Allocate a temporary buffer of `input_len` bytes.
4. Process every 16-byte block with `0xB1E90`.
5. Interpret the final byte as PKCS#7 padding length.
6. Verify every padding byte.
7. Copy the unpadded result to the caller buffer.
8. Store the unpadded length in `*output_len`.
9. Return `0` on success and `-1` on failure.

This proves that `0xB1E90` is the sample's large white-box/table-driven 16-byte block transform used by the inner unpack path.

## White-box block transform at `0xB1E90`

`B1E90` is unusually large (ending at `0xB968C`) and is dominated by table lookups, nibble recombination, scalar/SIMD bit moves and repeated 256-byte table copies.

Useful anchors:

```text
entry           0xB1E90
return          0xB968C
lookup pointer  relocation 0x3A5310 -> 0x2A7390
stack guard GOT 0x3A4F60
```

The function accepts one 16-byte input block and one 16-byte output block. Reproducing this transform offline is the remaining missing piece required to turn the current ChaCha20/zlib helper into a single-command extraction directly from the original SO.

## Current full path

```text
JNI_OnLoad
   |
   +-- FD140
   |     +-- small blob: 0x4615A0 / 0x1010
   |     +-- large blob: 0x4625B0 / 0x2A2649
   |
   +-- FD55C (VM)
          |
          +-- FDDC4 (VM loader orchestration)
                 |
                 +-- C781C set source
                 +-- virtual FD7C4
                         |
                         +-- B1D68 PKCS#7 wrapper
                         |      +-- B1E90 per 16-byte block
                         |
                         +-- assemble inner ciphertext
                         +-- ChaCha20
                         +-- zlib
                         |
                         v
                   inner memory image
```

Next concrete target: reproduce `B1E90` offline and then merge the descriptor extraction, white-box stage, ChaCha20 and zlib stages into one end-to-end extractor.
