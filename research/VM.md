# VM notes

The second protection layer virtualizes six functions reached from the decrypted outer `.main` section.

## Dispatcher

The interpreter entry is at `0xFBE94`. It reads one byte from the VM stream, masks the opcode with `0x7F`, validates it against `0x29`, indexes a signed 16-bit jump table and branches to the selected handler.

Observed opcode range:

```text
0x00 .. 0x29  (42 slots)
```

The VM keeps a stack plus a register abstraction. Register operands are encoded and mapped through a permutation table rather than being plain ARM64 register numbers.

Confirmed examples from the sample:

```text
0x0211 -> SP
0x02B9 -> PC / VM PC-base role
0x00A1 -> X0
0x00A2 -> W0
0x02F9 -> X1
0x0259 -> X2
0x0329 -> X3
0x01B1 -> X4
0x0269 -> X19
0x0071 -> X20
0x0139 -> X21
0x01A9 -> X22
0x00D9 -> X23
0x0129 -> X24
0x0089 -> X25
0x0171 -> X30
0x0231 -> XZR
```

## Instruction-length checkpoint

The following lengths were sufficient to linearly decode all six mapped streams without desynchronizing. Semantic names marked `?` are provisional.

| Opcode | Bytes | Current interpretation |
|---:|---:|---|
| `00` | 1 | stack/address mapping helper |
| `01` | 3 | pop/set virtual register variant |
| `03` | 1 | arithmetic/flag helper, unresolved |
| `07` | 5 | conditional branch variant |
| `08` | 1 | subtract |
| `09` | 1 | SP adjustment helper |
| `0D` | 1 | add |
| `0E` | 1 | bitwise NOT |
| `11` | 5 | push 32-bit immediate |
| `12` | 1 | end/return family |
| `14` | 4 | load through VM stack address |
| `15` | 1 | subtract from SP |
| `18` | 1 | pop/discard |
| `19` | 9 | push 64-bit immediate |
| `1B` | 1 | AND |
| `1C` | 5 | unconditional VM jump |
| `1D` | 4 | store through VM stack address |
| `1F` | 5 | peek/add immediate helper |
| `20` | 3 | push virtual register |
| `22` | 1 | left shift |
| `23` | 6 | ARM-condition-code-style branch |
| `24` | 5 | zero/non-zero conditional branch variant |
| `28` | 3 | second pop/set-register variant |
| `29` | 1 | indirect/native call through stack value |

Additional one-byte handlers observed but not yet assigned high-confidence semantics include the remaining opcode slots in `0x00..0x29`.

## Direct-call recovery pattern

A common sequence is:

```text
PUSH64 signed_delta
PUSH_REG PC
ADD
CALL
```

For these sequences, the native destination can be recovered from the protected-function PC base plus the signed delta. This was enough to identify calls into allocation, loader, crypto/decompression and cleanup helpers while following `FD55C`/`FD7C4`.

## Current role of the six programs

The exact class/function names are stripped, but current static behavior indicates:

- `FD55C` — high-level initialization/orchestration from `JNI_OnLoad`.
- `FDDC4` — loader/object dispatch around the recovered inner image.
- `FD3E4` / `FD33C` — object/descriptor setup helpers.
- `FD7C4` — inner unpack/decrypt/decompress path.
- `FDFFC` — additional setup/helper path used by the loader.

This file records only behavior that is useful for devirtualization. Unknown handlers should remain unknown until their stack and flag semantics are verified against multiple call sites.
