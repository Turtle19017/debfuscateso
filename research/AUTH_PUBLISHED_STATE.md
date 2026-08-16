# Auth-core published five-string state

Static analysis of the corrected v3 inner ELF shows that `0x298B94` publishes five libc++ `std::string` objects into the contiguous global block at `0x539AD0..0x539B47`.

This note documents natural data flow only. It does not describe changing the authentication decision.

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

## `g[3]` is the original authentication input string

Both login workers call `0x298B94` with the key string object as `x0`:

```asm
manual worker 0x29527C:
0x2952BC  add x0,x19,#0x8
0x2952C0  bl  0x298B94

auto worker 0x2948DC:
0x294918  add x0,x19,#0x8
0x29491C  bl  0x298B94
```

At the entry of `0x298B94` the argument is preserved:

```asm
0x298C04  mov x23,x0
```

Before `x23` is reused, the original argument pointer is saved:

```asm
0x299480  str x23,[sp,#0x50]
```

The publication block later loads that exact pointer and assigns its string into `g[3]`:

```asm
0x29F07C  ldr x1,[sp,#0x50]
0x29F080  ... x0 = 0x539B18
0x29F08C  basic_string::operator=(x0,x1)
```

Therefore:

```text
g[3] @ 0x539B18 = copy of the login key passed into auth_core
```

This corrects the weaker earlier description that all three strings consumed by `0x2B3528` are server-provided response fields.

## `g[0]` is the auth UI status/result text

Immediately after `0x298B94` returns, both login workers call getter `0x2BC7A8`, which copies `g[0] @ 0x539AD0` into a local string. They then replace the process-global status/error string at `0x537730` with that value.

Thus `g[0]` is the auth-core-published UI status/result text used by the menu worker.

## Remaining fields

Current high-confidence roles are:

```text
g[0]  0x539AD0  auth UI status/result text
g[1]  0x539AE8  post-auth transition field; watched by GLES3JNIView_step
g[2]  0x539B00  UI-displayed string (getter 0x2BC884)
g[3]  0x539B18  original login key input
g[4]  0x539B30  auth-core-produced string; exact semantic unresolved
```

Do **not** yet label `g[1]` as a token/session value merely because it triggers the render-loop worker. Its exact provenance must be traced through the `sp+0x158` dataflow. Likewise `g[4]` needs its `sp+0x198` producer mapped before assigning a protocol-field name.

## Consequence for the step-triggered worker

The natural chain is now more precise:

```text
auth_core 0x298B94
  -> publish g[0..4]

GLES3JNIView_step 0x26FAF0
  -> copy g[1] through getter 0x2BC804
  -> compare with previous value @ 0x537750
  -> on transition, spawn worker 0x297238
       -> 0x2B2D04
          -> require g[3], g[4], g[1] nonempty
          -> 0x2B3528(g[3], g[4], g[1])
```

Since `g[3]` is the original key input, `0x2B3528` receives a mixture of caller input and auth-core-produced state, not three independently recovered response fields.

## Next target

Trace the final producers of:

```text
sp+0x158 -> g[1]
sp+0x198 -> g[4]
```

and correlate them with the already recovered response fields `d`, `s`, `_n`. This should identify the exact semantic role of the render-loop transition field without guessing from control flow alone.
