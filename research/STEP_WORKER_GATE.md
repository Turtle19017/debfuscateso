# Step-triggered worker and early `0x2B2D04` gates

The worker at `0x297238` is real, but its trigger and the shape of `0x2B2D04` need two important corrections.

## 1. The worker is spawned from `GLES3JNIView_step`, not `GLES3JNIView_init`

The exact spawn site is:

```asm
0x26FD24  adr x2,0x297238
0x26FD28  add x0,sp,#0x8
0x26FD2C  mov x1,xzr
0x26FD30  bl  pthread_create@plt
0x26FD38  bl  std::__ndk1::thread::detach()
```

This address lies inside:

```text
Java_com_ysmteam_imgui_GLES3JNIView_step @ 0x26FAF0
```

not the `init` export at `0x26931C`.

The spawn is also conditional. Immediately before it, `step()`:

1. calls `0x2BBE50`;
2. only enters this path when its return value is exactly `1`;
3. calls `0x2BC804` to produce a local `std::string` at `[sp+0x10]`;
4. compares that string with the persistent global `std::string` at `0x537750`;
5. assigns the new value to `0x537750` and starts the detached worker only when the value changed.

Therefore the natural shape is closer to:

```c
if (state_2BBE50() == 1) {
    std::string current = value_2BC804();
    if (current != g_last_value_537750) {
        g_last_value_537750 = current;
        std::thread(worker_297238).detach();
    }
}
```

This means the worker is **state/string-transition triggered during rendering**, not simply an unconditional one-shot child of `onSurfaceCreated()`.

## 2. `0x297238` is only a C++ thread wrapper

The entrypoint performs libc++ thread bookkeeping and calls:

```asm
0x297274  bl 0x2B2D04
```

Its return value is not consumed. The side effects of `0x2B2D04` are therefore the important part of the worker.

## 3. The first `ret` inside `0x2B2D04` is an early exit, not the end of the routine

A linear disassembly script that stops at the first `ret` reports:

```text
0x2B322C ret
```

but the flattened control flow has a valid successor at:

```text
0x2B3230
```

reached by an indirect `br` when all three early string gates are satisfied. Thus the routine must not be truncated at `0x2B322C`.

## 4. Three `std::string` gates

`0x2B2D04` first copies three process-global strings into local temporaries. Static evaluation resolves their source objects to:

```text
local #1 <- global std::string @ 0x539B18
local #2 <- global std::string @ 0x539B30
local #3 <- global std::string @ 0x539AE8
```

The obfuscated call at `0x2B2EE0` resolves to:

```text
0x2A3F5C
```

whose body is exactly a libc++ `std::string::empty()`-style check:

```asm
ldrb w8,[x0]
ldr  x9,[x0,#8]
lsr  x10,x8,#1
tst  w8,#1
csel x8,x10,x9,eq
cmp  x8,#0
cset w0,eq
ret
```

The same helper is called on all three local strings.

The recovered CFF destinations are:

```text
first string nonempty  state 0  -> 0x2B2F60
first string empty     state 3  -> 0x2B3130

second string nonempty state 5  -> 0x2B3044
second string empty    state 7  -> 0x2B3130

third string nonempty  state 32 -> 0x2B3230
third string empty     state 16 -> 0x2B3130
```

So all three strings must be nonempty to reach the later continuation. Any empty string goes to the common cleanup/early-return block beginning at `0x2B3130`.

The three calls at `0x2B319C`, `0x2B31C8`, and `0x2B31F4` resolve to the libc++ `std::string` destructor at `0x4B0928`.

## 5. The all-nonempty continuation

When all three strings are nonempty, execution reaches:

```asm
0x2B3230 ...
0x2B3234  sub x0,x29,#0x20   ; local string #1
0x2B3238  add x1,sp,#0x28    ; local string #2
0x2B3240  add x2,sp,#0x10    ; local string #3
0x2B324C  bl  0x2B3528
```

Therefore `0x2B3528` is a three-string helper called only after the nonempty gates.

Its boolean-like result feeds another CFF dispatch:

```text
helper return low bit != 0 -> state 6 -> 0x2B32CC
helper return low bit == 0 -> state 1 -> 0x2B32FC
```

`0x2B3528` is large and contains additional obfuscated calls, `time()`, string operations, and state updates. At this checkpoint it is **not yet justified to label it as the IL2CPP hook engine**. The previous label "Core Game Engine Hook @ 0x2B2D04" is therefore premature.

## Architectural correction

Current high-confidence chain:

```text
GLES3JNIView_step @ 0x26FAF0
  -> state_2BBE50() == 1
  -> value_2BC804()
  -> compare against std::string @ 0x537750
  -> value changed
  -> pthread_create(entry=0x297238)
       -> 0x2B2D04
          -> require three nonempty global std::strings
          -> 0x2B3528(string1,string2,string3)
          -> later side-effect path still under analysis
```

This worker may eventually lead into the engine/hook subsystem, but the exact edge to `0x3016AC` remains unproven.

## Reproduce

```bash
python tools/recover_step_worker_gate.py \
  ysm_inner.original_placement_v3.so \
  --strict-hash
```
