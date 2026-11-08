# sigil

**Author:** Classified

**Pwn**

**Approach**

The target is 0x100 bytes of `.text`: static, no-PIE, `-nostdlib`, no canary, three functions, with
a 60-second alarm so the whole chain must finish inside a minute. The bug is a plain stack overflow —
a 0x40 buffer read with 0x400.

1. **The author's comment says SROP. It is not needed, and the alternative is strictly easier.** The
   syscall wrapper is compiled at `-O0`, so it loads the syscall registers *from memory relative to
   `rbp`*: `rax` from `[rbp-0x18]`, `rdi` from `[rbp-0x20]`, `rsi` from `[rbp-0x28]`, `rdx` from
   `[rbp-0x30]`, then `syscall`.
2. The binary contains no `pop rdi`/`pop rsi` gadget at all — only `pop rbp; ret`. But `pop rbp` is
   exactly what this construction needs: enter the register-loading instruction with a chosen `rbp`
   and you have an arbitrary four-argument syscall. SROP would additionally require setting `rax` to
   15, i.e. a third read of exactly fifteen bytes.
3. A second useful address is the read call site inside the listening function: it also derives its
   destination from `rbp`, making it an arbitrary-write primitive, and the function's `leave; ret`
   then pivots `rsp` onto whatever `rbp` pointed at.
4. **Two reads total.** The overflow sets `rbp` into the writable page and returns into that read
   call site; the second read writes the whole plan — a fake frame, the syscall arguments and
   `/bin/sh` — into `.bss`; the second `leave; ret` pivots onto it and the wrapper's tail executes
   `execve`.

**Why it works**

An unoptimised syscall wrapper that sources its registers from the stack frame turns control of
`rbp` into control of every syscall argument. In a binary with no argument-loading gadgets, the
function epilogue *is* the gadget.

**Validation**

Local shell in the VM before any remote contact. The chain is fully deterministic — no PIE, no leaked
addresses — so there is nothing to retry.

**Flag:** `CSCTF{LovLRxkh1ALNmyfU6OdCpP6p}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
