# echo_chamber

**Author:** Classified

**Pwn**

**Tools used**

`pwntools`; the isolated x86-64 VM for every local run; the shipped glibc 2.35.

**Approach**

Full RELRO, PIE, canary, NX. A 0x50 buffer at `rbp-0x60` is read into with 0x70 bytes, so the
overflow reaches **exactly one return address and not a byte more** — no ROP chain fits, and the
binary has only `leave; ret` and `ret`, no `pop rdi`, so `puts(got)` is unavailable too.

1. **The way in.** `printf("echo: %s\n", buf)` recomputes `buf` as `lea -0x60(%rbp), %rax` on every
   loop iteration, and `leave` is the one gadget there is. Returning into the echo branch with a
   forged `rbp` is simultaneously an arbitrary read (it prints `rbp-0x60`), an arbitrary write (the
   loop resumes with the buffer relocated), and a fresh return address.
2. **Leak the canary + stack**: send `0x59` bytes so the last overwrites the canary's own NUL and
   `%s` walks through it, yielding the canary and the saved `rbp`.
3. **Leak the PIE base**: fill through the saved rbp so `%s` runs into the return address
   (`main+0x37e`).
4. **Leak libc**: forge `rbp` so the echo branch prints `[R+0x18]`, the return address inside
   `__libc_start_call_main` (offset measured under gdb — the symbol is local and absent from the
   shipped libc's `.dynsym`).
5. **Pivot**: a final frame returns into `leave; ret` with `rbp` pointing at a relocated buffer that
   holds `pop rdi; "/bin/sh"; ret; system`.

**Why it works**

An unoptimised loop that recomputes its buffer pointer from `rbp` turns the one available epilogue
gadget into a universal read/write/pivot primitive, which is enough to leak everything and reach a
one-shot ROP into `system`.

**Validation**

Every address is leaked — nothing is guessed. Roughly 3% of runs have a `0x00` inside the canary or
saved rbp that truncates `%s`; the solver length-checks each leak, asserts both bases are page
aligned, and retries on a fresh connection, at most four times. Shell reproduced **10/10** locally
before the live instance was touched.

**Flag:** `CSCTF{oSD27pvaVCjvVt8hKJ1twgUI}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
