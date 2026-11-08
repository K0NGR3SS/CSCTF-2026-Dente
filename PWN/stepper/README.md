# stepper

**Author:** Classified

**Pwn**

**Tools used**

`pwntools`; the isolated x86-64 VM for every local run.

**Approach**

The service hands you an 8-byte RWX slot, twelve times. Each round it fills the slot with NOPs,
copies up to six of your bytes to the front, and jumps in; after the slot a trampoline snapshots all
sixteen registers and returns to the host. Registers persist across steps; the slot does not. The
bytes `0f 05` (`syscall`), `0f 34` (`sysenter`) and `cd` (`int`) are rejected on input.

1. **The forbidden bytes never have to cross the wire.** The code page is executable *and* writable,
   and each step's six bytes are NOP-padded out to the eighth byte. So the last step writes `0f 05`
   into `code+6` and then runs off the end of its own instruction, through two `0x90`s, and into the
   `syscall` it has just assembled. x86 keeps self-modifying code coherent, so no cache flush is
   needed.
2. **`0x050f` is itself built arithmetically** — `mov cx, 0x0a1e` then `shr cx, 1` — because writing
   it as an immediate would put the banned bytes straight into the instruction stream.
3. **The code address comes from the code itself**: `call +0 ; pop rax` is exactly six bytes and
   yields an address on the page despite PIE, which anchors the `mov [rbx+1], cx` that plants the
   syscall bytes.
4. Steps 1–10 stage an `execve("/bin//sh", 0, 0)` across the persistent registers and the stack;
   step 11 plants `0f 05` and falls into it.

**Why it works**

A writable-and-executable slot plus a byte filter is a contradiction: the filter only inspects what
crosses the wire, while the slot lets the running code assemble anything it likes in place. The
filter is bypassed not by smuggling the bytes but by *computing* them after the check.

**The mistake that cost the most, and why it was dangerous**

The first payload used the textbook 32-bit idiom `push '//sh' ; push '/bin' ; mov rdi, rsp`. In
64-bit mode `push imm32` pushes **eight** sign-extended bytes, so the stack held `"/bin\0\0\0\0"` and
`execve` was handed the path `/bin`. It returned `ENOENT`, the slot fell through to the trampoline,
and **the service calmly printed `step done.` and offered the next step** — a failed `execve` is
indistinguishable from a payload that never ran. The obvious reading ("the self-modifying trick does
not work") was exactly the wrong one. It was caught by reasoning about the *encoding* rather than
retrying variants, then fixed by assembling the path in a register. The solver now asserts
`path == b"/bin//sh"` before sending anything, so that class of error fails loudly and offline
instead of silently on the wire.

**Validation**

The payload is checked against the six-byte length limit and the banned-byte set before a single byte
is sent, and the whole exploit was developed against the local binary in the VM — the remote was
touched only to start our own instance and to run the finished exploit. The flag is minted per
container start, and the container was not restarted between solving and handover.

**Flag:** `CSCTF{4In1zraqseqoONZX9Rr7peLO}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
