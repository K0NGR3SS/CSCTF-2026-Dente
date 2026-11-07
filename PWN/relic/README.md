# relic

**Author:** K0NGR3SS

**Pwn**  
Handout: `files/relic.tar.gz`

## Solve

The source made the bug clear: `vault()` reads `0x120` bytes into a `0x40` stack buffer. There is no stack canary, the binary is non-PIE, and the saved return address is 72 bytes from the buffer start. `vault()` refuses a second visit, so I used its first read to install a ROP chain that calls `read()` again directly.

The binary has the old `__libc_csu_init` gadgets at `0x4012da` (six pops) and `0x4012c0` (set `rdx`, `rsi`, `edi`, then call through `[r15+rbx*8]`). I used them twice:

1. `write(1, write@GOT, 24)` leaks the resolved `write`, `alarm`, and `read` pointers. The offsets matched the supplied libc, giving its base.
2. `read(0, 0x404c00, 0x400)` places the second ROP stage high in the writable page.
3. The tail of the first chain uses `pop rbp; ret` and `leave; ret` to pivot `rsp` to `0x404c00`.
4. The second stage calls `system("/bin/sh")` from the supplied libc. I placed the pivot high in the page because `system()` needed more stack below it than my first pivot at `0x404200` left available.

Once the shell opened, `cat flag*` read the flag through `/flag -> /tmp/flag`. The script is in [exploit.py](exploit.py); change its host and port for a fresh instance.

**Flag:** `CSCTF{E84DlKS3h0kyGlqdUJVHl5UC}`

Run [the solver](exploit.py) with `python3 exploit.py <assigned-host> <port>`. Crypto solvers use the handouts in `files/`; the web and pwn addresses must be your assigned instance.
