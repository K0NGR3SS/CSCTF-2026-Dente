# Phantom Device

**Author:** mar

**Pwn** · 900 pts (hard)
Files: `files/client` (the vulnerable AFC client), `files/libc.so.6` (Ubuntu 2.39-0ubuntu8.9)

**TL;DR.** The "iOS device" is us. `libimobiledevice`'s AFC client trusts two independent
length fields in the reply header: it `malloc()`s `entire_length - 40` bytes and then `recv()`s
`this_length - 40` bytes into that buffer, with no `this <= entire` check. That is a linear heap
overflow from a single packet. A one-byte `FILE_OPEN` reply also leaves seven bytes of stale heap
in the eight-byte file handle the client hands back in the next request, which leaks both libc and
the heap page (defeating safe-linking). Two tcache-poisoning hops then write a fake
`_IO_2_1_stdin_` FILE into libc's `.data`; `exit()` flushes stdio, the fake wide vtable calls
`system(fp)`, and the command is the FILE's own first bytes.

## Solve

**Reconnaissance.** `socat TCP-LISTEN:1337,fork EXEC:"/challenge/handler.sh",stderr` runs
`timeout 60 /challenge/client` with the socket on stdin/stdout. The client duplicates stdin for
AFC and redirects its own stdout to `/dev/null`, but `stderr` is still the socket — so we can see
crash messages, and any command output has to come back over a descriptor the client actually
owns.

The client is the stock `libimobiledevice` AFC client, so we speak the *device* side of AFC. Its
request sequence is fixed and was measured on the live instance:

| # | op | request | reply we send |
| --- | --- | --- | --- |
| 0 | 3 | `READ_DIR "/"` | status |
| 1 | 3 | `READ_DIR "/DCIM"` | big listing (heap groom) |
| 2 | 11 | `GET_DEVINFO` | status |
| 3 | 10 | `GET_FILE_INFO "/etc/fstab"` | plist-ish body (heap groom) |
| 4 | 3 | `READ_DIR "/var"` | status |
| 5 | 13 | `FILE_OPEN "/etc/fstab"` | **leak** |
| 6 | 15 | `READ_FILE H1 0x1000` | status |
| 7 | 13 | `FILE_OPEN "/var/log/syslog"` | **leak** |
| 8 | 15 | `READ_FILE H2` | **overflow** |
| 9 | 13 | `FILE_OPEN "/var/log/auth.log"` | **overflow** |
| 10 | 15 | `READ_FILE H3` | **pop** |
| 11–13 | 20 | `FILE_CLOSE H1/H2/H3` | **hop 1 / pop / hop 2** |

Every reply is `CFA6LPAA` + u64 `entire_length` + u64 `this_length` + u64 `packet_num` +
u64 `operation` + body, little endian. `packet_num` must be the request's `pn + 1`; `pn + 0`
desynchronises the stream. `STATUS` is op 1 with exactly eight bytes of body (the error code);
`DATA` is op 2 with arbitrary body.

**The bug.** `afc_receive_data()` does, in essence:

```c
entire = (uint32_t)header.entire_length - 40;   /* malloc size  */
this   = (uint32_t)header.this_length   - 40;   /* recv size    */
buf = malloc(entire);
service_receive(fd, buf, this, &n);             /* ONE recv(), no this <= entire check */
if (n < this) { free(buf); return NOT_ENOUGH_DATA; }
```

`service_receive` is `select()` plus a single `recv()`. Two consequences drive the whole exploit:

1. `this > entire` is an attacker-controlled linear overflow;
2. the `recv()` returns after **one TCP segment**, so a body larger than roughly one MSS never
   lands completely. Measured live with a handle echo: 256/512/1024/1064-byte bodies arrive whole,
   1200/1400/2048/4096/4816-byte bodies come back short.

**Primitive 1 — controlled heap overflow.** Reply to the first `FILE_OPEN` with
`entire_length = 48` (a `malloc(8)`, i.e. a 0x20 chunk with 0x18 usable bytes) and
`this_length = 0x28 + 0x500`: the client writes 0x500 bytes past an 8-byte allocation. A 20-byte
body is harmless; a 0x500-byte body kills the client immediately, which proves the write is ours.
The full exploit keeps every write inside one segment instead — see the two-hop section.

**Primitive 2 — the eight-byte handle leak.** `afc_file_open()` does
`memcpy(handle, data, 8)` on the reply body without checking that the body is eight bytes long.
A one-byte `DATA` reply leaves seven bytes of whatever was in that heap chunk. The client prints
`H1=0x...` to `/dev/null`, but it also puts the same eight bytes at the start of the next
`READ_FILE` request body — so the leak channel is the *request stream*, not the output. On the
live box the handle came back as `41 b9 44 23 06 00 00 00` (`0x62344b941`): our `A` plus a heap
pointer.

**Primitive 3 — libc base and the heap page.** With the heap groomed so the eight-byte
allocation is carved from a freed chunk whose `fd` is an arena pointer, the stale bytes give
libc directly:

```
libc = ((h & ~0xff) | 0x20) - 0x204b20          # 0x204b20 = &main_arena.bins[0]
```

For the second `FILE_OPEN`, the same reply returns a safe-linked tcache `fd`
(`fd = PROTECT(chunk) ^ next`, with `PROTECT(x) = x >> 12`). The low byte is lost to our `'A'`,
but `fd >> 12 = P ^ (P >> 12)` where `P` is the heap page: iterating the 12-bit recurrence over
`0..0xfff` and keeping the candidate that satisfies the equation and lands in the heap range
recovers `P` exactly. With `P` known, `encode(target) = target ^ P` works for every later poison.

**The chain.** Two poisoned bins are needed because each bin can only be poisoned once — after the
target is popped the tcache head decodes to garbage — and because the live receive ceiling is about
1.1 KB, so the fake FILE has to be assembled in two hops. Replies are sent just-in-time (pipelining
them breaks the writes; see below). `ent`/`thi` below exclude the 40-byte header.

| # | request | reply `ent`/`thi` | body | role |
| --- | --- | --- | --- | --- |
| R0 | `read_dir "/"` | 0/0 | — | — |
| R1 | `read_dir "/DCIM"` | 0x418/0x418 | `big_body()` — 5 tokens of 0x48 | 0x60 tcache bin gets 5 entries; parse array is a 0x40 chunk |
| R2 | `get_devinfo` | 0/0 | — | — |
| R3 | `get_file_info` | 0x100/0x100 | 3 tokens of 0x27 | `X` = 0x110 chunk carved from R1's block; array + tokens are four 0x30 chunks |
| R4 | `read_dir "/var"` | 0/0 | — | — |
| R5 | `open #1` | 1/1 | `'A'` | libc leak |
| R6 | `read #1` | 0/0 | — | — |
| R7 | `open #2` | 0x58/1 | `'B'` | heap leak; the client stalls ~30 s waiting for the rest |
| R8 | `read #2` | 0x38/0x188 | overflow | from the 0x40 parse array: poison 0x60-bin head `fd = libc+0x2042f0`, forged `size = 0x41` |
| R9 | `open #3` | 0x100/0x140 | overflow | from `X` (0x110): poison 0x30-bin head `fd = libc+0x2046f0`, forged `size = 0x41` |
| R10 | `read #3` | 0x58/0x58 | `'P'*0x58` | pops the 0x60 head, frees it into the 0x40 bin → 0x60 head is now target 1 |
| R11 | `close #1` | 0x58/1024 | hop 1 | `malloc(0x58)` returns `libc+0x2042f0`; 1024-byte linear write |
| R12 | `close #2` | 0x28/0x28 | `'Q'*0x28` | pops the 0x30 head, frees it → 0x30 head is now target 2 |
| R13 | `close #3` | 0x28/960 | hop 2 | `malloc(0x28)` returns `libc+0x2046f0`; 960-byte write |

Heap offsets are stable relative to the `[heap]` base for this exact reply sequence (verified
with `/proc/<pid>/mem` locally):

```
P_X     = 0x17c0   # R3 reply buffer, 0x110 chunk
P_LIST  = 0x18d0   # R3 parse array, 0x30 chunk (0x30-bin head)
P_R1ARR = 0x1be0   # R1 parse array, 0x40 chunk (0x40-bin head)
P_STR5  = 0x1da0   # 0x60-bin head (last read_dir string)
```

**The FSOP payload.** Each hop is a faithful, relocated copy of libc's `.data` for its range
(`.rela.dyn` and `DT_RELR` applied — this libc uses packed relative relocations, and replaying only
`SHT_RELA` leaves every pointer unrelocated). Hop 1 covers `[0x2042f0, 0x2046f0)` and forges the
next chunk's size (`0x41` at `0x2046e8`) so hop 2 frees cleanly. Hop 2 covers
`[0x2046f0, 0x204ab0)` and builds the fake FILE at `_IO_2_1_stdin_ = libc+0x2048e0`:

| field | value |
| --- | --- |
| FILE + 0x00 | command string, starting `"  "` (clears `_IO_NO_WRITES`, `_IO_UNBUFFERED`, `_IO_USER_LOCK`) |
| + 0x68 `_chain` | 0 |
| + 0x88 `_lock` | `libc+0x204a88` (zeroed lock inside the hop) |
| + 0xa0 `_wide_data` | `libc+0x2049c0` |
| + 0xc0 `_mode` | 1 |
| + 0xd8 `vtable` | `libc+0x203228` (`_IO_wfile_jumps`) |
| wide + 0x18 `write_base` | 0 |
| wide + 0x20 `write_ptr` | 1 |
| wide + 0x30 `buf_base` | 0 |
| wide + 0xe0 `_wide_vtable` | `libc+0x204a10` |
| wide vtable + 0x68 `__doallocate` | `libc+0x58750` (`system`) |

`exit()` → `_IO_cleanup` → `_IO_flush_all` walks `_IO_list_all` as stderr → stdout → stdin. At
our fake stdin the wide branch is taken (`_mode > 0` and wide `write_ptr > write_base`), so
`_IO_wfile_overflow` → `_IO_wdoallocbuf` → `*(wide_vtable+0x68)(fp)` = `system(fp)`, and `fp`
points at the FILE whose first bytes are the command.

`_IO_2_1_stdin_` is not a stylistic choice: it is the last member of the flush chain, and a
960-byte write from `0x2046f0` is the only reach that fits inside the receive ceiling while still
covering a complete FILE plus wide data plus vtable. Stderr sits 0x11f0–0x12f0 bytes from the only
freeable chunks and stdout is caught between the two.

**The last gotcha: write to fd 0.** The client's AFC descriptor is fd 0; socat gives us the socket
there. `system("... >&2")` and `>&1` produce nothing on the wire (measured: a `sleep 5` delayed the
close by 5.03 s, so the shell really ran). The command is therefore:

```
"  cat /flag.txt>&0;echo __DONE__>&0"
```

**Result.** `R13 op=20 pn=14`, then the socket returns:

```
CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}
```

**Dead ends (all measured, do not re-run).**

- **One-shot 4816-byte write over stderr / `_IO_list_all`.** Requires one `recv()` to deliver the
  whole image; the live path caps at ~1.1 KB because `afc_receive_data` does a single `recv()`.
  1024/1064-byte bodies arrive; 1200+ do not. Bandwidth is not the limit (a 5416-byte burst lands
  in ~6 ms); segmentation is.
- **Pipelining the remaining replies.** Pre-queuing pop/hop/pop/hop in one `sendall` silently
  breaks the writes: a crasher variant with a wild `_lock` closed cleanly when pipelined and
  core-dumped when sent just-in-time. Each reply has to follow its request.
- **`__exit_funcs`.** `__run_exit_handlers` in this libc applies `PTR_DEMANGLE`
  (`ror rax, 0x11; xor %fs:0x30`), and the guard is not leakable through the handle channel.
  Trashing `main_arena` is survivable (all later allocations hit the tcache), but the exit-function
  list is not.
- **Rebuilding stdout as unbuffered (`_shortbuf`).** `_IO_setb` then writes `shortbuf`/`shortbuf+1`
  into stdout+0x38/0x40, which alias the fake stderr's wide `write_base`/`write_ptr` — verified in
  gdb, `_IO_wfile_overflow` skips `_IO_wdoallocbuf` and no `system()` runs.
- **A second poison after the first pop.** The tcache head becomes `REVEAL_PTR(*(target))`, i.e.
  garbage, so `close #3` cannot reach a second libc address from the same bin. The two hops need
  two independent poisoned bins, which is why R8 and R9 poison different size classes.

**Flag:** `CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}`

Run [the solver](solve.py) against a fresh instance:

```bash
NOPIPE=1 python3 solve.py remote <host> <port> -v --cmd 'cat /flag.txt>&0;echo __DONE__>&0'
```

`local` mode replays the same chain against the shipped client under the challenge loader (the
full `libdir_ubuntu/` loader set from the handout image is needed for that; remote mode only needs
`files/libc.so.6`, which is included, to build the relocated `.data` images). `exploit_local.py`
and `solve2.py` are the harness and reply builders; `--cmd` also accepts a marker command, which is
how the chain was validated locally before the live run.

*AI: Hermes (DeepSeek 4.1 Flash) assembled this writeup from the team's lane notes and packaged the
solver; every offset in it was measured on the live instance by the team, and the flag is the one
the platform accepted.*
