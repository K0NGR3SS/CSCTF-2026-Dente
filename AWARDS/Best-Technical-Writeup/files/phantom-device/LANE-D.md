# LANE D — live end-to-end chain for 9164 "Phantom Device"

Status: **all exploit primitives verified on the live instance; final `.data` image
write is blocked by a hard receive-path limit (documented below). No flag obtained.**
`work/9164_flag.txt` is intentionally absent — nothing was fabricated.

Instance used: `w01.ctf.chronos-security.ro` (ports 41944 / 41995, requested with
`python3 ../wave2/container.py request 9164`). Never stop the container.

## 1. What is proven on the live box

| Primitive | Evidence |
|---|---|
| libc leak | reply `DATA`, `entire=0x29 this=0x29`, body `'A'` to the first `FILE_OPEN`. Client echoes handle `'A'+7 stale bytes`; `(h & ~0xff) | 0x20` is 16-page aligned and `- 0x2042f0`... base passes `libc & 0xfff == 0`, `libc >> 48 == 0`. Same value on every run of a container. |
| heap page `P` | short reply to the 2nd `FILE_OPEN` (`entire=0x50 this=0x29`, body 1 byte). Handle = safe-linked `fd`; `fd>>12` solves the 12-bit recurrence (`solve_heap_page`), unique page found, `expect fd==leak masked=True`. |
| heap layout | `0x970` offset check passes live → the 3-NUL `FILE_INFO` parse produces `X | list | str3 | str2 | str1` exactly as planned. |
| tcache poison returns a libc address | run with `A1_OVERRIDE=0x414141414141`: client dies at `close#2` (no `[13]` request). With `A1 = libc+0x2042f0` the client survives `free(A1)` and does send `[13]` → the poisoned entry really was returned and freed. |
| chain reaches `exit()` | client sends `[13]` then closes. |

## 2. The plan that works locally end-to-end (`work/solve4.py`)

`python3 solve4.py local` prints `LOCALPWN` (client stderr) via exit-time
`_IO_flush_all → _IO_wfile_overflow → _IO_wdoallocbuf → __doallocate(fp) → system(fp)`

Per-request replies (AFC, `ent/thi` include the 40-byte header; body sizes are `ent-40`):

```
 idx  request            reply ent / thi        body
  0   read_dir "/"       0x28 / 0x28            -
  1   read_dir "/DCIM"   0x418+40 / same       big_body()  (0x418, 5 tokens of 0x48 + 5 NUL)
  2   device_info        0x28 / 0x28            -
  3   file_info          0x100+40 / same       parse_body() (3 NUL, 3 tokens of 0x18)
  4   read_dir "/var"    0x28 / 0x28            -
  5   open#1             0x29 / 0x29           'A'          -> libc leak
  6   read#1             0x28 / 0x28            -
  7   open#2             0x28+40 / 1+40        'B' (1 byte) -> heap leak, client stalls 30 s
  8   read#2             0x28 / 0x28            -            (in burst)
  9   open#3             0x50 / 0x50           'C'*0x28     (in burst)
 10   read#3             0x100+40 / 0x140+40   overflow_body(fd=A1^P, size_list=0x41)
 11   close#1            0x50 / 0x50           'E'*0x28     -> pops list, head := A1
 12   close#2            0x28+40 / len(img)+40 build_image(libc, cmd)  -> malloc(A1), write
 13   close#3            0x28 / 0x28            -
```

After the client's 30 s stall at `idx 7` it is idle waiting for reply 8, so replies
8–12 are pushed in **one** `sendall()` (5416 bytes). Locally the image is buffered
whole and the FSOP fires.

Image (`solve2.build_image`, `IMG_LEN = 0x12d0`): relocated copy of libc `.data`
`[libc+0x2042f0, libc+0x2055c0)` (RELR + RELA applied), with
`_IO_list_all = libc+0x2054e0`, the fake `_IO_2_1_stderr_` at `+0x2054e0`
(cmd at FILE start, `write_base=0`, `write_ptr=1`, `_chain=0`, `_lock=libc+0x206700`,
`_wide_data=libc+0x205478`, `_mode=0`, `vtable=libc+0x203228`), a fake wide-data at
`+0x205478`, and `system` at `+0x206860`. Image ends exactly at `_IO_2_1_stdout_`
(`0x2055c0`), so the real stdout FILE is untouched and `puts("EXIT")` is safe.

## 3. Why it cannot fire on the live instance (measured)

`afc_receive_data()` (`work/vendor/afc.c:209-280`) does:

```c
dump_here = malloc(entire_len);
service_receive(client->parent, dump_here, this_len, bytes_recv);   /* ONE recv() */
if (*bytes_recv < this_len) { free(dump_here); return NOT_ENOUGH_DATA; }
```
`service_receive` = `select()` + a single `recv(fd, buf, this_len)`. It returns as soon as
**one segment** has arrived — the rest of a multi-segment body stays in flight.

Live measurement (`work/big.py`, handle echoed back in the next request):

```
SIZE=1024 -> full=True     SIZE=1150 -> full=True     SIZE=1200 -> full=False
SIZE=1280 -> full=False    SIZE=1340 -> full=True     SIZE=1400 -> full=False
SIZE=2048/4096/4816 -> full=False
```

The boundary sits at one TCP segment (head+body ≤ MSS ≈ 1.3–1.4 KB) and the results jitter
right at it, i.e. the follow-up body bytes only make it into the socket buffer when the
whole payload fits in the segment that wakes the `recv`. Anything needing two or more
segments (any body ≳1.3 KB) is lost: `close#2`'s `malloc` is a plain tcache hit, so the
gap between the header `recv` and the body `recv` is sub-microsecond — there is no window
in which the rest of a multi-segment body can arrive.

* RTT to the box ≈ 26 ms (per-request timestamps, `[9]..[13]` spaced 26 ms).
* Burst of 5416 B is delivered ~6 ms after the 40-byte reply, i.e. ~7 Mbit/s — bandwidth is
  *not* the limit; segmentation is.
* Pre-sending the image earlier does not help: the client picks it up in the same
  `recv()` only up to the first segment (measured `[10]..[13]` 10–30 µs apart).
* A "loop" write (`this_len < entire_len`, tolerant of partial reads) is bounded by
  `entire_len`, which is also the `malloc` size, so it only works for `entire_len ≤ 0x410`
  (tcache) — max 1040 B, and the target chunk must size-match that bin.

The `.data` image needs **4816 B** in one `recv()`. Scan of the whole RW segment for
chunk headers whose size field is a plausible tcache size (`size&0xf==0`, `0x20..0x410`):

```
A1=0x203a00 size=0x3d0   -> stderr 0x1ae0 away
A1=0x203b10 size=0x100   -> stderr 0x19d0 away
A1=0x2041f0 size=0x40    -> stderr 0x12f0 away
A1=0x2042f0 size=0x40    -> stderr 0x11f0 away   <-- best (image 0x12d0 = 4816 B)
```
Nothing closer exists, and a second poisoned allocation is impossible: after popping the
libc target the tcache head becomes `REVEAL_PTR(*(A1))` = `0x204`/`0x60c`/`0x226`
(garbage), so `close#3` can never reach a second libc address. The chunk that gets
poisoned must also be in a bin with ≥2 entries or `tcache_get` returns NULL and the
poison is ignored.

What *is* reachable with ≤1040–1300 B at `0x2042f0` is only `mp_`, `__exit_funcs`
(`0x204680`) and the `__ctype_*` table pointers. `__exit_funcs` is not usable:
`__run_exit_handlers` in this libc contains the `PTR_DEMANGLE` sequence
(`ror rax,0x11; xor %fs:0x30`) at `0x47361/0x47450/0x47717`, so `fns[i].func.at` is
pointer-guard mangled and the guard is not leakable through the AFC handle channel.
`_IO_2_1_stdin_` (reachable via `_IO_list_all`'s chain) needs `0x6d0 = 1744 B` to cover
its vtable — still beyond the ~1 MSS limit.

## 4. Ways forward

1. **A libc build with a valid chunk header closer to `_IO_list_all`.** Any qword
   `== 0x20..0x410` (16-aligned) within ~1.3 KB below `_IO_2_1_stderr_` would make the
   whole chain work as-is: poison that address, write a compact fake FILE, done.
2. **A second poisoned allocation.** Needs another tcache bin with ≥2 entries whose head
   chunk is writable before the pop (e.g. the `/var` read_dir 0x420 chunk reached by a
   longer overflow) *plus* one extra client reply to spend on the "wasted" first pop —
   the client only issues 14 requests, so this needs a different request sequence.
3. **Loop-write hop chain.** `entire_len ≤ 0x410` gives a *reliable* multi-segment write;
   chaining three of them (0x2042f0 → 0x204700 → 0x204b00 → 0x204f00) still stops
   ~0x5e0 short of stderr, and each hop needs its own poisoned bin.
4. **Environment where a 4.8 KB body arrives in one segment** (loopback/`socat` on the
   same host, MSS ≥ 4864 or GRO coalescing the burst). The exploit as written wins there —
   this is exactly what local mode does.

## 5. Files

* `work/solve4.py` — the live/local chain with burst mode (`BURST_MODE=small` replies
  per request), `--cmd`, `A1_OVERRIDE`, `IMG_TEST=loop`.
* `work/solve2.py` — helpers: `read_request`, `reply`, `libc_image`, `build_image`,
  `big_body`, `parse_body`, `overflow_body`, `solve_heap_page`; `solve4` imports it.
* `work/big.py` — single-recv delivery probe (handle echo).
* `work/rate.py`, `work/spd2.py` — path bandwidth probes.
* `work/solve3.py` — no-stall variant; **broken by design**: with only one entry in the
  0x30 bin the count hits 0 after `close#1` and `tcache_get` returns NULL, so the poison
  is skipped (use `solve4`).
