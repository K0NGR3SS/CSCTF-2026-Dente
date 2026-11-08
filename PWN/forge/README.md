# forge

**Author:** Classified

**Pwn**

**Tools used**

`pwntools`; the isolated x86-64 VM for every local run.

**Approach**

The shipped source comments the intended path outright — House of Force against glibc 2.27 — and the
version is the whole point, since 2.29 added a top-chunk sanity check that kills the technique.

1. **The bug is one argument.** `read_until_nl(p + strlen(p), notes[i].size)` should have been
   `size - strlen(p)`. The append path still permits a full `size` bytes, so a note filled to the
   brim writes past its chunk. Two supporting details: the reader never NUL-terminates, so `inspect`
   runs on into whatever follows; and allocation accepts any size.
2. **Heap base.** `tcache_get` pops an entry without clearing its `next`. Allocate two 0x20 notes,
   free both, allocate again — the returned chunk still holds a pointer to the other.
3. **libc base.** A 0x500 chunk is above the tcache ceiling, so freeing it leaves `main_arena` in
   `fd`/`bk`; an 0x88 guard note stops it merging into the top chunk. Re-allocate and read them back.
4. **House of Force.** A 0x18 note filled with 0x18 bytes ends exactly at the top chunk's size field,
   so `strlen` runs into it and the append overwrites the top size with `0xff…`. `malloc` will now
   return any address.
5. **Shell.** Relocate the top chunk so the next allocation lands on the hook region, write `system`,
   then free the note holding `/bin/sh`.

**The dead end that taught the most**

Targeting `__free_hook` directly is the obvious move and it segfaults. The hook sits at an address
that is **8 mod 16**, while every chunk is 16-aligned — so the size-rounding macro places the chunk
eight bytes past the hook. This was found by printing the hook address and its remainder, not by
guessing at the crash. The fix is to aim one quadword earlier at the 16-aligned
`__after_morecore_hook` and write sixteen bytes across both. Two further dead ends cost real time:
an 0x18 guard chunk comes straight back out of the tcache instead of off the top, so it guards
nothing (hence 0x88); and sending exactly `size` bytes leaves the newline unconsumed, which the next
numeric read eats as an empty line and desynchronises the menu.

**Why it works**

House of Force turns the top chunk's size into an attacker-controlled bound, so one oversized request
relocates the top chunk to any address and the next allocation returns it.

**Validation**

Every address is leaked; nothing is guessed. The solver length-checks both leaks, asserts both bases
are page-aligned, detects the one unlucky case (a `0x0a` inside `system`'s low bytes) and retries on
a fresh connection, at most four times, never in a loop. Shell reproduced 10/10 locally before the
live instance was touched; first try remote.

**Flag:** `CSCTF{xzKJcMiqvjHPahwGA812lmvC}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
