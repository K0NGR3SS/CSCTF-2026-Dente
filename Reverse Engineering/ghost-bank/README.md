# Ghost Bank

**Author:** Classified

**Reverse engineering**

**Approach**

1. The bench exposes a **halted** controller over a raw debug-stub protocol. The controller never
   executes — so the firmware image is not code to run but a *specification to replay*. We perform its
   device-register sequence ourselves and do its cryptography offline.
2. The 956-byte AArch64 flat image was disassembled: a main loop, a `mix()` scrambler (xor constant,
   xorshift/rotate, two 64-bit multiplies — splitmix-like), a ChaCha20 block function (ten double
   rounds, the standard constant string), and a nonce with the counter starting at 1.
3. `mix()` was reimplemented in Python and **verified byte-exactly against the shipped capture**
   before the live bench was touched.
4. A local mock bench was built so the client could be debugged offline; the live bench then saw only
   a handful of hand-driven requests.
5. Replay: write the unlock value, read the challenge, select the page, write the mixed key halves,
   step the control register twice. The key page then exposes the 32-byte ChaCha key.

**The wrong turn, and what fixed it**

The firmware selects page 7, so page 7 looks like the data bank — and several rounds were burned
trying key/ciphertext combinations drawn from it. **Page 7 is a decoy of random bytes.** The
ciphertext lives on page 3, found by sweeping all sixteen pages and reading the ciphertext-length
register on each: 131 on page 3, zero everywhere else. The lesson generalised and was reused: when
halted firmware is the specification, sweep every page and slot — *the one the firmware itself selects
may be the decoy*. The capture's recorded key is stale, as the brief warns; the challenge is fresh per
session, so the key is recomputed each run rather than replayed.

**Why it works**

Nothing is broken cryptographically. The firmware is a complete, readable description of the unlock
protocol, and a halted CPU cannot object to someone else performing it.

**Validation**

`mix()` reproduces the capture byte-exactly; the recovered plaintext is a well-formed tasking record
rather than a fragment. Flag from a clean `solve.py` run, never from a string read out of the files.

**Flag:** `CSCTF{cz8ZjyH2dr930NxsH1CEvlr6}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
