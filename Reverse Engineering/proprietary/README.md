# proprietary

**Author:** Classified

**Reverse engineering**

**Tools used**

Ghidra (headless) for the decompile; `gdb` in the isolated VM; `radare2`.

**Approach**

The handout ships a stripped Rust validator and — crucially — the checker server's source, which runs
*the same validator* and accepts on its verdict. So the challenge is entirely solvable offline; the
remote service only issues the grant. The validator reports five stages and **deliberately withholds
the reason for stages 3 to 5.**

1. **Container format.** A 16-byte header: magic, version, flags, application count, reserved,
   declared length, checksum.
2. **Integrity algorithm.** Not a CRC — a table scan (self-tested against planted known tables first)
   found none in the binary. From the decompilation:
   `h = rotl32(h,5) ⊕ byte; h *= 0x9E3779B1; h ^= h >> 15`, computed over the **whole image with
   every checksum field zeroed**. Confirmed against the shipped empty card, which hashes to its own
   stored field.
3. **Two mandatory applications**, each with an exact per-file policy the binary pins individually,
   plus a 16-byte credential payload whose qualification window must cover a specific year, whose
   clearance bit 0 must be set and whose trailing bytes must be zero.
4. **The breakthrough: the withheld reasons are still constructed in memory before being discarded.** A
   breakpoint where every formatted message converges prints the real reason. That eight-line script
   turned a blind "stage 4 of 5" into a named defect on each run — `work-order geometry mismatch`,
   then `file 2 policy mismatch`, then `token length mismatch` — and each was a one-line fix. Before
   it, 2401 blind combinations of one field and 720 of another had produced nothing.
5. **The scripted session** is obfuscated in `.rodata` under a rolling XOR (`b = b*0x49 + 0x29`).
   Decoded, it is 35 commands of six bytes each: a `u16` at `6k` carrying opcode and flags, a `u32` at
   `6k+2` carrying the argument. Its arithmetic (`2500 + 200 + 300 − 250 × 3 = 2250`) pins the card's
   starting balance — the script itself is the specification for a field we would otherwise guess.
6. **Key derivation — the part that cost the most.** The obvious reading derives both keys from the
   operator ID; that authenticates the first key and stops dead at command 12 of 35. The second key is
   in fact **chained from the first**: `key1 = cksum(key0 ‖ 0x01)`.
7. The final command makes the card return its 4-byte token and compares it against a checksum over
   the session state — so the token *is* an attestation value, read out of the validator at the
   comparison point.

**Why it works**

Nothing here is a cryptographic break. The format is a specification the binary enforces exactly, and
every "secret" is derivable from values the card itself carries. The entire difficulty is recovering
that specification from a binary engineered to refuse to explain its own rejections.

**A decoding that was plausible and wrong**

The first decode of the command script grouped the six bytes as a flat stride and produced a
believable opcode list. It was rejected because the dispatcher only ever compares against three
specific bytes, none of which appeared — and re-reading the extraction (it walks the buffer with a
`u16` pointer, not a flat stride) gave the correct split, in which the first opcode immediately lined
up with an application identifier already known from elsewhere. Internal consistency is not
correctness.

**Validation**

`solve.py` builds the card from scratch and the local validator returns `accepted, 5/5` before
anything is submitted; the clean run then obtains the grant from the team's own instance. The
container was not restarted between solving and handover.

**Flag:** `CSCTF{OVoHp5Q5WvnOjxMNXOstVFP0}`

Run the solver (`solve.py`); it takes your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
