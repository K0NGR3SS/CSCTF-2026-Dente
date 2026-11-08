# Ground Lock

**Author:** Classified

**Reverse engineering**

**Approach**

1. A 682 KB statically linked, stripped ELF. `main` was located by cross-referencing the program's
   own strings rather than reading through hundreds of kilobytes of static glibc.
2. The check: `argc == 2`, length exactly 24, then for each of three 8-byte little-endian blocks `k`,
   compare `f(k)` against a stored target.
3. `f` is MurmurHash3's **fmix64** with its constants inlined. Recognising it turned the task from a
   search into an inversion.
4. The parameter block in `.rodata` holds seven quadwords — two multipliers, the shift, the block
   count, then the three targets. The code indexes it as `base + 8*(i+4)`, which is what identifies
   entries 4–6 as the targets rather than assuming an order.
5. fmix64 is a bijection: `x ^= x >> 33` is its own inverse on 64 bits (the shift discards more than
   half the word, so the top 31 bits survive untouched and regenerate the rest), and both multipliers
   are odd, so each multiply inverts with a modular inverse mod 2⁶⁴.

**Why it works**

The author used an avalanche finaliser as if it were a one-way function. It is not — it is invertible
by construction, so no searching is required at all.

**Validation**

The inverted targets decode to clean ASCII little-endian (`HALCYON_`, `1B5FC6D7`, `2036689A`), which
is itself confirmation: a wrong inversion would not produce printable text in all three blocks.
`solve.py` reads the parameter block out of the binary so it reproduces from `dist/` alone, and the
result was then confirmed by running the real binary **inside the isolated VM, never on the host** —
the recovered code releases the interlock and exits 0, a wrong code is denied and exits 1.

**Note on a planted string**

The injection scanner flagged a `CSCTF{...}` format string inside the binary. It was treated as a
template, not a flag; the submitted value came from `solve.py` and was re-checked against the
binary's own check.

**Flag:** `CSCTF{HALCYON_1B5FC6D72036689A}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
