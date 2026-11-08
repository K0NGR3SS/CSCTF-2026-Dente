# PoshTerm

**Author:** Classified

**Reverse engineering**

**Tools used**

`bsdtar` for extraction; static analysis only — the executable was never run, as the brief requires.

**Approach**

1. A 227 MB PE32+ whose section layout versus file size says most of it is overlay. Marker strings
   identify it as a small native host wrapping a bundled Node/JS payload. **A large "native" binary
   with a huge overlay is usually a thin shell over an embedded bundle** — comparing file size against
   the section table is the cheap test that says so in seconds.
2. The JavaScript was carved by walking outwards from the cmdlet table until the printable run ended,
   rather than guessing at a container format.
3. Every cmdlet registers through one helper; the hidden one is attached separately with a `hidden`
   flag, so the shell's own command listing never shows it. It is gated by two MD5 checks — one on an
   environment variable, one on its last argument — and then performs a chain: a Wikipedia search for
   the argument, fetch the article, find a literal marker, extract a date, convert it through a public
   Julian-date API pinned to seven decimals, and RC4-decrypt a 48-byte blob using the Julian-date
   **string** as the key.
4. **Neither MD5 gate needs to be cracked.** The seven-decimal format fixes the key shape, and a
   calendar date at midnight always yields the same fractional part, so the key space collapses to a
   few hundred thousand strings. Exactly one decrypts the blob to clean ASCII, and the plaintext is
   48 bytes — the blob's exact length, with no padding — which pins it beyond doubt.
5. The recovered date was cross-checked against the same public converter in the opposite direction.

**Why it works**

The gated arguments only select a *date*, and the date space is small. Recovering the derived key
offline is strictly cheaper than passing the checks that produce it — and it removes any dependence on
a live source the challenge has outgrown: current Wikipedia markup no longer contains the literal the
chain looks for, so the intended path would throw today.

**Planted decoys — read, never submitted**

One cmdlet returns ten fake flags and another base64-decodes an eleventh from any password. **One of
them is addressed directly to an AI assistant**; others read `N1C3_7RY_BU7_7H15_15_4_D3C0Y_FL4G`,
`570P_C0PY1NG_FL4G5_FR0M_C0MM3N75`, `GR3P_F0R_C5C7F_4LL_Y0U_W4N7`. They were logged and discarded on
sight. This challenge is the clearest justification for our standing rule: a `CSCTF{...}` string we
merely *read* is a decoy until `solve.py` produces it.

**Validation**

`solve.py` carves the blob out of the executable itself and reproduces from `dist/` alone; the 48-byte
exact-length plaintext is the confirmation that the key is right.

**Flag:** `CSCTF{4_G00D_P0W3RSH3LL_DO35_N0T_C4LL_W1K1P3D14}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
