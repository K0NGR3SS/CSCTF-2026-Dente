# Operation Dawn: Radio Recovery

**Author:** Classified

**Reverse engineering**

**Approach**

1. A 1 MiB flash image whose real content occupies only the first ~17 KB; the rest is `0xff` fill.
   The container format was read off the hexdump rather than guessed at: a magic (`DWFW`), a version,
   a record count, then 20-byte records of `{name, offset, size, crc32}`.
2. **Every CRC32 was verified before any part was trusted.** All four pass. That discipline is what
   made the real trap visible two steps later.
3. The root filesystem's zlib stream has `FDICT = 1`, so it needs a preset dictionary, and its 4-byte
   `DICTID` is the adler32 of that dictionary. The message catalogue's adler32 matches it exactly — so
   the catalogue **is** the dictionary. It was identified by matching the DICTID against adler32 of
   each candidate part, not by trial inflation. (That is also why the catalogue exists: a
   plausible-looking string table whose contents are the literals the archive repeats.)
4. Inflating with that dictionary yields a cpio archive. One config file holds a 60-hex-character
   admin token; one init script is the recovery routine in shell, and it is plainly
   `plain[i] = token[i] XOR mac[i mod 6]`.
5. **The actual trap: which MAC.** The U-Boot environment region holds **two** copies and **both have
   valid CRC32s**, with different `ethaddr` values. One decodes to binary garbage, the other to the
   token. The CRCs cannot disambiguate them. U-Boot's redundant-environment scheme runs whichever
   copy carries the higher flags byte — and picking "the first copy in the file" is the intended wrong
   turn.

**Why it works**

The challenge is a chain of self-describing structures in which each layer names the key to the next:
the DICTID names the dictionary, the init script names the XOR. The only genuine decision is the
redundant-environment rule, and that is documented behaviour rather than a guess.

**Validation**

Resolved from U-Boot's documented flags rule and then **confirmed empirically by decoding with both
MACs** — only the flags-7 copy produces ASCII. `solve.py` walks the whole chain from the raw image
alone.

**Flag:** `CSCTF{05_train_kestrel_d48e1f}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
