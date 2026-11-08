# Polyglot Requiem

**Author:** kiriesh

**Forensics**
Handout: `files/polyglot-requiem.zip`

## Solve

The archive is a retained `flight-telemetry-sdk` git repository. Two things hide in it.

**The build history.** `git fsck --unreachable` turns up a dangling commit `c435f88` ("build: add telemetry opt-in check"), still pointed at by `ORIG_HEAD`. It had added a `curl ... | sh` line to `build.sh` and was later rewritten out of history. I never contacted that URL — but the commit's committer timestamp, `1792061626`, is the epoch I need later.

**The dashboard asset.** `assets/telemetry_icon.png` is only 10×10 pixels yet weighs 23 KB — a polyglot. It carries:
- a `tEXt` chunk `Provenance = 0f18e37122ddbcca`;
- a ZIP appended after the `IEND` marker, holding `telemetry_cache.db` (SQLite) and `assetsignd` (an ELF x86-64).

In `telemetry_cache.db` the live `build_secrets` table only has decoy tokens, but the free space of page 2 still holds a **deleted** row (rowid 5): label `ci_provenance_seal` and a 36-byte BLOB — the ciphertext.

I disassembled `assetsignd` statically with capstone (never ran it). It takes `<provenance_tag_hex> <epoch> <infile> <outfile>` and:
1. parses the hex tag to bytes and **reverses the byte order**;
2. appends the epoch as 8 bytes little-endian;
3. takes `SHA-256` of that as a 32-byte key;
4. XORs the file with the key, repeating.

So the key is `sha256( reverse(bytes.fromhex("0f18e37122ddbcca")) + pack("<Q", 1792061626) )`, and XORing it against the deleted BLOB gives the marker. Everything was done statically — nothing from the evidence was executed or contacted.

**Flag:** `CSCTF{p0lygl0t_r3qu13m_1d0a73980738}`

Run [the solver](solve.py) with `python3 solve.py files/polyglot-requiem.zip`. It carves the polyglot and the deleted SQLite row and reproduces the decryption from the handout.
