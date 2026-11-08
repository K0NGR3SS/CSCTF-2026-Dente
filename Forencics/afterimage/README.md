# Afterimage

**Author:** kiriesh

**Forensics**
Handout: `files/relay-capture.png`

## Solve

`relay-capture.png` is a cropped screenshot, 520×340, ending on its `IEND` chunk at byte 14263 — but the file is 26174 bytes long. The extra ~12 KB after `IEND` are leftover `IDAT` chunks from the *original, taller* image: a textbook **aCropalypse** (CVE-2023-21036). The editor rewrote the screenshot in place and truncated the visible image without shrinking the file, so the bottom of the pre-crop frame is still sitting in the tail. The on-screen note "recovery panel retained in prior frame" is the hint.

To rebuild it:
1. Concatenate the `IDAT` payloads that follow `IEND`.
2. The deflate stream starts mid-block, so brute-force a bit offset until a block decodes, inflating with a zero dictionary in place of the missing earlier 32 KB (`zlib.decompressobj(wbits=-15, zdict=b"\0"*32768)`).
3. Split the result into 520-pixel rows counting from the end, undo the PNG filters, and write a fresh PNG.

The recovered strip shows "RELAY RECOVERY KEY — ROTATE AFTER USE", the flag, and "relay BR-7 / emergency key custody". The flag is a lowercase hex string, so no `1`/`l` or `0`/`O` ambiguity.

**Flag:** `CSCTF{6f86acdd1d10e0d8a5a541bb}`

Run [the solver](solve.py) with `python3 solve.py files/relay-capture.png recovered.png`, then read the flag off `recovered.png`.
