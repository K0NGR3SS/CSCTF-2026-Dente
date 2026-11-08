# Carrier Shadow

**Author:** kiriesh

**Rev**
Handout: `files/carrier-shadow`

## Solve

`carrier-shadow` is a stripped x86-64 ELF that presents itself as "hexkit 1.2.0", a hex/checksum utility. The payload isn't in any data section — it's encoded in the **distances between function start addresses**. The binary has ~24 800 tiny functions whose addresses come from the lookup table in `.eh_frame_hdr`; each gap between consecutive functions encodes one symbol, so the function sizes still look natural.

The decoder (function `0x995e0`) works like this:
1. **Sync marker.** An xorshift32 generator seeded `0x6a2b3c4d` produces 8 values of the form `x % 61 + 34`. The decoder scans for 8 consecutive gaps equal to those values (found at gap 123).
2. **Header.** The next 6 gaps, minus 2, give mode (0 → length-table at `0x9b340`), length (17733 bytes) and an XOR checksum (`0x74`).
3. **Data.** Each following gap minus 2 is a symbol 0–255; its canonical Huffman code (from the length table) is appended to a bitstream.
4. The bytes are XORed with the xorshift stream, yielding raw DEFLATE. Inflating gives a second-stage ELF (34192 bytes).

The stage-2 ELF prints `operation-dawn authorization = %s` and substitutes the flag, which sits in its `.rodata`. Everything is static — nothing is executed.

**Flag:** `CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}`

Run [the solver](solve.py) with `python3 solve.py files/carrier-shadow stage2.elf`; it extracts the stage-2 ELF and prints the flag from its strings.
