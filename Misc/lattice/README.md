# lattice

**Author:** Varenik14  
**Category:** Misc  
Handout: [lattice.tar.gz](files/lattice.tar.gz) (contains `lattice.py`)

## Solve

The handout is a single `lattice.py`: an 8-byte-block, 16-round ECB toy cipher with a `TARGET = encrypt(SECRET)` and, deliberately, no decrypt routine. The service (`nc HOST 9999`) wants the plaintext SECRET and returns the flag. So the whole challenge is writing the inverse.

Every round is invertible and the round structure is fully in the source:

1. even round: add the round key mod 256; odd round: xor the round key
2. substitute each byte through a key-dependent S-box (Fisher-Yates over a custom LCG — not AES)
3. pack the 8 bytes big-endian and rotate the 64-bit word left by `_rot_amount(r) = (7*r + 11) % 63 + 1`

To decrypt I run the rounds from 15 down to 0 and undo each step in reverse order: rotate right by the same amount, map bytes through the inverted S-box, then subtract (even) or xor (odd) the round key. I import `SBOX`, `RKEYS`, `TARGET` and `_rot_amount` straight from the handout so the tables always match, and I confirm the result by re-encrypting it and checking it equals `TARGET`.

The recovered secret was:

```
unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60
```

Sending that to the service returned the flag.

Run [solve.py](solve.py) with `python3 solve.py` (unpack `files/lattice.tar.gz` next to it first, or pass the path to `lattice.py`).

**Flag:** `CSCTF{oNYQkpsbjvhBKmFt7xukTOIq}`
