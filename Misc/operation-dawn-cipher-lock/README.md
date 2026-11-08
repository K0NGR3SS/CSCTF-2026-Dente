# Operation Dawn: The Cipher Lock

**Author:** kiriesh

**Misc**
Handout: `files/traces.npz`

## Solve

`traces.npz` holds three arrays:
- `traces` — 1500 power traces of 87 samples each;
- `plaintexts` — the 1500 candidate codes that were fed in, 47 bytes each;
- `sbox` — the standard AES S-box.

The flag is the 47-byte code recovered from the traces by **correlation power analysis (CPA)**.

In 47 of the 87 sample positions the mean value sits near 4 (the mean Hamming weight of a leaking byte); the rest are noise, and the 47 leaking positions are shuffled. For each of the 47 code bytes I run CPA: for every key guess `k` (0–255) model the leakage as `HW(sbox[p ^ k])` and take the Pearson correlation against every trace sample. The correct byte stands out clearly — correlation ≈ 0.30–0.37, roughly 2–3× the runner-up — and each byte leaks into its own sample. Concatenating the 47 best guesses gives the readable flag.

**Flag:** `CSCTF{12_the_depot_is_unguarded_at_noon_7d3e90}`

Run [the solver](solve.py) with `python3 solve.py files/traces.npz` (needs numpy).
