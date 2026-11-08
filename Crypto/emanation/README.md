# Emanation

**Author:** Classified

**Crypto**

**Tools used**

NumPy. The whole attack runs in under a second.

**Approach**

1. The handout is 8000 × 56 float32 synthetic power traces against 8000 × 16 known plaintexts, with
   two countermeasures the README states honestly: a random delay and one fresh byte mask per row.
2. **Profile before attacking.** Every row has exactly one sample above 15 (21.8–29.6) at an index
   uniform in 0–16, and nowhere else. That is a trigger, and its index *is* the random delay — so
   align by slicing from it, leaving 40 usable samples per row.
3. After alignment the structure falls out of per-sample statistics alone:

   | samples | mean | std | reading |
   |---|---|---|---|
   | 0 | 25.0 | 1.00 | trigger |
   | 3, 5…35 | 4.0 | 1.73 | leakage |
   | rest | 0.0 | 1.00 | noise |

   Hamming weight of a uniform byte has mean 4 and std 1.414; with N(0,1) noise that is 1.732.
   Seventeen leakage points = one mask plus sixteen masked S-box outputs.
4. First-order CPA is pointless by construction here — max |r| against HW(plaintext) was ~0.03.
   Second-order CPA on the centred product of two leakage points, correlated against the exact
   model `E_m[(HW(m)−4)(HW(Sbox(p⊕k)⊕m)−4)]`, sweeping all 136 point pairs × 16 bytes × 256 keys.
5. Every byte independently selected the pair `(3, 5+2i)` — point 3 is the mask, points 5…35 are
   bytes 0…15 in order — with r = 0.21–0.26 against a runner-up of 0.06. A 3–4× margin, no ambiguity
   anywhere.
6. Decrypt the sealed order with AES-128-CTR and an all-zero initial counter block.

**Why it works**

Masking defeats first-order correlation because the leakage of a masked value is independent of the
unmasked one. It does not defeat the *product* of the mask's leakage and the masked value's
leakage, which depends on their relationship. Choosing the exact centred-product model rather than
the usual absolute-difference heuristic is why 8000 traces were comfortably sufficient.

**Where the model earned its keep**

The trace profile — the mean/std table above — is what identified the trigger, the leakage points
and the noise floor, which made both countermeasures removable without guessing. That table was the
first artefact produced, before any attack code. It is the pattern we reused all weekend: profile
the data, then attack the structure you measured.

**Validation**

Not by eyeballing the decryption: the recovered plaintext was re-encrypted under the recovered key
and matched against the sealed order byte for byte. `solve.py` asserts that and runs from `dist/`
alone.

**Flag:** `CSCTF{relay_order_55a10bd8f06393bcc1ae8065}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
