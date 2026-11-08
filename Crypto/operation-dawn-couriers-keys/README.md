# Operation Dawn: The Courier's Keys

**Author:** Classified

**Crypto**

**Tools used**

`scapy` for the capture; Python's own `random` as the generator under test.

**Approach**

1. The handout is a single pcap. A UDP/7000 broadcast on it describes the fleet's key generation in
   full: `seed = (power_up_epoch << 16) | serial`, MT19937, two 512-bit primes with the top and
   bottom bits forced, `N = pq`, `e = 65537`. Nine units then send `REG serial=… e=… N=…`, and one
   `ORDER serial=… C=…` goes to the dispatcher.
2. **Settle the clock first.** The capture also carries DNS/HTTP noise whose `Date` header says
   2026 while the pcap frame timestamps say 2023-11-14. The frame timestamps are the capture's own
   clock and the registration times are what the seed is built from, so the header is set dressing.
   Getting that backwards costs the whole search.
3. The serial is public and in the clear. The only unknown in the seed is the unit's power-up
   second, which is a handful of seconds before its `REG` packet — roughly one second of real
   entropy.
4. Re-run `random.Random(seed).getrandbits(512)` with the documented bit-forcing for each candidate
   epoch, walking backwards from the registration time, and stop when the first prime divides `N`.
   Hit at three seconds before `REG`, in under a second of compute.
5. `q = N // p`, assert `p*q == N`, then plain RSA decrypt of the order ciphertext — textbook RSA,
   no padding.

**Why it works**

The scheme is strong in every part except the seed. A Mersenne Twister is fully determined by it,
and the seed is a public serial concatenated with a timestamp the capture itself brackets to within
a few seconds. There is no cryptanalysis here at all — the key space is simply enumerable.

**Validation**

The factorisation is asserted (`p*q == N`) before anything is decrypted, so a wrong epoch cannot
produce a plausible-looking plaintext. `solve.py` runs from the pcap alone.

**Flag:** `CSCTF{01_advance_on_the_mill_a7c3f1}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
