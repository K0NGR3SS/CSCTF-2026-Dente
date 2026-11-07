# The Key Wheel

**Author:** K0NGR3SS

**Crypto**  
Handout: `files/key-unit-journal.cbor`

## Solve

I checked the attachment SHA-256 against the challenge text, then decoded the CBOR map. It has a `register` list of 1,248 consecutive 32-bit outputs, `window_opens_tx: 156`, and a standing order at transaction 155. Each transaction consumes eight output words. So the recorded window starts at output 1,248; the missing key uses outputs 1,240 through 1,247.

The register is MT19937. I untempered the first 624 outputs to get a full state block. The next 624 outputs gave me a second block to check my implementation. I reversed one MT twist from the first block, tempered the final eight words of that previous block, and got:

```text
37ea0460 e9b9d7fc 8b1c2a45 4f33e6f3
e7f2f198 313cf5d5 e8f0c5ec 480a2ab1
```

I verified that twisting the recovered previous state reproduces the first recorded block, and twisting that block reproduces the second. The journal says to concatenate the eight words as big-endian `uint32` values, then build a keystream from `SHA256(key || uint32be(i))` for `i = 0, 1, …`. XORing that stream with the standing order's `sealed` bytes gave the flag.

**Flag:** `CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}`

Run [the solver](solve.py) with `python3 solve.py`. Crypto solvers use the handouts in `files/`; the web and pwn addresses must be your assigned instance.
