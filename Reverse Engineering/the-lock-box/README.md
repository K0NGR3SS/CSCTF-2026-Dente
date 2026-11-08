# The Lock Box

**Author:** Varenik14  
**Category:** Reverse engineering  
Handout: [lockbox.zip](files/lockbox.zip)

## Solve

I followed the `open` handler in the stripped ELF. Its visible 33-byte check XORs the input with `0x5b` and prints a message about last week's code. The branch that prints `GATE: pass phrase accepted` instead checks a value written by an earlier startup routine. That routine handles `open` with a 44-byte phrase.

I read the `LOCKBOX1` record in `.rodata`. It stores the length, an initial state byte of `0x5b`, eight key bytes, and 44 comparison bytes. For byte `i`, the startup routine XORs the input byte with the current state, rotates left by `1 + 3*i` bits, and adds the corresponding key byte. The next state is the current state plus `i` and the encoded byte, modulo 256.

I used the comparison bytes to walk the state forward while inverting the three operations on each input byte. I ran the recovered phrase through the forward transform and matched all 44 bytes.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{06_ash_hawk_road_at_garrisoned_38318f}`
