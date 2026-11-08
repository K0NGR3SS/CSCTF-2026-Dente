# Uplink Denied

**Author:** Varenik14  
**Category:** Reverse engineering  
Handout: [cau_verify](files/cau_verify)  
Mission: [Uplink Denied](https://2026.chronos-security.ro/challenges#Uplink%20Denied-9069)

## Solve

I checked the hash of `cau_verify` and disassembled the validation routine at `0x4014f0`. It checks a 24-byte reset key as three little-endian 64-bit words. Each word goes through three `x ^ (x >> 33)` steps with two odd multiplications in between. The code compares the results against constants stored at file offsets `0x159d`, `0x15bf` and `0x1608`.

I reversed the steps in reverse order. The XOR shift is its own inverse for a 64-bit word because shifting right by 33 twice discards every bit. I inverted each multiplication modulo 2^64, packed the recovered words back into ASCII, and ran the forward transform on all three words to confirm they matched the verifier constants.

Run [solve.cjs](solve.cjs) with `node solve.cjs` to reproduce the recovery and forward check.

**Flag:** `CSCTF{cau_reset_09ff4472cbe8e0}`
