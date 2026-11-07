# Watchword

**Author:** K0NGR3SS

**Crypto**  
Handout: `files/watchword.zip`

## Solve

The ZIP contains three AES-128-GCM ciphertext/tag pairs under one nonce. With empty AAD and ciphertexts of 16, 15, and 13 bytes, each GHASH has one padded ciphertext block and one length block:

```text
T_i = M xor (C_i · H²) xor (L_i · H)
M = AES_K(J0)
H = AES_K(0^128)
```

The reused nonce makes `M` identical in all three equations. I subtracted the first equation from the other two in `GF(2^128)`, eliminated `H²`, and solved for `H`. The different ciphertext lengths matter because the length blocks differ. I got `H = 730426f0d054fc7539d26145168be28a` and `M = 66b18782c578d8b27ec249a6298dfeb2`. All three original tags matched when I recomputed them.

The README in the ZIP says the master order is AES-128-CTR with a zero IV and `M` as its key. Decrypting `sealed_master_order_ctr_hex` with that key produced the exact token.

**Flag:** `CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}`

Run [the solver](solve.py) with `python3 solve.py`. Crypto solvers use the handouts in `files/`; the web and pwn addresses must be your assigned instance.
