# The Signet

**Author:** K0NGR3SS

**Crypto**  
Handouts: `files/case-note.txt`, `files/sealed-orders.der`

## Solve

I read the case note first. The DER bundle contains six secp256k1 ECDSA signatures, numbered 0 through 5, and an AES-GCM sealed order. The note says the signing nonces advanced by a constant stride: `k_i = k_0 + i·a (mod n)`. That turns the usual ECDSA equation into a linear one:

```text
s_i·k_0 + i·s_i·a - r_i·d = z_i  (mod n)
z_i = SHA256(exact message OCTET STRING) mod n
```

The unknowns are the first nonce `k_0`, stride `a`, and private key `d`. I parsed the DER messages and signatures, solved any three equations with modular Gaussian elimination, then checked the answer against all six equations. I also derived the public key from `d` and compared its SPKI bytes with the bundle. The recovered scalar was:

```text
79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f
```

The rest followed the note literally. I encoded `d` as 32 unsigned big-endian bytes, derived a 32-byte key with HKDF-SHA-256 using the seal salt and info `CSCTF26/TheSignet/v1/standing-order`, and decrypted the ciphertext with AES-256-GCM, its 12-byte nonce, its 16-byte tag, and empty AAD. The GCM tag verified.

**Flag:** `CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}`

Run [the solver](solve.py) with `python3 solve.py`. Crypto solvers use the handouts in `files/`; the web and pwn addresses must be your assigned instance.
