# keyring

**Author:** K0NGR3SS

**Web**

## Solve

I registered a normal liaison account. The `session` cookie was a JWT with `alg: RS256` and `role: user`. The `/developers` page published the RSA verification key at `/.well-known/kestrel-id.pem` and said the token carried `sub`, `role`, `iat`, `exp`, and `jti` claims.

I changed `role` to `admin`, changed the JWT header to `alg: HS256`, and HMAC-signed the new header and payload with the **exact PEM bytes** from that public endpoint. The trailing newline mattered; stripping the PEM made the signature fail. The server accepted the forged cookie at `/admin`, so it was using the RSA public key as an HMAC secret when the token selected HS256.

The admin page printed the break-glass recovery key.

**Flag:** `CSCTF{yIM6PTMNGH830ElHpIEkrnEB}`

Run [the solver](solve.py) with `python3 solve.py http://<assigned-host>:<port>`. Crypto solvers use the handouts in `files/`; the web and pwn addresses must be your assigned instance.
