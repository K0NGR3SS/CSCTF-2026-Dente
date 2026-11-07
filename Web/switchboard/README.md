# switchboard

**Author:** K0NGR3SS

**Web**

## Solve

The public board's `/static/switchboard.js` decoded an internal controller hostname: `exch-ctl.vjod.internal`. I sent requests to my assigned instance with that value in the HTTP `Host` header. The same server then served the controller interface, which listed `/auth`, `/operators`, and `/export/trunk-key`.

`POST /auth` accepted a JSON `username` and created a signed `ctl_sid` session. I first authenticated as `supervisor`, but that still gave me `role: operator`. `/operators` showed that `EX-01` was the on-duty supervisor. Adding `"role":"supervisor"` to the authentication body was accepted without an independent check:

```http
POST /auth
Host: exch-ctl.vjod.internal
Content-Type: application/json

{"username":"EX-01","role":"supervisor"}
```

I reused the returned `ctl_sid` cookie on `GET /export/trunk-key` with the same Host header. The controller returned the trunk key.

**Flag:** `CSCTF{5ZtMNMO1Ao8A2XN284awTR7G}`

Run [the solver](solve.py) with `python3 solve.py http://<assigned-host>:<port>`. Crypto solvers use the handouts in `files/`; the web and pwn addresses must be your assigned instance.
