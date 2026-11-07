# Operation Dawn: The Standing Order

**Author:** K0NGR3SS

**Web**

## Solve

The field relay gave me an operator cookie shaped like `hex(message).sha1_digest`. Decoding the message showed `user=guest&role=operator`. The `/relay` page required `role=admin`.

I treated the digest as a secret-prefix SHA-1 MAC and performed a length-extension attack. A 16-byte guessed secret length worked on the first try. I appended SHA-1 glue padding and `&role=admin` to the original message, then continued SHA-1 from the original digest to make a valid MAC. The relay accepted the forged cookie and showed its command page. My script for this step is [length_extension.py](length_extension.py).

The command page exposed a node probe and the internal provisioning URL `http://127.0.0.1:9091/order`. The probe explicitly refused `127.0.0.1`, but accepted the equivalent loopback spelling `127.1`. I sent:

```text
GET /relay/probe?target=http%3A%2F%2F127.1%3A9091%2Forder
```

The probe returned the standing order.

**Flag:** `CSCTF{DxjNlJRJyq6oODcvdZV0quX0}`

Run [the solver](length_extension.py) with `python3 length_extension.py http://<assigned-host>:<port>`. Crypto solvers use the handouts in `files/`; the web and pwn addresses must be your assigned instance.
