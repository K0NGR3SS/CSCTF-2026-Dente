# smuggler

**Author:** Varenik14  
**Category:** Web  
Handout: none provided — the data comes from the live portal. The reconstruction script is [solve.py](solve.py).

## Solve

The Meridian portal serves report pages at `/d/<id>`. Public packets render normally; the one controlled packet (`c2e4ba411ae39ac4`, an Operation Dawn corridor-logistics packet) is marked "Withheld" in the dashboard. But that gating is only in the dashboard JavaScript — requesting `/d/c2e4ba411ae39ac4` directly returns the full page, including a `window.__EXPORT__` object with every data part. The name is the hint: the export is "smuggled" past the logs and caches by being assembled in the browser rather than downloaded from the server.

`/assets/exporter.js` shows how the browser builds the file:

1. concatenate `parts` into one string
2. transcode it from a custom base64 `alphabet` back to the standard alphabet, then `atob` (base64-decode)
3. XOR the bytes with a keystream from `xorshift32(seed)`

The result is a ZIP. I reproduced those three steps in Python, unzipped the blob, and inside was `02-release-authorization.txt` containing the single-use authorization code:

```
Authorization code: CSCTF{47NhAcZqkC3cultvE0AF2xHi}
```

Run [solve.py](solve.py) with `python3 solve.py http://<assigned-host>:<port>` to pull the controlled page, rebuild the packet, and print the files inside.

**Flag:** `CSCTF{47NhAcZqkC3cultvE0AF2xHi}`
