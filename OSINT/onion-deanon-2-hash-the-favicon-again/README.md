# Onion Deanon 2: Hash the Favicon Again

**Author:** Varenik14  
**Category:** OSINT  
Evidence: [favicon.ico](../onion-deanon-2-find-origin/files/favicon.ico)

## Solve

I saved the raw `favicon.ico` response from the DarkPigeon portal and checked that its SHA-256 matched the icon saved for Find the Origin. I computed the MD5 directly over the ICO bytes and used its hexadecimal digest as the flag body.

```sh
python -c "from pathlib import Path; import hashlib; print(hashlib.md5(Path('../onion-deanon-2-find-origin/files/favicon.ico').read_bytes()).hexdigest())"
```

**Flag:** `CSCTF{ad866421d43a616ab0e4dd089fc94b06}`
