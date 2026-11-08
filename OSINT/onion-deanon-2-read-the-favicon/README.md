# Onion Deanon 2: Read the Favicon

**Author:** K0NGR3SS

**OSINT · Easy · Challenge by Covert Security**

## Tools used

Tor Browser and Python.

## Solve

I opened the DarkPigeon onion portal from the task in Tor Browser and viewed its page source. The HTML declared `/favicon.ico`, so I saved that exact response. The recovered icon is kept with [Find the Origin](../onion-deanon-2-find-origin/files/favicon.ico), together with the [hash script](../onion-deanon-2-find-origin/hash_favicon.py).

Shodan's favicon method base64-encodes the raw icon with line wrapping, then computes signed MurmurHash3 x86 32-bit over those encoded bytes. The script implements that calculation without an extra package. I submitted the resulting signed integer.

## Why it works

Hashing an individual icon frame, omitting base64 line breaks, or treating the 32-bit output as unsigned would produce a different value. The input must be the complete raw favicon response.

## Validation

The saved ICO is 6,434 bytes. Its SHA-256 matched a separate local checksum, and the signed MurmurHash3 result was accepted by the challenge platform.
