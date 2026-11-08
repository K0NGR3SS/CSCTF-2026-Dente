# The Layer That Wouldn't Die

**Author:** Varenik14  
**Category:** Forensics  
Handout: [historian-image.zip](files/historian-image.zip)  
Mission: [The Layer That Wouldn't Die](https://2026.chronos-security.ro/challenges#The%20Layer%20That%20Wouldn%27t%20Die-9135)

## Solve

I followed the OCI index to the manifest and inspected its layer tarballs in order. Layer 2 introduced `etc/cascade/.sealed_marker`. Layer 3 added `etc/cascade/historian.key.sealed` while that marker was in place. Layer 4 replaced the marker, and a whiteout in layer 5 removed it from the final view.

I took the original marker bytes from layer 2 and the ciphertext from layer 3. I decoded the configuration label `build.seal` from hex and used it as the HMAC-SHA256 key. I passed the marker as raw ASCII bytes and XORed the digest against the ciphertext. The blob sizes and SHA-256 digests matched the OCI descriptors, and the result was the complete flag.

Run [solve.cjs](solve.cjs) with `node solve.cjs`.

**Flag:** `CSCTF{layer_remembers_93e33478c}`
