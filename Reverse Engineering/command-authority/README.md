# Command Authority

**Author:** Varenik14  
**Category:** Reverse engineering  
Handout: [command-authority-evidence.zip](files/command-authority-evidence.zip)  
Mission: [Command Authority](https://2026.chronos-security.ro/challenges#Command%20Authority-9082)

## Solve

The evidence ZIP contained `id_photo.jpg` and an encrypted `pass_bundle.zip`. I checked the bytes after the JPEG's `FF D9` end marker and found an `ARCHIVE-KEY` trailer. The value opened the inner ZIP and gave me the token and the `field_verifier` ELF.

I inspected the verifier's `command-authority` branch. It reads 31 bytes starting at file offset `0x2120` and XORs each byte with `0x41`. Applying that transform to the bytes produced the clearance value.

Run [solve.cjs](solve.cjs) with `node solve.cjs`. It recovers the archive key from the JPEG and reads the ELF as data.

**Flag:** `CSCTF{f96f4417c75121c3d27b039d}`
