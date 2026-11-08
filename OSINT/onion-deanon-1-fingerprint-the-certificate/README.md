# Onion Deanon 1: Fingerprint the Certificate

**Author:** K0NGR3SS

**OSINT · Easy · Challenge by Covert Security**

## Solve

I used the certificate viewer for the same ParsnipLocker onion service as [Read the Certificate](../onion-deanon-1-read-the-certificate/README.md). Under **Fingerprints**, I copied the leaf certificate's SHA-256 fingerprint. I kept the viewer's uppercase hexadecimal pairs and colons, as the task specified.

## Why it works

SHA-256 fingerprints identify the exact certificate bytes. The serial from the first task helped make sure I was reading the same leaf certificate.

## Validation

The fingerprint contained 32 bytes, displayed as 32 colon-separated hex pairs. The submitted value was accepted by the challenge platform.
