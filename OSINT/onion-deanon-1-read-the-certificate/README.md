# Onion Deanon 1: Read the Certificate

**Author:** K0NGR3SS

**OSINT · Easy · Challenge by Covert Security**

## Solve

I opened the ParsnipLocker onion address from the ransom note in Tor Browser. From the site information panel, I opened **Secure Connection → More Information → View Certificate** and read the leaf certificate's serial number. The certificate viewer separated its hexadecimal bytes with colons; the challenge wanted the same bytes in uppercase with the separators removed.

## Why it works

The serial comes from the certificate presented by the named service, rather than from the page text or a certificate for a Tor relay.

## Validation

I checked the serial byte order and formatting against the viewer before submitting. The answer was accepted by the challenge platform.
