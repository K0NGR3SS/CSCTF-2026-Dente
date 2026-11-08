# Onion Deanon 1: Find the Origin

**Author:** K0NGR3SS

**OSINT · Medium · Challenge by Covert Security**

## Tools used

Tor Browser and Censys.

## Solve

1. I took the leaf certificate's SHA-256 fingerprint from [the previous task](../onion-deanon-1-fingerprint-the-certificate/README.md) and searched for that exact fingerprint in Censys's certificate dataset.
2. The certificate record had the same onion Common Name and serial. Its **Related Assets** tab showed three web properties and one host.
3. I opened the host record. Its port 443 TLS fingerprint matched the onion certificate exactly. The IP-based web property showed the same fingerprint. The other related web properties were hostnames, so I used the IPv4 host record for the answer.

## Why it works

The task asked for the one clear-web IPv4 presenting the same leaf certificate. Matching the certificate fingerprint on the host's current TLS service is stronger than relying on a domain name, relay address, or historical association.

## Validation

I checked the certificate record, related host record, and port 443 fingerprint against the value read in Tor Browser. The submitted IPv4 was accepted. No address range was scanned.
