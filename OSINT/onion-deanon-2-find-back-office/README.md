# Onion Deanon 2: Find the Back Office

**Author:** K0NGR3SS

**OSINT · Medium · Challenge by Covert Security**

## Tools used

Censys and `curl`.

## Solve

1. I reused the single origin verified in [Find the Origin](../onion-deanon-2-find-origin/README.md). Its Censys record listed HTTP on ports 80 and 8080, so there was no need to scan for a management service.
2. Port 80 served the public DarkPigeon negotiation page and identified Coop & Crumb as case `CC-0417`. Port 8080 served a page titled `DarkPigeon Admin`. Its case table included `CC-0417` and its form opened a ticket with `GET /ticket?case=<case-id>`.
3. I followed that form for the case already displayed in the table. The ticket identified Coop & Crumb and printed a decryption-key UUID. I used that UUID exactly as shown.

## Why it works

The admin service was exposed on a port already documented by the passive host record. Its own case table and form led directly to the Coop & Crumb ticket; the key came from the panel rather than a generated token or guessed path.

## Validation

The ticket showed both the expected case ID and victim name next to the decryption key. The submitted UUID was accepted by the challenge platform. All HTTP requests were reads to the single confirmed origin.
