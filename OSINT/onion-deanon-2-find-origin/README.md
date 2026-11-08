# Onion Deanon 2: Find the Origin

**Author:** K0NGR3SS

**OSINT · Medium · Challenge by Covert Security**

## Tools used

Tor Browser, Censys, Python, and `curl`.

## Solve

1. I opened the DarkPigeon onion portal from the first task in Tor Browser. Its HTML pointed to `/favicon.ico`, so I saved that icon without trying other paths. The recovered file is included at [files/favicon.ico](files/favicon.ico).
2. I hashed the raw icon bytes. [hash_favicon.py](hash_favicon.py) prints SHA-256 `195873a07c938f21ef8c016048230bc84861d08653e8c01ccf3620089c848dea` and the Shodan-style signed favicon hash. Shodan required a login for the favicon filter, so I used the SHA-256 in Censys:

   ```text
   host.services.endpoints.http.favicons.hash_sha256="195873a07c938f21ef8c016048230bc84861d08653e8c01ccf3620089c848dea"
   ```

3. That exact query returned one host. Censys showed the favicon match on its port 80 HTTP service. I opened only that host and checked its page title, DarkPigeon branding, and the Coop & Crumb case against the onion page.

## Why it works

The icon is a byte-for-byte fingerprint of the portal. An exact favicon match gives a candidate; the live page content ties that candidate to the specific victim portal, instead of relying on a historical or unrelated index hit.

## Validation

The Censys result count was one, the matched field was the favicon SHA-256, and the host served the same DarkPigeon negotiation page. The submitted IPv4 was accepted by the challenge platform. No address-range guessing or host scan was needed.
