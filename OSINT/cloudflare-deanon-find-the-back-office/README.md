# Cloudflare Deanon: Find the Back Office

**Author:** K0NGR3SS

**OSINT · Medium · Challenge by Covert Security**

## Tools used

FOFA, Shodan, and a browser.

## Solve

1. I started from the unique NestEgg Capital origin established in [Find the Origin](../cloudflare-deanon-find-the-origin/README.md). The earlier FOFA result and a direct page check had separated it from the Cloudflare edge.
2. Shodan's passive record for that one IPv4 showed an HTTP service on port 8080 titled `NestEgg CRM | Backend`.
3. I opened the root of that already identified service once. The page heading identified the NestEgg CRM backend and displayed a hot-wallet admin key. I submitted the key verbatim.

## Why it works

The backend was served by the confirmed origin on a port shown by the passive host record. Reading the page directly tied the displayed key to the simulated NestEgg backend; no address or key candidates were generated.

## Validation

The submitted key was accepted by the challenge platform. I did not scan ports or enumerate paths.
