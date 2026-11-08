# Onion Deanon 1: Find the Back Office

**Author:** K0NGR3SS

**OSINT · Medium · Challenge by Covert Security**

## Tools used

Censys and a browser.

## Solve

1. I reused the unique origin established in [Find the Origin](../onion-deanon-1-find-the-origin/README.md). Its Censys host record showed an HTTP service on port 8080.
2. I visited the root of that one service. The page title was `ParsnipLocker Internal Ops`, and the heading identified an internal negotiation panel.
3. The victim table contained Globex Artisanal Mayonnaise Co. and case `PL-0091`, both matching the original ransom note. The panel displayed an access-token UUID, which I submitted exactly as printed.

## Why it works

The panel was on a service already identified by the passive host record. The victim and case match tied its displayed token to this challenge, rather than to another tenant or an unrelated service.

## Validation

The submitted UUID was accepted by the challenge platform. I did not enumerate paths, scan ports, or generate candidate tokens.
