# CSCTF 2026 writeups

**Team:** Dente

**Members:** K0NGR3SS, mar, Classified, kiriesh, Varenik14

Writeups for challenges the team solved. Each challenge has its own folder under its scoreboard category. Live service addresses were temporary instances; use a fresh assigned address when replaying a web or pwn solve.

| Challenge | Category | Writeup author |
| --- | --- | --- |
| [The Signet](Crypto/the-signet/README.md) | Crypto | K0NGR3SS |
| [The Key Wheel](Crypto/the-key-wheel/README.md) | Crypto | K0NGR3SS |
| [Watchword](Crypto/watchword/README.md) | Crypto | K0NGR3SS |
| [Afterimage](Forencics/afterimage/README.md) | Forensics | kiriesh |
| [Last Commit](Forencics/last-commit/README.md) | Forensics | kiriesh |
| [Operation Dawn: The Medic's Phone](Forencics/operation-dawn-medics-phone/README.md) | Forensics | kiriesh |
| [Polyglot Requiem](Forencics/polyglot-requiem/README.md) | Forensics | kiriesh |
| [Shadow-Dispatch](Forencics/shadow-dispatch/README.md) | Forensics | kiriesh |
| [golem](Misc/golem/README.md) | Misc | K0NGR3SS |
| [Operation Dawn: The Cipher Lock](Misc/operation-dawn-cipher-lock/README.md) | Misc | kiriesh |
| [Operation Dawn: The Sentry's Model](ML/operation-dawn-sentrys-model/README.md) | ML | kiriesh |
| [Water Hammer Reconciliation](Network/water-hammer-reconciliation/README.md) | Network | kiriesh |
| [Onion Deanon 2: Find the Back Office](OSINT/onion-deanon-2-find-back-office/README.md) | OSINT | K0NGR3SS |
| [Onion Deanon 2: Find the Origin](OSINT/onion-deanon-2-find-origin/README.md) | OSINT | K0NGR3SS |
| [relic](PWN/relic/README.md) | PWN | K0NGR3SS |
| [Carrier Shadow](Rev/carrier-shadow/README.md) | Rev | kiriesh |
| [Corridor Transit Gate](Web/corridor-transit-gate/README.md) | Web | kiriesh |
| [keyring](Web/keyring/README.md) | Web | K0NGR3SS |
| [Landfall](Web/landfall/README.md) | Web | kiriesh |
| [Operation Dawn: The Standing Order](Web/operation-dawn-standing-order/README.md) | Web | K0NGR3SS |
| [switchboard](Web/switchboard/README.md) | Web | K0NGR3SS |
| [Countersign](Crypto/countersign/README.md) | Crypto | Classified |
| [Emanation](Crypto/emanation/README.md) | Crypto | Classified |
| [Operation Dawn: The Courier's Keys](Crypto/operation-dawn-couriers-keys/README.md) | Crypto | Classified |
| [Rollback Pair](Crypto/rollback-pair/README.md) | Crypto | Classified |
| [Signing Authority](Crypto/signing-authority/README.md) | Crypto | Classified |
| [grid-watch](Network/grid-watch/README.md) | Network | Classified |
| [echo_chamber](PWN/echo_chamber/README.md) | Pwn | Classified |
| [forge](PWN/forge/README.md) | Pwn | Classified |
| [sigil](PWN/sigil/README.md) | Pwn | Classified |
| [stepper](PWN/stepper/README.md) | Pwn | Classified |
| [Ground Lock](Reverse Engineering/ground-lock/README.md) | Reverse engineering | Classified |
| [PoshTerm](Reverse Engineering/poshterm/README.md) | Reverse engineering | Classified |
| [Operation Dawn: Radio Recovery](Reverse Engineering/operation-dawn-radio-recovery/README.md) | Reverse engineering | Classified |
| [HELIOS-RTU](Reverse Engineering/helios-rtu/README.md) | Reverse engineering | Classified |
| [Ghost Bank](Reverse Engineering/ghost-bank/README.md) | Reverse engineering | Classified |
| [Split Horizon](Reverse Engineering/split-horizon/README.md) | Reverse engineering | Classified |
| [proprietary](Reverse Engineering/proprietary/README.md) | Reverse engineering | Classified |
| [Apogee](Web/apogee/README.md) | Web | Classified |
| [Cutover](Web/cutover/README.md) | Web | Classified |
| [Cyberboy](Web/cyberboy/README.md) | Web | Classified |

The layout follows the category and challenge structure of the [CSCTF 2024 repository](https://github.com/ChronosPK/CSCTF-2024).

## AI methodology

Team members reported using GPT-6 Sol (Daybreak), Opus 5.5, Opus 4.8, and DeepSeek 4.1 Flash. For the two DarkPigeon writeups, GPT-6 Sol helped calculate the favicon fingerprints, correlate the Censys result, inspect the discovered pages, and draft the steps. The result was checked against the actual pages and accepted submissions. Other contributors should describe their own model use where it affected a solve.

Classified's writeups above were produced with Opus 5 cyber verification assisting on reversing, scripting and cross-checking; every flag came from a reproducible solver and was submitted by hand.
