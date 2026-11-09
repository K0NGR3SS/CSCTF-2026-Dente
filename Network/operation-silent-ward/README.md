# Operation Silent Ward

**Author:** mar

**Network** · 900 pts (hard)
Handout: `files/` — `dicom_device.xml`, `snmp_trap.log`, `hospital_network.pcap`,
`patient_records.csv`, `exfil_stream.bin`

**TL;DR.** The flag is `sha256("<serial>:<timestamp>:<leaks>:<cstores>:<seed>")[:8]`, and four
of the five fields are plain reads. The challenge is the timestamp: the log tags eight lines
`[ANOMALY]`, but the spec says *the* anomalous event (singular), and the event that explains the
whole incident is the **first second of the log** — four monitored devices drop link
simultaneously and the ward goes silent for the fifteen days the records leak.

## Solve

**Reconnaissance.** The handouts describe one incident at a MedScan site:

| artifact | what it contains |
| --- | --- |
| `dicom_device.xml` | device config: AETITLE `MEDSCAN-XR400`, serial `MEDSCAN-XR400-2019`, a "backup server" at `198.51.100.42:8443`, `<DeviceManifestSeed>8842</DeviceManifestSeed>` |
| `patient_records.csv` | 91 lines (header + 90 rows), every row `status=Leaked`, 45 Wing C / 45 Wing E, six per day from 2026-09-01 to 2026-09-15 |
| `hospital_network.pcap` | DICOM + SNMP traffic; 20 C-STORE-RQ to `198.51.100.42:104`, 50 C-ECHO-RQ to `10.20.40.10:104`, 15 HTTPS flows to `:8443`, 30 SNMP traps |
| `snmp_trap.log` | 249 lines: 240 `linkDown`, 8 `[ANOMALY: Unusual polling frequency]`, 1 `deviceBootReport` |
| `exfil_stream.bin` | XOR-encrypted stream; key is the serial, plaintext header carries `198.51.100.42`, port 8443 and the tag `ward_exfil_2026` |

The published serializer is exact and leaves no room for interpretation:

```
sha256("<dicom_serial>:<snmp_iso_timestamp>:<leak_count>:<anomaly_count>:<manifest_seed>")[:8]
```

**The four easy fields.**

- **serial** — `<serial_number>MEDSCAN-XR400-2019</serial_number>`. Not the AETITLE
  `MEDSCAN-XR400`: the spec says *device serial string*.
- **leak_count** — 90, the number of data rows with `status=Leaked`. Counting the header too (91)
  is the off-by-one trap.
- **anomaly_count** — 20, the number of C-STORE operations in the pcap (DIMSE command field
  `0x0001`), all to the external "backup" host. The 50 C-ECHO-RQ (`0x0030`) are the normal
  archive health checks and are not stores.
- **manifest_seed** — 8842, stated twice and consistently: `<DeviceManifestSeed>8842` in the XML
  and `DeviceManifestSeed=8842` in the boot trap.

**The timestamp — the actual puzzle.** `snmp_trap.log` has three line shapes, and only one of
them is a single event:

```
2026-09-01T00:00:00Z ... Trap: linkDown Device: Core Router
2026-09-01T00:00:00Z ... Trap: linkDown Device: Distribution Switch A
2026-09-01T00:00:00Z ... Trap: linkDown Device: Distribution Switch B
2026-09-01T00:00:00Z ... Trap: linkDown Device: Patient Records Server
2026-09-01T06:00:00Z ... Trap: linkDown Device: Core Router
...
2026-09-08T03:15:00Z ... Trap: SNMP GET bulk-walk ... [ANOMALY: Unusual polling frequency]
...
2026-09-01T00:00:01Z ... Trap: deviceBootReport Device: MEDSCAN-XR400 DeviceManifestSeed=8842
```

The four opening lines are one event: at `2026-09-01T00:00:00Z` the core router, both distribution
switches and the records server all report `linkDown` in the same second. That is the ward going
blind — exactly when the fifteen-day leak window opens, and why nobody noticed 90 records leaving.
It is singular, it is the first line of the file, and it is where the incident narrative starts.

The eight `[ANOMALY]` lines are the decoy. They are attacker reconnaissance (an SNMP bulk-walk
from `198.51.100.42` at 03:15 every day), but there are **eight** of them and the spec says "the
anomalous event" — nothing distinguishes 09-01 from 09-08, and picking any of them is a guess.
The `deviceBootReport` one second later is a device lifecycle event, not the anomaly (and it sits
last in the file, out of chronological order, which makes it look important).

**Deriving the flag.**

```bash
python3 solve.py
```

```
serial      MEDSCAN-XR400-2019
timestamp   2026-09-01T00:00:00Z
leak_count  90  (90 csv rows)
store_count 20  (C-ECHO-RQ seen: 50)
seed        8842
preimage    MEDSCAN-XR400-2019:2026-09-01T00:00:00Z:90:20:8842
FLAG        CSCTF{f75f58ab}
```

The hash can also be checked by hand:

```bash
printf %s 'MEDSCAN-XR400-2019:2026-09-01T00:00:00Z:90:20:8842' | sha256sum | cut -c1-8
# f75f58ab
```

**Rejected readings.** Every row below was hashed with the same serializer; the ones marked
*submitted* were sent to the platform and returned `incorrect`.

| reading | hash | why it is wrong |
| --- | --- | --- |
| `03:15:00Z` on 09-01 … 09-08 (8 ANOMALY lines) | e.g. `86a4ae95` for 09-01 | *submitted (6 of 8; the per-challenge 2/60 s guard blocked two)*. Eight candidates, spec says one event; the tag is the decoy |
| `2026-09-01T00:00:01Z` (boot report) | `ba007510` | *submitted*. A boot event, not the anomaly; also one second after the ward went silent |
| AETITLE `MEDSCAN-XR400` instead of the serial | `03dfba41` | *submitted*. The spec says serial string; the AETITLE is the DICOM identity |
| `leak_count=20` (records in the exfil stream) | `5e077644` | *submitted*. The CSV is the record of what leaked; 90 rows |
| `leak_count=91` (CSV lines incl. header) | `56f38d5c` | *submitted*. Header is not a record |
| `leak_count`/`anomaly_count` swapped | `2cd01d14` | field order is fixed by the spec |
| no trailing `Z`, `+00:00`, last ANOMALY, md5/sha1 | `a02a2b62` for the last ANOMALY | the serializer is literal: exact ISO 8601 with `T` and `Z`, truncated SHA-256 |

The temptation is to keep enumerating timestamps because each hash is cheap; the team burned 66
submissions on this card doing exactly that. The flag came from the reading, not from a missing
artifact.

**Flag:** `CSCTF{f75f58ab}`

Run [the solver](solve.py) with `python3 solve.py` (needs `scapy` for the pcap count); it prints
the preimage and the flag from the handouts in `files/`.

*AI: Hermes (DeepSeek 4.1 Flash) assembled this writeup and solver from the team's lane notes;
the derivation was re-run against the handouts and the resulting flag is the one the platform
accepted.*
