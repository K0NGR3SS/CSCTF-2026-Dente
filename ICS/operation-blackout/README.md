# Operation Blackout

**Author:** mar

**ICS** · 540 pts (hard)
Handouts: [scada_network.pcap](files/scada_network.pcap),
[hmi_config.xml](files/hmi_config.xml), [plc_firmware.bin](files/plc_firmware.bin),
[substation_log.json](files/substation_log.json), [alarm_override.dat](files/alarm_override.dat)

**TL;DR.** Five artifacts describe one Modbus incident at substation `0x4A2E`. The HMI's hidden
calibration routine carries a function-code 16 write to registers 40001–40064 with the pattern
`55 FA` repeated; the pcap contains exactly that write; the substation log records the write, a
247-byte buffer overflow against a 128-byte limit, three altered alarm thresholds and the outage
forty-five minutes later; the alarm-override file contains those three threshold changes. The only
ambiguity is the timestamp: the pcap stamps the FC16 write at `06:05:03Z`, the log at `06:15:03Z`,
and the card says to use the log entry. The marker is
`sha256("0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137")[:8]`.

## Solve

**What each artifact contributes.**

| artifact | evidence |
| --- | --- |
| `plc_firmware.bin` | first four bytes `50 4C 43 31` = **`0x504C4331`** ("PLC1"); the readable version string is `V3.2.1` |
| `hmi_config.xml` | `<station_id>0x4A2E</station_id>`, `<ManifestSeed>137</ManifestSeed>`, and a `HiddenModbusWrite function_code="16" start_address="40001" count="64"` with payload `55 FA` × 8 |
| `scada_network.pcap` | 36 frames, 31 Modbus/TCP packets (30 FC3 reads and one FC16 write); the anomalous write is transaction 2, unit 1, function `0x10`, start `0x9C41` = **40001**, count `0x0040` = 64, byte count `0x10` = 16, body `55fa55fa55fa55fa55fa55fa55fa55fa` |
| `substation_log.json` | `06:15:03Z` warning for the FC16 write to 40001–40064; `06:15:03Z` critical 247-byte overflow vs 128-byte limit; `06:15:04Z` alarm thresholds changed; `06:15:10Z` firmware integrity failure; `06:30:00Z` outage; `07:00:00Z` emergency shutdown |
| `alarm_override.dat` | `ALRM`, count 3, station `0x4A2E`; three records: High Temperature 85 → 250, Low Pressure 200 → 10 (0.01 bar units, i.e. 2.0 → 0.1 bar), Overcurrent 500 → 5000 |

**1. Reconstruct only where the evidence agrees.** The HMI routine and the pcap agree on the
function code, the start register, the count and the payload:

```
HMI:  function_code=16 start_address=40001 count=64  payload 55 FA × 8
pcap: FC 0x10         start 0x9C41 (40001) count 0x40 (64) byte_count 0x10  payload 55 FA × 8
```

The log and the alarm file agree on the three threshold changes:

```
log   06:15:04  High Temp 85 -> 250 C, Low Pressure 2.0 -> 0.1 bar, Overcurrent 500 -> 5000 A
ALRM  records  85 -> 250, 200 -> 10 (0.01 bar), 500 -> 5000
```

The firmware header and the HMI station id are single-source but unambiguous: the card's serializer
names `FIRMWARE_FIRST_4_BYTES_UPPER_HEX` and `STATION_ID`, so `0x504C4331` and `0x4A2E` are read
directly.

**2. The timestamp is the puzzle.** The pcap's first FC16 record is stamped `1763186703` =
`2025-11-15T06:05:03Z`. The log's FC16 entry is `2025-11-15T06:15:03Z`. The card says:

> `log_timestamp_iso` = exact ISO 8601 timestamp from the log entry for the malicious FC16 write,
> with `T` and trailing `Z`.

So the log wins. The pcap's ten-minute offset is a deliberate decoy: it is the same packet, but the
serializer is defined over the log record, not the capture clock.

**3. The preimage.** The card fixes the order and the literal separators:

```
0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137
```

- firmware header: `0x504C4331` (first four bytes, uppercase hex with `0x`; not the `V3.2.1` string)
- station: `0x4A2E` (uppercase hex with `0x`)
- log timestamp: `2025-11-15T06:15:03Z`
- register: `40001` (decimal start address, not `0x9C41`)
- seed: `137` (the `ManifestSeed` in the HMI config, also repeated in the log's startup row)

```bash
printf %s '0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137' | sha256sum
# 12fcdb0d35f7fde4685d2f6995958f107ec9b5dd8a2ffd74e8fd44a6ff8ea85b
```

**Flag:** `CSCTF{12fcdb0d}`

**Dead ends (all tested against the serializer).**

| candidate | preimage / digest | why it is wrong |
| --- | --- | --- |
| pcap time `06:05:03Z` | `0x504C4331:0x4A2E:2025-11-15T06:05:03Z:40001:137` → `f4159b24` | the card says the log entry, not the capture clock |
| alarm threshold time `06:15:04Z` | `…T06:15:04Z…` | that is the effect row, not the FC16 write |
| outage time `06:30:00Z` | `…T06:30:00Z…` | the incident, not the malicious write |
| firmware version string `3.2.1` or `V3.2.1` | `3.2.1:0x4A2E:…` | the spec says the first four bytes as hex, not the version string |
| register `0x9C41` | `…:0x9C41:137` | the spec says decimal `40001` |
| count `64` or byte count `16` as the register | `…:64:137` / `…:16:137` | the field is the start register |
| seed `3.2.1`, `64`, `247`, `128` | `…:3.2.1` etc. | the seed is the HMI `ManifestSeed` `137` |
| `scada_blackout_2026` as a seed | the card calls it a decoy | explicitly excluded |
| hash of `plc_firmware.bin`, `substation_log.json` or the pcap | file digests | the marker is over the literal text, not a file |
| binary packing of the fields | any `struct.pack` form | the card says literal `:` separators and no binary packing |

The card's "only where the evidence agrees" is doing real work here: the pcap and the log disagree
by ten minutes, and the serializer's wording resolves it. The other four fields are unambiguous from
the artifact the serializer names, so the timestamp is the only real choice.

Run [solve.py](solve.py) with `python3 solve.py`; it reads the five handouts, prints the cross-checks
(including the pcap-vs-log timestamp), and derives the flag.

*AI: Hermes (DeepSeek 4.1 Flash) assembled this writeup from the team's Operation Blackout lane
(`black3.json`, the handout analysis and the artifact cross-checks); the preimage and digest were
recomputed from the five files. The candidate is recorded in `black3.json` at the same minute as the
platform's 10:57:53Z solve.*
