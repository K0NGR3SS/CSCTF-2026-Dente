# Severed Link

**Author:** Varenik14  
**Category:** Network  
Handout: [severed-link.zip](files/severed-link.zip) (`mission.tlog`, `mission.pcap`, `ops_notes.txt`)

## Solve

The brief: a DRONE-01 ISR link runs MAVLink 2 with per-frame signing. Operator is sysid 255, drone is sysid 1. Mid-mission the signing key was rotated, and the rotation was pushed *in band* — the new key was sent as a `SETUP_SIGNING` message over the same link that is in the capture. The task is to recover that key and command the still-online station as the operator.

I parsed `mission.tlog` with pymavlink and pulled the one `SETUP_SIGNING` frame; its `secret_key` field is the rotated key in clear:

```
8f2b4e71a6c3d05f9217bc84e63a1d57f0482c6b9e13a7d5c84f26019bd3ea60
```

I confirmed it was the key actually in use by recomputing the MAVLink signature — `sha256(key + header + payload + crc + link_id + timestamp)[:6]` — over the signed frames in the capture; every frame from just before the rotation onward verified.

The live uplink is a MAVLink 2 TCP endpoint. On connect it sends a signed STATUSTEXT asking the client to authenticate as the operator, and it only requires that frames carry a valid signature with a current timestamp (replayed frames are refused). So I enabled outgoing signing with the leaked key and a fresh timestamp, sent a signed `HEARTBEAT`, then a signed `COMMAND_INT DO_REPOSITION` from sysid 255. The server replied:

```
OPERATOR AUTHENTICATED. Reposition accepted.
Audit receipt: CSCTF{8Zx988VJlu5I1ijIruWgrlVX}
```

Recover the key with [parse_key.py](parse_key.py) (`python3 parse_key.py files/mission.tlog`), then run [solve.py](solve.py) with `python3 solve.py <host> <port>` against the assigned instance.

**Flag:** `CSCTF{8Zx988VJlu5I1ijIruWgrlVX}`
