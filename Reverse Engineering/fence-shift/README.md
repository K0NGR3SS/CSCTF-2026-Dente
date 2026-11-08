# Fence Shift

**Author:** Varenik14  
**Category:** Reverse engineering  
Handout: [fence-shift.zip](files/fence-shift.zip)

## Solve

I disassembled the stripped `fcu` and followed the `fence` command. Its 28-byte little-endian block stores latitude, longitude, radius, altitude ceiling, east offset, north offset, margin percent and a format tag. The coordinates, ceiling and offsets are signed 32-bit integers. Radius is unsigned 32-bit. The last two fields are unsigned 16-bit and the tag is `0x5346`.

The controller applies the percentage margin to the radius with integer division. It converts the resulting radius and the signed center offsets from centimeters to e7 units by multiplying by `8983/10000` and rounding to the nearest integer, with ties away from zero. It accepts a request when the squared distance from the shifted center is at most the squared radius and the altitude in centimeters is at most the ceiling.

I decoded MAVLink 2 from `mission.pcapng`. The first aircraft position fixed the initial center at `(457913250, 241502100)`. The aircraft provisioned a 4000 cm radius, a 12000 cm ceiling, zero offsets and zero margin. I applied each ground `PARAM_SET` only after its matching aircraft `PARAM_VALUE`. The acknowledgments from the route manager show that it queued the requests.

I numbered the 22 ground `MAV_CMD_DO_REPOSITION` requests from zero and ran the recovered predicate with both the active and provisioned state. The masks were `2bbb27` and `3aa227`.

Install `pymavlink` and run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{active_2bbb27_provisioned_3aa227}`
