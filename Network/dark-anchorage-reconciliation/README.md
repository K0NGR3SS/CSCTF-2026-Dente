# Dark Anchorage Reconciliation

**Author:** Varenik14  
**Category:** Network

## Solve

I read the schema, AIS and radar exports, cable fault location and method note from the assigned instance. The radar export used a clock 120 minutes ahead of UTC. After subtracting the offset, both series aligned from 10:00 UTC at 120-second intervals.

I compared the median local-plane distance for every radar track and AIS vessel pair. Each of the 16 tracks had one candidate at a median distance of zero, with the alternatives above 230 m. Track `R-13` matched MMSI `986118613`. Four AIS samples from 11:22 to 11:28 UTC were shifted 390 m east and 330 m north. The radar track crossed the cable fault itself. The closest approach was 0.0 m at 11:31:38 UTC, inside the 11:18–11:32 fault window.

I sent the report to `POST /reconcile` using separate fields `ais_minus_radar_east_m`, `ais_minus_radar_north_m`, `start_utc` and `end_utc`. The server returned `incident export verified` and the flag. The original instance exports are unavailable.

**Flag:** `CSCTF{9HuU2XpnwOPwMmmg4xk227jh}`
