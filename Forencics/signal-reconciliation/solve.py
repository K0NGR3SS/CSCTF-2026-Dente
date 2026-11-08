import base64
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile


def report(samples):
    if len(samples) != 601:
        raise ValueError("Expected 601 observations")
    east = north = 0
    rows = []
    residuals = []
    for i, sample in enumerate(samples):
        if (sample["i"], sample["t_ms"]) != (i, 100 * i):
            raise ValueError("Unexpected sample order")
        gps_e, gps_n = sample["gps_e_mm"], sample["gps_n_mm"]
        de, dn = gps_e - east, gps_n - north
        residuals.append((de, dn))
        rows.append(f"E|{i}|{100*i}|{east}|{north}|{gps_e}|{gps_n}|{de}|{dn}")
        if i + 1 < len(samples):
            next_sample = samples[i + 1]
            ve = sample["ve_mmps"] + next_sample["ve_mmps"]
            vn = sample["vn_mmps"] + next_sample["vn_mmps"]
            if ve % 20 or vn % 20:
                raise ValueError("Non-integral navigation increment")
            east += ve // 20
            north += vn // 20
    starts = []
    for i in range(len(samples) - 9):
        window = residuals[i:i + 10]
        if (all(e*e + n*n >= 625000000 for e, n in window)
                and all(e1-e0 >= 1000 and abs(n1-n0) <= 500
                        for (e0, n0), (e1, n1) in zip(window, window[1:]))):
            starts.append(i)
    qset = ",".join(map(str, starts)) or "NONE"
    e, n = residuals[-1]
    decision = ("QUARANTINE_GNSS_PROFILE" if starts and e*e + n*n >= 10000000000
                else "REVIEW_ONLY")
    head = f"RECONCILIATION/2|samples=601|qset={qset}|decision={decision}"
    tail = f"SUMMARY|qset={qset}|final_res_e={e}|final_res_n={n}|decision={decision}"
    return ("\n".join([head, *rows, tail]) + "\n").encode("ascii")


zero = [dict(i=i, t_ms=i*100, ve_mmps=0, vn_mmps=0, gps_e_mm=0, gps_n_mm=0)
        for i in range(601)]
if hashlib.sha256(report(zero)).hexdigest() != "cc8c52dce750951980bb402846ff761fa2b471a9fbc20b5cb0c2a6ef675787f1":
    raise ValueError("Serialization differs from the public test vector")
with ZipFile(Path(__file__).parent / "files" / "signal-reconciliation.zip") as archive:
    evidence = [json.loads(line) for line in archive.read("flight.ndjson").splitlines()]
digest = hashlib.sha256(report(evidence)).digest()[:24]
print("CSCTF{" + base64.b32encode(digest).decode("ascii").rstrip("=") + "}")
