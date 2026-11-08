#!/usr/bin/env python3
"""Last Commit — CSCTF 2026 (Forensics).

Replays the SQLite WAL to the commit where export job LR-731 became COMPLETED,
runs the ownership export from export-profile.md against that snapshot, and
hashes the result into the flag.

Usage: python3 solve.py files/last-commit.zip
"""
import hashlib
import os
import struct
import sqlite3
import sys
import tempfile
import zipfile


def checksum(data, s0, s1, big):
    fmt = (">" if big else "<") + "%dI" % (len(data) // 4)
    w = struct.unpack(fmt, data)
    for i in range(0, len(w), 2):
        s0 = (s0 + w[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + w[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


def snapshots(db, wal, outdir):
    """Yield (frame_index, snapshot_path) at every valid commit in the WAL."""
    magic, _ver, psz, _ck, salt1, salt2, c1, c2 = struct.unpack(">IIIIIIII", wal[:32])
    big = magic & 1
    s0, s1 = checksum(wal[:24], 0, 0, big)
    assert (s0, s1) == (c1, c2), "WAL header checksum"

    off, fsz = 32, 24 + psz
    pages, i = {}, 0
    while off + fsz <= len(wal):
        h = wal[off : off + 24]
        pg, commit, fs1, fs2, fc1, fc2 = struct.unpack(">IIIIII", h)
        data = wal[off + 24 : off + fsz]
        t0, t1 = checksum(h[:8], s0, s1, big)
        t0, t1 = checksum(data, t0, t1, big)
        if (fs1, fs2) != (salt1, salt2) or (t0, t1) != (fc1, fc2):
            break
        s0, s1 = t0, t1
        pages[pg] = data
        if commit:
            img = bytearray(db[: commit * psz].ljust(commit * psz, b"\0"))
            for p, d in pages.items():
                if p <= commit:
                    img[(p - 1) * psz : p * psz] = d
            img[18] = img[19] = 1  # rollback-journal mode for a standalone copy
            fn = os.path.join(outdir, "snap_%02d.sqlite" % i)
            open(fn, "wb").write(bytes(img))
            yield i, fn
        off += fsz
        i += 1


def export_flag(snap, delivery_csv):
    con = sqlite3.connect("file:%s?mode=ro&immutable=1" % snap.replace("\\", "/"), uri=True)
    rows = [l.split(",") for l in delivery_csv.decode().rstrip("\n").split("\n")[1:]]
    con.execute("CREATE TEMP TABLE manifest(job_id TEXT, position INTEGER, parcel_id INTEGER)")
    con.executemany("INSERT INTO manifest VALUES(?,?,?)", [(r[0], int(r[1]), int(r[2])) for r in rows])
    q = """SELECT m.position,p.parcel_id,p.district,p.plot_ref,h.registry_ref,t.interest_bps,t.instrument_ref
           FROM manifest AS m JOIN parcel AS p ON p.parcel_id=m.parcel_id
           JOIN title AS t ON t.parcel_id=p.parcel_id JOIN holder AS h ON h.holder_id=t.holder_id
           WHERE m.job_id='LR-731' ORDER BY m.position ASC, h.registry_ref COLLATE BINARY ASC"""
    out = "position\tparcel_id\tdistrict\tplot_ref\tregistry_ref\tinterest_bps\tinstrument_ref\n"
    for r in con.execute(q):
        out += "\t".join(str(x) for x in r) + "\n"
    con.close()
    return "CSCTF{last_commit_%s}" % hashlib.sha256(out.encode()).hexdigest()


def main():
    zpath = sys.argv[1] if len(sys.argv) > 1 else "files/last-commit.zip"
    zf = zipfile.ZipFile(zpath)
    db = zf.read("registry.sqlite")
    wal = zf.read("registry.sqlite-wal")
    delivery = zf.read("delivery.csv")

    with tempfile.TemporaryDirectory() as tmp:
        for i, snap in snapshots(db, wal, tmp):
            con = sqlite3.connect("file:%s?mode=ro&immutable=1" % snap.replace("\\", "/"), uri=True)
            state = dict(con.execute("SELECT job_id, state FROM export_job").fetchall())
            con.close()
            if state.get("LR-731") == "COMPLETED":
                print("LR-731 COMPLETED at WAL frame", i)
                print(export_flag(snap, delivery))
                return
    raise SystemExit("no snapshot with LR-731 COMPLETED")


if __name__ == "__main__":
    main()
