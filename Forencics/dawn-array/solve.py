import hashlib
import json
import re
import sqlite3
import struct
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from contextlib import closing
from pathlib import Path
from zipfile import ZipFile

from capture import tcp_packets, tcp_streams
from ext4 import Ext4


def extract(archive, work):
    with ZipFile(archive) as handout:
        for name in ("acq-1.raw", "acq-2.raw", "acq-3.raw"):
            (work / name).write_bytes(handout.read(name))
        (work / "raid5_extract.py").write_bytes(handout.read("tools/raid5_extract.py"))
    output = work / "array.img"
    subprocess.run([sys.executable, str(work / "raid5_extract.py"), "--member-count", "4",
                    "--chunk-bytes", "32768", "--data-offset-bytes", "1048576",
                    "--array-bytes", "122683392", "--layout", "left-symmetric",
                    "--member", f"0:{work / 'acq-1.raw'}",
                    "--member", f"2:{work / 'acq-3.raw'}",
                    "--member", f"3:{work / 'acq-2.raw'}", "--output", str(output)],
                   check=True, stdout=subprocess.DEVNULL)
    fs = Ext4(output.read_bytes())
    for name in ("var/lib/rrca/dispatch.sqlite", "var/lib/rrca/dispatch.sqlite-wal",
                 "var/log/rrca/dispatch-gateway.syslog", "var/log/rrca/controller-access.pcapng"):
        (work / Path(name).name).write_bytes(fs.file(name))


def http_messages(stream):
    while stream:
        header, stream = stream.split(b"\r\n\r\n", 1)
        first, *rest = header.decode("ascii").split("\r\n")
        headers = dict((name.lower(), value.lstrip()) for name, value in
                       (line.split(":", 1) for line in rest))
        size = int(headers.get("content-length", 0))
        if size > len(stream):
            raise ValueError("Truncated HTTP body")
        payload, stream = stream[:size], stream[size:]
        yield first, headers, json.loads(payload) if payload else {}


def exchanges(capture):
    streams = tcp_streams(capture, 8080)
    chronological = defaultdict(list)
    for _, source, target, _, _, payload in tcp_packets(capture):
        key = (source, target) if target[1] == 8080 else (target, source)
        if target[1] == 8080 and payload.startswith((b"POST ", b"GET ")):
            chronological[key].append(payload.split(b" ", 1)[0])
        elif source[1] == 8080 and payload.startswith(b"HTTP/"):
            chronological[key].append(b"response")
    inventory = defaultdict(list)
    for (client, server), requests in streams.items():
        if server[1] != 8080:
            continue
        request = list(http_messages(requests))
        response = list(http_messages(streams.get((server, client), b"")))
        if len(request) == len(response) == 2:
            seq = int(request[0][1]["x-rrca-gateway-seq"])
            order = chronological[client, server]
            inventory[seq].append((request, response, order))
    return inventory


def witness(work):
    with closing(sqlite3.connect(work / "dispatch.sqlite")) as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Corrupt SQLite ledger")
        rows = db.execute("SELECT cycle_id, request_id, gateway_seq, prepare_revision, "
                          "reservation_nonce, release_register, release_value "
                          "FROM cycles ORDER BY gateway_seq").fetchall()
    if len(rows) != 128:
        raise ValueError("Expected 128 cycles after applying the WAL")
    phases = defaultdict(list)
    for line in (work / "dispatch-gateway.syslog").read_text(encoding="ascii").splitlines():
        fields = dict(re.findall(r'([a-z_]+)="([^"]+)"', line.split("[rrca@32473 ", 1)[1].split("]", 1)[0]))
        phases[int(fields["gateway_seq"])].append(fields)
    traffic = exchanges((work / "controller-access.pcapng").read_bytes())
    ids = Counter(item[0][0][1]["x-rrca-request"] for values in traffic.values() for item in values)
    qualified = []
    for cycle, request_id, seq, revision, nonce, register, value in rows:
        audit = phases[seq]
        if [phase["phase"] for phase in audit] != [
                "PREPARE_SENT", "RESPONSE_OBSERVED", "READBACK_OBSERVED", "COMMIT_WRITTEN"]:
            continue
        if any((phase["cycle_id"], phase["request_id"]) != (cycle, request_id) for phase in audit):
            continue
        if len(traffic[seq]) != 1 or ids[request_id] != 1:
            continue
        (prepare, get), (reserved, readback), order = traffic[seq][0]
        if order != [b"POST", b"response", b"GET", b"response"]:
            continue
        if not (prepare[0].startswith("POST /v1/reservations ")
                and get[0].startswith("GET /v1/readback ")
                and reserved[0].split()[1] == "201" and readback[0].split()[1] == "200"):
            continue
        if any((message[1].get("x-rrca-cycle"), message[1].get("x-rrca-request"))
               != (cycle, request_id) for message in (prepare, reserved)):
            continue
        if get[1].get("x-rrca-readback-for") != request_id:
            continue
        expected = dict(revision=revision, register=str(register), value=str(value))
        if prepare[2] != expected or readback[2] != dict(expected, nonce=nonce):
            continue
        if reserved[2].get("revision") != revision or reserved[2].get("nonce") != nonce:
            continue
        if (audit[1].get("nonce"), audit[1].get("revision")) != (nonce, revision):
            continue
        if tuple(audit[2].get(key) for key in ("nonce", "revision", "release_register", "release_value")) \
                != (nonce, revision, str(register), str(value)):
            continue
        qualified.append("|".join((cycle, request_id, revision, nonce, str(register), str(value))))
    if len(qualified) != 16:
        raise ValueError(f"Expected 16 qualifying cycles, got {len(qualified)}")
    return ("\n".join(["RRCA-DAWN-WITNESS-v1", *qualified]) + "\n").encode("ascii")


with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
    work = Path(temp)
    extract(Path(__file__).parent / "files" / "dawn-array.zip", work)
    digest = hashlib.sha256(witness(work)).hexdigest()
    print(f"CSCTF{{dawn_{digest}}}")
