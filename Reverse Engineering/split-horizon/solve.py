#!/usr/bin/env python
"""Split Horizon (CSCTF 2026, rev, 450 pts) -- reproducible solver.

The drone and the command server parse the SAME uplink JSON with different rules:

  drone  : vireo-ctl.dll, .NET System.Text.Json with `new JsonSerializerOptions()`
           -> PropertyNameCaseInsensitive defaults to FALSE, so [JsonPropertyName]
              matching is case-SENSITIVE EXACT. "WAYPOINT_LAT" is simply ignored.
  server : command-server.go, Go encoding/json
           -> key matching is case-INSENSITIVE and the LAST duplicate wins,
              so "WAYPOINT_LAT" overwrites "waypoint_lat".

So one command carrying both "waypoint_lat" (off-course) and a later "WAYPOINT_LAT"
(benign) makes the drone fly off-course while the server validates and commits the
benign value. The audit trail is genuinely signed and its hash chain is intact -- it
faithfully records the wrong parse. That is "why the server never saw it".

Run:  python solve.py [instance-url]     (url optional; omit to work offline)
"""
import hashlib
import hmac
import json
import math
import re
import sys
import urllib.request

HERE = __file__.rsplit('/', 1)[0] if '/' in __file__ else '.'
D = HERE + '/dist'

# ---------------------------------------------------------------- 1. uplink
# Constants lifted from Vireo.Uplink.Protocol in the decompiled vireo-ctl.dll.
MASK_A = bytes([149,222,42,176,101,182,225,147,123,108,254,225,63,41,141,49,
                229,99,139,86,169,42,33,223,14,9,67,126,236,61,181,174])
MASK_B = bytes([50,141,74,82,108,214,174,180,166,217,197,53,201,105,4,127,
                98,122,10,91,3,30,3,198,166,165,205,251,189,186,47,255])
SHARED = bytes(a ^ b for a, b in zip(MASK_A, MASK_B))


def frames(buf):
    """'VW' | type | len16 | payload"""
    i, out = 0, []
    while i + 5 <= len(buf):
        if buf[i] != 0x56 or buf[i + 1] != 0x57:
            i += 1
            continue
        t = buf[i + 2]
        n = (buf[i + 3] << 8) | buf[i + 4]
        if i + 5 + n > len(buf):
            break
        out.append((t, buf[i + 5:i + 5 + n]))
        i += 5 + n
    return out


def uplink_commands():
    from collections import defaultdict
    from scapy.all import rdpcap, Raw, TCP
    streams = defaultdict(bytes)
    for p in rdpcap(D + '/session.pcap'):
        if TCP in p and Raw in p:
            streams[(p[TCP].sport, p[TCP].dport)] += bytes(p[Raw].load)
    hello = [(k, frames(v)) for k, v in streams.items()
             if frames(v) and frames(v)[0][0] == 1 and len(frames(v)[0][1]) == 16]
    hello.sort(key=lambda kv: len(kv[1]))          # client sends only the hello
    (cli, cf), (srv, sf) = hello[0], hello[1]
    key = hmac.new(SHARED, cf[0][1] + sf[0][1], hashlib.sha256).digest()[:16]
    return [bytes(c ^ key[i % 16] for i, c in enumerate(p)) for t, p in sf if t == 2]


# ------------------------------------------------------- 2. the two parsers
NAMES = {'altitude', 'speed', 'waypoint_lat', 'waypoint_lon',
         'payload_weight', 'wind_compensation'}


def _pairs(raw):
    body = re.search(r'"params"\s*:\s*\{(.*)\}\s*\}\s*$', raw.decode(), re.S).group(1)
    return re.findall(r'"([^"]+)"\s*:\s*(-?[\d.]+)', body)


def go_parse(raw):
    """case-insensitive, last duplicate wins"""
    out = {}
    for k, v in _pairs(raw):
        out[k.lower()] = float(v)
    return out


def net_parse(raw):
    """case-sensitive exact match on the JsonPropertyName"""
    out = {}
    for k, v in _pairs(raw):
        if k in NAMES:
            out[k] = float(v)
    return out


# --------------------------------------------------------------- 3. analyse
def analyse():
    man = json.load(open(D + '/manifest.json'))
    alat, alon = man['approved_waypoint_lat'], man['approved_waypoint_lon']
    tol = man['server_validation_tolerance_deg']
    cmds = uplink_commands()
    entries = [json.loads(l) for l in open(D + '/audit.log') if '"seq"' in l]

    rows = []
    for raw in cmds:
        seq = int(re.search(rb'"seq"\s*:\s*(\d+)', raw).group(1))
        rows.append((seq, go_parse(raw), net_parse(raw)))

    # The commitment salt is random and undisclosed, so commits cannot be inverted --
    # but equal coordinates must give equal commits. The partition of the log by commit
    # is therefore a free oracle for "what did the server parse?".
    from collections import defaultdict
    pred, act = defaultdict(list), defaultdict(list)
    for (seq, g, _), e in zip(rows, entries):
        pred[(round(g['waypoint_lat'], 6), round(g['waypoint_lon'], 6))].append(seq)
        act[e['waypoint_commit']].append(seq)
    assert sorted(sorted(v) for v in pred.values()) == sorted(sorted(v) for v in act.values()), \
        'Go-parse model does not reproduce the audit commit classes'

    # hash chain
    prev = bytes(32)
    for e in entries:
        assert e['prev_hash'] == prev.hex()
        prev = hashlib.sha256(prev + f'{e["prev_hash"]}|{e["seq"]}|{e["status"]}|'
                                      f'{e["waypoint_commit"]}'.encode()).digest()
        assert prev.hex() == e['entry_hash']

    bad = [(seq, g, n) for seq, g, n in rows
           if abs(g['waypoint_lat'] - n['waypoint_lat']) > 1e-9
           or abs(g['waypoint_lon'] - n['waypoint_lon']) > 1e-9]
    assert len(bad) == 1, f'expected exactly one divergent command, got {len(bad)}'
    seq, g, n = bad[0]

    # the drone's value must breach tolerance while the server's does not
    assert abs(g['waypoint_lat'] - alat) <= tol and abs(g['waypoint_lon'] - alon) <= tol
    assert abs(n['waypoint_lat'] - alat) > tol or abs(n['waypoint_lon'] - alon) > tol

    fields = [f for f in ('waypoint_lat', 'waypoint_lon') if abs(g[f] - n[f]) > 1e-9]
    drift = math.hypot((n['waypoint_lat'] - alat) * 111320,
                       (n['waypoint_lon'] - alon) * 111320 * math.cos(math.radians(alat)))
    return {
        'malicious_seq': seq,
        'executed_lat': round(n['waypoint_lat'], 4),
        'executed_lon': round(n['waypoint_lon'], 4),
        'logged_lat': round(g['waypoint_lat'], 4),
        'logged_lon': round(g['waypoint_lon'], 4),
        'exploited_field': '+'.join(fields),
        'mechanism': 'case_insensitive_last_wins_vs_case_sensitive_exact',
    }, drift


if __name__ == '__main__':
    ans, drift = analyse()
    print('drift from approved waypoint: %.0f m' % drift)
    print(json.dumps(ans, indent=2))
    if len(sys.argv) > 1:
        url = sys.argv[1].rstrip('/') + '/submit'
        req = urllib.request.Request(url, json.dumps(ans).encode(),
                                     {'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode()
        print('\n' + body)
        m = re.search(r'CSCTF\{[^}]+\}', body)
        if m:
            print('\nFLAG:', m.group())
