#!/usr/bin/env python3
"""countersign: SHA-256 length extension against tag = SHA-256(key || message).

The relay signs commands with a secret PREFIX, which is the classic broken MAC. Merkle-
Damgard lets us continue hashing from the published tag, so we can append "&cmd=DISPATCH"
to the captured STATUS record and produce a valid tag without ever learning the key.
Only the key length is unknown, and the spec itself narrows it to 8..32 bytes.
"""
import json, sys, time, urllib.error, urllib.request
import hlextend

BASE = sys.argv[1] if len(sys.argv) > 1 else open('work/INSTANCE').read().strip()

def api(path, payload=None):
    req = urllib.request.Request(BASE + path)
    if payload is not None:
        req.data = json.dumps(payload).encode()
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=20) as f:
            return f.status, json.load(f)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')

spec = api('/api/spec')[1]
sample = api('/api/sample')[1]
known = bytes.fromhex(sample['message_hex'])
tag = sample['sig']
lo, hi = spec['key_length_band_bytes']
print('construction :', spec['construction'])
print('captured     :', known.decode())
print(f'key length   : unknown, spec says {lo}..{hi} bytes')

# "last value wins", so an appended cmd overrides the original STATUS.
# The glue padding lands inside the previous token's value and is simply ignored.
for klen in range(lo, hi + 1):
    sha = hlextend.new('sha256')
    forged = sha.extend(b'&cmd=DISPATCH', known, klen, tag)
    code, body = api('/api/command', {'message_hex': forged.hex(), 'sig': sha.hexdigest()})
    if code == 200 and 'CSCTF{' in json.dumps(body):
        print(f'key length   : {klen} bytes')
        print('forged msg   :', forged)
        print('forged tag   :', sha.hexdigest())
        print(json.dumps(body, indent=2))
        break
    print(f'  klen={klen:2d} -> {code} {json.dumps(body)[:90]}')
    time.sleep(0.25)
else:
    sys.exit('no key length in the band worked')
