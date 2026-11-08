#!/usr/bin/env python3
"""Recover the rotated MAVLink 2 signing key from the capture.

Usage: python3 parse_key.py files/mission.tlog   (unpack severed-link.zip first)

The operator rolled the signing key mid-mission and pushed the new key in band
as a SETUP_SIGNING message over the same recorded link, so the key is sitting in
the capture in clear. pymavlink parses it directly.
"""
import sys
from pymavlink import mavutil

m = mavutil.mavlink_connection(sys.argv[1], dialect='ardupilotmega')
while True:
    msg = m.recv_match(blocking=False)
    if msg is None:
        break
    if msg.get_type() == 'SETUP_SIGNING':
        d = msg.to_dict()
        print("SETUP_SIGNING from sys=%d init_ts=%d" % (msg.get_srcSystem(), d['initial_timestamp']))
        print("key hex:", bytes(d['secret_key']).hex())
