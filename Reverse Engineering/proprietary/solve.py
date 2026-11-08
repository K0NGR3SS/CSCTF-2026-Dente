#!/usr/bin/env python3
"""
PROPRIETARY / "District 7 - Switchyard Credential"  (CSCTF 2026, Rev, 891 pts)

Forges a VCDF operator card that cardval accepts 5/5, then submits it to the
team's own checkpoint instance, which prints the access grant (the flag).

Everything below was recovered from the stripped Rust binary `cardval`:
  * the VCDF container layout and its custom (non-CRC) integrity hash,
  * the two mandatory applications and every field rule they enforce,
  * the key derivation, and
  * the final attestation value the scripted shift session demands.

usage:
    python solve.py                       # build dist-equivalent card.bin, verify locally
    python solve.py <checker-url>         # ... and submit it, printing the grant
Local verification needs the Linux x86-64 `cardval`; on this Windows host run it
through the VM:  tools/x86.sh 'cd ~/ctf/challenges/rev/proprietary && python3 solve.py'
"""
import os, struct, subprocess, sys, json

M, K, INIT = 0xFFFFFFFF, 0x9E3779B1, 0xC1FC1E5A

def cksum(data, h=INIT):
    """cardval's integrity hash: rotl32(h,5) ^ byte, multiply, xor-shift.
    Not a CRC - the binary contains no CRC table. Check value: the shipped
    starter.bin hashes to its own stored field, 0xad6935bd."""
    for b in data:
        h = (((((h << 5) & M) | (h >> 27)) ^ b) * K) & M
        h ^= h >> 15
    return h

AID_CRED, AID_LEDGER = 0xA17E2D, 0x6D2A91
OPERATOR_ID = 0x1001                      # any nonzero u32 works
ATTESTATION = 0x5BF4C77B                  # see note at the bottom

def file_hdr(fid, ftype, access):         # [id][type][access][reserved=0]
    return bytes([fid, ftype, access, 0])
def f_data(fid, payload, access):         # type 0: u16 length + payload
    return file_hdr(fid, 0, access) + struct.pack('<H', len(payload)) + payload
def f_value(fid, lo, hi, val, access):    # type 1: three i32
    return file_hdr(fid, 1, access) + struct.pack('<iii', lo, hi, val)
def f_record(fid, ftype, rec_size, capacity, records, access):
    return (file_hdr(fid, ftype, access)
            + struct.pack('<HHH', rec_size, capacity, len(records) // rec_size if rec_size else 0)
            + records)

def application(aid, keys, files):
    """11-byte header: AID u24 | key_settings=0 | key_count | file_count | reserved=0 | cksum u32"""
    hdr = struct.pack('<I', aid)[:3] + bytes([0, len(keys), len(files), 0]) + b'\0\0\0\0'
    return hdr, b''.join(keys) + b''.join(files)

def build(apps):
    """16-byte image header + applications. Both checksum layers are computed over
    the image with EVERY checksum field zeroed."""
    chunks = []
    for hdr, payload in apps:
        c = cksum(hdr + payload)
        chunks.append((hdr[:7] + struct.pack('<I', c) + payload, c))
    body = b''.join(c for c, _ in chunks)
    total = 16 + len(body)
    img = bytearray(b'VCDF' + bytes([2, 0, len(apps), 0]) + struct.pack('<II', total, 0) + body)
    off = 16
    for c, _ in chunks:                       # zero app checksums for the image hash
        img[off+7:off+11] = b'\0\0\0\0'; off += len(c)
    img[12:16] = struct.pack('<I', cksum(bytes(img)))
    off = 16
    for c, ck in chunks:                      # restore them
        img[off+7:off+11] = struct.pack('<I', ck); off += len(c)
    return bytes(img)

def make_card(operator_id=OPERATOR_ID, attestation=ATTESTATION):
    # --- key derivation, from the session setup in sim.rs ---
    key0 = cksum(struct.pack('<I', operator_id))              # from the operator ID
    key1 = cksum(struct.pack('<I', key0) + b'\x01')           # from key0, with a 0x01 suffix

    # --- site credential: 1 data file, no keys, id 0, access 0xFF, payload exactly 16 bytes
    #     operator ID nonzero | qualification window must cover 2026 | flags bit 0 set | rest zero
    payload = (struct.pack('<I', operator_id)
               + struct.pack('<HH', 2000, 2050)
               + bytes([0, 1]) + bytes(6))
    cred = application(AID_CRED, [], [f_data(0, payload, 0xFF)])

    # --- work ledger: exactly 4 files (ids 0..3) and exactly 2 keys, each file's
    #     (type, access) policy fixed by the binary
    ledger = application(AID_LEDGER,
        [struct.pack('<I', key0), struct.pack('<I', key1)],
        [f_value (0, 0, 5000, 2500, 0x01),          # balance: the script needs it at 2500
         f_record(1, 2, 16, 8, b'', 0x01),          # work order : 16-byte records, capacity 8
         f_data  (2, struct.pack('<I', attestation), 0xFE),   # token: exactly 4 bytes
         f_record(3, 3,  8, 4, b'', 0x01)])         # event log  : 8-byte records, capacity 4
    return build([cred, ledger])

def verify_local(card, cardval):
    open('/tmp/solve-card.bin', 'wb').write(card)
    r = subprocess.run([cardval, 'check', '/tmp/solve-card.bin', '--json'],
                       capture_output=True, text=True)
    return json.loads(r.stdout)

def main():
    card = make_card()
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, 'card.bin')
    open(out, 'wb').write(card)
    print(f"[+] built {out}  ({len(card)} bytes)")

    cardval = os.path.join(here, 'work', 'unpacked', 'cardval')
    if os.path.exists(cardval) and os.name != 'nt':
        v = verify_local(card, cardval)
        print(f"[+] local validator: {v}")
        if not v.get('accepted'):
            print("[-] not accepted locally, refusing to submit"); return 1

    if len(sys.argv) > 1:
        url = sys.argv[1].rstrip('/') + '/check'
        html = subprocess.run(['curl', '-sS', '--max-time', '45',
                               '-F', f'card=@{out}', url],
                              capture_output=True, text=True).stdout
        import re
        m = re.search(r'CSCTF\{[^}]+\}', html)
        print("[+] ACCEPTED, grant:", m.group(0) if m else "(no grant found)")
        if not m:
            print("    verdict:", "Accepted" if 'class="accepted"' in html else "Rejected")
    return 0

# --- note on ATTESTATION -------------------------------------------------------
# The last scripted command (INS 0x5e) makes the card return its 4-byte token and
# compares it against cksum() over a serialization of the session state. The token
# is therefore the attestation value. Its expected value for this card template was
# read out of the validator at the comparison point:
#   gdb -batch -ex 'set disable-randomization on' -ex starti \
#       -ex 'break *0x55555556e0d1' -ex c -ex 'info registers r9' \
#       --args ./cardval check card.bin --json
# r9 holds the computed checksum after the final xor-shift (r10 ^ (r10>>15) == r9).
# It depends only on the fixed fields above, so it is a constant for this template;
# change operator_id / balance / window and it must be re-read the same way.
if __name__ == '__main__':
    raise SystemExit(main())
