import sys, struct

data = open(sys.argv[1], 'rb').read()
VERBOSE = '-v' in sys.argv

# outer: raw concatenated space packets
pkts = []
i = 0
while i < len(data):
    if i + 6 > len(data):
        sys.exit(f"truncated header at {i}")
    pid, seq, plen = struct.unpack('>HHH', data[i:i+6])
    n = plen + 1
    if i + 6 + n > len(data):
        sys.exit(f"truncated packet at {i}")
    pkts.append((i, pid, seq, data[i+6:i+6+n]))
    i += 6 + n
print("packets:", len(pkts), "consumed exactly:", i == len(data))

TUPLE = (1, 7, 2)
state = 'WAIT_METADATA'
md_size = None
cov = []
snapshot = None
eof_size = None

def parse_pdu(ud):
    if len(ud) < 4:
        return None, "short"
    b0 = ud[0]
    hdr = dict(ver=b0 >> 5, ptype=(b0 >> 4) & 1, dir=(b0 >> 3) & 1, mode=(b0 >> 2) & 1,
               crc=(b0 >> 1) & 1, large=b0 & 1)
    dfl = struct.unpack('>H', ud[1:3])[0]
    b3 = ud[3]
    hdr.update(segctl=b3 >> 7, eidlen=((b3 >> 4) & 7) + 1, segmd=(b3 >> 3) & 1, seqlen=(b3 & 7) + 1)
    hl = 4 + hdr['eidlen'] * 2 + hdr['seqlen']
    if hl + dfl != len(ud):
        return None, f"length mismatch hl={hl} dfl={dfl} ud={len(ud)}"
    e, s = hdr['eidlen'], hdr['seqlen']
    p = 4
    src = int.from_bytes(ud[p:p+e], 'big'); p += e
    sq = int.from_bytes(ud[p:p+s], 'big'); p += s
    dst = int.from_bytes(ud[p:p+e], 'big'); p += e
    hdr.update(src=src, seq=sq, dst=dst, b0=b0, b3=b3)
    return (hdr, ud[p:]), None

for off, pid, seq, ud in pkts:
    pvn = pid >> 13; ptype = (pid >> 12) & 1; shf = (pid >> 11) & 1; apid = pid & 0x7ff
    flags = seq >> 14
    tag = f"@{off:04x} apid={apid:03x} pvn={pvn} t={ptype} shf={shf} fl={flags} cnt={seq & 0x3fff}"
    if not (pvn == 0 and ptype == 0 and apid == 0x321 and shf == 0 and flags == 3):
        if VERBOSE: print(tag, "INELIGIBLE PKT")
        continue
    r, err = parse_pdu(ud)
    if err:
        if VERBOSE: print(tag, "MALFORMED", err)
        continue
    h, df = r
    target = (h['ver'] == 1 and h['dir'] == 0 and h['mode'] == 0 and h['crc'] == 0 and h['large'] == 0
              and h['eidlen'] == 1 and h['seqlen'] == 1 and (h['src'], h['seq'], h['dst']) == TUPLE)
    desc = f"b0={h['b0']:02x} b3={h['b3']:02x} tuple={h['src']:x}/{h['seq']:x}/{h['dst']:x} df={df.hex()}"
    if not target:
        if VERBOSE: print(tag, "NONTARGET", desc)
        continue
    note = ''
    if h['ptype'] == 1:  # file data
        if h['segctl'] != 0 or h['segmd'] != 0:
            note = 'FD bad seg flags'
        elif len(df) < 4:
            note = 'FD short'
        elif state != 'COLLECT':
            note = 'FD discarded (WAIT_METADATA)'
        else:
            o = struct.unpack('>I', df[:4])[0]
            L = len(df) - 4
            end = o + L
            if end > 0xFFFFFFFF:
                note = f'FD wraps {o}+{L}'
            elif end > md_size:
                note = f'FD beyond size [{o},{end})'
            elif snapshot is not None:
                cov.append((o, end)); note = f'FD after EOF [{o},{end}) (post-snapshot)'
            else:
                cov.append((o, end)); note = f'FD ACCEPT [{o},{end})'
    else:
        if not df:
            note = 'empty directive'
        else:
            dc = df[0]
            if dc == 0x07:
                ok = False
                if len(df) >= 8:
                    b = df[1]; fs = struct.unpack('>I', df[2:6])[0]
                    p = 6
                    try:
                        l1 = df[p]; p += 1 + l1
                        l2 = df[p]; p += 1 + l2
                        ok = (p == len(df) and b == 0x0F)
                    except IndexError:
                        ok = False
                if state == 'WAIT_METADATA' and ok:
                    md_size = fs; state = 'COLLECT'; note = f'MD ACCEPT size={fs}'
                else:
                    note = f'MD ignored ok={ok} state={state}'
            elif dc == 0x04:
                ok = (len(df) == 10 and df[1] == 0x00 and df[2:6] == b'\0\0\0\0')
                fs = struct.unpack('>I', df[6:10])[0] if len(df) >= 10 else None
                if state == 'COLLECT' and snapshot is None and ok and fs == md_size:
                    snapshot = list(cov); eof_size = fs; note = f'EOF ACCEPT size={fs}'
                else:
                    note = f'EOF ignored ok={ok} fs={fs} state={state}'
            else:
                note = f'directive {dc:02x} ignored'
    if VERBOSE or 'ACCEPT' in note or 'ignored' in note:
        print(tag, desc[:60], '|', note)

print("md_size", md_size, "eof_size", eof_size)
if snapshot is None:
    sys.exit("no EOF accepted")
# merge coverage
iv = sorted(snapshot)
merged = []
for a, b in iv:
    if a == b: continue
    if merged and a <= merged[-1][1]:
        merged[-1][1] = max(merged[-1][1], b)
    else:
        merged.append([a, b])
print("coverage", merged)
missing = []
cur = 0
for a, b in merged:
    if a > cur: missing.append((cur, min(a, eof_size)))
    cur = max(cur, b)
if cur < eof_size: missing.append((cur, eof_size))
missing = [(a, b) for a, b in missing if a < b]
print("missing", missing)

body = bytes([0x08]) + struct.pack('>II', 0, eof_size) + b''.join(struct.pack('>II', a, b) for a, b in missing)
pdu = bytes([0x28]) + struct.pack('>H', len(body)) + bytes([0x00, 1, 7, 2]) + body
print("CSCTF{" + pdu.hex().upper() + "}")
