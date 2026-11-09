# 9164 Phantom Device — state after first work block (2026-11-07 ~22:30Z)

## What it is
Instance runs `socat TCP-LISTEN:1337,fork EXEC:handler.sh`, handler execs `/challenge/client`
as user `ctf`; stdin/stdout are the socket, stdout is redirected to /dev/null, **stderr goes to
the socket** (socat `stderr` option). The client is the vulnerable libimobiledevice AFC client;
we play the malicious iOS device. Flag at /flag.txt (0444, ctf).
Goal: code exec in the client -> `cat /flag.txt >&2` (fd 2 = our socket).

## Root cause (public writeup, CVE-2026-116258 etc., bohmid-com.vercel.app/#/article/blog-afc-writeup)
libimobiledevice afc_receive_data:
```
entire = (uint32)header.entire_length - 40;   // malloc size
this   = (uint32)header.this_length   - 40;   // recv size
buf = malloc(entire);  service_receive(fd, buf, this, &n);   // no this<=entire check
```
Trigger: entire_length = 0x28+small, this_length = 0x28+big -> small chunk, big controlled write.
Related: CVE-116260 double free on receive error; CVE-116261 afc_file_open memcpy(8) from a short
body -> stale heap metadata becomes the file handle and is echoed in the next READ_FILE request.

## Protocol (measured, both local + live)
requests from client (header: magic CFA6LPAA, entire u64, this u64, pnum u64, op u64):
  op 3  READ_DIR        "/" then "/DCIM" then "/var"     payload path+NUL
  op 11 GET_DEVINFO     (no payload)
  op 10 GET_FILE_INFO   "/etc/fstab"
  op 13 FILE_OPEN       {u64 mode=2}{path+NUL}           -> reply DATA(op 2) with 8-byte handle
  op 15 READ_FILE       {u64 handle}{u64 size=0x1000}    -> reply DATA(op 2) with file bytes
  op 20 FILE_CLOSE      {u64 handle}
Replies: STATUS = op 1 with 8-byte error code (0 == ok, zero payload). DATA = op 2 with body.
NOTE: STATUS payload must be exactly 8 bytes; DATA body is returned to the caller.

## Confirmed primitive (LIVE)
Reply to FILE_OPEN with DATA carrying 1 byte 'A', then read the op=15 READ_FILE request:
  handle = 0x62344b941  (bytes: 41 b9 44 23 06 00 00 00)
The 7 bytes after our byte are stale heap data -> heap leak on the real instance.
Local run leaks the same shape (0x5e67ebb41) and prints H1=.. to /dev/null.

## Local harness (works)
files/libdir/ = libimobiledevice-1.0.so.6 + libplist-2.0.so.3 + .so.4 + libusbmuxd-2.0.so.6
(needed both plist sonames: libusbmuxd wants .so.3, libimobiledevice wants .so.4; the provided
libc/ld are unusable on Kali — use the system loader with LD_LIBRARY_PATH=libdir).
  server: python3 work/dev.py 9999   (or work/dev2.py for the DATA/leak reply)
  client: cd files && LD_LIBRARY_PATH=libdir ./client 127.0.0.1 9999
  live:   python3 work/live_leak.py w01.ctf.chronos-security.ro 41483

## Remaining chain (planned, not yet built)
1. Heap leak (done) -> defeats tcache safe-linking (fd = target ^ (chunk>>12)).
2. libc leak: free a >0x410 response buffer into the unsorted bin, then a tiny malloc splits it and
   the uninit 8-byte handle read returns a main_arena pointer.
3. Arbitrary alloc: overflow a freed tcache chunk's fd with the encoded target; two DATA replies
   make malloc return the target and afc_receive_data writes our bytes there.
4. Code exec: write a fake FILE + overwrite _IO_list_all (or _IO_2_1_stdout_) -> house-of-apple
   FSOP at exit -> system("cat /flag.txt >&2").
Fallback: overwrite the afc_client buffer pointer for a fixed-string write; not enough alone.

## Notes
- Do not stop the container; instance endpoint changes if restarted (request again via
  `python ../wave2/container.py request 9164`).
- 3-container team cap; 9165/9159 instances are gone.
