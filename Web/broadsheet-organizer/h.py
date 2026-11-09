
import socket, re, sys, json

import os
HOST=os.environ.get("CTF_HOST","w05.ctf.chronos-security.ro"); PORT=int(os.environ.get("CTF_PORT","33700"))

def req(path, headers=None, method=b"GET", body=None, timeout=10):
    """path: str or bytes (already %-encoded, may contain raw high bytes if bytes)"""
    hdrs = {"Host": HOST+":"+str(PORT), "User-Agent":"probe/1.0", "Accept":"*/*"}
    if headers: hdrs.update(headers)
    if body is not None:
        hdrs.setdefault("Content-Length", str(len(body)))
        hdrs.setdefault("Content-Type","application/x-www-form-urlencoded")
    p = path.encode("latin-1") if isinstance(path,str) else path
    raw = method+b" "+p+b" HTTP/1.1\r\n"
    for k,v in hdrs.items():
        raw += (k+": "+v).encode("latin-1")+b"\r\n"
    raw += b"\r\n" + (body or b"")
    s=socket.create_connection((HOST,PORT), timeout=timeout)
    s.sendall(raw)
    data=b""
    while True:
        try: chunk=s.recv(65536)
        except socket.timeout: break
        if not chunk: break
        data+=chunk
        if b"\r\n\r\n" in data:
            head,_,rest = data.partition(b"\r\n\r\n")
            m=re.search(rb"content-length:\s*(\d+)", head, re.I)
            if m and len(rest) >= int(m.group(1)): break
            if b"transfer-encoding: chunked" in head.lower():
                # crude: stop when terminal chunk present
                if rest.endswith(b"0\r\n\r\n"): break
    s.close()
    head,_,rest = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin-1")
    h = {}
    for ln in lines[1:]:
        k,_,v = ln.partition(b":")
        h[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    if h.get("transfer-encoding","").lower()=="chunked":
        out=b""
        i=0
        while True:
            j=rest.find(b"\r\n", i)
            if j<0: break
            n=int(rest[i:j].split(b";")[0],16)
            if n==0: break
            out+=rest[j+2:j+2+n]
            i=j+2+n+2
        body_b=out
    else:
        cl = int(h.get("content-length","-1"))
        body_b = rest if cl<0 else rest[:cl]
    return status, h, body_b

def tick(slot, text_bytes=None, extra_q=b"", headers=None, raw_query=None):
    if raw_query is not None:
        q = raw_query
    elif text_bytes is None:
        q = b""
    else:
        q = b"?text="+text_bytes
    p = b"/z/"+slot.encode()+b"/ticker.js"+q+extra_q
    return req(p, headers)

if __name__=="__main__":
    st,h,b = tick("ismoke0", b"hello")
    print(st); print({k:v for k,v in h.items() if k.lower() in ("content-type","cache-control","x-cache","content-length","x-content-type-options")})
    print(repr(b))
