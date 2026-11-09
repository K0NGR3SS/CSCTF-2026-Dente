# warden

**Author:** mar

**Misc** · 282 pts
Handout: [warden.tar.gz](files/warden.tar.gz) — `jail.py`

**TL;DR.** A one-line Python jail with no builtins and an audit hook that kills the interpreter on
almost every interesting event. The flag is in the environment, and reading `os.environ` raises no
audit event at all. `os` is reachable without builtins by walking `__subclasses__()` to
`_wrap_close`, whose `__init__` globals still hold `sys`; `os.write` then prints the environment.

## Solve

**The jail.** `jail.py` reads one line (4096 bytes max), rejects newlines and import statements,
compiles it *before* sealing, then installs an audit hook and executes with an empty builtins dict:

```python
exec(code, {"__builtins__": {}})
```

The hook lets through exactly two events: `object.__getattr__` (attribute reads) and the jail's own
single `exec` (a one-shot budget). Everything else — `open`, `import`, `subprocess`, `compile`, a
second `exec`, a `ctypes` dlopen — writes `[warden] I heard that: <event>` to stderr and exits.

**The blind spot.** Environment access is not audited. Neither is `os.write`. Attribute reads are
explicitly allowed, so the only problem is reaching a module object without importing one.

`object.__subclasses__()` gives every loaded class. `_wrap_close` is the class of the file objects
behind `sys.stdout`; its `__init__.__globals__` is the `subprocess` module globals, which contain
`sys`. From there `sys.modules['os']` is a direct reference:

```python
o=[c.__init__.__globals__['sys'].modules['os'] for c in ().__class__.__base__.__subclasses__() if c.__name__=='_wrap_close'][0]; o.write(1, o.environ.__repr__().encode())
```

Sent as the single line, it prints the full environment including `FLAG`, and the audit hook never
fires because no audited operation occurred.

**Flag:** `CSCTF{olnArD3F1Qvhne9eJ6i6jssW}`

**Evidence.** The flag literal is in `ctf-telecom/wave2/attempts_log.json` (`cid 9143`,
`status: correct`; CTFd solve 2026-11-07T13:15:03Z, 0 solves on the board when it fell). The exact
payload and the audit-event reasoning are preserved in `ctf-telecom/wave3/POSTMORTEMS.md`, written
from the live solve. `jail.py` is the captured handout and is copied here; `warden.tar.gz` is the
original archive found under `ctf-telecom/wave2/chal/9143/files/`.
