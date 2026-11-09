#!/usr/bin/env python3
# warden - one line, no builtins, and someone is always listening.
#
# You get a single line of Python. There are no builtins. And an audit hook
# watches every interesting thing the interpreter does - open a file, import a
# module, spawn a process, compile more code - and the moment it hears one, it
# pulls the plug. The flag is on the machine. Good luck.
import ast
import os
import sys

MAX_LEN = 4096

BANNER = r"""
 __      __                 .___
/  \    /  \_____ _______  __| _/____   ____
\   \/\/   /\__  \\_  __ \/ __ |/ __ \ /    \
 \        /  / __ \|  | \/ /_/ \  ___/|   |  \
  \__/\  /  (____  /__|  \____ |\___  >___|  /
       \/        \/           \/    \/     \/

The warden hears every word the interpreter says, and lets you say one line.
No builtins. No imports. No second chances.
"""


def check(src):
    """Static gate. The real lock is the audit hook; this just sets the rules:
    one line, no import statements, must parse."""
    if not src.strip():
        return "silence is not an answer"
    if len(src) > MAX_LEN:
        return "the warden stopped listening"
    if "\n" in src.strip("\n"):
        return "one line only"
    try:
        tree = ast.parse(src, mode="exec")
    except SyntaxError:
        return "the warden does not understand you"
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return "nothing comes in from outside"
    return None


def seal():
    """Install the warden: an audit hook that lets through only attribute reads
    (object.__getattr__) and the jail's own single exec. Anything else - open,
    import, subprocess, compile, a second exec, a ctypes dlopen - is fatal.

    The hook is a closure over locals only (os._exit, os.write captured by
    value), so code running under the empty-builtins namespace has nothing to
    grab to loosen or remove it. Audit hooks cannot be unregistered anyway."""
    die, shout = os._exit, os.write
    budget = [True]  # exactly one exec is allowed: the jail's own, below

    def warden(event, args):
        if event == "object.__getattr__":
            return
        if event == "exec" and budget:
            budget.pop()
            return
        shout(2, b"\n[warden] I heard that: " + event.encode() + b"\n")
        die(1)

    sys.addaudithook(warden)


def main():
    sys.stdout.write(BANNER + "\n> ")
    sys.stdout.flush()

    line = sys.stdin.readline()
    if not line:
        return
    src = line.rstrip("\r\n")

    why = check(src)
    if why:
        sys.stdout.write(why + "\n")
        sys.stdout.flush()
        return

    code = compile(src, "<cell>", "exec")  # compile BEFORE sealing (compile is audited)
    seal()
    try:
        exec(code, {"__builtins__": {}})
    except BaseException as e:
        # name only; never let an exception drag a live object back to the user
        os.write(1, b"the warden frowns: " + type(e).__name__.encode() + b"\n")


if __name__ == "__main__":
    main()
    sys.stdout.flush()
    os._exit(0)
