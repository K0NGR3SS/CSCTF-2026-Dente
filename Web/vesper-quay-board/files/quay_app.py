"""Vesper quay.

Parses the warrant with Python's json module and runs python3 -I -c only when
the quay courier and the desk courier disagree in the way the duty rule
requires. The child environment is an allowlist. FLAG must not be set.
"""

import hmac
import json
import os
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from warrant import decide
from world import build_world, desk_token, station_seed

MAX_BODY = 65536
STDOUT_MAX = 4096
STDERR_MAX = 1024
TIMEOUT_S = 5


def _hide_process() -> None:
    # The loader child runs with this uid. PR_SET_DUMPABLE=4 hides this
    # process's environment and memory from /proc readers that are not root.
    try:
        import ctypes

        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)
    except Exception:
        pass


def _scope_ptrace() -> None:
    # Under the per-team launcher (docker --init) PID 1 is docker-init. It does
    # not set PR_SET_DUMPABLE=0 and its environment still holds FLAG, so a
    # same-uid loader child could read /proc/1/environ. A Landlock domain on
    # the quay, inherited by the loader child, denies /proc/<pid>/environ and
    # /proc/<pid>/mem of every process outside the domain. Filesystem access is
    # unchanged: the only handled right is make_block, which an unprivileged
    # process cannot use anyway. Fail closed if the kernel lacks Landlock.
    import ctypes
    import struct

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    attr = ctypes.create_string_buffer(struct.pack("=Q", 1 << 11), 8)
    fd = libc.syscall(444, attr, ctypes.c_size_t(8), ctypes.c_uint32(0))
    if fd < 0:
        raise SystemExit("landlock_create_ruleset failed: " + os.strerror(ctypes.get_errno()))
    try:
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise SystemExit("prctl(PR_SET_NO_NEW_PRIVS) failed")
        if libc.syscall(446, ctypes.c_int(fd), ctypes.c_uint32(0)) != 0:
            raise SystemExit("landlock_restrict_self failed: " + os.strerror(ctypes.get_errno()))
    finally:
        os.close(fd)


def _read_seed() -> str:
    seed = os.environ.get("TEAM_SEED", "")
    if seed:
        return seed
    if os.environ.get("SEED_FROM_STDIN") == "1":
        # The supervisor writes the seed to stdin. It stays out of this
        # process's environment.
        line = sys.stdin.readline(1024)
        if line:
            return line.strip()
    raise SystemExit("TEAM_SEED is missing")


class Station:
    def __init__(self):
        _hide_process()
        _scope_ptrace()
        self.seed = _read_seed()
        if os.environ.get("FLAG"):
            raise SystemExit("station must not receive FLAG")
        self.sign_path = os.environ.get("STATION_SIGN", "/usr/local/bin/station-sign")
        self.key_path = os.environ.get("STATION_KEY", "/tmp/station.key")
        self.edge_url = os.environ.get("EDGE_URL", "http://edge:8080").rstrip("/")
        self.world = build_world(self.seed)
        self.token = desk_token(self.seed)
        self._write_key()
        self._self_check()

    def _write_key(self) -> None:
        raw = station_seed(self.seed)
        parent = os.path.dirname(self.key_path) or "."
        os.makedirs(parent, exist_ok=True)
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
        os.chmod(self.key_path, 0o400)

    def _self_check(self) -> None:
        if not os.path.isfile(self.sign_path) or not os.access(self.sign_path, os.X_OK):
            raise SystemExit(f"signing helper missing: {self.sign_path}")
        probe = subprocess.run(
            [self.sign_path],
            input=b"vesper-quay-self-check",
            capture_output=True,
            timeout=2,
            env=self._sign_env(),
            check=False,
        )
        if probe.returncode != 0 or len(probe.stdout) != 64:
            raise SystemExit("signing helper self-check failed")

    def _sign_env(self) -> dict:
        return {
            "PATH": "/usr/local/bin:/usr/bin",
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "STATION_KEY": self.key_path,
            "STATION_SIGN": self.sign_path,
        }

    def authorized(self, headers) -> bool:
        supplied = headers.get("X-Desk-Token") or ""
        if len(supplied) != len(self.token):
            return False
        return hmac.compare_digest(supplied, self.token)

    def _child_env(self, submission_id: str) -> dict:
        # Allowlist. The parent environment, including TEAM_SEED, is not copied.
        return {
            "PATH": "/usr/local/bin:/usr/bin",
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "STATION_KEY": self.key_path,
            "STATION_SIGN": self.sign_path,
            "EDGE_URL": self.edge_url,
            "SUBMISSION_ID": submission_id,
            "QUAY_ID": self.world["quay_id"],
            "WARRANT_ID": self.world["warrant_id"],
            "COURIER_ID": self.world["legacy_courier"],
        }

    def apply(self, headers, raw: bytes) -> dict:
        desk = headers.get("X-Desk-Courier") or ""
        submission = headers.get("X-Submission-Id") or ""
        if not submission or len(submission) > 80:
            raise ValueError("submission id")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("json") from exc
        decision = decide(
            document,
            desk,
            self.world["approved_courier"],
            self.world["legacy_courier"],
        )
        result = {
            "courier": decision["courier"],
            "desk_courier": decision["desk_courier"],
            "loader": decision["loader"],
            "loader_status": decision["loader_status"],
            "argv_ignored": decision["argv_ignored"],
            "loader_exit": None,
            "loader_stdout": "",
            "loader_stderr": "",
        }
        if decision["loader_status"] != "run":
            return result
        return self._run(result, submission, decision["argv"])

    def _run(self, result: dict, submission_id: str, argv: list) -> dict:
        # Fixed interpreter. argv is only "-c" and the script. No shell.
        command = [sys.executable, "-I", *argv]
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd="/tmp",
                env=self._child_env(submission_id),
                start_new_session=True,
            )
        except OSError as exc:
            result["loader_status"] = "error"
            result["loader_stderr"] = str(exc)[:STDERR_MAX]
            return result
        try:
            out, err = proc.communicate(timeout=TIMEOUT_S)
            result["loader_exit"] = proc.returncode
            result["loader_stdout"] = out[:STDOUT_MAX].decode("utf-8", "replace")
            result["loader_stderr"] = err[:STDERR_MAX].decode("utf-8", "replace")
            result["loader_status"] = "ok" if proc.returncode == 0 else "error"
        except subprocess.TimeoutExpired:
            _kill_group(proc.pid)
            out, err = proc.communicate()
            result["loader_status"] = "timed_out"
            result["loader_exit"] = None
            result["loader_stdout"] = out[:STDOUT_MAX].decode("utf-8", "replace")
            result["loader_stderr"] = err[:STDERR_MAX].decode("utf-8", "replace")
        finally:
            if proc.poll() is None:
                _kill_group(proc.pid)
                try:
                    proc.wait(timeout=1)
                except (subprocess.TimeoutExpired, OSError):
                    pass
        return result


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return


def _listen():
    raw = os.environ.get("LISTEN", "127.0.0.1:18472")
    host, _, port = raw.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit("LISTEN must be host:port")
    return host, int(port)


def make_handler(station: Station):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._send(200, {"status": "ok"})
                return
            if path == "/internal/warrant":
                if not station.authorized(self.headers):
                    self._send(401, {"error": "UNAUTHORIZED"})
                    return
                self._send(200, station.world)
                return
            self._send(404, {"error": "NOT_FOUND"})

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if path != "/internal/apply":
                self._send(404, {"error": "NOT_FOUND"})
                return
            if not station.authorized(self.headers):
                self._send(401, {"error": "UNAUTHORIZED"})
                return
            length = int(self.headers.get("Content-Length") or "0")
            if length < 0 or length > MAX_BODY:
                self._send(400, {"error": "BAD_WARRANT"})
                return
            raw = self.rfile.read(length) if length else b""
            try:
                body = station.apply(self.headers, raw)
            except ValueError:
                self._send(400, {"error": "BAD_WARRANT"})
                return
            self._send(200, body)

        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _send(self, status, payload):
            raw = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

    return Handler


def main():
    station = Station()
    host, port = _listen()
    httpd = ThreadingHTTPServer((host, port), make_handler(station))

    def stop(signum, frame):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    httpd.serve_forever()


if __name__ == "__main__":
    main()

