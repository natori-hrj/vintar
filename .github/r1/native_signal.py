"""Send real native interrupts to the public product process."""

import ctypes
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time


class Blocked(Exception):
    pass


def interrupt(args, cwd, ready, delay):
    if os.name == "nt":
        request = json.dumps([list(map(str, args)), str(cwd), str(ready) if ready else None, delay])
        try:
            worker = subprocess.run([sys.executable, "-B", __file__, request], capture_output=True,
                                    text=True, encoding="utf-8", timeout=20,
                                    creationflags=subprocess.CREATE_NEW_CONSOLE)
        except OSError as error:
            raise Blocked(f"could not create a separate Windows console: {error}") from error
        if worker.returncode:
            raise AssertionError(f"console worker failed: {worker.stderr[-700:]}")
        return decode_worker(worker.stdout)
    return interrupt_child(args, cwd, ready, delay)


def decode_worker(output):
    outcome, payload = json.loads(output)
    if outcome == "blocked":
        raise Blocked(payload)
    if outcome != "observed":
        raise AssertionError(payload)
    return tuple(payload)


def interrupt_child(args, cwd, ready, delay):
    with subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            if ready:
                until = time.monotonic() + 6
                while not ready.exists() and child.poll() is None and time.monotonic() < until:
                    time.sleep(0.01)
                if child.poll() is None and not ready.exists():
                    raise AssertionError("local HTTP server did not receive a request before interruption")
            else:
                time.sleep(delay)
            if child.poll() is None:
                if os.name == "nt":
                    if not ctypes.windll.kernel32.GenerateConsoleCtrlEvent(0, 0):
                        raise Blocked("GenerateConsoleCtrlEvent(CTRL_C_EVENT) failed")
                else:
                    try:
                        child.send_signal(signal.SIGINT)
                    except ProcessLookupError:
                        pass  # The command finished before signal delivery.
            stdout, stderr = child.communicate(timeout=8)
            return child.returncode, stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")
        finally:
            if child.poll() is None:
                child.kill()


def worker():
    # The worker owns a separate console. Ignore Ctrl+C only in the worker,
    # using a callback, so the actual product child still receives it.
    callback_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)
    callback = callback_type(lambda code: int(code == 0))
    if not ctypes.windll.kernel32.SetConsoleCtrlHandler(callback, True):
        raise Blocked("SetConsoleCtrlHandler failed")
    args, cwd, ready, delay = json.loads(sys.argv[1])
    result = interrupt_child(args, cwd, Path(ready) if ready else None, delay)
    print(json.dumps(["observed", result]))


def http_send(binary):
    with tempfile.TemporaryDirectory(prefix="vintar-r1-interrupt-") as temp:
        work = Path(temp)
        ready = work / "request-received"
        release = threading.Event()
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                ready.touch()
                release.wait(15)

            def log_message(self, *args):
                pass

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                uri = f"http://127.0.0.1:{server.server_port}/interrupt-fixture"
                code, stdout, stderr = interrupt([binary, "http", "send", "GET", uri, "-t", "20"],
                                                work, ready, 0)
                if code != 130 or stdout or stderr != "Error: interrupted\n" or received != ["/interrupt-fixture"]:
                    raise AssertionError(f"unexpected interruption: {(code, stdout, stderr, received)!r}")
            finally:
                release.set()
                server.shutdown()
                thread.join()
    return "native Ctrl+C/SIGINT after one loopback request: exit 130, no summary or resend"


def offline(root, binary, command):
    spec = (root / "tests/fixtures/discovery/openapi30.json").read_bytes()
    if command == "discover":
        document = json.loads(spec)
        paths = document["paths"]
        fixture_path = paths["/a"]
        for index in range(160):
            paths[f"/r1-fixture-{index}"] = fixture_path
        spec = json.dumps(document, separators=(",", ":")).encode()
    if len(spec) > 900_000:
        raise AssertionError("offline cancellation input is too large")
    golden = root / "tests/golden/cli/discover/drafts.json"
    drafts = json.loads(golden.read_bytes())["draft_files"]
    name, draft = next((name, draft) for name, draft in drafts.items() if name.startswith("case-24a9c"))
    observed = []
    for delay in (0.002, 0.003, 0.004, 0.006, 0.009, 0.014, 0.023, 0.040):
        with tempfile.TemporaryDirectory(prefix="vintar-r1-interrupt-") as temp:
            work = Path(temp)
            (work / "openapi.json").write_bytes(spec.ljust(900_000, b" "))
            (work / name).write_text(draft, encoding="utf-8")
            (work / "answers.json").write_text(
                '{"version":1,"expected_verdict":"not_detected","parameters":{"q":{"value":"fixture-baseline"}}}',
                encoding="utf-8")
            args = [binary, command, "--spec", "openapi.json", "--output", "report.json"]
            if command == "review-draft":
                args += ["--draft", name, "--answers", "answers.json"]
            code, stdout, stderr = interrupt(args, work, None, delay)
            observed.append(code)
            if code == 130:
                if stdout or "interrupted" not in stderr:
                    raise AssertionError(f"{command}: interruption violated output boundary: {(stdout, stderr)!r}")
                if (work / "report.json").exists():
                    json.loads((work / "report.json").read_bytes())
                    continue  # A complete artifact may already have been published.
                return f"native interrupt before publication: exit 130, no report (attempt exits {observed})"
            if code not in (0, -signal.SIGINT, 0xC000013A):
                raise AssertionError(f"{command}: unexpected exit {code}: {stderr[-700:]}")
    raise Blocked(f"no controllable pre-publication signal window; observed exits {observed}")


if __name__ == "__main__":
    try:
        worker()
    except Blocked as error:
        print(json.dumps(["blocked", str(error)]))
    except Exception as error:
        print(json.dumps(["failed", f"{type(error).__name__}: {error}"]))
