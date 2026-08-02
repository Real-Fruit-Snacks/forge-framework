"""End-to-end handler tests: jobbed listener + real generated payload.

Run: python3 -m unittest discover -s tests
"""

import contextlib
import io
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import output  # noqa: E402
from core.console import FrameworkConsole  # noqa: E402
from core.registry import ModuleRegistry  # noqa: E402
from core.store import Store  # noqa: E402

output.color_enabled = False


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class TestHandler(unittest.TestCase):
    def setUp(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        self.console = FrameworkConsole(registry, Store(":memory:"))
        self.port = free_port()

    def tearDown(self):
        self.console.store.close()

    def cmd(self, *commands):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            for command in commands:
                self.console.onecmd(command)
        return buf.getvalue()

    def start_handler(self):
        self.cmd(
            "use exploits/multi/handler",
            "set LHOST 127.0.0.1",
            f"set LPORT {self.port}",
            "run -j",
        )
        job = self.console.jobs.all()[0]
        self.assertTrue(
            wait_for(lambda: "Listening" in job.output_text()),
            f"handler never listened: {job.output_text()}",
        )
        return job

    def test_payload_to_session_to_shell(self):
        job = self.start_handler()

        # generate the real payload and fire it at the handler
        out = self.cmd(
            "back",
            "use payloads/python_reverse_tcp",
            "set LHOST 127.0.0.1",
            f"set LPORT {self.port}",
            "generate",
        )
        payload = [line for line in out.splitlines() if line.startswith("python3 -c")]
        self.assertTrue(payload, f"no payload generated: {out}")
        proc = subprocess.Popen(
            payload[0], shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            self.assertTrue(
                wait_for(lambda: len(self.console.sessions.all()) == 1),
                "payload never connected",
            )
            # announcement fires on the next console command
            announced = self.cmd("sessions")
            self.assertIn("Session 1 opened", announced)

            # drive the shell through the session socket
            session = self.console.sessions.get(1)
            session.sock.settimeout(10)
            session.send("echo $((6*7))\n")
            data = b""
            deadline = time.time() + 10
            while b"42" not in data and time.time() < deadline:
                try:
                    data += session.recv(4096)
                except socket.timeout:
                    break
            self.assertIn(b"42", data)
        finally:
            proc.kill()

        # cooperative stop via jobs -k
        self.cmd("back", f"jobs -k {job.id}")
        self.assertTrue(wait_for(lambda: not job.running, timeout=5))
        self.assertIn("Handler stopped", job.output_text())

    def test_stop_without_connections(self):
        job = self.start_handler()
        self.cmd(f"jobs -k {job.id}")
        self.assertTrue(wait_for(lambda: not job.running, timeout=5))
        self.assertEqual(job.status, "done")


if __name__ == "__main__":
    unittest.main()
