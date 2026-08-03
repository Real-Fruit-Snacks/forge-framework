"""Unit tests for the xfer module, serve command, and netutil helpers.

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import ipaddress
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "xfer_mod", ROOT / "modules" / "auxiliary" / "transfer" / "xfer.py"
)
xf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(xf)

from core.netutil import detect_local_ip, psq  # noqa: E402


class TestFetchLines(unittest.TestCase):
    def test_linux_pair(self):
        primary, alt = xf.fetch_lines("http://10.0.0.1:8000/f", "/tmp/f", "linux")
        self.assertIn("curl -fsSL", primary)
        self.assertIn("wget -q", alt)

    def test_windows_pair(self):
        primary, alt = xf.fetch_lines("http://10.0.0.1:8000/f",
                                      r"C:\Temp\f", "windows")
        self.assertIn("curl.exe", primary)  # curl is an Invoke-WebRequest alias
        self.assertIn("certutil -urlcache", alt)


class TestServeStaging(unittest.TestCase):
    def test_404_written_before_symlink(self):
        line = xf.http_serve_line("./payload.sh", 8000)
        self.assertLess(line.index("index.html"), line.index("ln -sf"))
        self.assertIn("rm -rf", line)  # staging resets each run

    def test_ps_upload_line(self):
        line = xf.ps_upload_line("10.10.14.5", 8000, r"C:\Temp\l.zip")
        self.assertIn("TcpClient('10.10.14.5',8000)", line)
        self.assertIn(r"ReadAllBytes('C:\Temp\l.zip')", line)


class TestQuoting(unittest.TestCase):
    def test_psq_doubles_quotes(self):
        self.assertEqual(psq("a'b"), "'a''b'")
        self.assertEqual(psq("plain"), "'plain'")


class TestDetectLocalIp(unittest.TestCase):
    def test_returns_ipv4(self):
        ip = detect_local_ip()
        ipaddress.IPv4Address(ip)  # raises when malformed


class TestModuleContract(unittest.TestCase):
    def test_no_requirements(self):
        self.assertEqual(xf.Xfer.requirements, [])


class TestServeCommand(unittest.TestCase):
    """serve stages behind a 404, serves the file, and stops cleanly."""

    def test_serve_and_off(self):
        import contextlib
        import io
        import urllib.request

        from core.console import FrameworkConsole
        from core.registry import ModuleRegistry
        from core.store import Store

        payload = Path(self._testMethodName + ".tmp")
        payload.write_text("hello forge")
        try:
            console = FrameworkConsole(ModuleRegistry(ROOT / "modules"),
                                       Store(":memory:"))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                console.onecmd(f"serve {payload} 18098")
            out = buf.getvalue()
            self.assertIn("serving", out)
            self.assertIn("root answers 404", out)

            body = urllib.request.urlopen(
                "http://127.0.0.1:18098/" + payload.name, timeout=5).read()
            self.assertEqual(body, b"hello forge")
            root = urllib.request.urlopen(
                "http://127.0.0.1:18098/", timeout=5).read().decode()
            self.assertIn("404 Not Found", root)

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                console.onecmd("serve off")
            self.assertIn("stopped", buf.getvalue())
        finally:
            payload.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
