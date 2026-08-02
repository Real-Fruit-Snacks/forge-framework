"""Integration tests against real lab containers.

Skipped entirely when the docker daemon is unreachable, so the suite stays
green on machines without docker running. With docker up, this exercises the
full loop: lab up -> module against real service -> assertions -> lab down.

Run: python3 -m unittest discover -s tests
"""

import base64
import contextlib
import http.client
import importlib.util
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
from core.lab import LabManager  # noqa: E402
from core.registry import ModuleRegistry  # noqa: E402
from core.store import Store  # noqa: E402

output.color_enabled = False

HOST = "127.0.0.1"
PORT = 18080


def docker_available():
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=15
        )
        return proc.returncode == 0
    except Exception:
        return False


def get(path, headers=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
class _WebLabCase(unittest.TestCase):
    """Shared fixture: web lab up before the class, down after."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("web")
        deadline = time.time() + 30
        while True:
            try:
                if get("/") == 200:
                    break
            except OSError:
                pass
            if time.time() > deadline:
                cls.manager.down("web")
                raise RuntimeError("web lab did not come up within 30s")
            time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("web")

    def setUp(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        self.console = FrameworkConsole(registry, Store(":memory:"))

    def tearDown(self):
        self.console.store.close()

    def console_out(self, *commands):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            for command in commands:
                self.console.onecmd(command)
        return buf.getvalue()


class TestWebLab(_WebLabCase):
    def test_http_headers_module_against_lab(self):
        out = self.console_out(
            "use auxiliary/scanner/http_headers",
            f"set RHOSTS {HOST}",
            f"set RPORT {PORT}",
            "run",
        )
        self.assertIn("FrameworkLab", out)
        services = self.console.store.services(HOST)
        self.assertEqual([s["port"] for s in services], [PORT])

    def test_dir_busting_fixture(self):
        # the contract a dir-buster module must handle: real 200s, a 403,
        # a 401, and decoy 404s (see labs/web/wordlists/dirs.txt)
        for path, want in (
            ("/admin", 200), ("/backup", 200), ("/secret", 200),
            ("/forbidden", 403), ("/protected", 401), ("/wp-admin", 404),
        ):
            self.assertEqual(get(path), want, path)

    def test_basic_auth_fixture(self):
        self.assertEqual(get("/protected"), 401)
        creds = base64.b64encode(b"admin:hunter2").decode()
        self.assertEqual(
            get("/protected", {"Authorization": f"Basic {creds}"}), 200
        )


class TestHttpLoginLab(_WebLabCase):
    def _run_login(self, mode, path, extra):
        wordlist = ROOT / "labs" / "web" / "wordlists" / "passwords.txt"
        return self.console_out(
            "use auxiliary/login/http_login",
            f"set RHOSTS {HOST}",
            f"set RPORT {PORT}",
            f"set MODE {mode}",
            f"set TARGETPATH {path}",
            "set USERNAME admin",
            f"set PASS_FILE {wordlist}",
            *extra,
            "run",
        )

    def test_basic_mode_finds_cred(self):
        out = self._run_login("basic", "/protected", [])
        self.assertIn("admin:hunter2", out)
        creds = self.console.store.creds()
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["username"], "admin")
        self.assertEqual(creds[0]["password"], "hunter2")
        self.assertEqual(creds[0]["service"], "http")

    def test_form_mode_finds_cred_with_baseline(self):
        # no SUCCESS/FAILURE strings set: baseline deviation must do the job
        out = self._run_login("form", "/login", [])
        self.assertIn("admin:hunter2", out)
        self.assertEqual(len(self.console.store.creds()), 1)
        # second run: stored creds are tried first — findings compound
        out2 = self._run_login("form", "/login", [])
        self.assertIn("stored credential", out2)

    def test_wrong_password_no_false_positive(self):
        out = self.console_out(
            "use auxiliary/login/http_login",
            f"set RHOSTS {HOST}",
            f"set RPORT {PORT}",
            "set MODE basic",
            "set TARGETPATH /protected",
            "set USERNAME admin",
            "set PASSWORD definitely-wrong",
            "run",
        )
        self.assertNotIn("[+]", out)
        self.assertEqual(self.console.store.creds(), [])


class TestDirBusterLab(_WebLabCase):
    def test_dirbuster_finds_hits_filters_decoys(self):
        wordlist = ROOT / "labs" / "web" / "wordlists" / "dirs.txt"
        out = self.console_out(
            "use auxiliary/scanner/dir_buster",
            f"set RHOSTS {HOST}",
            f"set RPORT {PORT}",
            f"set WORDLIST {wordlist}",
            "run",
        )
        # every real hit, across statuses
        for hit in ("/admin", "/backup", "/secret", "/uploads", "/api", "/docs"):
            self.assertIn(hit, out)
        self.assertIn("403 /forbidden", out)
        self.assertIn("401 /protected", out)
        # decoys must not appear as findings
        self.assertNotIn("/wp-admin", out)
        self.assertNotIn("/phpmyadmin", out)
        self.assertNotIn("/config", out)
        # findings recorded as loot
        loot = self.console.store.loot("web-dirs")
        self.assertEqual(len(loot), 1)
        self.assertIn("/admin", loot[0]["content"])

    def test_recursion_finds_depth_two(self):
        wordlist = ROOT / "labs" / "web" / "wordlists" / "dirs.txt"
        out = self.console_out(
            "use auxiliary/scanner/dir_buster",
            f"set RHOSTS {HOST}",
            f"set RPORT {PORT}",
            f"set WORDLIST {wordlist}",
            "set RECURSE true",
            "set MAX_DEPTH 2",
            "run",
        )
        # panel/db 404 at root but exist under /admin and /backup
        self.assertIn("/admin/panel", out)
        self.assertIn("/backup/db", out)
        self.assertNotIn("[+] 404", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
class TestSshLab(unittest.TestCase):
    """Smoke test: the ssh lab builds, starts, and speaks SSH."""

    SSH_PORT = 12222

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ssh")
        cls.banner = ""
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, cls.SSH_PORT), timeout=2) as s:
                    cls.banner = s.recv(64).decode(errors="replace").strip()
                    if cls.banner:
                        break
            except OSError:
                time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ssh")

    def test_ssh_banner(self):
        self.assertTrue(
            self.banner.startswith("SSH-"),
            f"expected an SSH banner, got {self.banner!r}",
        )


def paramiko_available():
    return importlib.util.find_spec("paramiko") is not None

@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(paramiko_available(), "paramiko not installed")
class TestSshLoginLab(unittest.TestCase):
    """ssh_login against the real ssh lab container."""

    SSH_PORT = 12222

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ssh")
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, cls.SSH_PORT), timeout=2) as s:
                    if s.recv(64):
                        break
            except OSError:
                time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ssh")

    def test_ssh_brute_finds_cred(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            wordlist = ROOT / "labs" / "web" / "wordlists" / "passwords.txt"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/login/ssh_login",
                    f"set RHOSTS {HOST}",
                    f"set RPORT {self.SSH_PORT}",
                    "set USERNAME admin",
                    f"set PASS_FILE {wordlist}",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertIn("admin:admin", out)
            creds = console.store.creds()
            self.assertEqual(len(creds), 1)
            self.assertEqual(creds[0]["service"], "ssh")
        finally:
            console.store.close()


def impacket_available():
    return importlib.util.find_spec("impacket") is not None


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestSmbEnumLab(unittest.TestCase):
    """smb_enum against the real Samba lab container."""

    SMB_PORT = 10445

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("smb")
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                SMBConnection(HOST, HOST, sess_port=cls.SMB_PORT, timeout=2).close()
                break
            except Exception:
                time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("smb")

    def test_smb_enum_finds_shares_and_signing(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/scanner/smb_enum",
                    f"set RHOSTS {HOST}",
                    f"set RPORT {self.SMB_PORT}",
                    "set USERNAME labuser",
                    "set PASSWORD labpass",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertIn("signing NOT required", out)
            self.assertIn("public", out)
            self.assertIn("labuser", out)
            loot = console.store.loot("smb-shares")
            self.assertEqual(len(loot), 1)
            self.assertIn("public", loot[0]["content"])
        finally:
            console.store.close()


if __name__ == "__main__":
    unittest.main()
