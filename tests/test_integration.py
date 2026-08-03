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


def windows_lab_enabled():
    """Opt-in: first boot installs Windows (~20 min), so this is off
    unless FORGE_WINDOWS_LAB=1 is set in the environment."""
    return os.environ.get("FORGE_WINDOWS_LAB") == "1"


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
@unittest.skipUnless(windows_lab_enabled(), "set FORGE_WINDOWS_LAB=1 to enable")
class TestWindowsLab(unittest.TestCase):
    """windows lab: real Windows Server answers SMB with the lab creds."""

    @classmethod
    def setUpClass(cls):
        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("windows")  # READY waits for guest SMB (2400s cap)

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
class TestAdEnumLab(unittest.TestCase):
    """ad_enum against the Samba AD DC lab (provisions on first boot)."""

    @classmethod
    def setUpClass(cls):
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        # first boot provisions the domain (~30-60s) — poll a real bind
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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

    def test_asreproast_graceful_when_kdc_refuses(self):
        # The Samba AD KDC in this build does not honor
        # UF_DONT_REQUIRE_PREAUTH (or NO_AUTH_DATA_REQUIRED): it demands
        # preauth from every account, so AS-REP roasting is impossible
        # against it. The module must handle that cleanly: no traceback,
        # no hashes, honest summary. (Against a Windows KDC it roasts.)
        out, hashes = self._run(
            "use auxiliary/attack/asreproast",
            f"set RHOSTS {HOST}",
            "set DOMAIN forge.local",
            "set USERS noauth,analyst",
            "run",
        )
        self.assertNotIn("Traceback", out)
        self.assertIn("0/2 roastable", out)
        self.assertEqual(hashes, [])


@unittest.skipUnless(docker_available(), "docker daemon not available")
@unittest.skipUnless(impacket_available(), "impacket not installed")
class TestDelegationLab(unittest.TestCase):
    """delegation against the AD lab's delegation fixtures."""

    @classmethod
    def setUpClass(cls):
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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
class TestDcSyncLab(unittest.TestCase):
    """dcsync against the AD lab: Administrator replicates the directory.
    Exercises the pinned RPC range (135 + 49152-49160) end to end."""

    @classmethod
    def setUpClass(cls):
        from impacket.ldap import ldap as impacket_ldap

        cls.manager = LabManager(ROOT / "labs")
        cls.manager.up("ad")
        # docker-proxy accepts on 445 the moment the container starts, long
        # before provisioning finishes — wait for a real LDAP bind instead
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                conn = impacket_ldap.LDAPConnection("ldap://127.0.0.1")
                conn.login("Administrator", "P@ssw0rd123", "forge.local")
                break
            except Exception:
                time.sleep(2)
        else:
            cls.manager.down("ad")
            raise RuntimeError("AD lab did not provision within 120s")

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


if __name__ == "__main__":
    unittest.main()
