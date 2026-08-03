"""Unit tests for the login spray modules (load fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ll = load("ldap_login_mod", "modules/auxiliary/login/ldap_login.py")
ms = load("multi_spray_mod", "modules/auxiliary/login/multi_spray.py")
mq = load("mssql_login_mod", "modules/auxiliary/login/mssql_login.py")
wr = load("winrm_login_mod", "modules/auxiliary/login/winrm_login.py")


class TestLdapBindClassifier(unittest.TestCase):
    def test_win32_subcodes(self):
        self.assertEqual(ll.classify_bind_error("... data 52e ...")[0], "fail")
        self.assertEqual(ll.classify_bind_error("... data 775 ...")[0], "locked")
        self.assertEqual(ll.classify_bind_error("... data 532 ..."),
                         ("success", "valid, password expired"))
        self.assertEqual(ll.classify_bind_error("... data 773 ..."),
                         ("success", "valid, must change password"))
        verdict, note = ll.classify_bind_error("... data 533 ...")
        self.assertEqual(verdict, "fail")
        self.assertIn("disabled", note)

    def test_ntstatus_names(self):
        self.assertEqual(
            ll.classify_bind_error("NT_STATUS_LOGON_FAILURE")[0], "fail")
        self.assertEqual(
            ll.classify_bind_error("NT_STATUS_ACCOUNT_LOCKED_OUT")[0], "locked")
        self.assertEqual(
            ll.classify_bind_error("NT_STATUS_PASSWORD_EXPIRED")[0], "success")

    def test_unknown_is_plain_fail(self):
        verdict, _ = ll.classify_bind_error("some other bind error")
        self.assertEqual(verdict, "fail")


class TestMultiSprayMaps(unittest.TestCase):
    def test_default_ports_round_trip(self):
        for proto, port in ms.DEFAULT_PORTS.items():
            self.assertEqual(ms.PORT_TO_PROTO[port], proto)

    def test_hints_cover_all_protocols(self):
        self.assertEqual(sorted(ms.HINTS), sorted(ms.DEFAULT_PORTS))

    def test_ntstatus_free_requirements(self):
        self.assertIn("impacket", ms.MultiSpray.requirements)
        self.assertIn("paramiko", ms.MultiSpray.requirements)


class TestModuleContracts(unittest.TestCase):
    def test_requirements_declared(self):
        self.assertIn("impacket", ll.LdapLogin.requirements)
        self.assertIn("impacket", mq.MssqlLogin.requirements)
        self.assertIn("winrm", wr.WinrmLogin.requirements)

    def test_modules_load_without_deps(self):
        for cls in (ll.LdapLogin, ms.MultiSpray, mq.MssqlLogin,
                    wr.WinrmLogin):
            self.assertIsNotNone(cls)


if __name__ == "__main__":
    unittest.main()
