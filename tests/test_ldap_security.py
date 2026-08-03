"""Unit tests for ldap_security's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ldap_sec_mod", ROOT / "modules" / "auxiliary" / "enum" / "ldap_security.py"
)
ls = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ls)


class TestClassifyBindError(unittest.TestCase):
    def test_stronger_auth_means_required(self):
        self.assertEqual(ls.classify_bind_error(
            "LDAPStrongerAuthRequiredError: strongerAuthRequired"), "required")
        self.assertEqual(ls.classify_bind_error("signing required by policy"),
                         "required")

    def test_other_errors_are_errors(self):
        self.assertEqual(ls.classify_bind_error("invalidCredentials"), "error")
        self.assertEqual(ls.classify_bind_error("connection refused"), "error")


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ls.LdapSecurity.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ls.LdapSecurity)


if __name__ == "__main__":
    unittest.main()
