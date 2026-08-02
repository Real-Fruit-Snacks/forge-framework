"""Unit tests for ad_enum's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ad_enum_mod", ROOT / "modules" / "auxiliary" / "enum" / "ad_enum.py"
)
ae = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ae)


class TestHelpers(unittest.TestCase):
    def test_domain_to_base(self):
        self.assertEqual(ae.domain_to_base("forge.local"), "DC=forge,DC=local")
        self.assertEqual(ae.domain_to_base("corp.acme.io"),
                         "DC=corp,DC=acme,DC=io")

    def test_entry_to_dict(self):
        entry = {"attributes": [
            {"type": "sAMAccountName", "vals": ["analyst"]},
            {"type": "servicePrincipalName", "vals": ["HTTP/web", "HTTP/web2"]},
        ]}
        attrs = ae.entry_to_dict(entry)
        self.assertEqual(attrs["sAMAccountName"], ["analyst"])
        self.assertEqual(len(attrs["servicePrincipalName"]), 2)

    def test_is_kerberoastable(self):
        roastable = {
            "sAMAccountName": ["backup_svc"],
            "servicePrincipalName": ["HTTP/web"],
            "objectClass": ["top", "person", "user"],
        }
        # AD computers inherit 'person' — must still be excluded
        machine = {
            "sAMAccountName": ["DC01$"],
            "servicePrincipalName": ["HOST/dc01"],
            "objectClass": ["top", "person", "user", "computer"],
        }
        krbtgt = {
            "sAMAccountName": ["krbtgt"],
            "servicePrincipalName": ["kadmin/changepw"],
            "objectClass": ["top", "person", "user"],
        }
        plain = {"objectClass": ["top", "person", "user"]}
        self.assertTrue(ae.is_kerberoastable(roastable))
        self.assertFalse(ae.is_kerberoastable(machine))
        self.assertFalse(ae.is_kerberoastable(krbtgt))
        self.assertFalse(ae.is_kerberoastable(plain))

    def test_intervals_to_days(self):
        # 42 days in 100-ns intervals, stored negative as AD does
        self.assertEqual(ae.intervals_to_days(str(-42 * 10_000_000 * 86400)), 42)
        self.assertEqual(ae.intervals_to_days("0"), 0)
        self.assertEqual(ae.intervals_to_days("garbage"), 0)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ae.AdEnum.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ae.AdEnum)


if __name__ == "__main__":
    unittest.main()
