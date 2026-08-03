"""Unit tests for ldap_query's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ldap_query_mod", ROOT / "modules" / "auxiliary" / "enum" / "ldap_query.py"
)
lq = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lq)


class TestValidateFilter(unittest.TestCase):
    def test_accepts_sane_filters(self):
        self.assertIsNone(lq.validate_filter("(objectClass=user)"))
        self.assertIsNone(lq.validate_filter("(&(objectClass=user)(adminCount=1))"))
        self.assertIsNone(lq.validate_filter("(|(cn=a)(cn=b))"))

    def test_rejects_broken_filters(self):
        self.assertEqual(lq.validate_filter(""), "empty filter")
        self.assertIsNotNone(lq.validate_filter("objectClass=user"))
        self.assertIsNotNone(lq.validate_filter("((objectClass=user)"))
        self.assertIsNotNone(lq.validate_filter("(objectClass=user))"))


class TestFormatEntry(unittest.TestCase):
    ATTRS = {"sAMAccountName": ["analyst"], "description": ["coffee"],
             "memberOf": ["CN=Domain Admins", "CN=Backup Operators"]}

    def test_joins_requested_attributes(self):
        line = lq.format_entry(self.ATTRS, ["sAMAccountName", "description"])
        self.assertEqual(line, "sAMAccountName=analyst  description=coffee")

    def test_multi_value_attributes(self):
        line = lq.format_entry(self.ATTRS, ["memberOf"])
        self.assertEqual(line, "memberOf=CN=Domain Admins;CN=Backup Operators")

    def test_missing_attributes_fall_back(self):
        self.assertEqual(lq.format_entry(self.ATTRS, ["nope"]),
                         "(none of the requested attributes)")


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", lq.LdapQuery.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(lq.LdapQuery)


if __name__ == "__main__":
    unittest.main()
