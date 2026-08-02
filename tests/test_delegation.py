"""Unit tests for delegation's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "delegation_mod", ROOT / "modules" / "auxiliary" / "enum" / "delegation.py"
)
de = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(de)


class TestHelpers(unittest.TestCase):
    def test_domain_to_base(self):
        self.assertEqual(de.domain_to_base("forge.local"), "DC=forge,DC=local")

    def test_uac_int(self):
        self.assertEqual(de.uac_int({"userAccountControl": ["524800"]}), 524800)
        self.assertEqual(de.uac_int({}), 0)
        self.assertEqual(de.uac_int({"userAccountControl": ["garbage"]}), 0)

    def test_is_computer(self):
        self.assertTrue(de.is_computer(
            {"objectClass": ["top", "person", "user", "computer"]}))
        self.assertFalse(de.is_computer({"objectClass": ["top", "person", "user"]}))

    def test_delegation_kinds(self):
        plain = {"userAccountControl": ["512"],
                 "objectClass": ["top", "person", "user"]}
        self.assertEqual(de.delegation_kinds(plain), [])

        unconstrained = {"userAccountControl": ["524800"]}  # 512 | 0x80000
        self.assertEqual(de.delegation_kinds(unconstrained), ["unconstrained"])

        constrained = {"userAccountControl": ["512"],
                       "msDS-AllowedToDelegateTo": ["HTTP/api.forge.local"]}
        self.assertEqual(de.delegation_kinds(constrained), ["constrained"])

        transition = {"userAccountControl": ["16777728"],  # 512 | 0x1000000
                      "msDS-AllowedToDelegateTo": ["HTTP/api.forge.local"]}
        self.assertEqual(de.delegation_kinds(transition),
                         ["constrained (protocol transition)"])

        rbcd = {"userAccountControl": ["512"],
                "msDS-AllowedToActOnBehalfOfOtherIdentity": ["<binary sd>"]}
        self.assertEqual(de.delegation_kinds(rbcd), ["rbcd-target"])

        # DC machine account: SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION
        dc = {"userAccountControl": ["532480"],  # 0x82000
              "objectClass": ["top", "person", "user", "computer"]}
        self.assertEqual(de.delegation_kinds(dc), ["unconstrained"])
        self.assertTrue(de.is_computer(dc))

    def test_search_filter_is_bitwise(self):
        # 1.2.840.113556.1.4.803 = LDAP_MATCHING_RULE_BIT_AND — without it
        # the UAC test would be equality, not a flag check
        self.assertIn(":1.2.840.113556.1.4.803:=524288", de.SEARCH_FILTER)
        self.assertIn("msDS-AllowedToDelegateTo=*", de.SEARCH_FILTER)

    def test_rbcd_queried_by_presence_only(self):
        # the RBCD attribute is a raw security descriptor — requesting its
        # VALUE kills impacket's LDAP codec, so the module filters on
        # presence with a separate query and never requests the attribute
        self.assertIn("msDS-AllowedToActOnBehalfOfOtherIdentity=*", de.RBCD_FILTER)
        self.assertNotIn("msDS-AllowedToActOnBehalfOfOtherIdentity",
                         de.SEARCH_ATTRS)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", de.DelegationEnum.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(de.DelegationEnum)


if __name__ == "__main__":
    unittest.main()
