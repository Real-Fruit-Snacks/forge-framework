"""Unit tests for ad_groups' pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ad_groups_mod", ROOT / "modules" / "auxiliary" / "enum" / "ad_groups.py"
)
ag = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ag)


class TestGroupType(unittest.TestCase):
    def test_signed_int32_strings(self):
        # AD serves groupType as a SIGNED int32 string
        global_sec = {"groupType": ["-2147483646"]}   # 0x80000002
        global_dist = {"groupType": ["2"]}            # 0x00000002
        self.assertEqual(ag.group_type_int(global_sec), 0x80000002)
        self.assertTrue(ag.is_security_group(global_sec))
        self.assertFalse(ag.is_security_group(global_dist))

    def test_garbage_is_distribution(self):
        self.assertFalse(ag.is_security_group({}))
        self.assertFalse(ag.is_security_group({"groupType": ["junk"]}))


class TestDnToCn(unittest.TestCase):
    def test_extracts_cn(self):
        self.assertEqual(ag.dn_to_cn("CN=Ana Lyst,CN=Users,DC=forge,DC=local"),
                         "Ana Lyst")
        self.assertEqual(ag.dn_to_cn("cn=lowercase,DC=x"), "lowercase")

    def test_no_cn_returns_input(self):
        self.assertEqual(ag.dn_to_cn("OU=Groups,DC=forge,DC=local"),
                         "OU=Groups,DC=forge,DC=local")


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ag.AdGroups.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ag.AdGroups)


if __name__ == "__main__":
    unittest.main()
