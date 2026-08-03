"""Unit tests for ad_privileged's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ad_priv_mod", ROOT / "modules" / "auxiliary" / "enum" / "ad_privileged.py"
)
ap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ap)


class TestPrivilegedGroups(unittest.TestCase):
    def test_finds_privileged_memberships(self):
        member_of = [
            "CN=Domain Admins,CN=Users,DC=forge,DC=local",
            "CN=Users,CN=Builtin,DC=forge,DC=local",
            "CN=Backup Operators,CN=Builtin,DC=forge,DC=local",
        ]
        self.assertEqual(ap.privileged_groups(member_of),
                         ["Domain Admins", "Backup Operators"])

    def test_orphan_detection(self):
        member_of = ["CN=Helpdesk,CN=Users,DC=forge,DC=local"]
        self.assertEqual(ap.privileged_groups(member_of), [])
        self.assertEqual(ap.privileged_groups([]), [])


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ap.AdPrivileged.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ap.AdPrivileged)


if __name__ == "__main__":
    unittest.main()
