"""Unit tests for bitlocker_keys' pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "fve_mod", ROOT / "modules" / "auxiliary" / "enum" / "bitlocker_keys.py"
)
bk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bk)


class TestParentCn(unittest.TestCase):
    def test_extracts_owner(self):
        dn = ("CN=2024-01-01T00-00-00-08-00FVE-KEY,"
              "CN=WS01,CN=Computers,DC=forge,DC=local")
        self.assertEqual(bk.parent_cn(dn), "WS01")

    def test_garbage(self):
        self.assertEqual(bk.parent_cn("OU=Nothing"), "?")


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", bk.BitlockerKeys.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(bk.BitlockerKeys)


if __name__ == "__main__":
    unittest.main()
