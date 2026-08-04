"""Unit tests for the bloodhound collector (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "bh_mod", ROOT / "modules" / "auxiliary" / "enum" / "bloodhound.py"
)
bh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bh)


class TestHelpers(unittest.TestCase):
    def test_bh_name(self):
        self.assertEqual(bh.bh_name("analyst", "forge.local"),
                         "ANALYST@FORGE.LOCAL")

    def test_bh_doc_shape(self):
        doc = json.loads(bh.bh_doc("users", [{"ObjectIdentifier": "S-1-5"}]))
        self.assertEqual(doc["meta"]["type"], "users")
        self.assertEqual(doc["meta"]["count"], 1)
        self.assertEqual(doc["meta"]["version"], 5)
        self.assertEqual(doc["data"][0]["ObjectIdentifier"], "S-1-5")

    def test_epoch_from_ad(self):
        # 2026-01-01 00:00:00 UTC in AD ticks
        ticks = 133_830_048_000_000_000
        self.assertEqual(bh.epoch_from_ad(str(ticks)),
                         (ticks - 116444736000000000) // 10_000_000)
        self.assertEqual(bh.epoch_from_ad("0"), 0)
        self.assertEqual(bh.epoch_from_ad("garbage"), 0)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", bh.Bloodhound.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(bh.Bloodhound)


if __name__ == "__main__":
    unittest.main()
