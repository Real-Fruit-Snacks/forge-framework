"""Unit tests for ad_policies' pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ad_pol_mod", ROOT / "modules" / "auxiliary" / "enum" / "ad_policies.py"
)
ap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ap)


class TestIntervalToMinutes(unittest.TestCase):
    def test_converts_negative_ticks(self):
        # 30 minutes as AD stores it: negative 100-ns ticks
        self.assertEqual(ap.interval_to_minutes(str(-30 * 60 * 10_000_000)), 30)

    def test_garbage(self):
        self.assertEqual(ap.interval_to_minutes("junk"), 0)
        self.assertEqual(ap.interval_to_minutes(""), 0)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ap.AdPolicies.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ap.AdPolicies)


if __name__ == "__main__":
    unittest.main()
