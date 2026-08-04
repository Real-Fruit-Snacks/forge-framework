"""Unit tests for the pre2k_spray module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "pre2k_mod", ROOT / "modules" / "auxiliary" / "login" / "pre2k_spray.py"
)
p2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p2)


class TestCandidates(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(p2.pre2k_candidate("NT4WS$"), "nt4ws")

    def test_truncates_to_14(self):
        self.assertEqual(p2.pre2k_candidate("VERYLONGMACHINENAME$"),
                         "verylongmachin")

    def test_already_lower(self):
        self.assertEqual(p2.pre2k_candidate("ws01$"), "ws01")

    def test_mixed_case(self):
        self.assertEqual(p2.pre2k_candidate("DeSkToP-A1B2$"), "desktop-a1b2")


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", p2.Pre2kSpray.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(p2.Pre2kSpray)


if __name__ == "__main__":
    unittest.main()
