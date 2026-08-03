"""Unit tests for golden_ticket's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "golden_mod", ROOT / "modules" / "auxiliary" / "attack" / "golden_ticket.py"
)
gt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gt)


class TestValidation(unittest.TestCase):
    def test_valid_hex(self):
        self.assertTrue(gt.valid_hex("31d6cfe0d16ae931b73c59d7e0c089c0"))
        self.assertFalse(gt.valid_hex("31d6cfe0d16ae931b73c59d7e0c089"))   # short
        self.assertFalse(gt.valid_hex("zzd6cfe0d16ae931b73c59d7e0c089c0"))  # not hex
        self.assertFalse(gt.valid_hex(""))

    def test_valid_domain_sid(self):
        self.assertTrue(gt.valid_domain_sid("S-1-5-21-1200847940-1826158639-3819377024"))
        self.assertFalse(gt.valid_domain_sid("S-1-5-32-544"))
        self.assertFalse(gt.valid_domain_sid("forge.local"))


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", gt.GoldenTicket.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(gt.GoldenTicket)


if __name__ == "__main__":
    unittest.main()
