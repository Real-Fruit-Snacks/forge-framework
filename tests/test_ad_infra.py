"""Unit tests for ad_infra (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ad_infra_mod", ROOT / "modules" / "auxiliary" / "enum" / "ad_infra.py"
)
ai = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ai)


class TestDcFilter(unittest.TestCase):
    def test_bitwise_server_trust(self):
        # 1.2.840.113556.1.4.803 = bit-AND; 8192 = SERVER_TRUST_ACCOUNT.
        # An equality check would miss DCs (their UAC is a flag set).
        self.assertIn(":1.2.840.113556.1.4.803:=8192", ai.DC_FILTER)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ai.AdInfra.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ai.AdInfra)


if __name__ == "__main__":
    unittest.main()
