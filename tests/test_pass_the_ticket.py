"""Unit tests for the pass_the_ticket module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ptt_mod", ROOT / "modules" / "auxiliary" / "attack" / "pass_the_ticket.py"
)
ptt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ptt)


class TestSniff(unittest.TestCase):
    def test_ccache_v4_and_v3(self):
        self.assertEqual(ptt.sniff_ticket(b"\x05\x04\x00\x00rest"), "ccache")
        self.assertEqual(ptt.sniff_ticket(b"\x05\x03\x00\x00rest"), "ccache")

    def test_as_rep_and_tgs_rep(self):
        self.assertEqual(ptt.sniff_ticket(b"\x6b\x82rest"), "as-rep")
        self.assertEqual(ptt.sniff_ticket(b"\x6d\x82rest"), "tgs-rep")

    def test_unknown(self):
        self.assertEqual(ptt.sniff_ticket(b"\x30\x82rest"), "unknown")
        self.assertEqual(ptt.sniff_ticket(b""), "unknown")


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ptt.PassTheTicket.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ptt.PassTheTicket)


if __name__ == "__main__":
    unittest.main()
