"""Unit tests for laps_dump's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "laps_mod", ROOT / "modules" / "auxiliary" / "enum" / "laps_dump.py"
)
la = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(la)


class TestFiletime(unittest.TestCase):
    def test_converts(self):
        # 2024-01-01 00:00:00 UTC in FILETIME ticks
        ticks = (1704067200 + 11644473600) * 10_000_000
        self.assertEqual(la.filetime_to_epoch(str(ticks)), 1704067200)

    def test_zero_and_garbage(self):
        self.assertEqual(la.filetime_to_epoch("0"), 0)
        self.assertEqual(la.filetime_to_epoch("junk"), 0)

    def test_past_is_past(self):
        # 2015 in ticks — comfortably before now
        ticks = (1420070400 + 11644473600) * 10_000_000
        self.assertLess(la.filetime_to_epoch(str(ticks)), time.time())


class TestParseLapsJson(unittest.TestCase):
    def test_parses_unencrypted(self):
        blob = '{"n":"Administrator","t":"1d8f3a2","p":"S3cret!99"}'
        self.assertEqual(la.parse_laps_json(blob), ("Administrator", "S3cret!99"))

    def test_rejects_other_shapes(self):
        self.assertIsNone(la.parse_laps_json('{"encrypted":"blob"}'))
        self.assertIsNone(la.parse_laps_json("not json"))
        self.assertIsNone(la.parse_laps_json('{"n":"only-account"}'))


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", la.LapsDump.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(la.LapsDump)


if __name__ == "__main__":
    unittest.main()
