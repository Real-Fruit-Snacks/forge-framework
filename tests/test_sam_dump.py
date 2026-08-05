"""Unit tests for the sam_dump module (loads fine without impacket).

The hive machinery it exercises lives in core/regdump.py (shared with
dpapi_system) — those helpers are tested here against the core module.

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import regdump

_spec = importlib.util.spec_from_file_location(
    "sam_dump_mod", ROOT / "modules" / "auxiliary" / "attack" / "sam_dump.py"
)
sd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sd)


class TestHelpers(unittest.TestCase):
    def test_rand_tmp_shape(self):
        for _ in range(10):
            name = regdump.rand_tmp("sam")
            self.assertTrue(name.startswith("fz_sam_"))
            self.assertTrue(name.endswith(".tmp"))
            self.assertEqual(len(name), len("fz_sam_") + 6 + 4)

    def test_hive_map(self):
        self.assertEqual(set(regdump.HIVES), {"SAM", "SYSTEM", "SECURITY"})


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", sd.SamDump.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(sd.SamDump)


if __name__ == "__main__":
    unittest.main()
