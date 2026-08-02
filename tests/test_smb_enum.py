"""Unit tests for the smb_enum module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "smb_enum_mod", ROOT / "modules" / "auxiliary" / "scanner" / "smb_enum.py"
)
se = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(se)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", se.SmbEnum.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(se.SmbEnum)

    def test_missing_requirements_reflects_environment(self):
        mod = se.SmbEnum()
        if se.SMBConnection is None:
            self.assertEqual(mod.missing_requirements(), ["impacket"])
        else:
            self.assertEqual(mod.missing_requirements(), [])


if __name__ == "__main__":
    unittest.main()
