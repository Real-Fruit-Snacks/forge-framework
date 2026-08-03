"""Unit tests for adcs_enum's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "adcs_mod", ROOT / "modules" / "auxiliary" / "enum" / "adcs_enum.py"
)
ac = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ac)


class TestTemplateIsEsc1(unittest.TestCase):
    CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    CODE_SIGN = "1.3.6.1.5.5.7.3.3"

    def test_esc1_shape(self):
        self.assertTrue(ac.template_is_esc1({
            "msPKI-Certificate-Name-Flag": ["1"],
            "pKIExtendedKeyUsage": [self.CLIENT_AUTH],
        }))

    def test_no_subject_flag_is_safe(self):
        self.assertFalse(ac.template_is_esc1({
            "msPKI-Certificate-Name-Flag": ["0"],
            "pKIExtendedKeyUsage": [self.CLIENT_AUTH],
        }))

    def test_non_auth_eku_is_safe(self):
        self.assertFalse(ac.template_is_esc1({
            "msPKI-Certificate-Name-Flag": ["1"],
            "pKIExtendedKeyUsage": [self.CODE_SIGN],
        }))

    def test_missing_attrs_are_safe(self):
        self.assertFalse(ac.template_is_esc1({}))


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ac.AdcsEnum.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ac.AdcsEnum)


if __name__ == "__main__":
    unittest.main()
