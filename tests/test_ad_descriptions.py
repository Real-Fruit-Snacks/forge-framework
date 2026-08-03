"""Unit tests for ad_descriptions' pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ad_desc_mod", ROOT / "modules" / "auxiliary" / "enum" / "ad_descriptions.py"
)
ad = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ad)


class TestLooksSensitive(unittest.TestCase):
    def test_flags_credential_words(self):
        self.assertTrue(ad.looks_sensitive("temp password: Backup2024!"))
        self.assertTrue(ad.looks_sensitive("Service account — ask IT for credentials"))
        self.assertTrue(ad.looks_sensitive("API key rotation due Friday"))
        self.assertTrue(ad.looks_sensitive("PWD reset pending"))

    def test_ignores_ordinary_text(self):
        self.assertFalse(ad.looks_sensitive("Nightly backup service"))
        self.assertFalse(ad.looks_sensitive(""))
        self.assertFalse(ad.looks_sensitive("Marketing team lead"))


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ad.AdDescriptions.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ad.AdDescriptions)


if __name__ == "__main__":
    unittest.main()
