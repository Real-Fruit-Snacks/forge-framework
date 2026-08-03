"""Unit tests for share_spider's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "spider_mod", ROOT / "modules" / "auxiliary" / "enum" / "share_spider.py"
)
sp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sp)


class TestIsInteresting(unittest.TestCase):
    def test_hits(self):
        for name in ("web.config", "unattend.xml", "UnattendGC.xml",
                     "id_rsa", "id_rsa.pub", "backup.kdbx", "passwords.xlsx",
                     "credentials.txt", ".env", "ntds.dit", "key.ppk"):
            self.assertTrue(sp.is_interesting(name), name)

    def test_misses(self):
        for name in ("readme.txt", "report.pdf", "web.config.bak.txt",
                     "myid_rsa_notes.docx", "picture.png"):
            self.assertFalse(sp.is_interesting(name), name)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", sp.ShareSpider.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(sp.ShareSpider)


if __name__ == "__main__":
    unittest.main()
