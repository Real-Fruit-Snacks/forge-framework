"""Unit tests for gpp_password's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "gpp_mod", ROOT / "modules" / "auxiliary" / "enum" / "gpp_password.py"
)
gp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gp)

# cpassword for "GPP2024!Secret" under the published MS key (same value
# as the lab fixture)
FIXTURE = "ebwF2Pa9BpEFOuivsimZp0tcyXArTxCVK8PAgmdLxZQ="


class TestFindCpasswords(unittest.TestCase):
    def test_properties_order(self):
        xml = '<Properties action="U" cpassword="AAA" userName="svc1"/>'
        self.assertEqual(gp.find_cpasswords(xml), [("svc1", "AAA")])

    def test_reverse_order(self):
        xml = '<Properties userName="svc2" cpassword="BBB"/>'
        self.assertEqual(gp.find_cpasswords(xml), [("svc2", "BBB")])

    def test_no_hits(self):
        self.assertEqual(gp.find_cpasswords("<Groups/>"), [])


class TestDecrypt(unittest.TestCase):
    def test_fixture_roundtrip(self):
        if gp.AES is None:
            self.skipTest("Cryptodome not available")
        self.assertEqual(gp.decrypt_cpassword(FIXTURE), "GPP2024!Secret")

    def test_rejects_garbage(self):
        if gp.AES is None:
            self.skipTest("Cryptodome not available")
        with self.assertRaises(Exception):
            gp.decrypt_cpassword("!!!")


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", gp.GppPassword.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(gp.GppPassword)


if __name__ == "__main__":
    unittest.main()
