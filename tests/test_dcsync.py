"""Unit tests for dcsync's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "dcsync_mod", ROOT / "modules" / "auxiliary" / "attack" / "dcsync.py"
)
dc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dc)


class TestParseSecret(unittest.TestCase):
    LINE = ("FORGE.LOCAL\\Administrator:500:"
            "aad3b435b51404eeaad3b435b51404ee:"
            "31d6cfe0d16ae931b73c59d7e0c089c0:::")

    def test_parses_hashcat_line(self):
        user, rid, lm, nt = dc.parse_secret(self.LINE)
        self.assertEqual(user, "Administrator")
        self.assertEqual(rid, "500")
        self.assertEqual(lm, "aad3b435b51404eeaad3b435b51404ee")
        self.assertEqual(nt, "31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_user_without_domain_prefix(self):
        user, rid, _, _ = dc.parse_secret(
            "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:deadbeef:::")
        self.assertEqual((user, rid), ("krbtgt", "502"))

    def test_rejects_garbage(self):
        self.assertIsNone(dc.parse_secret(""))
        self.assertIsNone(dc.parse_secret("some status line"))
        self.assertIsNone(dc.parse_secret("user:notarid:aa:bb:::"))
        self.assertIsNone(dc.parse_secret("too:few"))


class TestAttidForOid(unittest.TestCase):
    def test_standard_encoding(self):
        # unicodePwd: prefix 1.2.840.113556.1.4 -> standard index 0x0009,
        # suffix 90 (0x5A)
        self.assertEqual(dc.attid_for_oid("1.2.840.113556.1.4.90"), 0x9005A)
        # ntPwdHistory: suffix 94
        self.assertEqual(dc.attid_for_oid("1.2.840.113556.1.4.94"), 0x9005E)

    def test_large_suffix_marker(self):
        # lastValue >= 16384 gets the 0x8000 continuation marker
        self.assertEqual(dc.attid_for_oid("1.2.840.113556.1.4.20000"),
                         (0x0009 << 16) + (20000 % 16384) + 32768)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", dc.DcSync.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(dc.DcSync)


if __name__ == "__main__":
    unittest.main()
