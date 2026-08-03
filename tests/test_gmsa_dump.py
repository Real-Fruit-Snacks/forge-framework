"""Unit tests for gmsa_dump's pure helpers (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "gmsa_mod", ROOT / "modules" / "auxiliary" / "enum" / "gmsa_dump.py"
)
gm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gm)


def make_blob(password, previous=None):
    """Build an MSDS-MANAGEDPASSWORD_BLOB for tests."""
    header_len = 16  # 2+2+4+2+2+2+2
    cur = password.encode("utf-16-le")
    cur_off = header_len
    prev = (previous or "").encode("utf-16-le")
    prev_off = cur_off + len(cur) if previous else 0
    blob = struct.pack("<HHIHHHH", 1, 0,
                       header_len + len(cur) + len(prev),
                       cur_off, prev_off, 0, 0)
    return blob + cur + prev


class TestParseManagedPassword(unittest.TestCase):
    def test_parses_current_password(self):
        blob = make_blob("Str0ng!Managed#Password123")
        self.assertEqual(gm.parse_managed_password(blob),
                         "Str0ng!Managed#Password123")

    def test_current_wins_over_previous(self):
        blob = make_blob("NewPassword!", previous="OldPassword!")
        self.assertEqual(gm.parse_managed_password(blob), "NewPassword!")

    def test_rejects_garbage(self):
        self.assertIsNone(gm.parse_managed_password(b""))
        self.assertIsNone(gm.parse_managed_password(b"\x00" * 20))
        self.assertIsNone(gm.parse_managed_password(b"short"))


class TestNthash(unittest.TestCase):
    def test_known_hash(self):
        # NT hash of "Password123" is a published constant
        self.assertEqual(
            gm.nthash_hex("Password123"),
            "58a478135a93ac3bf058a5ea0e8fdb71",
        )


class TestSidBytes(unittest.TestCase):
    def test_roundtrip_well_known(self):
        # S-1-5-32-544 (Builtin Administrators) — layout: rev(1) count(1)
        # authority(6 BE) subauths(4 LE each); 544 = 0x220
        raw = gm.sid_bytes("S-1-5-32-544")
        self.assertEqual(raw.hex(), "01020000000000052000000020020000")

    def test_domain_sid(self):
        raw = gm.sid_bytes("S-1-5-21-100-200-300-1108")
        self.assertEqual(raw[0], 1)          # revision
        self.assertEqual(raw[1], 5)          # 5 subauthorities (21,100,200,300,1108)
        self.assertEqual(raw[-4:], (1108).to_bytes(4, "little"))


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", gm.GmsaDump.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(gm.GmsaDump)


if __name__ == "__main__":
    unittest.main()
