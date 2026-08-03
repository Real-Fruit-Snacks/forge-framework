"""Unit tests for the s4u module (loads fine without impacket).

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
    "s4u_mod", ROOT / "modules" / "auxiliary" / "attack" / "s4u.py"
)
s4u = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s4u)


class TestChecksumData(unittest.TestCase):
    """The PA-FOR-USER checksum input layout Heimdal verifies
    (LE32 name-type || user || realm || "Kerberos", no separators)."""

    def test_exact_layout(self):
        blob = s4u.s4u_checksum_data("Administrator", "forge.local")
        self.assertEqual(
            blob,
            struct.pack("<I", 1) + b"Administrator" + b"FORGE.LOCAL" + b"Kerberos",
        )

    def test_realm_uppercased(self):
        blob = s4u.s4u_checksum_data("analyst", "Forge.Local")
        self.assertIn(b"FORGE.LOCAL", blob)
        self.assertNotIn(b"Forge.Local", blob)

    def test_name_type_default_nt_principal(self):
        blob = s4u.s4u_checksum_data("u", "d")
        self.assertEqual(struct.unpack("<I", blob[:4])[0], 1)


class TestValidation(unittest.TestCase):
    def test_valid_hex(self):
        self.assertTrue(s4u.valid_hex("31d6cfe0d16ae931b73c59d7e0c089c0"))
        self.assertFalse(s4u.valid_hex("31d6cfe0d16ae931b73c59d7e0c089"))  # short
        self.assertFalse(s4u.valid_hex("zzd6cfe0d16ae931b73c59d7e0c089c0"))
        self.assertFalse(s4u.valid_hex(""))


@unittest.skipUnless(s4u.constants is not None, "impacket not installed")
class TestRfc4757Checksum(unittest.TestCase):
    """pa_for_user_cksum must equal impacket's own _HMACMD5 profile with
    usage 17 — the construction Heimdal's mssfu.c verifies."""

    def test_matches_impacket_profile(self):
        from impacket.krb5.crypto import _get_checksum_profile, Cksumtype, Key

        key = Key(23, b"\x01" * 16)
        blob = s4u.s4u_checksum_data("Administrator", "forge.local")
        expected = _get_checksum_profile(Cksumtype.HMAC_MD5).checksum(key, 17, blob)
        self.assertEqual(s4u.pa_for_user_cksum(key.contents, blob), expected)

    def test_nt_hash(self):
        # NT("Web2024!") — must match what impacket/MD4 derive
        from Cryptodome.Hash import MD4

        h = MD4.new()
        h.update("Web2024!".encode("utf-16-le"))
        self.assertEqual(s4u.nt_hash_hex("Web2024!"), h.hexdigest())


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", s4u.S4U.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(s4u.S4U)


if __name__ == "__main__":
    unittest.main()
