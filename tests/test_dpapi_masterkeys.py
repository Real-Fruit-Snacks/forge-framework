"""Unit tests for the dpapi_masterkeys module (loads without deps).

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
    "mk_mod", ROOT / "modules" / "auxiliary" / "attack" / "dpapi_masterkeys.py"
)
mk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mk)


class TestRequirements(unittest.TestCase):
    def test_declares_deps(self):
        self.assertIn("impacket", mk.DpapiMasterkeys.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(mk.DpapiMasterkeys)


@unittest.skipUnless(mk.dpapi is not None, "impacket not installed")
class TestMasterkeyRoundtrip(unittest.TestCase):
    def _build_masterkey_file(self, rsa, masterkey, cb=None):
        """Forward-build a MasterKeyFile the way Windows writes one:
        the 64-byte masterkey sits in a DPAPI_DOMAIN_RSA_MASTER_KEY
        struct, RSA-wrapped (little-endian, like CAPI) inside the
        DomainKey blob."""
        from Cryptodome.Cipher import PKCS1_v1_5
        plain = struct.pack("<LL", cb if cb is not None else 64, 2) + \
            masterkey + b"\x00" * 32
        wrapped = PKCS1_v1_5.new(rsa.publickey()).encrypt(plain)[::-1]
        dk_blob = (struct.pack("<LLL", 1, len(wrapped), 0) + b"\x00" * 16 +
                   wrapped)

        guid_utf16 = "{11111111-2222-3333-4444-5555555555}".encode(
            "utf-16-le")  # exactly 72 bytes — the Guid field's size
        mk_blob = b"\x00" * 136  # user-password path — unused here
        mkf = (struct.pack("<LLL", 1, 0, 0) + guid_utf16 +
               struct.pack("<LLL", 0, 0, 0) +
               struct.pack("<QQQQ", len(mk_blob), 0, 0, len(dk_blob)) +
               mk_blob + dk_blob)
        return mkf

    def test_roundtrip(self):
        from Cryptodome.PublicKey import RSA
        backup = RSA.generate(2048)
        masterkey = bytes(range(64))
        blob = self._build_masterkey_file(backup, masterkey)
        guid, recovered = mk.decrypt_masterkey_file(blob, backup)
        self.assertEqual(guid, "{11111111-2222-3333-4444-5555555555}")
        self.assertEqual(recovered, masterkey)

    def test_wrong_key_returns_none(self):
        from Cryptodome.PublicKey import RSA
        backup = RSA.generate(2048)
        blob = self._build_masterkey_file(backup, bytes(range(64)))
        wrong = RSA.generate(2048)
        guid, recovered = mk.decrypt_masterkey_file(blob, wrong)
        self.assertIsNone(recovered)

    def test_bad_structure_returns_none(self):
        from Cryptodome.PublicKey import RSA
        backup = RSA.generate(2048)
        blob = self._build_masterkey_file(backup, bytes(range(64)), cb=32)
        guid, recovered = mk.decrypt_masterkey_file(blob, backup)
        self.assertIsNone(recovered)

    def test_local_account_file_gives_none_guid(self):
        """A local account's masterkey file has no DomainKey blob —
        (None, None), so the module skips it quietly."""
        from Cryptodome.PublicKey import RSA
        backup = RSA.generate(2048)
        guid_utf16 = "{11111111-2222-3333-4444-5555555555}".encode(
            "utf-16-le")
        mk_blob = b"\x00" * 136
        blob = (struct.pack("<LLL", 1, 0, 0) + guid_utf16 +
                struct.pack("<LLL", 0, 0, 0) +
                struct.pack("<QQQQ", len(mk_blob), 0, 0, 0) + mk_blob)
        guid, recovered = mk.decrypt_masterkey_file(blob, backup)
        self.assertIsNone(guid)
        self.assertIsNone(recovered)


class TestGuidName(unittest.TestCase):
    def test_accepts_guid(self):
        self.assertTrue(mk.is_guid_name(
            "cb5be38f-dc7c-47d6-b7b9-f1a43397e44d"))

    def test_rejects_backup_blob_and_friends(self):
        for name in ("BK-FORGE", "Preferred", ".", "..", "desktop.ini",
                     "cb5be38f-dc7c-47d6-b7b9-f1a43397e44",  # short limb
                     "cb5be38g-dc7c-47d6-b7b9-f1a43397e44d"):  # not hex
            self.assertFalse(mk.is_guid_name(name), name)


if __name__ == "__main__":
    unittest.main()
