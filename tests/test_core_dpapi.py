"""Unit tests for core/dpapi.py — the crypto shared by the dpapi_*
modules. Loads without deps; the crypto tests skip without impacket.

Run: python3 -m unittest discover -s tests
"""

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import dpapi as dpapix

try:
    import impacket  # noqa: F401
    HAVE_IMPACKET = True
except ImportError:
    HAVE_IMPACKET = False

TEST_GUID = "11111111-2222-3333-4444-555555555555"  # 36 chars = the 72-byte UTF-16 field


def build_masterkey_file(rsa, masterkey, cb=None):
    """Forward-build a MasterKeyFile the way Windows writes one: the
    64-byte masterkey sits in a DPAPI_DOMAIN_RSA_MASTER_KEY struct,
    RSA-wrapped (little-endian, like CAPI) inside the DomainKey blob."""
    from Cryptodome.Cipher import PKCS1_v1_5
    plain = struct.pack("<LL", cb if cb is not None else 64, 2) + \
        masterkey + b"\x00" * 32
    wrapped = PKCS1_v1_5.new(rsa.publickey()).encrypt(plain)[::-1]
    dk_blob = (struct.pack("<LLL", 1, len(wrapped), 0) + b"\x00" * 16 +
               wrapped)
    guid_utf16 = TEST_GUID.encode("utf-16-le")  # exactly the 72-byte field
    mk_blob = b"\x00" * 136  # user-password path — unused here
    return (struct.pack("<LLL", 1, 0, 0) + guid_utf16 +
            struct.pack("<LLL", 0, 0, 0) +
            struct.pack("<QQQQ", len(mk_blob), 0, 0, len(dk_blob)) +
            mk_blob + dk_blob)


def build_credential_file(masterkey, target, username, secret,
                          guid="11111111-2222-3333-4444-555555555555"):
    """Forward-build a CredentialFile the way Windows writes one: the
    CREDENTIAL_BLOB plaintext DPAPI-encrypted with the masterkey —
    session key = HMAC(SHA1(mk), salt), AES-256-CBC iv=0, PKCS7 pad,
    signature = HMAC(keyHash, hmacfield) over the signed range."""
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import HMAC, SHA1, SHA512
    from Cryptodome.Util.Padding import pad
    from impacket import dpapi
    from impacket.uuid import string_to_bin

    def u16z(s):
        return s.encode("utf-16-le") + b"\x00\x00"

    t, u, sec = u16z(target), u16z(username), u16z(secret)
    cred = struct.pack("<LLLLL", 0, 0, 0, 1, 0)  # Flags Size Unk0 Type Flags2
    cred += struct.pack("<Q", 0)  # LastWritten
    cred += struct.pack("<LLLQ", 0, 2, 0, 0)  # Unk2 Persist AttrCount Unk3
    cred += struct.pack("<L", len(t)) + t
    cred += struct.pack("<LLL", 0, 0, 0)  # alias/desc/unknown sizes
    cred += struct.pack("<L", len(u)) + u
    cred += struct.pack("<L", len(sec)) + sec
    cred = cred[:4] + struct.pack("<L", len(cred)) + cred[8:]

    salt = b"\x44" * 32
    hmac_field = b"\x55" * 64
    key_hash = SHA1.new(masterkey).digest()
    session = HMAC.new(key_hash, salt, SHA512).digest()
    # deriveKey with SHA512: len(session)=64 <= block 128 -> as-is;
    # 64 >= AES-256 key 32 -> no extension. Mirror impacket exactly.
    cipher = AES.new(session[:32], AES.MODE_CBC, iv=b"\x00" * 16)
    data_enc = cipher.encrypt(pad(cred, AES.block_size))

    def assemble(sign):
        return (struct.pack("<L", 1) + b"\x00" * 16 +
                struct.pack("<L", 1) + string_to_bin(guid) +
                struct.pack("<L", 0) +      # Flags
                struct.pack("<L", 0) +      # DescriptionLen
                struct.pack("<LL",
                            dpapi.ALGORITHMS.CALG_AES_256.value, 256) +
                struct.pack("<L", len(salt)) + salt +
                struct.pack("<L", 0) +      # HMacKeyLen
                struct.pack("<LL",
                            dpapi.ALGORITHMS.CALG_SHA_512.value, 512) +
                struct.pack("<L", len(hmac_field)) + hmac_field +
                struct.pack("<L", len(data_enc)) + data_enc +
                struct.pack("<L", len(sign)) + sign)

    blob = assemble(b"\x00" * 64)
    to_sign = blob[20:len(blob) - 64 - 4]
    h = HMAC.new(key_hash, hmac_field, SHA512)
    h.update(to_sign)
    blob = assemble(h.digest())
    return struct.pack("<LLL", 1, len(blob), 0) + blob


class TestGuidName(unittest.TestCase):
    def test_accepts_guid(self):
        self.assertTrue(dpapix.is_guid_name(
            "cb5be38f-dc7c-47d6-b7b9-f1a43397e44d"))

    def test_rejects_backup_blob_and_friends(self):
        for name in ("BK-FORGE", "Preferred", ".", "..", "desktop.ini",
                     "cb5be38f-dc7c-47d6-b7b9-f1a43397e44",  # short limb
                     "cb5be38g-dc7c-47d6-b7b9-f1a43397e44d"):  # not hex
            self.assertFalse(dpapix.is_guid_name(name), name)


class TestFindBackupKey(unittest.TestCase):
    def test_no_store(self):
        key, reason = dpapix.find_backup_key(None)
        self.assertIsNone(key)
        self.assertIn("dpapi_backupkey", reason)

    def test_no_loot(self):
        class FakeStore:
            def loot(self, kind):
                return []
        key, reason = dpapix.find_backup_key(FakeStore())
        self.assertIsNone(key)
        self.assertIn("dpapi_backupkey", reason)


@unittest.skipUnless(HAVE_IMPACKET, "impacket not installed")
class TestMasterkeyRoundtrip(unittest.TestCase):
    def test_roundtrip(self):
        from Cryptodome.PublicKey import RSA
        backup = RSA.generate(2048)
        masterkey = bytes(range(64))
        blob = build_masterkey_file(backup, masterkey)
        guid, recovered = dpapix.decrypt_masterkey_file(blob, backup)
        self.assertEqual(guid, TEST_GUID)
        self.assertEqual(recovered, masterkey)

    def test_wrong_key_returns_none(self):
        from Cryptodome.PublicKey import RSA
        backup = RSA.generate(2048)
        blob = build_masterkey_file(backup, bytes(range(64)))
        wrong = RSA.generate(2048)
        guid, recovered = dpapix.decrypt_masterkey_file(blob, wrong)
        self.assertIsNone(recovered)

    def test_bad_structure_returns_none(self):
        from Cryptodome.PublicKey import RSA
        backup = RSA.generate(2048)
        blob = build_masterkey_file(backup, bytes(range(64)), cb=32)
        guid, recovered = dpapix.decrypt_masterkey_file(blob, backup)
        self.assertIsNone(recovered)

    def test_local_account_file_gives_none_guid(self):
        """A local account's masterkey file has no DomainKey blob —
        (None, None), so the modules skip it quietly."""
        from Cryptodome.PublicKey import RSA
        backup = RSA.generate(2048)
        guid_utf16 = TEST_GUID.encode("utf-16-le")
        mk_blob = b"\x00" * 136
        blob = (struct.pack("<LLL", 1, 0, 0) + guid_utf16 +
                struct.pack("<LLL", 0, 0, 0) +
                struct.pack("<QQQQ", len(mk_blob), 0, 0, 0) + mk_blob)
        guid, recovered = dpapix.decrypt_masterkey_file(blob, backup)
        self.assertIsNone(guid)
        self.assertIsNone(recovered)


@unittest.skipUnless(HAVE_IMPACKET, "impacket not installed")
class TestCredentialRoundtrip(unittest.TestCase):
    def test_roundtrip(self):
        masterkey = bytes(range(64))
        data = build_credential_file(
            masterkey, "fileserver.forge.local", "FORGE\\backupsvc",
            "BackupPass2024!")
        guid, blob = dpapix.decrypt_credential_file(
            data, {"11111111-2222-3333-4444-555555555555": masterkey})
        self.assertEqual(guid, "11111111-2222-3333-4444-555555555555")
        self.assertIsNotNone(blob)
        target, username, secret = dpapix.credential_fields(blob)
        self.assertEqual(target, "fileserver.forge.local")
        self.assertEqual(username, "FORGE\\backupsvc")
        self.assertEqual(secret, "BackupPass2024!")

    def test_missing_key_returns_none(self):
        masterkey = bytes(range(64))
        data = build_credential_file(masterkey, "t", "u", "s")
        guid, blob = dpapix.decrypt_credential_file(data, {})
        self.assertIsNone(blob)

    def test_wrong_key_returns_none(self):
        data = build_credential_file(bytes(range(64)), "t", "u", "s")
        guid, blob = dpapix.decrypt_credential_file(
            data, {"11111111-2222-3333-4444-555555555555": b"\xff" * 64})
        self.assertIsNone(blob)


if __name__ == "__main__":
    unittest.main()
