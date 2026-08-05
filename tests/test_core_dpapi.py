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


def dpapi_encrypt(masterkey, plaintext, guid):
    """Forward-build a DPAPI blob the way Windows writes one: session
    key = HMAC(SHA1(mk), salt), AES-256-CBC iv=0, PKCS7 pad, signature
    = HMAC(keyHash, hmacfield) over the signed range."""
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import HMAC, SHA1, SHA512
    from Cryptodome.Util.Padding import pad
    from impacket import dpapi
    from impacket.uuid import string_to_bin

    salt = b"\x44" * 32
    hmac_field = b"\x55" * 64
    key_hash = SHA1.new(masterkey).digest()
    session = HMAC.new(key_hash, salt, SHA512).digest()
    # deriveKey with SHA512: len(session)=64 <= block 128 -> as-is;
    # 64 >= AES-256 key 32 -> no extension. Mirror impacket exactly.
    cipher = AES.new(session[:32], AES.MODE_CBC, iv=b"\x00" * 16)
    data_enc = cipher.encrypt(pad(plaintext, AES.block_size))

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
    return assemble(h.digest())


def build_system_masterkey_file(pre_shared, masterkey,
                                guid="11111111-2222-3333-4444-555555555555"):
    """Forward-build a SYSTEM-context MasterKeyFile the way Windows
    writes one: the masterkey PBKDF2/HMAC-encrypted with a raw
    pre-shared key (the DPAPI_SYSTEM machine/user key path — no RSA
    anywhere on this path, unlike the domain-user chain)."""
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import HMAC, SHA512
    from impacket import dpapi
    salt = b"\x11" * 16
    iterations = 4000
    prf = lambda p, s: HMAC.new(p, s, SHA512).digest()
    helper = dpapi.MasterKey()
    derived = helper.deriveKey(pre_shared, salt, 32 + 16,
                               count=iterations, hashFunction=prf)
    crypt_key, iv = derived[:32], derived[32:48]
    hmac_salt = b"\x22" * 16
    hmac_key = HMAC.new(pre_shared, hmac_salt, SHA512).digest()
    # decrypt checks hmac against ALGORITHMS_DATA[SHA512][0] = 16 bytes
    hmac_val = HMAC.new(hmac_key, masterkey, SHA512).digest()[:16]
    # layout decrypt expects: salt(16) hmac(16) pad(16) key(64) at END
    plain = hmac_salt + hmac_val + b"\x00" * 16 + masterkey
    cipher = AES.new(crypt_key, AES.MODE_CBC, iv)
    data = cipher.encrypt(plain)
    mk_blob = (struct.pack("<L", 1) + salt +
               struct.pack("<L", iterations) +
               struct.pack("<L", dpapi.ALGORITHMS.CALG_SHA_512.value) +
               struct.pack("<L", dpapi.ALGORITHMS.CALG_AES_256.value) +
               data)
    guid_utf16 = guid.encode("utf-16-le")  # exactly the 72-byte field
    return (struct.pack("<LLL", 1, 0, 0) + guid_utf16 +
            struct.pack("<LLL", 0, 0, 0) +
            struct.pack("<QQQQ", len(mk_blob), 0, 0, 0) + mk_blob)


def build_credential_file(masterkey, target, username, secret,
                          guid="11111111-2222-3333-4444-555555555555"):
    """Forward-build a CredentialFile the way Windows writes one: the
    CREDENTIAL_BLOB plaintext DPAPI-encrypted with the masterkey."""

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

    blob = dpapi_encrypt(masterkey, cred, guid)
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


@unittest.skipUnless(HAVE_IMPACKET, "impacket not installed")
class TestBrowserKey(unittest.TestCase):
    GUID = "11111111-2222-3333-4444-555555555555"

    def _local_state(self, masterkey):
        import base64
        blob = dpapi_encrypt(masterkey, b"\x07" * 32, self.GUID)
        b64 = base64.b64encode(b"DPAPI" + blob).decode()
        return ('{"os_crypt":{"encrypted_key":"%s"}}' % b64).encode()

    def test_roundtrip(self):
        masterkey = bytes(range(64))
        key = dpapix.decrypt_browser_key(
            self._local_state(masterkey), {self.GUID: masterkey})
        self.assertEqual(key, b"\x07" * 32)

    def test_missing_masterkey(self):
        masterkey = bytes(range(64))
        self.assertIsNone(
            dpapix.decrypt_browser_key(self._local_state(masterkey), {}))

    def test_garbage_json(self):
        self.assertIsNone(dpapix.decrypt_browser_key(
            b"not json", {self.GUID: bytes(range(64))}))


@unittest.skipUnless(HAVE_IMPACKET, "impacket not installed")
class TestBrowserLogin(unittest.TestCase):
    def _v10(self, aes_key, password):
        from Cryptodome.Cipher import AES
        nonce = b"\x99" * 12
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(password.encode())
        return b"v10" + nonce + ct + tag

    def test_roundtrip(self):
        plain = dpapix.decrypt_browser_login(
            self._v10(b"\x07" * 32, "ChromePass2024!"), b"\x07" * 32)
        self.assertEqual(plain, b"ChromePass2024!")

    def test_v20_skipped(self):
        self.assertIsNone(
            dpapix.decrypt_browser_login(b"v20" + b"\x00" * 40,
                                         b"\x07" * 32))

    def test_bad_tag_returns_none(self):
        blob = bytearray(self._v10(b"\x07" * 32, "x"))
        blob[-1] ^= 0xFF
        self.assertIsNone(
            dpapix.decrypt_browser_login(bytes(blob), b"\x07" * 32))


class TestParseLoginData(unittest.TestCase):
    def test_rows(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE logins (origin_url TEXT, "
                     "username_value TEXT, password_value BLOB, "
                     "date_created INTEGER)")
        conn.execute("INSERT INTO logins VALUES (?, ?, ?, 0)",
                     ("https://sso.forge.local", "analyst", b"v10xyz"))
        data = conn.serialize() if hasattr(conn, "serialize") else None
        conn.close()
        if data is None:
            self.skipTest("sqlite serialize unavailable")
        rows = dpapix.parse_login_data(data)
        self.assertEqual(rows, [("https://sso.forge.local", "analyst",
                                 b"v10xyz")])


@unittest.skipUnless(HAVE_IMPACKET, "impacket not installed")
class TestSystemMasterkey(unittest.TestCase):
    def test_roundtrip_user_and_machine_key(self):
        masterkey = bytes(range(64))
        for slot in ("UserKey", "MachineKey"):
            pre_shared = bytes([0x42]) * 20
            blob = build_system_masterkey_file(pre_shared, masterkey)
            guid, recovered = dpapix.decrypt_system_masterkey_file(
                blob, {slot: pre_shared})
            self.assertEqual(guid,
                             "11111111-2222-3333-4444-555555555555")
            self.assertEqual(recovered, masterkey, slot)

    def test_wrong_key_returns_none(self):
        blob = build_system_masterkey_file(b"\x42" * 20,
                                           bytes(range(64)))
        guid, recovered = dpapix.decrypt_system_masterkey_file(
            blob, {"UserKey": b"\xff" * 20, "MachineKey": b"\xee" * 20})
        self.assertIsNone(recovered)


class TestParseDpapiSystem(unittest.TestCase):
    def test_parses_secret_lines(self):
        keys = dpapix.parse_dpapi_system([
            "dpapi_machinekey:0x" + "41" * 20,
            "dpapi_userkey:0x" + "42" * 20,
            "sc__svcaccount:password123",
        ])
        self.assertEqual(keys["MachineKey"], b"\x41" * 20)
        self.assertEqual(keys["UserKey"], b"\x42" * 20)


@unittest.skipUnless(HAVE_IMPACKET, "impacket not installed")
class TestWifiPasswords(unittest.TestCase):
    GUID = "11111111-2222-3333-4444-555555555555"
    XML = ('<?xml version="1.0"?>\n'
           '<WLANProfile xmlns="http://www.microsoft.com/networking/'
           'WLAN/profile/v1">\n'
           ' <name>ForgeLabWiFi</name>\n'
           ' <SSIDConfig><SSID><name>ForgeLabWiFi</name></SSID>'
           '</SSIDConfig>\n'
           ' <MSM><security><sharedKey>\n'
           '   <keyType>passPhrase</keyType><protected>true</protected>\n'
           '   <keyMaterial>{blob}</keyMaterial>\n'
           ' </sharedKey></security></MSM>\n'
           '</WLANProfile>')

    def _xml(self, masterkey):
        blob = dpapi_encrypt(masterkey, b"WiFiPass2024!", self.GUID)
        return self.XML.replace("{blob}", blob.hex()).encode()

    def test_roundtrip(self):
        masterkey = bytes(range(64))
        ssid, password = dpapix.wifi_passwords(
            self._xml(masterkey), {self.GUID: masterkey})
        self.assertEqual(ssid, "ForgeLabWiFi")
        self.assertEqual(password, "WiFiPass2024!")

    def test_open_network(self):
        xml = self.XML.replace(
            '   <keyMaterial>{blob}</keyMaterial>\n', "").encode()
        ssid, password = dpapix.wifi_passwords(xml, {})
        self.assertEqual(ssid, "ForgeLabWiFi")
        self.assertIsNone(password)

    def test_missing_masterkey(self):
        ssid, password = dpapix.wifi_passwords(
            self._xml(bytes(range(64))), {})
        self.assertIsNone(password)


if __name__ == "__main__":
    unittest.main()
