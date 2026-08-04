"""Unit tests for the dpapi_backupkey module (loads fine without deps).

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
    "bk_mod", ROOT / "modules" / "auxiliary" / "attack" / "dpapi_backupkey.py"
)
bk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bk)


class TestRequirements(unittest.TestCase):
    def test_declares_deps(self):
        self.assertIn("impacket", bk.DpapiBackupKey.requirements)
        self.assertIn("cryptography", bk.DpapiBackupKey.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(bk.DpapiBackupKey)


@unittest.skipUnless(bk.bkrp is not None, "impacket not installed")
class TestDrsUnwrap(unittest.TestCase):
    def _wrap(self, key, plaintext):
        import hashlib
        import zlib
        from Cryptodome.Cipher import ARC4
        confounder = b"\xaa" * 16
        body = zlib.crc32(plaintext).to_bytes(4, "little") + plaintext
        md5 = hashlib.new("md5")
        md5.update(key + confounder)
        return confounder + ARC4.new(md5.digest()).encrypt(body)

    def test_roundtrip(self):
        key = b"\x11" * 16
        plain = b"\x02\x00\x00\x00" + b"\x55" * 100
        blob = self._wrap(key, plain)
        self.assertEqual(bk.unwrap_drs_secret(key, blob), plain)

    def test_wrong_key_raises(self):
        blob = self._wrap(b"\x11" * 16, b"secret" * 20)
        with self.assertRaises(ValueError):
            bk.unwrap_drs_secret(b"\x22" * 16, blob)

    def test_attid_for_oid(self):
        self.assertEqual(bk._attid_for_oid("1.2.840.113556.1.4.27"),
                         (0x0009 << 16) + 27)
        self.assertEqual(bk._attid_for_oid("1.2.840.113556.1.4.865"),
                         (0x0009 << 16) + 865)


@unittest.skipUnless(bk.x509 is not None and bk.bkrp is not None,
                     "deps not installed")
class TestPreferredBackupKeyParse(unittest.TestCase):
    def _synthetic_blob(self):
        """A PREFERRED_BACKUP_KEY blob around a real RSA key, built the
        CAPI PRIVATEKEYBLOB way (little-endian fields)."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from impacket import dpapi
        key = rsa.generate_private_key(public_exponent=65537,
                                       key_size=2048)
        numbers = key.private_numbers()
        pub = numbers.public_numbers

        def le(value, size):
            return value.to_bytes(size, "little")

        blob = struct.pack("<L", 2048) + struct.pack("<L", pub.e)
        blob += le(pub.n, 256)          # modulus
        blob += le(numbers.p, 128)      # prime1
        blob += le(numbers.q, 128)      # prime2
        blob += le(numbers.dmp1, 128)   # exponent1
        blob += le(numbers.dmq1, 128)   # exponent2
        blob += le(numbers.iqmp, 128)   # coefficient
        blob += le(numbers.d, 256)      # privateExponent
        keyblob = (struct.pack("<BBHI", 0x07, 0x02, 0, 0x00002400)
                   + b"RSA2" + blob)
        cert_der = b"\x30\x82\x01\x01fakecert"
        preferred = (struct.pack("<LLL", 2, len(keyblob), len(cert_der))
                     + keyblob + cert_der)
        return preferred, key, cert_der

    def test_parse_roundtrip(self):
        blob, key, cert_der = self._synthetic_blob()
        parsed_key, parsed_cert = bk.parse_preferred_backup_key(blob)
        self.assertEqual(parsed_cert, cert_der)
        numbers = key.public_key().public_numbers()
        self.assertEqual(parsed_key.n, numbers.n)
        self.assertEqual(parsed_key.e, numbers.e)

    def test_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            bk.parse_preferred_backup_key(struct.pack("<LLL", 2, 5, 5)
                                          + b"short")


if __name__ == "__main__":
    unittest.main()
