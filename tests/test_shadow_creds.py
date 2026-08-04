"""Unit tests for the shadow_creds module (loads fine without deps).

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
    "shadow_mod", ROOT / "modules" / "auxiliary" / "attack" / "shadow_creds.py"
)
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)


class TestRequirements(unittest.TestCase):
    def test_declares_deps(self):
        self.assertIn("impacket", sc.ShadowCreds.requirements)
        self.assertIn("cryptography", sc.ShadowCreds.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(sc.ShadowCreds)


class TestKclStructure(unittest.TestCase):
    def _blob(self):
        pub = b"\xde\xad" * 150  # fake KeyMaterial
        device = bytes(range(16))
        creation = struct.pack("<Q", 123456789)
        value = sc.build_kcl_dn_with_binary(pub, device, creation,
                                            "CN=analyst,DC=forge,DC=local")
        return pub, device, creation, value

    def test_dn_with_binary_format(self):
        _pub, _dev, _creation, value = self._blob()
        head, count, hexed, dn = value.split(":", 3)
        self.assertEqual(head, "B")
        self.assertEqual(int(count), len(hexed))
        self.assertEqual(dn, "CN=analyst,DC=forge,DC=local")
        bytes.fromhex(hexed)  # parses as hex

    def test_version_and_entries(self):
        pub, device, creation, value = self._blob()
        blob = bytes.fromhex(value.split(":")[2])
        version, = struct.unpack_from("<I", blob, 0)
        self.assertEqual(version, 0x00000200)
        entries = dict(sc._walk_entries(blob[4:]))
        import hashlib
        self.assertEqual(entries[0x0001], hashlib.sha256(pub).digest())
        values = b"".join(entries[i] for i in
                          (0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
                           0x0008, 0x0009))
        self.assertEqual(entries[0x0002], hashlib.sha256(values).digest())
        self.assertEqual(entries[0x0003], pub)
        self.assertEqual(entries[0x0004], b"\x01")
        self.assertEqual(entries[0x0005], b"\x00")
        self.assertEqual(entries[0x0006], device)
        self.assertEqual(entries[0x0007], b"\x01\x00")
        self.assertEqual(entries[0x0008], b"\x00" * 8)
        self.assertEqual(entries[0x0009], creation)

    def test_filetime_shape(self):
        ft = sc.filetime_now()
        ticks, = struct.unpack("<Q", ft)
        # sane FILETIME for the 2020s: between 2020 and 2040
        self.assertGreater(ticks, 132_000_000_000_000_000)
        self.assertLess(ticks, 200_000_000_000_000_000)


@unittest.skipUnless(sc.x509 is not None, "cryptography not installed")
class TestKeyAndCert(unittest.TestCase):
    def test_bcrypt_blob_layout(self):
        _cert, key = sc.make_cert("analyst")
        blob = sc.bcrypt_rsakey_blob(key.public_key())
        self.assertEqual(blob[:4], b"RSA1")
        bitlen, cb_exp, cb_mod, cb_p1, cb_p2 = struct.unpack_from(
            "<IIIII", blob, 4)
        self.assertEqual(bitlen, 2048)
        self.assertEqual(cb_mod, 256)
        self.assertEqual((cb_p1, cb_p2), (0, 0))
        self.assertEqual(len(blob), 24 + cb_exp + 256)

    def test_cert_is_self_signed_with_cn(self):
        cert, key = sc.make_cert("analyst")
        self.assertEqual(cert.issuer, cert.subject)
        cn = cert.subject.get_attributes_for_oid(sc.NameOID.COMMON_NAME)
        self.assertEqual(cn[0].value, "analyst")


if __name__ == "__main__":
    unittest.main()
