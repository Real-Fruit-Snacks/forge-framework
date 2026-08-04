"""Unit tests for the esc1 module (loads fine without impacket/crypto).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "esc1_mod", ROOT / "modules" / "auxiliary" / "attack" / "esc1.py"
)
e1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e1)


class TestHelpers(unittest.TestCase):
    def test_config_base(self):
        self.assertEqual(e1.config_base("forge.local"),
                         "CN=Configuration,DC=forge,DC=local")

    def test_der_to_pem_cert(self):
        pem = e1.der_to_pem_cert(b"\x01\x02\x03\x04")
        self.assertTrue(pem.startswith("-----BEGIN CERTIFICATE-----\n"))
        self.assertTrue(pem.endswith("-----END CERTIFICATE-----\n"))
        body = pem.split("\n")[1:-1]
        self.assertTrue(all(len(line) <= 64 for line in body))


@unittest.skipUnless(e1.x509 is not None, "cryptography not installed")
class TestCsrBuilder(unittest.TestCase):
    def test_csr_and_key(self):
        csr, key_pem = e1.build_csr("analyst", 2048)
        self.assertTrue(key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        req = e1.x509.load_der_x509_csr(csr)
        common = req.subject.get_attributes_for_oid(e1.NameOID.COMMON_NAME)
        self.assertEqual(common[0].value, "analyst")
        self.assertEqual(req.public_key().key_size, 2048)

    def test_csr_with_san_embeds_upn_othername(self):
        csr, _ = e1.build_csr("analyst", 2048, "Administrator@forge.local")
        req = e1.x509.load_der_x509_csr(csr)
        san = req.extensions.get_extension_for_class(
            e1.x509.SubjectAlternativeName).value
        others = [n for n in san if isinstance(n, e1.x509.OtherName)]
        self.assertEqual(len(others), 1)
        self.assertEqual(others[0].type_id.dotted_string,
                         e1.UPN_OTHERNAME_OID)
        self.assertEqual(others[0].value,
                         e1._der_utf8("Administrator@forge.local"))

    def test_san_in_cert_roundtrip(self):
        import datetime
        csr, key_pem = e1.build_csr("analyst", 2048,
                                    "Administrator@forge.local")
        req = e1.x509.load_der_x509_csr(csr)
        from cryptography.hazmat.primitives import serialization as ser
        key = ser.load_pem_private_key(key_pem, password=None)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (e1.x509.CertificateBuilder()
                .subject_name(req.subject)
                .issuer_name(req.subject)
                .public_key(req.public_key())
                .serial_number(1)
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(req.extensions[0].value, critical=False)
                .sign(key, e1.hashes.SHA256()))
        der = cert.public_bytes(e1.serialization.Encoding.DER)
        self.assertTrue(e1.san_in_cert(der, "Administrator@forge.local"))
        self.assertFalse(e1.san_in_cert(der, "analyst@forge.local"))


class TestRequirements(unittest.TestCase):
    def test_declares_deps(self):
        self.assertIn("impacket", e1.Esc1.requirements)
        self.assertIn("cryptography", e1.Esc1.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(e1.Esc1)


if __name__ == "__main__":
    unittest.main()
