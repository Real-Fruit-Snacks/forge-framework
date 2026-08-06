"""Unit tests for the pkinit wire core + module (loads without deps).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "pkinit_core", ROOT / "core" / "pkinit.py"
)
pk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pk)

_mod_spec = importlib.util.spec_from_file_location(
    "pkinit_mod", ROOT / "modules" / "auxiliary" / "attack" / "pkinit.py"
)
mod = importlib.util.module_from_spec(_mod_spec)
_mod_spec.loader.exec_module(mod)


class TestRequirements(unittest.TestCase):
    def test_declares_deps(self):
        self.assertIn("impacket", mod.Pkinit.requirements)
        self.assertIn("cryptography", mod.Pkinit.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(mod.Pkinit)

    def test_core_exposes_wire_functions(self):
        self.assertTrue(callable(pk.request_tgt))
        self.assertTrue(callable(pk.unpac_nthash))
        self.assertTrue(callable(pk.parse_pem_bundle))


class TestDerToolkit(unittest.TestCase):
    def test_int_roundtrip(self):
        for value in (0, 1, 127, 128, 255, 65535, 2 ** 64):
            der = pk._int(value)
            tag, content, end = pk._read_tlv(der)
            self.assertEqual(tag, 0x02)
            self.assertEqual(end, len(der))
            self.assertEqual(int.from_bytes(content, "big"), value)

    def test_oid_encoding(self):
        der = pk._oid("1.2.840.113549.1.7.2")
        tag, content, _ = pk._read_tlv(der)
        self.assertEqual(tag, 0x06)
        self.assertEqual(content, bytes.fromhex("2a864886f70d010702"))

    def test_long_form_length(self):
        blob = pk._octet(b"\xaa" * 300)
        tag, content, end = pk._read_tlv(blob)
        self.assertEqual(tag, 0x04)
        self.assertEqual(len(content), 300)
        self.assertEqual(end, len(blob))

    def test_truncate_key(self):
        import hashlib
        key = pk.truncate_key(b"shared-secret", 32)
        self.assertEqual(len(key), 32)
        self.assertTrue(key.startswith(
            hashlib.sha1(b"\x00shared-secret").digest()[:8]))
        # counter increments feed the tail
        self.assertNotEqual(key[:20], key[20:32].ljust(20, b"\x00")[:20])


@unittest.skipUnless(pk.x509 is not None, "cryptography not installed")
class TestCmsAndAuthpack(unittest.TestCase):
    def _cert_key(self):
        import datetime
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "fz")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (cx509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(424242)
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=1))
                .sign(key, hashes.SHA256()))
        return cert, key

    def test_authpack_shape(self):
        import datetime
        import hashlib
        body = b"\x30\x03\x02\x01\x05"
        pack = pk.build_authpack(body, dh_pub=7, client_nonce=b"n" * 32,
                                 nonce=99,
                                 moment=datetime.datetime(2026, 8, 4, 12, 0, 0))
        tag, content, end = pk._read_tlv(pack)
        self.assertEqual(tag, 0x30)
        self.assertEqual(end, len(pack))
        # [3] paChecksum = sha1(req-body)
        self.assertIn(hashlib.sha1(body).digest(), pack)
        # [2] clientDHNonce present
        self.assertIn(b"n" * 32, pack)

    def test_cms_signature_verifies(self):
        cert, key = self._cert_key()
        content = b"\x30\x05\x04\x03abc"
        cms = pk.cms_signed_data(content, pk.OID_PKINIT_AUTH, cert, key)
        # ContentInfo shape: SEQUENCE { OID signedData, [0] ... }
        tag, body, end = pk._read_tlv(cms)
        self.assertEqual(tag, 0x30)
        self.assertEqual(end, len(cms))
        tag, oid_body, pos = pk._read_tlv(body, 0)
        self.assertEqual(tag, 0x06)
        self.assertEqual(oid_body, bytes.fromhex("2a864886f70d010702"))
        # the content rides inside
        self.assertIn(b"abc", cms)
        # and the signature verifies against the cert's public key
        import hashlib
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        # the two CMS interop shapes the Windows KDC holds us to: the
        # signedAttrs FIELD rides [0] IMPLICIT (attrs inline, no SET
        # wrapper — double-tagging fails decode), while the SIGNATURE
        # input stays the UNIVERSAL SET-tagged encoding (crypt32
        # computes over the SET form, not the RFC 5652 implicit form)
        attrs_body = (
            pk._seq(pk._oid(pk.OID_CONTENT_TYPE) +
                    pk._set(pk._oid(pk.OID_PKINIT_AUTH))) +
            pk._seq(pk._oid(pk.OID_MESSAGE_DIGEST) +
                    pk._set(pk._octet(hashlib.sha1(content).digest()))))
        attrs_field = pk._ctx(0, attrs_body)  # the wire form
        attrs_set = pk._set(attrs_body)       # the signature input
        self.assertIn(attrs_field, cms)
        self.assertNotIn(attrs_set, cms)
        start = cms.rindex(attrs_field)
        sig_tlv = cms[start + len(attrs_field):]
        # skip the signatureAlgorithm SEQ, read the OCTET STRING
        tag, _alg, pos2 = pk._read_tlv(sig_tlv, 0)
        # find the OCTET STRING after signedAttrs
        tag, sig, _ = pk._read_tlv(cms, _find_sig_octet(cms, attrs_field))
        cert.public_key().verify(sig, attrs_set, padding.PKCS1v15(),
                                 hashes.SHA1())

    def test_pem_bundle_roundtrip(self):
        from cryptography.hazmat.primitives import serialization
        cert, key = self._cert_key()
        pem = (cert.public_bytes(serialization.Encoding.PEM) +
               key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()))
        c2, k2 = pk.parse_pem_bundle(pem)
        self.assertEqual(c2.serial_number, 424242)


def _find_sig_octet(cms, attrs):
    """offset of the signature OCTET STRING TLV inside the blob."""
    start = cms.rindex(attrs) + len(attrs)
    # next TLV is signatureAlgorithm SEQUENCE, then the OCTET STRING
    _tag, _content, end = pk._read_tlv(cms, start)
    return end


@unittest.skipUnless(pk.x509 is not None, "cryptography not installed")
class TestDhRepInfoParsing(unittest.TestCase):
    def test_roundtrip(self):
        # build a synthetic DHRepInfo the same shape the KDC sends
        kdc_pub = 0xC0FFEE
        nonce = b"S" * 32
        keyinfo = pk._seq(pk._ctx(0, pk._bitstring(pk._int(kdc_pub))) +
                          pk._ctx(1, pk._octet(nonce)))
        encap = pk._seq(pk._oid(pk.OID_PKINIT_KDCDH) +
                        pk._ctx(0, pk._octet(keyinfo)))
        signed = pk._seq(pk._int(3) + pk._set(b"") + encap)
        ci = pk._seq(pk._oid(pk.OID_SIGNED_DATA) + pk._ctx(0, signed))
        dhrep = pk._seq(pk._ctx(0, ci) + pk._ctx(1, pk._octet(nonce)))
        pub2, nonce2 = pk.parse_dh_rep_info(dhrep)
        self.assertEqual(pub2, kdc_pub)
        self.assertEqual(nonce2, nonce)


if __name__ == "__main__":
    unittest.main()
