"""Unit tests for the kerberos_login module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "kerb_login_mod",
    ROOT / "modules" / "auxiliary" / "login" / "kerberos_login.py",
)
kl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kl)


@unittest.skipUnless(kl.constants is not None, "impacket not installed")
class TestAsReqBuilder(unittest.TestCase):
    def test_encodes_parseable_as_req(self):
        from impacket.krb5.asn1 import AS_REQ
        from pyasn1.codec.der import decoder

        raw = kl.build_as_req("analyst", "forge.local")
        req = decoder.decode(raw, asn1Spec=AS_REQ())[0]
        self.assertEqual(str(req["req-body"]["realm"]), "forge.local")
        cname = req["req-body"]["cname"]
        self.assertEqual([str(c) for c in cname["name-string"]], ["analyst"])
        # no preauth data — the enum oracle sends nothing that touches
        # account state
        self.assertFalse(req["padata"].hasValue())


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", kl.KerberosLogin.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(kl.KerberosLogin)


if __name__ == "__main__":
    unittest.main()
