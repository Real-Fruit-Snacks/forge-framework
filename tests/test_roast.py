"""Unit tests for the roast modules (load fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


kb = load("kerberoast_mod", "modules/auxiliary/attack/kerberoast.py")
ar = load("asreproast_mod", "modules/auxiliary/attack/asreproast.py")


class TestTgsHashFormat(unittest.TestCase):
    def test_rc4(self):
        enc = bytes(range(48))
        h = kb.tgs_to_hash("svc", "forge.local", "HTTP/web", enc, kb.RC4)
        self.assertTrue(h.startswith("$krb5tgs$23$*svc$forge.local$HTTP/web*$"))
        self.assertIn(enc[:16].hex() + "$" + enc[16:].hex(), h)

    def test_aes256(self):
        enc = bytes(range(48))
        h = kb.tgs_to_hash("svc", "forge.local", "HTTP/web", enc, kb.AES256)
        self.assertTrue(h.startswith("$krb5tgs$18$svc$forge.local$HTTP/web$"))
        self.assertIn(enc[-12:].hex() + "$" + enc[:-12].hex(), h)

    def test_bad_etype_raises(self):
        with self.assertRaises(ValueError):
            kb.tgs_to_hash("svc", "d", "s", b"x" * 48, 17)

    def test_asrep_format(self):
        enc = bytes(range(48))
        h = ar.asrep_to_hash("noauth", "forge.local", enc)
        self.assertTrue(h.startswith("$krb5asrep$23$noauth@forge.local:"))
        self.assertIn(enc[:16].hex() + "$" + enc[16:].hex(), h)


@unittest.skipUnless(ar.constants is not None, "impacket not installed")
class TestAsReqBuilder(unittest.TestCase):
    def test_encodes_parseable_as_req(self):
        raw = ar.build_as_req("noauth", "forge.local")
        self.assertIsInstance(raw, bytes)
        req = ar.decoder.decode(raw, asn1Spec=ar.AS_REQ())[0]
        self.assertEqual(str(req["req-body"]["realm"]), "forge.local")
        cname = req["req-body"]["cname"]
        self.assertEqual([str(c) for c in cname["name-string"]], ["noauth"])
        sname = req["req-body"]["sname"]
        self.assertEqual([str(c) for c in sname["name-string"]],
                         ["krbtgt", "forge.local"])


class TestTargetedHelpers(unittest.TestCase):
    def test_throwaway_spn_shape(self):
        import re
        for _ in range(20):
            spn = kb.throwaway_spn("forge.local")
            self.assertRegex(spn, r"^fzr/[a-z0-9]{8}\.forge\.local$")

    def test_spn_add_del_ops_are_value_specific(self):
        add = kb.spn_add_ops("fzr/abc12345.forge.local")
        self.assertEqual(add, {"servicePrincipalName":
                               [(0, ["fzr/abc12345.forge.local"])]})
        delete = kb.spn_del_ops("fzr/abc12345.forge.local")
        self.assertEqual(delete, {"servicePrincipalName":
                                  [(1, ["fzr/abc12345.forge.local"])]})


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", kb.Kerberoast.requirements)
        self.assertIn("impacket", ar.AsRepRoast.requirements)


if __name__ == "__main__":
    unittest.main()
