"""Unit tests for the coerce module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "coerce_mod", ROOT / "modules" / "auxiliary" / "attack" / "coerce.py"
)
co = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(co)


class TestMethodMatrix(unittest.TestCase):
    def test_methods(self):
        self.assertEqual(co.METHODS, ("printerbug", "petitpotam",
                                      "dfscoerce", "shadowcoerce"))
        for method in co.METHODS:
            self.assertTrue(hasattr(co.Coerce, f"_coerce_{method}"))


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", co.Coerce.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(co.Coerce)


@unittest.skipUnless(co.rprn is not None, "impacket not installed")
class TestVendoredNdr(unittest.TestCase):
    def test_opnums(self):
        self.assertEqual(co.EfsRpcOpenFileRaw.opnum, 0)
        self.assertEqual(co.NetrDfsRemoveStdRoot.opnum, 13)
        self.assertEqual(co.IsPathSupported.opnum, 8)

    def test_efs_request_encodes(self):
        request = co.EfsRpcOpenFileRaw()
        request["FileName"] = "\\\\10.0.0.5\\share\\file.txt\x00"
        request["Flag"] = 0
        data = request.getData()
        self.assertIn(b"1\x000\x00.\x000\x00.\x000\x00.\x005\x00", data)

    def test_uuids_parse(self):
        self.assertEqual(len(co.EFSRPC_UUID), 20)
        self.assertEqual(len(co.DFSNM_UUID), 20)
        self.assertEqual(len(co.FSRVP_UUID), 20)


if __name__ == "__main__":
    unittest.main()
