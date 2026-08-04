"""Unit tests for the mssql modules (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "me_mod", ROOT / "modules" / "auxiliary" / "enum" / "mssql_enum.py"
)
me = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(me)

_spec2 = importlib.util.spec_from_file_location(
    "mx_mod", ROOT / "modules" / "auxiliary" / "attack" / "mssql_exec.py"
)
mx = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(mx)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", me.MssqlEnum.requirements)
        self.assertIn("impacket", mx.MssqlExec.requirements)

    def test_modules_load_without_deps(self):
        self.assertIsNotNone(me.MssqlEnum)
        self.assertIsNotNone(mx.MssqlExec)


class TestExecHelpers(unittest.TestCase):
    def test_quote(self):
        inst = mx.MssqlExec.__new__(mx.MssqlExec)
        self.assertEqual(inst._quote("whoami"), "whoami")
        self.assertEqual(inst._quote("type c:\\users' file"),
                         "type c:\\users'' file")


if __name__ == "__main__":
    unittest.main()
