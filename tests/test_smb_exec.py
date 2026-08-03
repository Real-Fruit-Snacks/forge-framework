"""Unit tests for the smb_exec module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "smb_exec_mod", ROOT / "modules" / "exploits" / "windows" / "smb_exec.py"
)
sx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sx)


class TestChainBuilder(unittest.TestCase):
    def test_chain_shape(self):
        chain = sx.build_exec_chain("whoami", r"%SYSTEMROOT%\Temp\x.bat",
                                    r"\\127.0.0.1\ADMIN$\Temp\o.txt")
        # echo into bat, escaped redirects, run bat, delete bat
        self.assertTrue(chain.startswith("%COMSPEC% /Q /c echo whoami "))
        self.assertIn(r"^> \\127.0.0.1\ADMIN$\Temp\o.txt 2^>^&1 > "
                      r"%SYSTEMROOT%\Temp\x.bat", chain)
        self.assertIn(r"& %COMSPEC% /Q /c %SYSTEMROOT%\Temp\x.bat", chain)
        self.assertTrue(chain.endswith(r"& del %SYSTEMROOT%\Temp\x.bat"))


class TestNormalizeCommand(unittest.TestCase):
    def test_plain_unchanged(self):
        self.assertEqual(sx.normalize_command("whoami /all"), "whoami /all")

    def test_metachars_wrapped(self):
        self.assertEqual(sx.normalize_command("hostname & whoami"),
                         'cmd /c "hostname & whoami"')
        self.assertEqual(sx.normalize_command("ipconfig | findstr IPv4"),
                         'cmd /c "ipconfig | findstr IPv4"')

    def test_already_quoted_untouched(self):
        cmd = 'cmd /c "hostname & whoami"'
        self.assertEqual(sx.normalize_command(cmd), cmd)


class TestSniffDecode(unittest.TestCase):
    def test_utf16_bom(self):
        data = b"\xff\xfe" + "nt authority\\system".encode("utf-16-le")
        self.assertEqual(sx.sniff_decode(data), "nt authority\\system")

    def test_utf16_no_bom(self):
        data = "whoami".encode("utf-16-le")
        self.assertEqual(sx.sniff_decode(data), "whoami")

    def test_ansi_passthrough(self):
        self.assertEqual(sx.sniff_decode(b"nt authority\\system\r\n"),
                         "nt authority\\system\r\n")


class TestRandName(unittest.TestCase):
    def test_prefix_and_length(self):
        name = sx.rand_name("svc", 12)
        self.assertTrue(name.startswith("svc"))
        self.assertEqual(len(name), 3 + 12)
        self.assertTrue(name[3:].islower())


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", sx.SmbExec.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(sx.SmbExec)


if __name__ == "__main__":
    unittest.main()
