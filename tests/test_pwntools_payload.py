"""Unit tests for the pwntools shellcode payload.

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "shellcode_mod", ROOT / "modules" / "payloads" / "shellcode_reverse_tcp.py"
)
sc_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc_mod)

PWNTOOLS = sc_mod.shellcraft is not None


class TestRequirements(unittest.TestCase):
    def test_declares_pwntools(self):
        self.assertIn("pwntools", sc_mod.ShellcodeReverseTcp.requirements)

    def test_module_loads_without_pwntools(self):
        self.assertIsNotNone(sc_mod.ShellcodeReverseTcp)


@unittest.skipUnless(PWNTOOLS, "pwntools not installed")
class TestGenerate(unittest.TestCase):
    def test_shellcode_bytes(self):
        mod = sc_mod.ShellcodeReverseTcp()
        mod["LHOST"] = "10.10.14.5"
        mod["LPORT"] = "4444"
        out = mod.generate()
        self.assertIn('shellcode = b"', out)
        self.assertIn("10.10.14.5", out)
        self.assertNotIn("\\x00", out)  # shellcode must be null-free
        self.assertIn("\\x0f\\x05", out)  # syscall opcode — real code, not padding


if __name__ == "__main__":
    unittest.main()
