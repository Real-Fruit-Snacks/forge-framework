"""Unit tests for the encoder payloads. Run: python3 -m unittest discover -s tests"""

import base64
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


b64 = load("b64_enc", "modules/payloads/encoders/base64_command.py")
ps = load("ps_enc", "modules/payloads/encoders/ps_base64.py")


class TestBase64Command(unittest.TestCase):
    def test_roundtrip(self):
        wrapped = b64.wrap_base64("id; cat /etc/passwd")
        encoded = wrapped.split()[1]
        self.assertEqual(base64.b64decode(encoded).decode(), "id; cat /etc/passwd")
        self.assertTrue(wrapped.endswith("| base64 -d | sh"))

    def test_no_shell_keywords_leak(self):
        wrapped = b64.wrap_base64("python3 -c 'import socket'")
        self.assertNotIn("python", wrapped.split()[1])
        self.assertNotIn("socket", wrapped.split()[1])


class TestPsBase64(unittest.TestCase):
    def test_utf16le_encoding(self):
        wrapped = ps.wrap_ps("whoami")
        encoded = wrapped.split()[-1]
        self.assertEqual(base64.b64decode(encoded).decode("utf-16-le"), "whoami")


if __name__ == "__main__":
    unittest.main()
