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
hex_enc = load("hex_enc", "modules/payloads/encoders/hex_command.py")
bad = load("bad_enc", "modules/payloads/encoders/badchar.py")


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


class TestHexCommand(unittest.TestCase):
    def test_roundtrip(self):
        wrapped = hex_enc.wrap_hex("id; cat /etc/passwd")
        encoded = wrapped.split()[1]
        self.assertEqual(bytes.fromhex(encoded).decode(), "id; cat /etc/passwd")
        self.assertTrue(wrapped.endswith("| xxd -r -p | sh"))

    def test_alphabet_is_hex_only(self):
        wrapped = hex_enc.wrap_hex("python3 -c 'import socket'")
        encoded = wrapped.split()[1]
        self.assertTrue(all(c in "0123456789abcdef" for c in encoded))


class TestBadchar(unittest.TestCase):
    def _generate(self, payload, badchars):
        mod = bad.Badchar()
        mod["PAYLOAD"] = payload
        mod["BADCHARS"] = badchars
        return mod.generate()

    def test_avoids_null_and_newline(self):
        wrapped = self._generate("id; cat /etc/passwd", "\\x00\\x0a")
        self.assertNotIn("\x00", wrapped)
        self.assertNotIn("\x0a", wrapped)

    def test_falls_back_when_base64_alphabet_is_forbidden(self):
        # Base64 output always contains at least one of these for any
        # non-trivial payload; hex should be chosen instead.
        wrapped = self._generate("id", "+/=")
        self.assertIn("xxd", wrapped)

    def test_impossible_badchars_raise(self):
        with self.assertRaises(ValueError):
            self._generate(
                "id",
                "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"
                "\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f"
                "\\x20\\x7c",
            )

    def test_empty_badchars_defaults_to_base64(self):
        wrapped = self._generate("id", "")
        self.assertIn("base64", wrapped)


if __name__ == "__main__":
    unittest.main()
