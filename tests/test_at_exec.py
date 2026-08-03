"""Unit tests for the at_exec module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "at_exec_mod", ROOT / "modules" / "exploits" / "windows" / "at_exec.py"
)
at = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(at)


class TestTaskXml(unittest.TestCase):
    def test_parens_grouped_command(self):
        xml = at.build_task_xml("whoami", r"C:\Windows\Temp\o.txt")
        self.assertIn("/C ( whoami )", xml)
        self.assertIn("&gt; C:\\Windows\\Temp\\o.txt 2&gt;&amp;1", xml)
        self.assertIn("<Hidden>true</Hidden>", xml)
        self.assertIn("S-1-5-18", xml)  # LocalSystem

    def test_metacharacters_escaped_not_wrapped(self):
        # & must be XML-escaped but NOT shell-wrapped — the parens group
        # is what makes it work
        xml = at.build_task_xml("hostname & whoami", r"C:\o.txt")
        self.assertIn("/C ( hostname &amp; whoami )", xml)

    def test_xml_injection_safe(self):
        xml = at.build_task_xml('a<b>"c"', "o")
        self.assertIn("a&lt;b&gt;&quot;c&quot;", xml)


class TestSniffDecode(unittest.TestCase):
    def test_utf16_bom(self):
        self.assertEqual(at.sniff_decode(b"\xff\xfeh\x00i\x00"), "hi")

    def test_utf16_no_bom(self):
        self.assertEqual(at.sniff_decode("hi".encode("utf-16-le")), "hi")

    def test_ansi(self):
        self.assertEqual(at.sniff_decode(b"plain"), "plain")


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", at.AtExec.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(at.AtExec)


if __name__ == "__main__":
    unittest.main()
