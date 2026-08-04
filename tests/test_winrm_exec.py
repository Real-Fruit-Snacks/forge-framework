"""Unit tests for the winrm_exec module (loads fine without pywinrm).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "winrm_exec_mod", ROOT / "modules" / "exploits" / "windows" / "winrm_exec.py"
)
wx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wx)


class TestHelpers(unittest.TestCase):
    def test_endpoint(self):
        self.assertEqual(wx.endpoint("http", "10.0.0.5", 5985),
                         "http://10.0.0.5:5985/wsman")
        self.assertEqual(wx.endpoint("https", "dc.forge.local", 5986),
                         "https://dc.forge.local:5986/wsman")

    def test_principal_for(self):
        self.assertEqual(wx.principal_for(".", "labadmin"), "labadmin")
        self.assertEqual(wx.principal_for("", "labadmin"), "labadmin")
        self.assertEqual(wx.principal_for("forge.local", "analyst"),
                         "forge.local\\analyst")


class TestRequirements(unittest.TestCase):
    def test_declares_deps(self):
        self.assertIn("winrm", wx.WinrmExec.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(wx.WinrmExec)


if __name__ == "__main__":
    unittest.main()
