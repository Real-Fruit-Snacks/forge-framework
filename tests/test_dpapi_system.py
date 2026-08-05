"""Unit tests for the dpapi_system module (loads without deps).

The crypto it exercises lives in core/dpapi.py — tested in
tests/test_core_dpapi.py. This file covers module-level concerns only.

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "sys_mod", ROOT / "modules" / "auxiliary" / "attack" / "dpapi_system.py"
)
sys_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sys_mod)


class TestRequirements(unittest.TestCase):
    def test_declares_deps(self):
        self.assertIn("impacket", sys_mod.DpapiSystem.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(sys_mod.DpapiSystem)

    def test_paths_are_system_scoped(self):
        self.assertIn("System32", sys_mod.PROTECT)
        self.assertIn("Wlansvc", sys_mod.WLANSVC)


if __name__ == "__main__":
    unittest.main()
