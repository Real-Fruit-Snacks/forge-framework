"""Unit tests for the dpapi_credentials module (loads without deps).

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
    "cred_mod", ROOT / "modules" / "auxiliary" / "attack" /
    "dpapi_credentials.py"
)
cred = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cred)


class TestRequirements(unittest.TestCase):
    def test_declares_deps(self):
        self.assertIn("impacket", cred.DpapiCredentials.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(cred.DpapiCredentials)

    def test_profile_litter_is_skipped(self):
        for d in (".", "..", "Public", "Default", "Default User",
                  "All Users"):
            self.assertIn(d, cred.SKIP_DIRS)


if __name__ == "__main__":
    unittest.main()
