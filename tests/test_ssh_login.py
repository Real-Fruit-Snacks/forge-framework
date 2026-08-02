"""Unit tests for the ssh_login module (loads fine without paramiko).

Run: python3 -m unittest discover -s tests
"""

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ssh_login_mod", ROOT / "modules" / "auxiliary" / "login" / "ssh_login.py"
)
sl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sl)


class TestRequirements(unittest.TestCase):
    def test_declares_paramiko(self):
        self.assertIn("paramiko", sl.SshLogin.requirements)

    def test_module_loads_without_paramiko(self):
        # the lazy-import convention: file loads even if the dep is absent
        self.assertIsNotNone(sl.SshLogin)

    def test_missing_requirements_reflects_environment(self):
        mod = sl.SshLogin()
        if sl.paramiko is None:
            self.assertEqual(mod.missing_requirements(), ["paramiko"])
        else:
            self.assertEqual(mod.missing_requirements(), [])


class TestRunValidation(unittest.TestCase):
    def test_missing_creds_is_a_clean_error(self):
        mod = sl.SshLogin()
        mod["RHOSTS"] = "127.0.0.1"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mod.run()
        self.assertIn("Need at least one username", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
