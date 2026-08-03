"""Unit tests for the smb_login module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "smb_login_mod", ROOT / "modules" / "auxiliary" / "login" / "smb_login.py"
)
sl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sl)


class TestClassifyStatus(unittest.TestCase):
    def test_logon_failure_is_plain_fail(self):
        verdict, _ = sl.classify_status(sl.STATUS_LOGON_FAILURE)
        self.assertEqual(verdict, "fail")

    def test_expired_password_counts_success(self):
        for code in (sl.STATUS_PASSWORD_EXPIRED, sl.STATUS_PASSWORD_MUST_CHANGE):
            verdict, note = sl.classify_status(code)
            self.assertEqual(verdict, "success", f"0x{code:08x}")
            self.assertIn("expired", note)

    def test_locked_out_gets_own_verdict(self):
        verdict, note = sl.classify_status(sl.STATUS_ACCOUNT_LOCKED_OUT)
        self.assertEqual(verdict, "locked")
        self.assertIn("locked", note)

    def test_disabled_is_fail_with_note(self):
        verdict, note = sl.classify_status(sl.STATUS_ACCOUNT_DISABLED)
        self.assertEqual(verdict, "fail")
        self.assertIn("disabled", note)

    def test_unknown_codes_collapse_to_fail(self):
        self.assertEqual(sl.classify_status(0xDEADBEEF)[0], "fail")


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", sl.SmbLogin.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(sl.SmbLogin)


if __name__ == "__main__":
    unittest.main()
