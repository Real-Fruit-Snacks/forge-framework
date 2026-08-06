"""Unit tests for core option types."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.options import OptPassword, OptString  # noqa: E402


class TestOptPassword(unittest.TestCase):
    def test_masks_value_in_display(self):
        opt = OptPassword("TOKEN", default="")
        opt.set("ghp_super_secret_token_value")
        self.assertEqual(opt.display_value(), "*" * 16)

    def test_empty_display_is_empty(self):
        opt = OptPassword("TOKEN", default="")
        self.assertEqual(opt.display_value(), "")

    def test_current_returns_real_value(self):
        opt = OptPassword("TOKEN", default="")
        opt.set("secret")
        self.assertEqual(opt.current, "secret")

    def test_string_option_still_shows_plaintext(self):
        opt = OptString("TOKEN", default="")
        opt.set("secret")
        self.assertEqual(opt.display_value(), "secret")


if __name__ == "__main__":
    unittest.main()
