"""Unit tests for core.output spool plumbing. Run: python3 -m unittest discover -s tests"""

import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import output  # noqa: E402


class TestSpoolWrite(unittest.TestCase):
    def tearDown(self):
        output.set_spool(None)

    def test_spool_write_strips_csi_sequences(self):
        buf = io.StringIO()
        output.set_spool(buf)
        output.spool_write("\x1b[32mgreen\x1b[0m and \x1b[2Kcleared\x1b[1G\n")
        output.set_spool(None)
        self.assertEqual(buf.getvalue(), "green and cleared\n")

    def test_spool_write_noop_without_spool(self):
        output.spool_write("nothing happens")  # must not raise

    def test_console_lines_also_spooled(self):
        buf = io.StringIO()
        output.set_spool(buf)
        output.print_line("plain line")
        output.set_spool(None)
        self.assertIn("plain line", buf.getvalue())


class TestDebug(unittest.TestCase):
    def tearDown(self):
        output.debug_enabled = False

    def test_debug_suppressed_by_default(self):
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            output.print_debug("secret detail")
        self.assertEqual(buf.getvalue(), "")

    def test_debug_shown_when_enabled(self):
        import contextlib

        output.debug_enabled = True
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            output.print_debug("secret detail")
        self.assertIn("secret detail", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
