"""Unit tests for the proc_watch module (loads fine without pywinrm).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "proc_watch_mod", ROOT / "modules" / "auxiliary" / "enum" / "proc_watch.py"
)
pw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pw)

CSV_SAMPLE = """"ProcessId","ParentProcessId","Name","CommandLine"
"4","0","System",""
"500","4","smss.exe","\\SystemRoot\\System32\\smss.exe"
"700","500","services.exe","C:\\Windows\\system32\\services.exe"
"1234","700","cmd.exe","cmd.exe /c hostname"
"""


class TestParseSnapshot(unittest.TestCase):
    def test_parses_rows(self):
        snap = pw.parse_snapshot(CSV_SAMPLE)
        self.assertEqual(len(snap), 4)
        self.assertEqual(snap[1234], ("cmd.exe", 700, "cmd.exe /c hostname"))
        self.assertEqual(snap[700], ("services.exe", 500,
                                     "C:\\Windows\\system32\\services.exe"))

    def test_missing_cmdline_tolerated(self):
        snap = pw.parse_snapshot(CSV_SAMPLE)
        self.assertEqual(snap[4][2], "")

    def test_garbage_skipped(self):
        snap = pw.parse_snapshot('"ProcessId","ParentProcessId","Name"\n'
                                 '"notanum","4","x.exe"\n"1","0","ok.exe"')
        self.assertEqual(set(snap), {1})


class TestAnnotate(unittest.TestCase):
    def test_service(self):
        self.assertEqual(pw.annotate("cmd.exe", "services.exe"),
                         "service started")

    def test_scheduled_task(self):
        for parent in ("svchost.exe", "taskeng.exe", "taskhostw.exe"):
            self.assertEqual(pw.annotate("x.exe", parent),
                             "scheduled task fired", parent)

    def test_wmi(self):
        self.assertEqual(pw.annotate("x.exe", "wmiprvse.exe"),
                         "wmi provider spawn")

    def test_other(self):
        self.assertEqual(pw.annotate("x.exe", "explorer.exe"),
                         "process spawn")

    def test_unknown_parent(self):
        self.assertEqual(pw.annotate("x.exe", "?"), "process spawn")


class TestRequirements(unittest.TestCase):
    def test_declares_winrm(self):
        self.assertIn("winrm", pw.ProcWatch.requirements)

    def test_module_loads_without_pywinrm(self):
        self.assertIsNotNone(pw.ProcWatch)


if __name__ == "__main__":
    unittest.main()
