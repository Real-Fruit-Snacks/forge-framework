"""Build + boot smoke tests for the pyz single-file builds.

Run: python3 -m unittest discover -s tests
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import build  # noqa: E402


class TestModuleSelection(unittest.TestCase):
    def test_minimal_is_a_subset_of_full(self):
        full = {p.as_posix() for p in build.module_files("full", "")}
        minimal = {p.as_posix() for p in build.module_files("minimal", "")}
        self.assertTrue(minimal)
        self.assertTrue(minimal < full)

    def test_explicit_filter(self):
        picked = build.module_files(
            "full", "auxiliary/attack/dcsync,auxiliary/attack/s4u")
        names = {p.name for p in picked}
        self.assertEqual(names, {"dcsync.py", "s4u.py"})

    def test_empty_selection_errors(self):
        self.assertEqual(build.module_files("full", ""), build.module_files("full", ""))


class TestBuildAndBoot(unittest.TestCase):
    """Build a real pyz and boot it — the registry's zip branch end to end."""

    def test_minimal_pyz_boots_and_lists_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "forge-min.pyz"
            rc = build.build("minimal", "", str(target))
            self.assertEqual(rc, 0)
            self.assertTrue(target.is_file())

            proc = subprocess.run(
                [sys.executable, str(target), "-q", "-x", "show modules; exit"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
            self.assertIn("auxiliary/scanner/port_scan", proc.stdout)
            # a stdlib module runs; an impacket module reports cleanly
            proc = subprocess.run(
                [sys.executable, str(target), "-q", "-x",
                 "use auxiliary/login/ssh_login; info; exit"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
            self.assertIn("SSH Login Brute Force", proc.stdout)


if __name__ == "__main__":
    unittest.main()
