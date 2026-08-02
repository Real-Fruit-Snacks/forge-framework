"""Unit tests for http_login's pure helpers (no sockets involved).

Run: python3 -m unittest discover -s tests
"""

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "http_login_mod", ROOT / "modules" / "auxiliary" / "login" / "http_login.py"
)
hl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hl)

Result = hl.Result


class TestLoadLines(unittest.TestCase):
    def test_skips_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("# comment\n\nadmin\nroot\n")
            path = f.name
        try:
            self.assertEqual(hl.load_lines(path), ["admin", "root"])
        finally:
            Path(path).unlink()


class TestBuildCombos(unittest.TestCase):
    def test_user_major_cross_product(self):
        combos = list(hl.build_combos(["a", "b"], ["1", "2", "3"]))
        self.assertEqual(
            combos,
            [("a", "1"), ("a", "2"), ("a", "3"),
             ("b", "1"), ("b", "2"), ("b", "3")],
        )


class TestBasicAuthValue(unittest.TestCase):
    def test_encoding(self):
        self.assertEqual(
            hl.basic_auth_value("admin", "hunter2"),
            "Basic YWRtaW46aHVudGVyMg==",
        )


class TestClassifyBasic(unittest.TestCase):
    def test_branches(self):
        self.assertEqual(hl.classify_basic(200), "success")
        self.assertEqual(hl.classify_basic(204), "success")
        self.assertEqual(hl.classify_basic(401), "fail")
        self.assertEqual(hl.classify_basic(404), "error")
        self.assertEqual(hl.classify_basic(500), "error")


class TestClassifyForm(unittest.TestCase):
    def test_success_string_wins(self):
        res = Result(200, 50, "Welcome back!")
        self.assertTrue(hl.classify_form(res, None, "Welcome", "invalid"))
        self.assertFalse(hl.classify_form(res, None, "Dashboard", ""))

    def test_failure_string_absence(self):
        self.assertFalse(
            hl.classify_form(Result(200, 50, "invalid username"), None, "", "invalid")
        )
        self.assertTrue(
            hl.classify_form(Result(200, 50, "hello"), None, "", "invalid")
        )

    def test_baseline_deviation(self):
        baseline = (200, 100)
        self.assertTrue(hl.classify_form(Result(200, 250, "x"), baseline, "", ""))
        self.assertTrue(hl.classify_form(Result(302, 0, "x"), baseline, "", ""))
        self.assertFalse(hl.classify_form(Result(200, 100, "x"), baseline, "", ""))

    def test_no_signals_means_no_guess(self):
        self.assertFalse(hl.classify_form(Result(200, 100, "x"), None, "", ""))


class TestModuleRunValidation(unittest.TestCase):
    def test_missing_creds_is_a_clean_error(self):
        mod = hl.HttpLogin()
        mod["RHOSTS"] = "127.0.0.1"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mod.run()
        self.assertIn("Need at least one username", buf.getvalue())


class TestBruteEngine(unittest.TestCase):
    """The queue/stop-event engine, exercised with a fake attempt function."""

    def test_processes_every_combo(self):
        mod = hl.HttpLogin()
        combos = [(f"user{i}", f"pass{j}") for i in range(3) for j in range(20)]
        seen = []

        def attempt(u, p):
            seen.append((u, p))
            return Result(401, 0, "")

        found, attempts, errors = mod._brute("h", combos, attempt, lambda r: "fail")
        self.assertEqual(found, [])
        self.assertEqual(attempts, 60)
        self.assertEqual(errors, 0)
        self.assertEqual(len(seen), 60)

    def test_stop_on_first_success(self):
        mod = hl.HttpLogin()
        combos = [("admin", f"pass{i}") for i in range(100)]

        def attempt(u, p):
            return Result(200 if p == "pass7" else 401, 0, "")

        classify = lambda r: "success" if r.status == 200 else "fail"  # noqa: E731
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            found, attempts, errors = mod._brute("h", combos, attempt, classify)
        self.assertEqual(found, [("admin", "pass7")])
        self.assertLess(attempts, 100)

    def test_errors_are_counted(self):
        mod = hl.HttpLogin()
        combos = [("u", "p")] * 5
        found, attempts, errors = mod._brute(
            "h", combos, lambda u, p: Result(500, 0, ""), lambda r: "error"
        )
        self.assertEqual((found, attempts, errors), ([], 5, 5))


if __name__ == "__main__":
    unittest.main()
