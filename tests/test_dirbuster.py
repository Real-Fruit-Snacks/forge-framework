"""Unit tests for the dir buster's pure helpers (no sockets involved).

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
    "dir_buster_mod", ROOT / "modules" / "auxiliary" / "scanner" / "dir_buster.py"
)
db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(db)

Response = db.Response


class TestParseWordlist(unittest.TestCase):
    def test_skips_comments_blanks_and_slashes(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("# comment\n\nadmin\n/secret\n  padded  \n")
            path = f.name
        try:
            self.assertEqual(db.parse_wordlist(path), ["admin", "secret", "padded"])
        finally:
            Path(path).unlink()

    def test_missing_file_raises(self):
        with self.assertRaises(OSError):
            db.parse_wordlist("/nope/does-not-exist.txt")


class TestParseStatusCodes(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(db.parse_status_codes("200, 301,403"), {200, 301, 403})

    def test_rejects_garbage(self):
        for bad in ("abc", "99", "600", ""):
            with self.assertRaises(ValueError, msg=bad):
                db.parse_status_codes(bad)


class TestBuildPaths(unittest.TestCase):
    def test_base_normalization(self):
        self.assertEqual(
            list(db.build_paths(["admin"], [], "app")),
            ["/app/admin"],
        )
        self.assertEqual(
            list(db.build_paths(["admin"], [], "/")),
            ["/admin"],
        )

    def test_extensions(self):
        self.assertEqual(
            list(db.build_paths(["login"], ["php", "bak"])),
            ["/login", "/login.php", "/login.bak"],
        )

    def test_extend_paths_prefixes(self):
        self.assertEqual(
            list(db.extend_paths(["panel"], [], ["/", "/admin/"])),
            ["/panel", "/admin/panel"],
        )


class TestLooksLikeDir(unittest.TestCase):
    def test_dirs_and_files(self):
        self.assertTrue(db.looks_like_dir(200, "/admin"))
        self.assertTrue(db.looks_like_dir(403, "/secret"))
        self.assertTrue(db.looks_like_dir(301, "/docs"))
        self.assertFalse(db.looks_like_dir(200, "/db.sql"))
        self.assertFalse(db.looks_like_dir(404, "/nope"))


class TestFiltering(unittest.TestCase):
    def test_status_list(self):
        codes = {200, 403}
        self.assertTrue(db.is_interesting(Response(200, 100, ""), codes, None))
        self.assertTrue(db.is_interesting(Response(403, 100, ""), codes, None))
        self.assertFalse(db.is_interesting(Response(404, 100, ""), codes, None))

    def test_wildcard_suppression(self):
        codes = {200}
        wildcard = (200, 555)
        self.assertFalse(db.is_interesting(Response(200, 555, ""), codes, wildcard))
        self.assertTrue(db.is_interesting(Response(200, 12, ""), codes, wildcard))


class TestWildcardFingerprint(unittest.TestCase):
    def test_detects_soft_404(self):
        probe = lambda path: Response(200, 999, "")  # noqa: E731
        self.assertEqual(db.wildcard_fingerprint(probe), (200, 999))

    def test_well_behaved_server(self):
        probe = lambda path: Response(404, 10, "")  # noqa: E731
        # identical 404s are also a fingerprint — and harmless, since 404
        # won't be in STATUS_CODES anyway
        self.assertEqual(db.wildcard_fingerprint(probe), (404, 10))

    def test_inconsistent_server(self):
        responses = iter([Response(200, 1, ""), Response(200, 2, "")])
        probe = lambda path: next(responses)  # noqa: E731
        self.assertIsNone(db.wildcard_fingerprint(probe))


class TestModuleRun(unittest.TestCase):
    def test_missing_wordlist_is_a_clean_error(self):
        mod = db.DirBuster()
        mod["RHOSTS"] = "127.0.0.1"
        mod["WORDLIST"] = "/nope/nope.txt"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mod.run()
        self.assertIn("Cannot read wordlist", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
