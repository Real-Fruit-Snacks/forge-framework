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
        self.assertTrue(db.is_interesting(Response(200, 100, "", b"x"), codes, None))
        self.assertTrue(db.is_interesting(Response(403, 100, "", b"x"), codes, None))
        self.assertFalse(db.is_interesting(Response(404, 100, "", b"x"), codes, None))

    def test_wildcard_suppression(self):
        codes = {200}
        page = b"same page body"
        canary = (200, 555, page)
        # same family: suppressed — even with a nonce-length wiggle
        self.assertFalse(db.is_interesting(
            Response(200, 560, "", page), codes, canary))
        # different page entirely: reported
        self.assertTrue(db.is_interesting(
            Response(200, 12, "", b"real content here"), codes, canary))

    def test_nonce_variant_suppressed(self):
        # the SPA case: bodies differ by an embedded nonce but are
        # similar enough to match the canary family
        codes = {200}
        canary = (200, 100, b"<title>SPA</title><script src=a.js?b=ab12cd>")
        resp = Response(200, 105, "",
                        b"<title>SPA</title><script src=a.js?b=99ff00ee>")
        self.assertFalse(db.is_interesting(resp, codes, canary))


class TestWildcardFingerprint(unittest.TestCase):
    def test_detects_soft_404(self):
        probe = lambda path: Response(200, 999, "", b"soft 404 page")  # noqa: E731
        self.assertEqual(db.wildcard_fingerprint(probe),
                         (200, 999, b"soft 404 page"))

    def test_detects_despite_nonce(self):
        pages = iter([b"shell build=a1", b"shell build=b22ccc"])
        sizes = iter([15, 18])
        probe = lambda path: Response(200, next(sizes), "", next(pages))  # noqa: E731
        canary = db.wildcard_fingerprint(probe)
        self.assertIsNotNone(canary)
        self.assertEqual(canary[0], 200)

    def test_well_behaved_server(self):
        probe = lambda path: Response(404, 10, "", b"nope")  # noqa: E731
        # identical 404s are also a fingerprint — and harmless, since 404
        # won't be in STATUS_CODES anyway
        self.assertEqual(db.wildcard_fingerprint(probe), (404, 10, b"nope"))

    def test_inconsistent_server(self):
        responses = iter([Response(200, 1, "", b"aaaa"),
                          Response(200, 2, "", b"completely different")])
        probe = lambda path: next(responses)  # noqa: E731
        self.assertIsNone(db.wildcard_fingerprint(probe))


class TestContentValidators(unittest.TestCase):
    def test_env_valid(self):
        self.assertTrue(db.looks_like_env(b"APP_ENV=prod\nDB_PASSWORD=x\n"))

    def test_env_rejects_html(self):
        self.assertFalse(db.looks_like_env(b"<html><body>page</body></html>"))

    def test_env_rejects_free_text(self):
        self.assertFalse(db.looks_like_env(b"just some notes\nno equals here"))

    def test_actuator(self):
        self.assertTrue(db.looks_like_actuator(b'{"_links": {"self": {}}}'))
        self.assertFalse(db.looks_like_actuator(b"<html>"))

    def test_validator_for(self):
        self.assertIs(db.validator_for("/.env"), db.looks_like_env)
        self.assertIsNone(db.validator_for("/admin"))


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
