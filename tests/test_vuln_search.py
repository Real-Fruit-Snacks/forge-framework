"""Unit tests for vuln_search scoring + port_scan banners (no network).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "vuln_mod", ROOT / "modules" / "auxiliary" / "scanner" / "vuln_search.py"
)
vs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vs)

_spec2 = importlib.util.spec_from_file_location(
    "ps_mod", ROOT / "modules" / "auxiliary" / "scanner" / "port_scan.py"
)
ps = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(ps)


class TestVersionMatching(unittest.TestCase):
    def test_substring(self):
        self.assertTrue(vs.version_matches("apache 2.4.49 exploit", "2.4.49"))

    def test_fuzzy(self):
        self.assertTrue(vs.version_matches("openssh 8.2p1 rce", "8.2"))

    def test_mismatch(self):
        self.assertFalse(vs.version_matches("apache 2.2.15 exploit", "2.4.49"))

    def test_blank_version_always_matches(self):
        self.assertTrue(vs.version_matches("anything", ""))


class TestRelevanceScore(unittest.TestCase):
    def _r(self, **kw):
        base = {"kind": "github", "title": "", "desc": "", "url": "",
                "updated": "", "stars": 0}
        base.update(kw)
        return base

    def test_service_in_title_beats_description(self):
        strong = vs.relevance_score(
            self._r(title="apache exploit", desc=""), "apache", "", None)
        weak = vs.relevance_score(
            self._r(title="some repo", desc="apache"), "apache", "", None)
        self.assertGreater(strong, weak)

    def test_version_in_title_beats_fuzzy(self):
        strong = vs.relevance_score(
            self._r(title="apache 2.4.49 rce"), "apache", "2.4.49", None)
        weak = vs.relevance_score(
            self._r(title="apache something"), "apache", "2.4.49", None)
        self.assertGreater(strong, weak)

    def test_type_keywords_add(self):
        with_type = vs.relevance_score(
            self._r(title="svc rce poc"), "svc", "", "rce")
        without = vs.relevance_score(
            self._r(title="svc rce poc"), "svc", "", None)
        self.assertGreater(with_type, without)

    def test_searchsploit_bonus(self):
        gh = vs.relevance_score(
            self._r(kind="github", title="x exploit"), "x", "", None)
        edb = vs.relevance_score(
            self._r(kind="searchsploit", title="x exploit"), "x", "", None)
        self.assertEqual(edb, gh + 5)

    def test_score_capped_sanity(self):
        r = self._r(title="apache 2.4.49 rce poc exploit", stars=600,
                    updated="2999-01-01")
        score = vs.relevance_score(r, "apache", "2.4.49", "rce")
        self.assertLessEqual(score, 100)


class TestStoreDrivenQueries(unittest.TestCase):
    def test_pulls_named_services(self):
        class FakeStore:
            def services(self):
                return [
                    {"name": "ssh", "info": "OpenSSH_8.2p1 Ubuntu-4"},
                    {"name": "http", "info": "Apache/2.4.49"},
                    {"name": "", "info": ""},
                ]

        mod = vs.VulnSearch()
        mod.framework = type("F", (), {"store": FakeStore(),
                                       "global_options": {}})()
        mod.options["SERVICE"] = ""
        mod.options["VERSION"] = ""
        queries = mod._queries()
        self.assertEqual(len(queries), 2)
        self.assertEqual(queries[0], ("openssh", "8.2p1"))
        self.assertEqual(queries[1], ("apache", "2.4.49"))


class TestServiceVersionParsing(unittest.TestCase):
    def test_slash_form(self):
        self.assertEqual(vs._service_version("Apache/2.4.49 (Ubuntu)"),
                         ("apache", "2.4.49"))

    def test_openssh_banner(self):
        self.assertEqual(
            vs._service_version("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10"),
            ("openssh", "9.2p1"))

    def test_generic_fallback(self):
        self.assertEqual(vs._service_version("FrameworkLab/1.0 Python/3.14.6"),
                         ("frameworklab", "1.0"))  # slash form wins


class TestCleanBanner(unittest.TestCase):
    def test_first_printable_line(self):
        self.assertEqual(ps.clean_banner(b"\xffSSH-2.0-OpenSSH_8.2p1\r\n"),
                         "SSH-2.0-OpenSSH_8.2p1")

    def test_empty(self):
        self.assertEqual(ps.clean_banner(b"\x00\x01\x02"), "")


class TestFetchGithub(unittest.TestCase):
    @mock.patch.object(vs.urllib.request, "urlopen")
    def test_passes_token_argument(self, mock_urlopen):
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b'{"items": []}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        vs.fetch_github("apache", "2.4.49", "rce", token="ghp_secret")

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertEqual(req.headers.get("Authorization"), "Bearer ghp_secret")

    @mock.patch.dict("os.environ", {"GITHUB_TOKEN": "env_token"})
    @mock.patch.object(vs.urllib.request, "urlopen")
    def test_falls_back_to_env_token(self, mock_urlopen):
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b'{"items": []}'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        vs.fetch_github("apache", "2.4.49", "rce", token="")

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertEqual(req.headers.get("Authorization"), "Bearer env_token")


if __name__ == "__main__":
    unittest.main()
