"""Unit tests for the credpatterns corpus (stdlib-only).

Run: python3 -m unittest discover -s tests
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import credpatterns as cp  # noqa: E402


class TestTierFilename(unittest.TestCase):
    def test_critical_containers(self):
        for name in ("vault.kdbx", "user.ppk", "cert.pfx", "svc.keytab"):
            self.assertEqual(cp.tier_filename(name)[0], "CRITICAL", name)

    def test_interest_extensions(self):
        for name in ("id_rsa.pem", ".env", "site.bak", "db.sqlite"):
            self.assertEqual(cp.tier_filename(name)[0], "INTEREST", name)

    def test_name_tokens(self):
        for name in ("passwords.txt", "unattend.xml", "secret-notes.doc"):
            self.assertEqual(cp.tier_filename(name)[0], "NAME", name)

    def test_boring_files_ignored(self):
        for name in ("readme.md", "photo.jpg", "app.py", "report.pdf"):
            self.assertIsNone(cp.tier_filename(name), name)


class TestPlaceholderFilter(unittest.TestCase):
    def test_templates_dropped(self):
        for v in ("${DB_PASS}", "<%= passwd %>", "{{secret}}",
                  "getenv('PW')", "vault:prod/db", "${API_KEY}"):
            self.assertTrue(cp.looks_like_placeholder(v), v)

    def test_encrypted_refs_dropped(self):
        for v in ("ENC(aes256,abc)", "{cipher}xyz", "$ANSIBLE_VAULT;x"):
            self.assertTrue(cp.looks_like_placeholder(v), v)

    def test_obvious_placeholders_dropped(self):
        for v in ("changeme", "password", "xxx", "aaaa", "****"):
            self.assertTrue(cp.looks_like_placeholder(v), v)

    def test_real_passwords_kept(self):
        for v in ("Str0ng!DbPass99", "r34lEnvS3cret!", "Summer2024!",
                  "P@ssw0rd123"):
            self.assertFalse(cp.looks_like_placeholder(v), v)


class TestScanText(unittest.TestCase):
    def labels(self, name, text, floor="NAME"):
        return {label for _sev, label, _ex in cp.scan_text(name, text, floor)}

    def test_connection_string(self):
        hits = self.labels("web.config",
                           "User Id=app;Password=Str0ng!DbPass99;")
        self.assertIn("connection string password", hits)

    def test_password_assignment(self):
        hits = self.labels("app.env", "DB_PASSWORD=r34lEnvS3cret!")
        self.assertIn("password assignment", hits)

    def test_url_embedded(self):
        hits = self.labels("app.cfg", "db = postgres://svc:Hunter2!@db01/app")
        self.assertIn("URL-embedded creds", hits)

    def test_command_line_creds(self):
        for line, label in (
            ("net use \\\\fs\\share S3cret! /user:admin", "net use with password"),
            ("net user deploy P@ss123", "net user with password"),
            ("mysql -u root -pS3cret db", "mysql inline password"),
            ("sshpass -p hunter2 ssh host", "sshpass"),
            ("cmdkey /add:fs /user:admin /pass:S3cret", "cmdkey add"),
        ):
            self.assertIn(label, self.labels("hist.sh", line), line)

    def test_wp_config(self):
        hits = self.labels("wp-config.php",
                           "define('DB_PASSWORD', 'Bl0g!Pass2024');")
        self.assertIn("wp-config DB_PASSWORD", hits)

    def test_tokens(self):
        for line, label in (
            ("aws_key = AKIAIOSFODNN7EXAMPLE", "aws access key"),
            ("token: ghp_abcdefghij0123456789abcd", "github token"),
        ):
            self.assertIn(label, self.labels("ci.env", line), line)

    def test_hashes(self):
        self.assertIn("NTLM hash line", self.labels(
            "dump.txt", "admin:500:aad3b435b51404eeaad3b435b51404ee:"
                        "31d6cfe0d16ae931b73c59d7e0c089c0:::"))
        self.assertIn("shadow hash", self.labels(
            "shadow", "root:$6$saltsalt$Xq3M0xN9y3Z/abc:19000:0:99999:7:::"))

    def test_private_key(self):
        self.assertIn("private key block", self.labels(
            "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMII..."))

    def test_unattend_multiline(self):
        text = ("<AutoLogon><Enabled>true</Enabled>\n"
                "<Password>\n<Value>D3ploy!Lab2024</Value>\n</Password>"
                "</AutoLogon>")
        hits = self.labels("unattend.xml", text)
        self.assertIn("unattend autologon password", hits)

    def test_placeholders_produce_no_hits(self):
        text = ("password = changeme\n"
                "Password=${DB_PASS};\n"
                "apiKey = ${API_KEY_FROM_VAULT}")
        self.assertEqual(cp.scan_text("notes.txt", text), [])

    def test_severity_floor(self):
        hits = cp.scan_text("app.env", "DB_PASSWORD=r34l!",
                            min_severity="CRITICAL")
        self.assertEqual(hits, [])


class TestDecode(unittest.TestCase):
    def test_utf16_bom(self):
        self.assertEqual(cp.decode_maybe_utf16(
            b"\xff\xfeh\x00i\x00"), "hi")

    def test_utf16_stride_sniff(self):
        data = "password = hunter2".encode("utf-16-le")
        self.assertIn("hunter2", cp.decode_maybe_utf16(data))

    def test_plain_utf8(self):
        self.assertEqual(cp.decode_maybe_utf16(b"plain text"), "plain text")


class TestTextCandidate(unittest.TestCase):
    def test_candidates(self):
        for name in ("web.config", "app.env", "unattend.xml", "hist.sh"):
            self.assertTrue(cp.is_text_candidate(name), name)

    def test_binaries_rejected(self):
        for name in ("photo.jpg", "vault.kdbx", "app.exe"):
            self.assertFalse(cp.is_text_candidate(name), name)


if __name__ == "__main__":
    unittest.main()
