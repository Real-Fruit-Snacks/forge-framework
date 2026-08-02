"""Unit tests for core.report. Run: python3 -m unittest discover -s tests"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import report  # noqa: E402
from core.store import Store  # noqa: E402


class TestReport(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.add_service("10.0.0.1", 80, name="http", info="nginx")
        self.store.add_service("10.0.0.1", 22, name="ssh")
        self.store.add_cred("10.0.0.1", "ssh", "admin", "admin", "ssh-brute")
        self.store.add_loot("note", "smb", "signing disabled", "10.0.0.1")

    def tearDown(self):
        self.store.close()

    def test_collect_and_json_roundtrip(self):
        data = report.collect(self.store)
        parsed = json.loads(report.render_json(data))
        self.assertEqual(parsed["workspace"], "default")
        self.assertEqual(len(parsed["hosts"]), 1)
        self.assertEqual(len(parsed["services"]), 2)
        self.assertEqual(parsed["creds"][0]["username"], "admin")
        self.assertEqual(parsed["loot"][0]["label"], "smb")

    def test_markdown_sections(self):
        text = report.render_markdown(report.collect(self.store))
        self.assertIn("## Hosts (1)", text)
        self.assertIn("### 10.0.0.1", text)
        self.assertIn("| 80 | tcp | http | nginx |", text)
        self.assertIn("## Credentials (1)", text)
        self.assertIn("| 10.0.0.1 | ssh | admin | admin | ssh-brute |", text)
        self.assertIn("signing disabled", text)

    def test_empty_workspace_renders_clean(self):
        empty = Store(":memory:")
        try:
            text = report.render_markdown(report.collect(empty))
            self.assertIn("None recorded.", text)
        finally:
            empty.close()


if __name__ == "__main__":
    unittest.main()
