"""Unit tests for core.store. Run: python3 -m unittest discover -s tests"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.store import Store  # noqa: E402


class TestStore(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def test_add_host_dedupes(self):
        self.store.add_host("10.0.0.1")
        self.store.add_host("10.0.0.1")
        self.assertEqual(len(self.store.hosts()), 1)

    def test_add_service_upserts_info(self):
        self.store.add_service("10.0.0.1", 80)
        self.store.add_service("10.0.0.1", 80, name="http", info="nginx")
        services = self.store.services("10.0.0.1")
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["name"], "http")
        self.assertEqual(services[0]["info"], "nginx")

    def test_add_service_creates_host(self):
        self.store.add_service("10.0.0.2", 22)
        self.assertEqual([h["address"] for h in self.store.hosts()], ["10.0.0.2"])

    def test_loot_roundtrip(self):
        lid = self.store.add_loot("hash", "admin ntlm", "aad3b435b...", "10.0.0.1")
        entries = self.store.loot()
        self.assertEqual(len(entries), 1)
        self.assertEqual(self.store.loot_get(lid)["content"], "aad3b435b...")
        self.assertEqual(self.store.loot("hash")[0]["label"], "admin ntlm")
        self.assertEqual(self.store.loot("cred"), [])

    def test_workspaces_isolate_data(self):
        self.store.add_host("10.0.0.1")
        self.store.set_workspace("htb-season8")
        self.assertEqual(self.store.hosts(), [])
        self.store.add_host("10.0.0.2")
        self.store.set_workspace("default")
        self.assertEqual([h["address"] for h in self.store.hosts()], ["10.0.0.1"])
        self.assertIn("htb-season8", self.store.workspaces())

    def test_workspace_name_validation(self):
        with self.assertRaises(ValueError):
            self.store.set_workspace("   ")

    def test_creds_dedupe_and_lookup(self):
        self.store.add_cred("10.0.0.1", "ssh", "admin", "admin", "ssh-brute")
        self.store.add_cred("10.0.0.1", "ssh", "admin", "admin", "ssh-brute")
        self.store.add_cred("10.0.0.1", "http", "admin", "hunter2", "http-form")
        self.assertEqual(len(self.store.creds()), 2)  # dup ignored
        self.assertEqual(
            self.store.creds_for("10.0.0.1", "ssh"), [("admin", "admin")]
        )
        self.assertEqual(self.store.creds_for("10.0.0.1", "smb"), [])

    def test_creds_workspace_isolation(self):
        self.store.add_cred("10.0.0.1", "ssh", "a", "b")
        self.store.set_workspace("other")
        self.assertEqual(self.store.creds(), [])
        self.assertEqual(self.store.creds_for("10.0.0.1", "ssh"), [])

    def test_delete_cred(self):
        self.store.add_cred("10.0.0.1", "ssh", "a", "b")
        cid = self.store.creds()[0]["id"]
        self.assertTrue(self.store.delete_cred(cid))
        self.assertEqual(self.store.creds(), [])
        self.assertFalse(self.store.delete_cred(cid))

    def test_delete_loot(self):
        lid = self.store.add_loot("note", "x", "y")
        self.assertTrue(self.store.delete_loot(lid))
        self.assertFalse(self.store.delete_loot(lid))

    def test_add_loot_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "shadow.txt"
            src.write_text("root:$6$xyz:1\n")
            store = Store(":memory:", loot_dir=Path(tmp) / "blobs")
            try:
                lid = store.add_loot_file("file", "target shadow", src, "10.0.0.1")
                entry = store.loot_get(lid)
                self.assertTrue(entry["content"].startswith("file:"))
                blob = Path(entry["content"][5:])
                self.assertEqual(blob.read_text(), "root:$6$xyz:1\n")
            finally:
                store.close()

    def test_add_loot_file_without_dir_raises(self):
        with self.assertRaises(ValueError):
            self.store.add_loot_file("file", "x", "/etc/hostname")


class TestSchemaVersion(unittest.TestCase):
    def test_fresh_db_gets_current_version(self):
        store = Store(":memory:")
        try:
            version = store._db.execute("PRAGMA user_version").fetchone()[0]
            from core.store import SCHEMA_VERSION

            self.assertEqual(version, SCHEMA_VERSION)
        finally:
            store.close()

    def test_preversion_db_is_migrated(self):
        import sqlite3
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "old.db"
            # simulate a pre-creds, pre-versioning database
            db = sqlite3.connect(db_path)
            db.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, workspace TEXT,"
                " address TEXT, name TEXT, created REAL)"
            )
            db.commit()
            db.close()

            store = Store(db_path)
            try:
                tables = {
                    r[0]
                    for r in store._db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                self.assertIn("creds", tables)
                self.assertIn("loot", tables)
                # and it survives a reopen without re-running anything
            finally:
                store.close()
            store2 = Store(db_path)
            try:
                store2.add_host("10.0.0.1")
                self.assertEqual(len(store2.hosts()), 1)
            finally:
                store2.close()


if __name__ == "__main__":
    unittest.main()
