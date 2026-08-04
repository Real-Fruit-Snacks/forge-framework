"""Unit tests for core.lab — no docker daemon required (subprocess mocked).

Run: python3 -m unittest discover -s tests
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.lab import Lab, LabError, LabManager  # noqa: E402


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        self.mgr = LabManager(ROOT / "labs")

    def test_discovers_shipped_labs(self):
        self.assertEqual(
            {"web", "ssh", "smb", "ad", "windows", "workstation", "domain",
             "mssql", "snmp"},
            set(self.mgr.labs()),
        )

    def test_parses_targets(self):
        labs = self.mgr.labs()
        self.assertEqual(labs["web"].targets, [(18080, 8080)])
        self.assertEqual(labs["ssh"].targets, [(12222, 22)])
        self.assertEqual(labs["smb"].targets, [(10139, 139), (10445, 445)])
        self.assertEqual(labs["mssql"].targets, [(11433, 1433)])
        self.assertEqual(labs["snmp"].targets, [(10161, 161)])
        # windows: trailing comments on port lines are tolerated
        self.assertEqual(
            labs["windows"].targets,
            [(1445, 445), (10135, 135), (13389, 3389), (15985, 5985),
             (8006, 8006)],
        )
        self.assertEqual(
            labs["workstation"].targets,
            [(2445, 445), (23389, 3389), (8007, 8006)],
        )
        # domain: the DC's 1:1 AD bindings (incl. RPC mapper 135, the
        # 15353 DNS pair, and the expanded 49152-49160 dynamic range),
        # then the member's, then the CA's
        self.assertEqual(
            labs["domain"].targets,
            [(135, 135), (389, 389), (88, 88), (88, 88), (445, 445)]
            + [(15353, 53), (15353, 53)]
            + [(49152 + i, 49152 + i) for i in range(9)]
            + [(3445, 445), (33389, 3389), (8008, 8006)]
            + [(4445, 445), (8009, 8006)],
        )

    def test_unknown_lab_raises(self):
        with self.assertRaises(LabError) as ctx:
            self.mgr.get("nope")
        self.assertIn("Unknown lab", str(ctx.exception))


class TestComposeInvocation(unittest.TestCase):
    def setUp(self):
        self.mgr = LabManager(ROOT / "labs")

    def test_up_invokes_compose_correctly(self):
        fake = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("core.lab.subprocess.run", return_value=fake) as run, \
                mock.patch.object(LabManager, "_wait_ready"):
            self.mgr.up("web")
        cmd = run.call_args[0][0]
        self.assertIn("forge-lab-web", cmd)
        self.assertIn("up", cmd)
        self.assertIn("--build", cmd)
        self.assertTrue(any("compose.yml" in part for part in cmd))

    def test_up_preflight_blocks_busy_ports(self):
        import socket as _socket

        listener = _socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        busy_port = listener.getsockname()[1]
        try:
            lab = Lab("conflict", Path("t"), Path("t/compose.yml"),
                      [(busy_port, 80)])
            with mock.patch.object(LabManager, "labs", return_value={"conflict": lab}), \
                    mock.patch.object(LabManager, "is_running", return_value=False):
                with self.assertRaises(LabError) as ctx:
                    self.mgr.up("conflict")
            self.assertIn("in use", str(ctx.exception))
        finally:
            listener.close()

    def test_up_preflight_skips_running_lab(self):
        fake = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("core.lab.subprocess.run", return_value=fake), \
                mock.patch.object(LabManager, "is_running", return_value=True), \
                mock.patch.object(LabManager, "_check_ports_free") as check, \
                mock.patch.object(LabManager, "_wait_ready"):
            self.mgr.up("web")
        check.assert_not_called()

    def test_wait_ready_happy_path_and_timeout(self):
        import socket as _socket

        listener = _socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        live_port = listener.getsockname()[1]
        try:
            lab = Lab("t", Path("t"), Path("t/compose.yml"),
                      [(live_port, 80)])
            checks, _ = self.mgr._ready_checks(lab)
            self.mgr._wait_ready(lab, 5, checks)  # returns, no raise

            dead = Lab("t", Path("t"), Path("t/compose.yml"), [(1, 80)])
            checks, _ = self.mgr._ready_checks(dead)
            with self.assertRaises(LabError) as ctx:
                self.mgr._wait_ready(dead, 1, checks)
            self.assertIn("readiness check", str(ctx.exception))
        finally:
            listener.close()

    def test_ready_file_parsing(self):
        labs = self.mgr.labs()
        self.assertEqual(self.mgr._ready_checks(labs["web"]),
                         ([("http", 18080, "/")], None))
        self.assertEqual(self.mgr._ready_checks(labs["ssh"]),
                         ([("banner", 12222, "")], None))
        self.assertEqual(self.mgr._ready_checks(labs["smb"]),
                         ([("tcp", 10445, "")], None))
        self.assertEqual(self.mgr._ready_checks(labs["windows"])[1], 2400)
        self.assertEqual(self.mgr._ready_checks(labs["workstation"])[1], 2400)
        # domain: readiness tracks the DC only — the Windows member keeps
        # installing in the background
        self.assertEqual(self.mgr._ready_checks(labs["domain"]),
                         ([("tcp", 389, "")], 300))

    def test_ready_fallback_to_tcp(self):
        lab = Lab("t", Path("/nonexistent-lab-dir"), Path("/x/compose.yml"),
                  [(1234, 80), (1235, 81)])
        checks, timeout = self.mgr._ready_checks(lab)
        self.assertEqual(checks, [("tcp", 1234, ""), ("tcp", 1235, "")])
        self.assertIsNone(timeout)

    def test_no_docker_installed(self):
        with mock.patch("core.lab.shutil.which", return_value=None):
            with self.assertRaises(LabError) as ctx:
                self.mgr.compose_cmd()
        self.assertIn("installed", str(ctx.exception))

    def test_daemon_down_message(self):
        fake = subprocess.CompletedProcess(
            [], 1, "",
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
        )
        with mock.patch("core.lab.subprocess.run", return_value=fake):
            with self.assertRaises(LabError) as ctx:
                self.mgr.up("web")
        self.assertIn("daemon is not running", str(ctx.exception))

    def test_generic_failure_includes_stderr(self):
        fake = subprocess.CompletedProcess([], 1, "", "build exploded")
        with mock.patch("core.lab.subprocess.run", return_value=fake):
            with self.assertRaises(LabError) as ctx:
                self.mgr.up("web")
        self.assertIn("build exploded", str(ctx.exception))

    def test_is_running_none_when_daemon_down(self):
        fake = subprocess.CompletedProcess(
            [], 1, "", "Cannot connect to the Docker daemon"
        )
        with mock.patch("core.lab.subprocess.run", return_value=fake):
            self.assertIsNone(self.mgr.is_running("web"))

    def test_is_running_parses_json_lines(self):
        fake = subprocess.CompletedProcess(
            [], 0, '{"Name":"web-1","State":"running"}\n', ""
        )
        with mock.patch("core.lab.subprocess.run", return_value=fake):
            self.assertTrue(self.mgr.is_running("web"))

    def test_is_running_false_when_no_containers(self):
        fake = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("core.lab.subprocess.run", return_value=fake):
            self.assertFalse(self.mgr.is_running("web"))

    def test_running_projects_parses_compose_ls(self):
        fake = subprocess.CompletedProcess(
            [], 0,
            '[{"Name":"forge-lab-web","ConfigFiles":"/p/compose.yml"},'
            '{"Name":"someone-else","ConfigFiles":"/q/compose.yml"}]',
            "",
        )
        with mock.patch("core.lab.subprocess.run", return_value=fake):
            projects = self.mgr.running_projects()
        self.assertEqual(projects, [("forge-lab-web", "/p/compose.yml")])

    def test_clean_downs_via_config_file(self):
        ls = subprocess.CompletedProcess(
            [], 0,
            '[{"Name":"forge-lab-web","ConfigFiles":"/tmp/fake/compose.yml"}]',
            "",
        )
        ok = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("core.lab.subprocess.run", side_effect=[ls, ok]) as run, \
                mock.patch("core.lab.Path.is_file", return_value=True):
            cleaned = self.mgr.clean()
        self.assertEqual(cleaned, ["web"])
        down_cmd = run.call_args_list[1][0][0]
        self.assertIn("-p", down_cmd)
        self.assertIn("forge-lab-web", down_cmd)
        self.assertIn("down", down_cmd)

    def test_clean_orphan_without_config_uses_docker_rm(self):
        ls = subprocess.CompletedProcess(
            [], 0,
            '[{"Name":"forge-lab-old","ConfigFiles":"/gone/compose.yml"}]',
            "",
        )
        ps = subprocess.CompletedProcess([], 0, "abc123\n", "")
        rm = subprocess.CompletedProcess([], 0, "", "")
        nets = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("core.lab.subprocess.run",
                        side_effect=[ls, ps, rm, nets]) as run, \
                mock.patch("core.lab.Path.is_file", return_value=False):
            cleaned = self.mgr.clean()
        self.assertEqual(cleaned, ["old"])
        rm_cmd = run.call_args_list[2][0][0]
        self.assertEqual(rm_cmd[-3:], ["rm", "-f", "abc123"])

    def test_purge_invokes_full_teardown(self):
        ok = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("core.lab.subprocess.run", return_value=ok) as run:
            self.mgr.purge("web")
        cmd = run.call_args[0][0]
        self.assertIn("down", cmd)
        self.assertIn("--rmi", cmd)
        self.assertIn("all", cmd)
        self.assertIn("-v", cmd)


if __name__ == "__main__":
    unittest.main()
