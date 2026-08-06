"""Tests for nmap_import and nmap_scan modules."""

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.store import Store  # noqa: E402


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nmap_import = load("nmap_import", "modules/auxiliary/scanner/nmap_import.py")
nmap_scan = load("nmap_scan", "modules/auxiliary/scanner/nmap_scan.py")


SAMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
        <script id="ssh-hostkey" output="RSA key fingerprint"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" extrainfo="ubuntu"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="98"/>
      <osmatch name="Linux 5.x" accuracy="94"/>
    </os>
    <hostscript>
      <script id="smb-security-mode" output="account_used: guest"/>
    </hostscript>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished summary="Nmap done"/>
  </runstats>
</nmaprun>
"""


class TestParseNmapXml(unittest.TestCase):
    def test_parses_up_host_services_and_hostname(self):
        results = nmap_import.parse_nmap_xml(SAMPLE_XML)
        self.assertEqual(len(results), 1)
        address, hostname, services, os_matches, scripts = results[0]
        self.assertEqual(address, "192.168.1.1")
        self.assertEqual(hostname, "router.local")
        self.assertEqual(len(services), 2)
        self.assertEqual(services[0], ("tcp", 22, "ssh", "OpenSSH 8.2"))
        self.assertEqual(services[1], ("tcp", 80, "http", "nginx ubuntu"))

    def test_parses_os_matches_and_scripts(self):
        results = nmap_import.parse_nmap_xml(SAMPLE_XML)
        self.assertEqual(len(results), 1)
        _address, _hostname, _services, os_matches, scripts = results[0]
        self.assertEqual(os_matches, [("Linux 5.4", "98"), ("Linux 5.x", "94")])
        self.assertEqual(scripts, [
            ("tcp/22", "ssh-hostkey", "RSA key fingerprint"),
            ("host", "smb-security-mode", "account_used: guest"),
        ])

    def test_ignores_down_hosts(self):
        results = nmap_import.parse_nmap_xml(SAMPLE_XML)
        addresses = [r[0] for r in results]
        self.assertNotIn("192.168.1.2", addresses)


class TestNmapImport(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def _run_module(self, path, file_path):
        mod = nmap_import.NmapImport()
        mod.framework = type("_", (), {"store": self.store})()
        mod["FILE"] = str(file_path)
        mod["SAVE_LOOT"] = False
        mod.run()

    def test_imports_hosts_and_services(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml",
                                         delete=False) as tmp:
            tmp.write(SAMPLE_XML)
            tmp_path = Path(tmp.name)
        try:
            self._run_module(nmap_import, tmp_path)
            hosts = [r["address"] for r in self.store.hosts()]
            self.assertIn("192.168.1.1", hosts)
            services = self.store.services("192.168.1.1")
            self.assertEqual(len(services), 2)
            self.assertEqual(services[0]["port"], 22)
            self.assertEqual(services[0]["name"], "ssh")
            self.assertEqual(services[1]["info"], "nginx ubuntu")

            loot = self.store.loot()
            types = [r["type"] for r in loot]
            self.assertIn("nmap-os", types)
            self.assertIn("nmap-script", types)
        finally:
            tmp_path.unlink(missing_ok=True)


class TestNmapScan(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    @unittest.skipUnless(shutil.which("nmap"), "nmap binary not installed")
    def test_scans_localhost(self):
        mod = nmap_scan.NmapScan()
        mod.framework = type("_", (), {"store": self.store})()
        mod["RHOSTS"] = "127.0.0.1"
        mod["NMAP_ARGS"] = "-sT -p 22,80,443"
        mod["TIMEOUT"] = 60
        mod["SAVE_LOOT"] = False
        mod.run()
        services = self.store.services("127.0.0.1")
        # We cannot assert which ports are open, but the parse/import path
        # should complete without error and leave zero or more services.
        self.assertGreaterEqual(len(services), 0)


if __name__ == "__main__":
    unittest.main()
