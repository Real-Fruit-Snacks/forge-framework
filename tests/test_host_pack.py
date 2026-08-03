"""Unit tests for the host pack modules (load fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hi = load("host_info_mod", "modules/auxiliary/enum/host_info.py")
hs = load("host_sessions_mod", "modules/auxiliary/enum/host_sessions.py")
la = load("local_admins_mod", "modules/auxiliary/enum/local_admins.py")


class TestOsVersion(unittest.TestCase):
    class FakeConn:
        def __init__(self, major, minor, build, os_string):
            self._v = (major, minor, build, os_string)

        def getServerOSMajor(self):
            return self._v[0]

        def getServerOSMinor(self):
            return self._v[1]

        def getServerOSBuild(self):
            return self._v[2]

        def getServerOS(self):
            return self._v[3]

    def test_numeric_version(self):
        conn = self.FakeConn(10, 0, 22621, "Windows 11 22H2")
        self.assertEqual(hi.os_version(conn), "10.0.22621")

    def test_fallback_to_os_string(self):
        conn = self.FakeConn(None, None, None, "Windows 5.1")
        self.assertEqual(hi.os_version(conn), "Windows 5.1")


class TestConstants(unittest.TestCase):
    def test_administrators_rid(self):
        self.assertEqual(la.ADMINISTRATORS_RID, 544)

    def test_session_null_filter(self):
        self.assertEqual(hs.NULL_NAME, "\x00")


class TestRequirements(unittest.TestCase):
    def test_declare_impacket(self):
        self.assertIn("impacket", hi.HostInfo.requirements)
        self.assertIn("impacket", hs.HostSessions.requirements)
        self.assertIn("impacket", la.LocalAdmins.requirements)

    def test_modules_load_without_impacket(self):
        self.assertIsNotNone(hi.HostInfo)
        self.assertIsNotNone(hs.HostSessions)
        self.assertIsNotNone(la.LocalAdmins)


if __name__ == "__main__":
    unittest.main()
