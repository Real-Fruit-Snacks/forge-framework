"""Unit tests for the ad_probe module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ad_probe_mod", ROOT / "modules" / "auxiliary" / "scanner" / "ad_probe.py"
)
ap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ap)


class TestAnnotate(unittest.TestCase):
    def test_known_interfaces(self):
        self.assertEqual(
            ap.annotate_rpc("12345778-1234-abcd-ef00-0123456789ac"), "SAMR")
        self.assertEqual(
            ap.annotate_rpc("e3514235-4b06-11d1-ab04-00c04fc2dcd2"),
            "DRSUAPI (DCSync channel)")

    def test_coercion_hints(self):
        hints = {
            "12345678-1234-abcd-ef00-0123456789ab": "PrinterBug",
            "df1941c5-fe89-4e79-bf10-463657acf44d": "PetitPotam",
            "c681d488-d850-11d0-8c52-00c04fd90f7e": "PetitPotam",
            "a8e0653c-2744-4389-a61d-7373df8b2292": "ShadowCoerce",
            "4fc742e0-4a10-11cf-8273-00aa004ae673": "DFSCoerce",
            "ae33069b-a2a8-46ee-a235-ddfd339be281": "PrintNightmare",
        }
        for uuid, hint in hints.items():
            self.assertIn(hint, ap.annotate_rpc(uuid), uuid)

    def test_unknown_returns_none(self):
        self.assertIsNone(ap.annotate_rpc("00000000-0000-0000-0000-000000000000"))

    def test_case_insensitive(self):
        self.assertEqual(
            ap.annotate_rpc("12345778-1234-ABCD-EF00-0123456789AC"), "SAMR")


class TestVersions(unittest.TestCase):
    def test_every_entry_has_version(self):
        for uuid, (name, hint, version) in ap.WELL_KNOWN_RPC.items():
            self.assertRegex(version, r"^\d+\.\d+$", uuid)


class TestCanonicalPipes(unittest.TestCase):
    def test_every_tcp_capable_interface_has_a_pipe(self):
        # DRSUAPI is TCP-only and the EPM is the probe channel rather
        # than a finding — everything else binds on a canonical pipe
        excluded = {
            "e3514235-4b06-11d1-ab04-00c04fc2dcd2",  # DRSUAPI: TCP-only
            "e1af8308-5d1f-11c9-91a4-08002b14a0fa",  # EPM: the channel
        }
        for uuid in ap.WELL_KNOWN_RPC:
            if uuid in excluded:
                self.assertNotIn(uuid, ap.CANONICAL_PIPES)
            else:
                self.assertIn(uuid, ap.CANONICAL_PIPES)
                self.assertTrue(ap.CANONICAL_PIPES[uuid].startswith("\\"))


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ap.AdProbe.requirements)

    def test_module_loads_without_impacket(self):
        self.assertIsNotNone(ap.AdProbe)


if __name__ == "__main__":
    unittest.main()
