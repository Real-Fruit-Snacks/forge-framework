"""Unit tests for the relay_smb module (loads without deps).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "relay_mod", ROOT / "modules" / "auxiliary" / "attack" / "relay_smb.py"
)
relay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relay)


class TestRequirements(unittest.TestCase):
    def test_declares_deps(self):
        self.assertEqual(relay.RelaySmb.requirements, ["impacket"])

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(relay.RelaySmb)


@unittest.skipUnless(relay.SMBRelayServer is not None,
                     "impacket/ldap3 not installed")
class TestAttackClass(unittest.TestCase):
    def test_attack_registers_ldap(self):
        self.assertEqual(relay.RbcdAttack.PLUGIN_NAMES, ["LDAP"])


if __name__ == "__main__":
    unittest.main()
