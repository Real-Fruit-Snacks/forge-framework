"""Unit tests for add_computer and rbcd helpers (load fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ac = load("add_computer_mod", "modules/auxiliary/attack/add_computer.py")
rb = load("rbcd_mod", "modules/auxiliary/attack/rbcd.py")


class TestAddComputerHelpers(unittest.TestCase):
    def test_machine_name_shape(self):
        for _ in range(20):
            name = ac.rand_machine_name()
            self.assertTrue(name.startswith("FZ"))
            self.assertTrue(name.endswith("$"))
            self.assertEqual(len(name), 9)
            self.assertTrue(name[2:-1].isupper())

    def test_password_shape(self):
        import string
        for _ in range(20):
            pw = ac.rand_password()
            self.assertEqual(len(pw), 16)
            self.assertTrue(all(c in ac.PASSWORD_ALPHABET for c in pw))
            # AD/Samba complexity: 3 of 4 classes — the generator seeds
            # all four, so this must hold for EVERY draw
            classes = [any(c in string.ascii_uppercase for c in pw),
                       any(c in string.ascii_lowercase for c in pw),
                       any(c in string.digits for c in pw),
                       any(c in "!#$%" for c in pw)]
            self.assertGreaterEqual(sum(classes), 3)


class TestRbcdHelpers(unittest.TestCase):
    def test_sddl_shape(self):
        sddl = rb.sddl_for("S-1-5-21-1-2-3-1115")
        self.assertEqual(
            sddl,
            "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1115)")
        self.assertTrue(sddl.startswith("O:BAD:(A;;"))
        self.assertTrue(sddl.endswith("S-1-5-21-1-2-3-1115)"))


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", ac.AddComputer.requirements)
        self.assertIn("impacket", rb.Rbcd.requirements)

    def test_modules_load_without_impacket(self):
        self.assertIsNotNone(ac.AddComputer)
        self.assertIsNotNone(rb.Rbcd)


if __name__ == "__main__":
    unittest.main()
