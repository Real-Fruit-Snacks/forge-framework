"""Unit tests for the esc4 module (loads fine without impacket).

Run: python3 -m unittest discover -s tests
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "esc4_mod", ROOT / "modules" / "auxiliary" / "attack" / "esc4.py"
)
e4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e4)


class TestEsc1Ops(unittest.TestCase):
    def test_weakweb_shape_gets_full_op_set(self):
        # the lab fixture: name-flag 0, enrollment-flag 2, NO schema
        # version, NO structural fields, NO OID, EKU + app-policy present
        current = {
            "msPKI-Certificate-Name-Flag": ["0"],
            "msPKI-Enrollment-Flag": ["2"],
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            "msPKI-Certificate-Application-Policy": ["1.3.6.1.5.5.7.3.2"],
        }
        reference = {
            "pKIExpirationPeriod": [b"\x00"],
            "pKIOverlapPeriod": [b"\x01"],
            "pKIKeyUsage": [b"\xa0\x00"],
        }
        ops = e4.esc1_ops(current, reference)
        self.assertEqual(ops["msPKI-Certificate-Name-Flag"], [(2, ["1"])])
        self.assertEqual(ops["msPKI-Enrollment-Flag"], [(2, ["0"])])
        self.assertEqual(ops["msPKI-Template-Schema-Version"], [(0, ["1"])])
        self.assertEqual(ops["pKIExpirationPeriod"], [(0, [b"\x00"])])
        self.assertEqual(ops["pKIOverlapPeriod"], [(0, [b"\x01"])])
        self.assertEqual(ops["pKIKeyUsage"], [(0, [b"\xa0\x00"])])
        self.assertTrue(ops["msPKI-Cert-Template-OID"][0][1][0]
                        .startswith("1.3.6.1.4.1.311.21.8."))

    def test_weakweb_without_reference(self):
        current = {
            "msPKI-Certificate-Name-Flag": ["0"],
            "msPKI-Enrollment-Flag": ["2"],
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            "msPKI-Certificate-Application-Policy": ["1.3.6.1.5.5.7.3.2"],
        }
        ops = e4.esc1_ops(current)
        self.assertEqual(ops, {
            "msPKI-Certificate-Name-Flag": [(2, ["1"])],
            "msPKI-Enrollment-Flag": [(2, ["0"])],
            "msPKI-Template-Schema-Version": [(0, ["1"])],
            "msPKI-Cert-Template-OID": ops["msPKI-Cert-Template-OID"],
        })

    def test_already_esc1_gets_no_ops(self):
        current = {
            "msPKI-Certificate-Name-Flag": ["1"],
            "msPKI-Enrollment-Flag": ["0"],
            "msPKI-Template-Schema-Version": ["1"],
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            "msPKI-Certificate-Application-Policy": ["1.3.6.1.5.5.7.3.2"],
            "msPKI-Cert-Template-OID": ["1.3.6.1.4.1.311.21.8.1.2"],
            "pKIExpirationPeriod": [b"\x00"],
            "pKIOverlapPeriod": [b"\x01"],
            "pKIKeyUsage": [b"\xa0\x00"],
        }
        self.assertEqual(e4.esc1_ops(current), {})

    def test_missing_eku_gets_added(self):
        current = {
            "msPKI-Certificate-Name-Flag": ["1"],
            "msPKI-Enrollment-Flag": ["0"],
            "msPKI-Template-Schema-Version": ["1"],
            "pKIExtendedKeyUsage": [],
            "msPKI-Certificate-Application-Policy": ["1.3.6.1.5.5.7.3.2"],
            "msPKI-Cert-Template-OID": ["1.3.6.1.4.1.311.21.8.1.2"],
        }
        self.assertEqual(e4.esc1_ops(current),
                         {"pKIExtendedKeyUsage": [(0, ["1.3.6.1.5.5.7.3.2"])]})


class TestReadiness(unittest.TestCase):
    def test_missing_report(self):
        ready, missing = e4.readiness({
            "msPKI-Certificate-Name-Flag": ["0"],
            "msPKI-Enrollment-Flag": ["2"],
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
        })
        self.assertFalse(ready)
        self.assertIn("enrollee-supplies-subject OFF", missing)
        self.assertIn("manager approval ON", missing)
        self.assertIn("no schema-version (policy denies enrollment)", missing)


class TestRequirements(unittest.TestCase):
    def test_declares_impacket(self):
        self.assertIn("impacket", e4.Esc4.requirements)

    def test_module_loads_without_deps(self):
        self.assertIsNotNone(e4.Esc4)


if __name__ == "__main__":
    unittest.main()
