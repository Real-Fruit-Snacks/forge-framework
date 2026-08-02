"""Unit tests for the framework core. Run: python3 -m unittest discover -s tests"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.options import (  # noqa: E402
    OptBool,
    OptEnum,
    OptInt,
    OptPort,
    OptString,
    OptionContainer,
)
from core.registry import ModuleRegistry  # noqa: E402


class TestOptions(unittest.TestCase):
    def test_port_validation(self):
        opt = OptPort("RPORT")
        opt.set("443")
        self.assertEqual(opt.current, 443)
        with self.assertRaises(ValueError):
            opt.set("70000")
        with self.assertRaises(ValueError):
            opt.set("abc")

    def test_bool(self):
        opt = OptBool("SSL", default=False)
        self.assertFalse(opt.current)
        for truthy in ("true", "yes", "1"):
            opt.set(truthy)
            self.assertTrue(opt.current)
        with self.assertRaises(ValueError):
            opt.set("maybe")

    def test_enum(self):
        opt = OptEnum("MODE", ["fast", "full"], default="fast")
        self.assertEqual(opt.current, "fast")
        opt.set("full")
        self.assertEqual(opt.current, "full")
        with self.assertRaises(ValueError):
            opt.set("slow")

    def test_case_insensitive_container(self):
        c = OptionContainer([OptString("RHOSTS", required=True)])
        c["rhosts"] = "10.10.10.10"
        self.assertEqual(c["RHOSTS"], "10.10.10.10")
        self.assertIn("RhOsTs", c)
        with self.assertRaises(KeyError):
            c["NOPE"] = "x"

    def test_missing_required(self):
        c = OptionContainer([
            OptString("RHOSTS", required=True),
            OptInt("THREADS", default=4),
        ])
        self.assertEqual(c.missing_required(), ["RHOSTS"])
        c["RHOSTS"] = "x"
        self.assertEqual(c.missing_required(), [])

    def test_unset_falls_back_to_default(self):
        c = OptionContainer([OptInt("THREADS", default=4)])
        c["THREADS"] = 16
        self.assertEqual(c["THREADS"], 16)
        c.unset("THREADS")
        self.assertEqual(c["THREADS"], 4)


class TestRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = ModuleRegistry(ROOT / "modules")
        cls.registry.load()

    def test_no_load_errors(self):
        self.assertEqual(self.registry.errors, {})

    def test_expected_modules_loaded(self):
        for path in (
            "auxiliary/scanner/port_scan",
            "auxiliary/scanner/http_headers",
            "exploits/example/demo_shell",
            "payloads/python_reverse_tcp",
        ):
            self.assertIn(path, self.registry.modules)

    def test_create_and_configure(self):
        mod = self.registry.create("auxiliary/scanner/port_scan")
        mod["rhosts"] = "127.0.0.1"
        self.assertEqual(mod.get_option("RHOSTS"), "127.0.0.1")
        self.assertTrue(mod.validate_options())

    def test_global_fallback(self):
        class FakeFramework:
            global_options = {"RHOSTS": "10.0.0.1"}

        mod = self.registry.create("auxiliary/scanner/port_scan")
        mod.framework = FakeFramework()
        self.assertEqual(mod.get_option("RHOSTS"), "10.0.0.1")
        self.assertTrue(mod.validate_options())

    def test_search(self):
        self.assertIn("auxiliary/scanner/port_scan", self.registry.search("port scan"))
        self.assertEqual(self.registry.search("no-such-thing-xyz"), [])

    def test_payload_generate(self):
        mod = self.registry.create("payloads/python_reverse_tcp")
        mod["LHOST"] = "10.0.0.1"
        out = mod.generate()
        self.assertIn("10.0.0.1", out)
        self.assertIn("4444", out)


class TestPortParse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "port_scan_mod", ROOT / "modules" / "auxiliary" / "scanner" / "port_scan.py"
        )
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)

    def test_parse_ports(self):
        self.assertEqual(self.mod.parse_ports("22,80-82"), [22, 80, 81, 82])
        self.assertEqual(self.mod.parse_ports("443"), [443])

    def test_parse_ports_rejects_bad_input(self):
        for bad in ("0", "70000", "90-80", "abc"):
            with self.assertRaises(ValueError, msg=bad):
                self.mod.parse_ports(bad)


class TestTemplate(unittest.TestCase):
    def test_create_and_reload(self):
        import tempfile

        from core.template import create_template

        with tempfile.TemporaryDirectory() as tmp:
            dest = create_template(tmp, "auxiliary/scanner/my_test_mod")
            self.assertTrue(dest.exists())
            registry = ModuleRegistry(tmp)
            registry.load()
            self.assertEqual(registry.errors, {})
            self.assertIn("auxiliary/scanner/my_test_mod", registry.modules)
            inst = registry.create("auxiliary/scanner/my_test_mod")
            self.assertEqual(inst.type, "auxiliary")

    def test_rejects_bad_type(self):
        import tempfile

        from core.template import create_template

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                create_template(tmp, "nonsense/scanner/x")


if __name__ == "__main__":
    unittest.main()
