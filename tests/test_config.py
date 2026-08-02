"""Unit tests for core.config. Run: python3 -m unittest discover -s tests"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import config, output  # noqa: E402
from core.console import FrameworkConsole  # noqa: E402
from core.registry import ModuleRegistry  # noqa: E402
from core.store import Store  # noqa: E402

output.color_enabled = False


class TestLoad(unittest.TestCase):
    def test_missing_file_is_none(self):
        self.assertIsNone(config.load("/nope/config.toml"))

    def test_valid_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write('[general]\nworkspace = "htb"\n[options]\nLHOST = "tun0"\n')
            path = f.name
        try:
            cfg = config.load(path)
            self.assertEqual(cfg["general"]["workspace"], "htb")
            self.assertEqual(cfg["options"]["LHOST"], "tun0")
        finally:
            Path(path).unlink()

    def test_invalid_file_warns_and_returns_none(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write("this is = [ not toml\n")
            path = f.name
        try:
            self.assertIsNone(config.load(path))
        finally:
            Path(path).unlink()


class TestApply(unittest.TestCase):
    def test_applies_workspace_color_and_options(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            output.color_enabled = True
            config.apply(console, {
                "general": {"workspace": "htb", "color": False},
                "options": {"LHOST": "tun0", "lport": "4444"},
            })
            self.assertEqual(console.store.workspace, "htb")
            self.assertEqual(console.global_options["LHOST"], "tun0")
            self.assertEqual(console.global_options["LPORT"], "4444")
            self.assertFalse(output.color_enabled)
        finally:
            output.color_enabled = False
            console.store.close()

    def test_debug_flag_applies(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            output.debug_enabled = False
            config.apply(console, {"general": {"debug": True}})
            self.assertTrue(output.debug_enabled)
        finally:
            output.debug_enabled = False
            console.store.close()

    def test_none_is_a_noop(self):
        registry = ModuleRegistry(ROOT / "modules")
        registry.load()
        console = FrameworkConsole(registry, Store(":memory:"))
        try:
            config.apply(console, None)
            self.assertEqual(console.store.workspace, "default")
        finally:
            console.store.close()


class TestResolveSpool(unittest.TestCase):
    def test_no_config(self):
        self.assertIsNone(config.resolve_spool(None, "/tmp/home"))

    def test_auto_variants(self):
        for value in (True, "auto"):
            target = config.resolve_spool({"general": {"spool": value}}, "/tmp/home")
            self.assertTrue(target.startswith("/tmp/home/logs/spool-"), target)
            self.assertTrue(target.endswith(".log"), target)

    def test_explicit_path(self):
        target = config.resolve_spool(
            {"general": {"spool": "/tmp/x.log"}}, "/tmp/home"
        )
        self.assertEqual(target, "/tmp/x.log")

    def test_garbage_ignored(self):
        self.assertIsNone(
            config.resolve_spool({"general": {"spool": "  "}}, "/tmp/home")
        )


if __name__ == "__main__":
    unittest.main()
