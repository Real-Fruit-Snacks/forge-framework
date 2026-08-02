"""Startup configuration from ~/.forge/config.toml.

    [general]
    workspace = "default"   # workspace to switch to on boot
    color = true            # false disables colors (--no-color wins)
    spool = "auto"          # "auto" = timestamped spool in logs/, or a path

    [options]               # applied as `setg` globals on boot
    LHOST = "tun0"

Read-only (tomllib can only parse): you edit the file, the framework
consumes it. Missing file means defaults; broken TOML means a warning
and a boot with defaults.
"""

import time
import tomllib
from pathlib import Path
from typing import Dict, Optional

from core import output


def load(path) -> Optional[Dict]:
    """Parse the config file. None when absent; warns + None when invalid."""
    path = Path(path)
    if not path.is_file():
        return None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as e:
        output.print_warning(f"Ignoring invalid config {path}: {e}")
        return None


def apply(console, config: Optional[Dict]) -> None:
    """Apply a loaded config to a console: workspace, color, setg defaults."""
    if not config:
        return
    general = config.get("general", {})
    if general.get("color") is False:
        output.color_enabled = False
    if general.get("debug") is True:
        output.debug_enabled = True
    for name, value in config.get("options", {}).items():
        console.global_options[str(name).upper()] = str(value)
    workspace = general.get("workspace")
    if workspace:
        try:
            console.store.set_workspace(str(workspace))
        except ValueError as e:
            output.print_warning(f"Ignoring bad workspace in config: {e}")


def resolve_spool(config: Optional[Dict], home) -> Optional[str]:
    """The spool target from config, or None.

    spool = true / "auto"  -> logs/spool-<timestamp>.log under home
    spool = "/path/x.log"  -> that path (append mode, as usual)
    """
    if not config:
        return None
    value = config.get("general", {}).get("spool")
    if value is True or value == "auto":
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return str(Path(home) / "logs" / f"spool-{stamp}.log")
    if isinstance(value, str) and value.strip():
        return value
    return None
