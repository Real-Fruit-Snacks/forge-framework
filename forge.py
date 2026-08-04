#!/usr/bin/env python3
"""Forge — modular offensive-security framework. Entry point.

    forge                           interactive console (if pip-installed)
    ./forge.py                      same, straight from the repo
    ./forge.py -q                   no banner
    ./forge.py -x "search http; exit"   run commands non-interactively
    ./forge.py -r recon.rc          run a resource file, then stay interactive

User data lives in $FORGE_HOME (default ~/.forge/; $FRAMEWORK_HOME is still
honored for backward compatibility):
    framework.db    hosts / services / loot / creds database
    modules/        your modules — they shadow bundled ones on path collision
    history         console command history
    loot/           file loot blobs
    logs/           framework.log debug log
    config.toml     optional startup config
"""

import argparse
import atexit
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import log, output
from core import config as fw_config
from core.console import FrameworkConsole
from core.lab import LabManager
from core.registry import ModuleRegistry
from core.store import Store


def framework_home() -> Path:
    """Data dir: $FORGE_HOME > $FRAMEWORK_HOME > ~/.forge (migrating ~/.framework)."""
    for var in ("FORGE_HOME", "FRAMEWORK_HOME"):
        if os.environ.get(var):
            return Path(os.environ[var]).expanduser()
    new = Path.home() / ".forge"
    old = Path.home() / ".framework"
    if old.is_dir() and not new.exists():
        old.rename(new)
        print(f"[*] Migrated data directory: {old} -> {new}")
    return new


def bundled_dirs():
    """Locate bundled modules/ and labs/: repo layout (dev) first, the
    installed share/forge/ layout (pipx/pip installs) next, the in-pyz
    package layout (single-file builds) last."""
    here = Path(__file__).resolve().parent
    if (here / "modules").is_dir():
        return here / "modules", here / "labs"
    share = Path(sys.prefix) / "share" / "forge"
    if (share / "modules").is_dir():
        return share / "modules", share / "labs"
    # inside a zip: not real dirs — the registry's zip branch handles it
    return here / "modules", here / "labs"


def main() -> None:
    parser = argparse.ArgumentParser(description="Forge — modular offensive-security framework")
    parser.add_argument(
        "-x", "--exec", metavar="CMDS",
        help="run commands (separated by ';'), then stay interactive if on a tty",
    )
    parser.add_argument(
        "-r", "--resource", metavar="FILE",
        help="run a resource file of console commands at startup (like msfconsole -r)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="skip the banner")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    args = parser.parse_args()

    if args.no_color:
        output.color_enabled = False

    home = framework_home()
    (home / "modules").mkdir(parents=True, exist_ok=True)
    log.setup(home)

    bundled_modules, bundled_labs = bundled_dirs()
    registry = ModuleRegistry([bundled_modules, home / "modules"])
    registry.load()

    store = Store(home / "framework.db", loot_dir=home / "loot")
    labs = LabManager(bundled_labs)
    console = FrameworkConsole(registry, store, labs, home / "history")
    atexit.register(console._shutdown_labs)  # crash insurance; idempotent
    atexit.register(console.save_history)
    cfg = fw_config.load(home / "config.toml")
    fw_config.apply(console, cfg)
    spool_target = fw_config.resolve_spool(cfg, home)
    if spool_target:
        console.onecmd(f"spool {spool_target}")
    if not args.quiet:
        console.print_banner()

    if args.resource:
        console.onecmd(f"resource {args.resource}")

    if args.exec:
        for command in args.exec.split(";"):
            command = command.strip()
            if command and console.onecmd(command):
                return
        if not sys.stdin.isatty():
            return

    while True:
        try:
            console.cmdloop()
            break
        except KeyboardInterrupt:
            output.print_line()
            output.print_status("Interrupted -- type 'exit' to quit")


if __name__ == "__main__":
    main()
