#!/usr/bin/env python3
"""Single-file builds: forge.pyz — the framework as one executable zip.

    python3 build.py                     # full framework -> forge.pyz
    python3 build.py --preset ad         # the AD/SMB toolkit only
    python3 build.py --preset minimal    # scanners + logins + transfer
    python3 build.py --modules auxiliary/attack/dcsync,auxiliary/attack/s4u
    python3 build.py -o drop.pyz --preset minimal

What goes in: core/, forge.py, modules/ (filtered by preset or list).
What's deliberately NOT in: impacket and friends (they're requirements,
probed at runtime — a pyz runs stdlib-only modules and reports the rest
cleanly), the docker labs, your workspace.

zipapp needs real packages, so the staging step writes empty __init__.py
into every modules/ directory (the repo tree stays untouched).
"""

import argparse
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent

PRESETS = {
    "full": None,  # everything
    "ad": (
        "auxiliary/attack", "auxiliary/enum", "auxiliary/login",
        "auxiliary/scanner/ad_probe", "auxiliary/scanner/smb_enum",
        "auxiliary/scanner/port_scan", "exploits/windows",
    ),
    "minimal": (
        "auxiliary/scanner", "auxiliary/login", "auxiliary/transfer",
        "exploits/multi", "payloads",
    ),
}

MAIN_SHIM = """import sys
from forge import main

if __name__ == "__main__":
    main()
"""


def module_files(preset, explicit):
    """Module .py files to bundle, filtered by preset or explicit paths."""
    modules_root = ROOT / "modules"
    all_files = sorted(p for p in modules_root.rglob("*.py")
                       if not p.name.startswith("_")
                       and "__pycache__" not in p.parts)
    if explicit:
        wanted = {e.strip() for e in explicit.split(",") if e.strip()}
        return [p for p in all_files
                if p.relative_to(modules_root).with_suffix("").as_posix()
                in wanted]
    prefixes = PRESETS[preset]
    if prefixes is None:
        return all_files
    return [p for p in all_files
            if p.relative_to(modules_root).as_posix().startswith(prefixes)]


def build(preset, explicit, output):
    files = module_files(preset, explicit)
    if not files:
        print("no modules matched the selection", file=sys.stderr)
        return 2
    modules_root = ROOT / "modules"
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        shutil.copy(ROOT / "forge.py", stage / "forge.py")
        shutil.copytree(ROOT / "core", stage / "core",
                        ignore=shutil.ignore_patterns("__pycache__"))
        for py_file in files:
            dest = stage / "modules" / py_file.relative_to(modules_root)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(py_file, dest)
        # zipimport needs real packages: __init__.py everywhere
        for directory in [stage / "modules"] + \
                [d for d in (stage / "modules").rglob("*") if d.is_dir()]:
            (directory / "__init__.py").touch()
        (stage / "__main__.py").write_text(MAIN_SHIM, encoding="utf-8")
        zipapp.create_archive(stage, target=output,
                              interpreter="/usr/bin/env python3",
                              compressed=True)
    size = Path(output).stat().st_size
    print(f"built {output}: {len(files)} modules, "
          f"{size / 1024:.0f} KiB")
    print(f"run: {output} -q")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preset", choices=sorted(PRESETS), default="full")
    parser.add_argument("--modules", default="",
                        help="explicit module paths, comma-separated "
                             "(overrides --preset)")
    parser.add_argument("-o", "--output", default="forge.pyz")
    args = parser.parse_args()
    sys.exit(build(args.preset, args.modules, args.output))


if __name__ == "__main__":
    main()
