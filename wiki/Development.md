# Development

## Layout

```
forge.py        entry point (also the pip console-script target)
pyproject.toml      packaging (pip install -e . → `framework`)
core/               the engine room (see [[Core-Architecture]])
modules/            bundled modules: <type>/<category>/<name>.py
labs/               docker targets + READY files + wordlists
tests/              unittest suite (unit + docker-gated integration)
wiki/               this documentation
```

User-side (never in the repo): `~/.forge/` — db, history, loot, logs,
config, personal modules.

## Conventions

- **Stdlib-only core.** No exceptions. Third-party belongs in modules via
  `requirements` + lazy import.
- **Type hints** on core public APIs; modules follow the exemplar style
  (`dir_buster.py`, `handler.py`).
- **No speculative generality.** Features land when a workflow demands
  them, proven by a test.
- **Broken ≠ fatal.** Modules fail into `show errors`; labs fail with
  plain-language messages; config warns and boots. The framework runs
  with whatever subset of itself is healthy.
- **Docs travel with code.** Module docstrings teach; this wiki covers
  the rest. Update both when behavior changes.

## Adding to core

Core changes need the most care — every module depends on them. The bar:
type hints, unit tests, no interface breaks to `BaseModule`, and a wiki
update ([[Core-Architecture]]). If two modules need the same logic, it
moves to core (`wordlists.py`, `brute.py` precedent).

## Roadmap

Depth, not scaffolding:

- AD growth path on `ad_enum` + the `ad` lab: kerberoast TGS extraction
  (impacket GetUserSPNs), AS-REP roasting, delegation enumeration, ADCS
- more encoders (hex, badchar-aware shellcode transforms)
- pwntools exploit helpers (cyclic, ROP chains) for pwn work
- C2-style session channels

## Versioning

`pyproject.toml` holds the version; the banner shows it. Bump on feature
batches, not every commit.
