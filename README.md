# forge

A personal, Metasploit-style framework for CTF and pentest work, in pure
Python (stdlib core). Load modules, set options, run them — with local
docker labs to test everything end to end. You built it, so you know
exactly how every piece works.

**Documentation: [`wiki/Home.md`](wiki/Home.md)**

## Quick start

```bash
./forge.py            # or: python3 forge.py
# or install it: pipx install .   →   forge command, isolated venv
```

```
forge > lab up web                          # local target
forge > use auxiliary/scanner/dir_buster
forge (auxiliary/scanner/dir_buster) > set RHOSTS 127.0.0.1
forge (auxiliary/scanner/dir_buster) > set RPORT 18080
forge (auxiliary/scanner/dir_buster) > set WORDLIST labs/web/wordlists/dirs.txt
forge (auxiliary/scanner/dir_buster) > run
```

Flags: `-q` (no banner) · `-x "cmd; cmd"` · `-r file.rc` · `--no-color`.
Your data lives in `~/.forge/` (override with `FORGE_HOME`).

## What it does

- msfconsole-style REPL: `use` / `set` / `show options` / `run`, tab
  completion, persistent history
- background jobs with captured output and cooperative stop
- reverse-shell handler → sessions with pty upgrade and live resize sync
- evidence layer: workspaces, hosts/services/creds/loot (SQLite,
  self-migrating), spool logs, Markdown/JSON reports
- docker labs (web/ssh/smb) for testing against real services —
  `lab up web`
- 14 bundled modules: scanners, login brute force, handler, payloads,
  encoders — all tested (152 tests, `python3 -m unittest discover -s tests`)

## Read next

- [Getting started](wiki/Getting-Started.md)
- [All commands](wiki/Console-Commands.md)
- [Writing modules](wiki/Modules.md)
- [Workflows / playbooks](wiki/Workflows.md)
- [Troubleshooting](wiki/Troubleshooting.md)
