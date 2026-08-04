<div align="center">

# Forge

A modular, Metasploit-style offensive-security framework — pure Python,
stdlib core, with docker lab targets and a full test suite.

[![Version](https://img.shields.io/badge/version-0.5.0-63f2ab)](https://github.com/Real-Fruit-Snacks/forge-framework/releases)
[![License](https://img.shields.io/badge/license-MIT-6bdcff)](LICENSE)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.10-f0c674)](https://www.python.org)
[![Tests](https://img.shields.io/badge/tests-513%20passing-63f2ab)](https://github.com/Real-Fruit-Snacks/forge-framework)

</div>

## Overview

Forge is a modular offensive-security framework built the way Metasploit is
organized — `use` a module, `set` options, `run` it — but small enough to read
end-to-end and honest about what it does. Everything is tested against real
services: the framework ships its own docker lab targets (web app, SSH server,
Samba SMB, a Samba AD domain controller, Windows Server 2022 and Windows 11
VMs, and a full mini-domain with an AD CS Enterprise CA), and every module is
exercised against them.

Findings compound: scans write to a persistent workspace (hosts, services,
credentials, loot), login modules try stored credentials before wordlists,
and one command exports an engagement report.

## Features

- **msfconsole-style REPL** — `use`/`set`/`run`, tab completion, persistent
  history, resource files, output spooling with session capture
- **62 modules** — scanners (port, HTTP, recursive dir buster, unauth AD
  profiler with coercion annotation, PoC/vuln search), SMB and AD
  enumeration (users, groups, delegation, descriptions, gMSA, LAPS,
  policies, misconfigs, raw LDAP, wire-format DNS with AD SRV discovery),
  credential hunting over share contents, HTTP/SSH/SMB/Kerberos/LDAP/
  MSSQL/WinRM/SNMP brute force plus a store-driven multi-protocol sprayer (pass-the-hash, lockout circuit-breakers),
  kerberoast + AS-REP roast, DCSync, golden ticket, S4U delegation abuse,
  pass-the-ticket, NTLM hash-bait coercion, SAM/LSA dump, ESC1 cert
  request, psexec-class SMB exec, atexec-class scheduled-task exec,
  reverse-shell handler, and a payload set (bash, python, PHP, PowerShell,
  shellcode, encoders)
- **Background jobs** — thread-based with captured output and cooperative stop
- **Sessions** — raw-tty interactive shells, pty upgrade, live resize sync,
  Ctrl-] detach
- **Evidence layer** — SQLite workspace with hosts/services/creds/loot,
  file-loot blobs, Markdown/JSON reports, spool logs for exam evidence
- **Docker labs** — seven throwaway targets (web, ssh, smb, Samba AD,
  Windows Server, Windows 11 client, a full mini-domain) with readiness
  checks, automatic teardown on exit, janitor (`lab clean`) and full
  reclaim (`lab purge`)
- **Debug mode** — `debug on` for verbose `[D]` tracing, always-on debug log
- **513 tests** — unit plus docker-gated integration running real modules
  against real labs

## Quick start

```bash
pipx install git+https://github.com/Real-Fruit-Snacks/forge-framework
forge
```

Or from the repo (stdlib only, no install needed):

```bash
git clone https://github.com/Real-Fruit-Snacks/forge-framework
cd forge-framework
./forge.py
```

Or as one executable file for a jump host (no pip, no venv — python3
only; impacket-class modules report their missing requirement cleanly):

```bash
python3 build.py              # full framework -> forge.pyz
python3 build.py --preset ad  # the AD/SMB toolkit only
./forge.pyz
```

```
  _____ ___  ____   ____ _____
 |  ___/ _ \|  _ \ / ___| ____|
 | |_ | | | | |_) | |  _|  _|
 |  _|| |_| |  _ <| |_| | |___
 |_|   \___/|_| \_\\____|_____|
       forge v0.5 -- personal CTF/pentest framework
+ -- --=[ 62 modules loaded

forge > lab up web
forge > use auxiliary/scanner/dir_buster
forge (auxiliary/scanner/dir_buster) > set RHOSTS 127.0.0.1
forge (auxiliary/scanner/dir_buster) > set RPORT 18080
forge (auxiliary/scanner/dir_buster) > set WORDLIST labs/web/wordlists/dirs.txt
forge (auxiliary/scanner/dir_buster) > set RECURSE true
forge (auxiliary/scanner/dir_buster) > run
```

Catch a reverse shell:

```
forge > use exploits/multi/handler
forge (exploits/multi/handler) > set LPORT 4444
forge (exploits/multi/handler) > run -j
forge (exploits/multi/handler) > use payloads/bash_reverse_tcp
forge (payloads/bash_reverse_tcp) > set LHOST 10.10.14.5
forge (payloads/bash_reverse_tcp) > generate
# [+] Session 1 opened — sessions -i 1, sessions -u 1 for the pty upgrade
```

## Lab targets

| Lab | Target | Purpose |
|---|---|---|
| `web` | `127.0.0.1:18080` | dir busting, HTTP brute force, scanner fixtures |
| `ssh` | `127.0.0.1:12222` | SSH brute force with weak users |
| `smb` | `127.0.0.1:10139/10445` | SMB shares, signing-policy checks |
| `ad` | `127.0.0.1:389/88/445/135` | Samba AD DC (FORGE.LOCAL) with roastable + delegation fixtures |
| `windows` | `127.0.0.1:1445/13389` | Windows Server 2022 VM for psexec/wmiexec-class work |
| `workstation` | `127.0.0.1:2445/23389` | Windows 11 client VM |
| `domain` | DC `389/88/445`, member `3445/33389` | small AD domain: Samba DC + auto-joining Win11 member |

`lab up <name>` builds and starts a target; labs are torn down on exit and
can be fully reclaimed with `lab purge <name>`. Each lab has a build README
in `labs/<name>/`.

## Requirements

Core and bundled modules are standard-library only. Some modules declare
optional dependencies and refuse to run until present: `paramiko` (SSH),
`impacket` (SMB/AD/kerberos), `pwntools` (shellcode). Docker powers the labs.

```bash
pipx inject forge paramiko impacket pwntools   # into the pipx venv
# or system-wide on Arch: sudo pacman -S python-paramiko python-pwntools
```

## Documentation

The full documentation lives in the [wiki](wiki/Home.md):

- [Getting started](wiki/Getting-Started.md) and [console commands](wiki/Console-Commands.md)
- [Writing modules](wiki/Modules.md) and [core architecture](wiki/Core-Architecture.md)
- [Labs](wiki/Labs.md) (including the hard-won gotcha collection) and [testing](wiki/Testing.md)
- [Workflows / playbooks](wiki/Workflows.md) and [troubleshooting](wiki/Troubleshooting.md)

## Testing

```bash
python3 -m unittest discover -s tests
```

Integration tests self-skip without docker or module dependencies; on a full
machine they build the labs, run real modules against them, and assert on
both output and stored evidence.

## License

[MIT](LICENSE)
