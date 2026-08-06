<div align="center">

# Forge

A modular, Metasploit-style offensive-security framework — pure Python,
stdlib core, with docker lab targets and a full test suite.

[![Version](https://img.shields.io/badge/version-0.6.0-63f2ab)](https://github.com/Real-Fruit-Snacks/forge-framework/releases)
[![License](https://img.shields.io/badge/license-MIT-6bdcff)](LICENSE)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.10-f0c674)](https://www.python.org)
[![Tests](https://img.shields.io/badge/tests-634%20passing-63f2ab)](https://github.com/Real-Fruit-Snacks/forge-framework)

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
- **78 modules** — full inventory below
- **Background jobs** — thread-based with captured output and cooperative stop
- **Sessions** — raw-tty interactive shells, pty upgrade, live resize sync,
  Ctrl-] detach
- **Evidence layer** — SQLite workspace with hosts/services/creds/loot,
  file-loot blobs, Markdown/JSON reports, spool logs for exam evidence
- **Docker labs** — nine throwaway targets (web, ssh, smb, mssql, snmp,
  Samba AD, Windows Server, Windows 11 client, a full mini-domain with
  an AD CS Enterprise CA) with readiness checks, automatic teardown on
  exit, janitor (`lab clean`) and full reclaim (`lab purge`)
- **Debug mode** — `debug on` for verbose `[D]` tracing, always-on debug log
- **637 tests** — unit plus docker-gated integration running real modules
  against real labs

## Modules

| Area | What it covers |
|---|---|
| Scanners | port, HTTP, recursive dir buster, unauth AD profiler with coercion annotation, PoC/vuln search |
| Enumeration | SMB/AD/MSSQL (users, groups, delegation, descriptions, gMSA, LAPS, policies, misconfigs, raw LDAP, wire-format DNS, BloodHound CE collection), credential hunting over share contents |
| Brute force | HTTP/SSH/SMB/Kerberos/LDAP/MSSQL/WinRM/SNMP logins, store-driven multi-protocol sprayer (pass-the-hash, lockout circuit-breakers) |
| AD attacks | kerberoast (+targeted mode), AS-REP roast, pre-2000 machine spray, DCSync, golden ticket, S4U delegation abuse, RBCD, add_computer, PKINIT cert-to-TGT with UnPAC-the-hash, shadow credentials |
| Certificate abuse | ESC1 (enrollee-supplied SAN), ESC4 (writable-template surgery), DPAPI full chain (domain backup key, masterkeys, Credential Manager, browser passwords, system/WiFi) |
| Coercion & capture | NTLM hash bait, multi-method RPC coercion, NetNTLMv2 capture server, SMB relay to LDAP (RBCD write) |
| Exec | psexec-class SMB, atexec-class scheduled task, WinRM, MSSQL with linked-server pivots |
| Shells & payloads | reverse-shell handler, bash/python/PHP/PowerShell one-liners, shellcode, encoders |

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
       forge v0.6 -- offensive-security framework
+ -- --=[ 78 modules loaded

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
| `mssql` | `127.0.0.1:11433/11434` | SQL Server 2022 ×2, auto-linked (chain pivots) |
| `snmp` | `127.0.0.1:10161` | SNMP community spray |
| `ad` | `127.0.0.1:389/88/445/135` | Samba AD DC (FORGE.LOCAL) with roastable + delegation + ADCS fixtures |
| `windows` | `127.0.0.1:1445/13389` | Windows Server 2022 VM for psexec/wmiexec-class work |
| `workstation` | `127.0.0.1:2445/23389` | Windows 11 client VM |
| `domain` | DC `389/88/445`, member `3445/33389`, CA `4445`, windc `127.0.0.2:389/88/445` | mini-domain: Samba DC + Win11 member + AD CS CA (ESC1/ESC4) + standalone Windows forest (wforge.local, PKINIT/RBCD) |

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
