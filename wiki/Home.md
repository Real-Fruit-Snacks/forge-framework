# Forge Wiki

A personal, Metasploit-style framework for CTF and pentest work — pure
Python (stdlib core), with local docker labs for testing everything
end to end. You built it, so you know exactly what every module does
and when to reach for it.

**Start here:** [[Getting-Started]] · [[Console-Commands]] · [[Workflows]]

## Using the framework

- [[Getting-Started]] — install, first run, the core loop
- [[Console-Commands]] — every command, every flag
- [[Payloads-and-Handlers]] — generating payloads, catching shells, sessions
- [[Data-and-Evidence]] — hosts/services/creds/loot, workspaces, reports, spool
- [[Workflows]] — CTF/HTB playbooks that chain it all together
- [[Troubleshooting]] — docker perms, PEP 668, common errors

## Building on it

- [[Modules]] — module types, anatomy, how to write your own
- [[Core-Architecture]] — how the pieces fit (options, registry, jobs, sessions, store)
- [[Labs]] — docker test targets: using them, adding your own
- [[Testing]] — the test philosophy: unit, integration, docker gating
- [[Development]] — repo layout, conventions, roadmap

## The map

```
forge.py        entry point (-x, -r, -q, --no-color)
core/               options, module bases, registry, console, jobs,
                    sessions, store, labs, brute engine, report, config, log
modules/            your arsenal: <type>/<category>/<name>.py
labs/               docker targets (web, ssh, smb) + how to add more
tests/              144 tests: unit + docker-gated integration
wiki/               you are here
~/.forge/       your data: db, modules, history, loot, logs, config
```

## Current arsenal

| Module | Purpose |
|---|---|
| `auxiliary/scanner/port_scan` | Threaded TCP connect scanner |
| `auxiliary/scanner/http_headers` | Web server fingerprinting |
| `auxiliary/scanner/dir_buster` | Content discovery (recursion, wildcard filtering) |
| `auxiliary/scanner/smb_enum` | SMB shares + signing policy (impacket) |
| `auxiliary/login/http_login` | HTTP basic/form brute force |
| `auxiliary/login/ssh_login` | SSH brute force (paramiko) |
| `exploits/multi/handler` | Reverse-shell listener → sessions |
| `exploits/example/demo_shell` | Teaching exploit (check → run → session) |
| `payloads/python_reverse_tcp` | Python reverse shell one-liner |
| `payloads/bash_reverse_tcp` | Bash /dev/tcp reverse shell one-liner |
| `payloads/php_reverse_tcp` | PHP fsockopen reverse shell one-liner |
| `payloads/powershell_reverse_tcp` | PowerShell reverse shell one-liner |
| `payloads/shellcode_reverse_tcp` | Null-free shellcode (pwntools) |
| `payloads/encoders/base64_command` | sh base64 wrapper |
| `payloads/encoders/ps_base64` | PowerShell -enc wrapper |
