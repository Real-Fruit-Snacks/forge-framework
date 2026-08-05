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
- [[Roadmap]] — the working backlog: scope, design notes, testing plans

## The map

```
forge.py        entry point (-x, -r, -q, --no-color)
core/               options, module bases, registry, console, jobs,
                    sessions, store, labs, brute engine, report, config, log
modules/            your arsenal: <type>/<category>/<name>.py
labs/               nine docker targets (web, ssh, smb, mssql, snmp, ad,
                    windows, workstation, domain) + build READMEs
tests/              590 tests: unit + docker-gated integration
wiki/               you are here
~/.forge/       your data: db, modules, history, loot, logs, config
```

## Current arsenal

73 modules and growing — `show modules` (or `search <term>`) lists the
live inventory. The shape of it:

| Area | Examples |
|---|---|
| Scanners | port_scan, http_headers, dir_buster (recursive), ad_probe, poc_search |
| Enumeration | smb_enum, ad_* (users/groups/delegation/gMSA/LAPS/policies/misconfigs), dns_recon, bloodhound (CE JSON), mssql_enum, host packs, cred hunting |
| Brute force | http/ssh/smb/kerberos/ldap/mssql/winrm/snmp logins, multi_spray, pre2k_spray |
| AD attacks | kerberoast (+targeted), asreproast, dcsync, golden_ticket, s4u, rbcd, add_computer, pkinit (+UnPAC), shadow_creds, esc1, esc4, dpapi_backupkey, dpapi_masterkeys, dpapi_credentials, dpapi_chrome, hash_bait, coerce, smb_capture, relay_smb, pass_the_ticket |
| Exec | smb_exec, at_exec, winrm_exec, mssql_exec (linked pivots) |
| Payloads | bash/python/php/powershell reverse one-liners, shellcode, encoders, handler |
