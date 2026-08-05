# Testing

The framework's answer to "how do I know my tool works?" — the hardest
part of building security tooling.

## Layers

| Layer | Where | Needs | What it proves |
|---|---|---|---|
| Unit | `tests/test_*.py` | nothing | Pure helpers, validation, engine logic, store, console commands |
| Integration | `tests/test_integration.py` | docker (+ module deps) | Modules vs real services, through the console |
| End-to-end | manual / `-r` scripts | docker | Full playbooks (lab → module → loot → report) |

```bash
python3 -m unittest discover -s tests          # everything available runs
python3 -m unittest tests.test_dirbuster       # one file
```

Integration classes self-skip without docker/paramiko/impacket/pwntools —
the suite is green on any machine, and *complete* on a full one. When a
dependency is missing, that's a skip you can read, not a silent hole:
`python3 -m unittest discover -s tests -v` shows each skip's reason.

## The rules we test by

1. **Pure helpers get unit tests, no sockets.** Parsing, filtering,
   classification — the logic that decides, tested with plain values.
   If a module's logic can't be tested without a network, it's structured
   wrong (see [[Modules#the-quality-bar]]).
2. **Integration drives the console, not the function.** `onecmd("use …;
   set …; run")` — the same path a user takes — asserting on output AND
   on store contents.
3. **Labs are deterministic.** Tests assert exact hits AND exact
   non-hits (decoys in wordlists, wrong passwords, 404 traps).
4. **A bug found in e2e gets a unit test.** The brute-engine startup race
   was caught by docker integration, then pinned by socket-free engine
   tests so it can never sneak back.

## Docker gating details

`docker_available()` runs `docker info` per class; labs are up/down per
class (`setUpClass`/`tearDownClass`) with readiness waits. Agent shells
that lack the docker group can wrap: `echo "cmd" | newgrp docker`.

## Coverage map (what's proven today)

- options/registry/store/jobs/sessions/labs — unit
- console commands (incl. resource, spool, creds, loot, report, history,
  shell passthrough, lab teardown/clean) — unit with mocked labs
- web lab: http_headers, dir_buster (+recursion), http_login — integration
- ssh lab: banner, ssh_login (real paramiko handshake) — integration
- smb lab: smb_enum, smb_login — integration
- ad lab: full AD matrix — enum/groups/policies/misconfigs, kerberoast
  (+targeted), asreproast, dcsync, golden ticket, s4u, rbcd, add_computer,
  adcs_enum, shadow_creds plant/restore, bloodhound, pre2k, dpapi_backupkey
  (DRS unwrap), pkinit clean-refusal — integration
- windows lab: smb_exec, winrm_login/exec, coerce verdicts, sam_dump,
  proc_watch — integration
- domain lab: member enums + at_exec clean denial, ESC1 (analyst mints an
  Administrator cert from the real CA), ESC4 (reshape → enroll → restore),
  dpapi_masterkeys/credentials/chrome (scheduled-task fixtures — real
  masterkey, probe blob, cmdkey entry, DPAPI-wrapped Local State —
  proven by recovering the plaintext from each live artifact), relay_smb
  (NTLM relay to Samba LDAP: manual auth + machine-account auth via the
  in-network relay container, full attack path, clean ACL denial) —
  integration, incl. cold CA builds
- mssql lab: login, enum (sysadmin/links), xp_cmdshell Linux reporting,
  OPENQUERY through the link — integration
- snmp lab: spray hits + honest silence — integration
- smb_capture: real NetNTLMv2 captured, hashcat-shaped — integration
- handler: real payload → session → shell → cooperative stop — live
  sockets (no docker needed)
- payloads/encoders — unit (+ generate when pwntools present)

## Cold-rebuild validation (the honest test)

Persistent lab state hides broken build scripts: every hand-fix you
apply live makes the lab work while the script that should reproduce it
drifts stale. The only test of the whole system is periodically:

```
lab purge <name>     # destroy volumes
lab up <name>        # rebuild from the scripts, cold
<run the e2e classes that cover it>
```

Rules the last cold-rebuild sweep taught (all now encoded):

- Absence is a state too: lazily-created things (the CA's Policy
  registry key) only fail at cold start — guard clauses built on
  presence (`Test-Path`) silently skip them.
- Readiness must be protocol-level, never `sleep` or bare TCP: a real
  SMB login, a TDS login, an HTTP answer on /wsman, an LDAP bind, the
  sentinel file. Readiness windows must cover the COLD case (a Windows
  install is ~15-20 min, not 300s).
- Tests must be state-independent: assert against values read live
  (SIDs shift per provision), and lab tests that create objects clean
  up in setUpClass or they poison the next run against persisted state.
