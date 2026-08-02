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
- web lab: http_headers, dir_buster (+recursion), http_login (both modes,
  baseline, wrong-password) — integration
- ssh lab: banner, ssh_login (real paramiko handshake) — integration
- smb lab: smb_enum (signing policy, shares, loot) — integration
- handler: real payload → session → shell → cooperative stop — live
  sockets (no docker needed)
- payloads/encoders — unit (+ generate when pwntools present)
