# snmp lab

**Purpose:** a deterministic SNMP (UDP/161) target for `snmp_login`
today, walk/enum modules later.

**Build:** `python:3-slim`, one stdlib agent (`app.py`) + the repo's own
`core/snmp.py` as its codec — the lab and the modules share one wire
implementation (compose builds with the repo root as context for this).

**Behavior (the fixture):** answers ONLY the `private-lab` community —
sysDescr/sysName/sysUptime for it, silence for everything else. That IS
real SNMP: a wrong community looks identical to a dead host, which is
why `snmp_login` reports inconclusive attempts as "possible", not
"no service".

**Ports:** 161/udp → `127.0.0.1:10161` (READY is a udp-connect check, so
`lab up` can't truly prove readiness — poll a real query in tests).
