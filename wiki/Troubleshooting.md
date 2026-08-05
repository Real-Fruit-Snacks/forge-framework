# Troubleshooting

## docker

**`lab up` says "Docker daemon is not running"**
`sudo systemctl start docker` (once per boot, or `enable` it).

**`lab up` says "permission denied ... docker.sock"**
You're not in the `docker` group:
`sudo usermod -aG docker $USER`, then `newgrp docker` (or re-login).
Group changes only apply to *new* sessions — a CLI/tool started before
the change keeps the old groups; restart it.

**`lab up` hangs then fails readiness**
`docker compose -p forge-lab-<name> logs` — the container's app
crashed. (Seen live: Debian smbd rejecting `--log-stdout`.)

**Containers left running everywhere**
`lab clean` — tears down every `forge-lab-*` project, even orphans.

## Dependencies (Arch / PEP 668)

**"externally-managed-environment" from pip**
System python is sealed. Per-package answers:
`sudo pacman -S python-paramiko python-pwntools`, or the project venv
(`.venv/bin/python forge.py`) for things pacman lacks (impacket).

**Module says "Missing dependencies" on run**
That's the requirements gate working: `pip/pacman` the named package, or
run the framework from the venv that has it. `info` shows which are
missing.

## Console

**Colors broken / weird line wrapping**
Update: colors auto-disable when stdout isn't a tty and honor
`NO_COLOR`/`--no-color`. If your terminal lacks truecolor, export
`NO_COLOR=1`.

**Long input wraps wrong over the prompt**
Fixed by design (readline `\001/\002` markers) — if you see it, your
`TERM` is lying to readline; check `echo $TERM`.

**`sessions -i` feels line-buffered**
You're on a pipe, not a tty — line mode is the fallback. Interactive
terminals get raw mode with remote tab completion.

**Job won't stop with `jobs -k`**
Only modules implementing `stop()` (like the handler) can be stopped;
everything else runs to completion by honest design. `jobs -o <id>` to
watch it finish.

## Modules

**`show errors` lists your module**
Read the traceback right there (also in `logs/framework.log`). Most
common cause: importing a third-party package at module top instead of
lazily — see [[Modules#requirements]].

**Your shadow module isn't loading**
`~/.forge/modules/` must mirror the type/category path:
`~/.forge/modules/auxiliary/scanner/x.py` shadows
`modules/auxiliary/scanner/x.py`. Run `reload`.

## Tests

**Integration tests all skip**
Expected without docker running or with module deps missing — `-v` shows
each skip's reason. `sudo systemctl start docker` to light them up.

## Decomposing "no output" (the expensive error shape)

Exec and RPC failures on Windows almost always present as pure silence.
Different causes, identical symptom — bisect the chain artifact by
artifact instead of guessing:

1. **Does the service launch?** `service <name> launched` proves SCMR +
   ADMIN$ + creds. Not it.
2. **Do artifacts land?** Read the target's Temp over the share: the
   .bat exists? Its content is right? (Console quoting eats backslashes
   and quotes — echo the exact chain back and compare.)
3. **Does the command even run?** `%ERRORLEVEL%` into the output file:
   `cmd & echo EL=%ERRORLEVEL% > out`. EL=0 + empty output means it ran
   and produced nothing (see the session-0 case below) — a different
   bug than never running.
4. **Does the flush survive?** The SCM reaps the service tree when the
   parent exits. Local redirects die mid-flush on Server 2022 (hence
   the bat+UNC shape); the UNC writeback is denied for SYSTEM on Win11.
   Read the file over the share — existing-but-empty vs missing is the
   signature.
5. **Is it the platform, not you?** Win11's session 0: console exes
   launched from a service write NOTHING (builtins echo fine; whoami /
   ipconfig / powershell exit 0 silently). Confirm with `echo` vs
   `whoami` — if builtins work and externals don't, it's the platform.

Change one thing at a time and read the artifact after each. The chain
tells you where it died if you ask it piece by piece.
