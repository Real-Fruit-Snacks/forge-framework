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
