# Data and Evidence

Everything persists in `$FRAMEWORK_HOME` (default `~/.forge/`):

```
framework.db     SQLite: hosts, services, loot, creds (schema-versioned)
modules/         your module tree (shadows bundled modules)
history          console history across sessions
loot/            file blobs from `loot -f`
logs/            framework.log — always-on debug log (1MB × 3 rotations)
config.toml      optional startup config
```

## Workspaces

Per-engagement isolation. `workspace htb-s8` switches (creating on first
use); every table is scoped to the current workspace. Use one per HTB
season, client, or course module. `workspace` alone lists them.

## What gets recorded (and what reads it back)

| Table | Written by | Read by |
|---|---|---|
| hosts | any module touching a host | `hosts`, `report` |
| services | port_scan, dir_buster, http_headers, login modules | `services`, modules, `report` |
| creds | http_login, ssh_login, smb_login, kerberos_login, ldap_login, mssql_login, winrm_login, multi_spray | `creds`, login modules (**tried before wordlists**), `report` |
| loot | dir_buster (web-dirs), smb_enum (smb-shares), cred_hunt (cred-hunt), `loot -a/-f` | `loot`, `report` |

The compounding rule: findings are written so later modules (and
later-you) can use them. Brute force a web login Monday; Saturday the SSH
module asks `creds_for` before touching a wordlist.

## Evidence commands

- `spool engagement.log` — everything on screen, ANSI-stripped, append
  mode — **including interactive session traffic** (shells tee into the
  log, control sequences stripped). Start-of-session habit for cert exams.
  Automate it with `spool = "auto"` in `config.toml` (timestamped file in
  `logs/` per launch) or a fixed path. Want timed *replays* instead?
  Wrap externally: `asciinema rec box.cast --command "./forge.py"` —
  replay tooling, not report text; spool stays the evidence format.
- `report [file.md|file.json]` — structured export: hosts with services
  nested, creds table, loot with contents. No arg prints to screen.
- `loot -f file shadow-dump ./shadow` — binary/file findings stored as
  blobs; `loot -i` prints them back.

## config.toml

```toml
[general]
workspace = "default"   # switch to this on boot
color = true            # false = --no-color every time
spool = "auto"          # "auto" = timestamped log in logs/, or a path
debug = false           # true = verbose [D] debug output from boot

[options]               # applied as `setg` on boot
LHOST = "tun0"
```

Missing file = defaults. Invalid TOML = a warning and defaults (never a
failed boot).

## The debug log

`logs/framework.log` records module load failures, job failures (with
full tracebacks), and console hook exceptions — independent of spool.
When a module you wrote misbehaves, start here.

## Database notes

Single-writer lock; jobs and console share one connection. Schema
migrations run automatically on open (`PRAGMA user_version`), so old
databases keep working as the schema grows. To start clean: delete
`framework.db` (or just make a new workspace).
