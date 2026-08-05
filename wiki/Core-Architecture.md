# Core Architecture

~2,500 lines of stdlib Python. Small enough to hold in your head — which is
the point of the whole project.

```
                  forge.py
                       │
        ┌──────────────┼───────────────────┐
        │              │                   │
   ModuleRegistry    Store            LabManager
        │              │                   │
   FrameworkConsole ───┴───────────────────┘
        │   ▲
        │   │ framework handle (sessions, store, global_options)
   your modules (loaded per `use`, from modules/ trees)
```

## options.py — the datastore

Typed options: each `Opt` subclass (`OptPort`, `OptBool`, `OptEnum`, …)
validates and normalizes at assignment, raising `ValueError` — so a bad
value fails at `set`, not mid-run. `OptionContainer` is case-insensitive
(`module["rhosts"]`), tracks defaults, and reports missing required
options. Modules read via `get_option`, which falls back to the global
(`setg`) datastore.

## module.py — the contract

`BaseModule`: metadata, `register_options`, `run`, output helpers,
`get_option`, `validate_options`, `missing_requirements`. Subclasses
`AuxiliaryModule` / `ExploitModule` (`check`) / `PayloadModule` (`generate`)
are the only public API module authors touch. The **stability of this
contract is the project's main design constraint** — everything else can
be rewritten under it.

## registry.py — discovery

Walks `modules/` roots (bundled + `~/.forge/modules`, user shadows
bundled on path collision), loads each file with `importlib`, and picks
the one `BaseModule` subclass *defined in that file*. Broken modules land
in `errors` (shown by `show errors`, logged to `logs/framework.log`) —
they never kill startup. This tolerance matters once you have dozens of
half-finished modules.

## console.py — the REPL

`cmd.Cmd` subclass: command parsing, tab completion, tables, prompt.
Also owns `SessionManager`, `JobManager`, `global_options`, and the lab
handle — injected into modules as `module.framework`. `postcmd` announces
finished jobs and newly opened sessions. `onecmd` is overridden so
scripted (`-x`) flows get the same announcements.

## jobs.py — background execution

`run -j` executes a fresh copy of the module in a daemon thread with all
output captured into `job.log` (thread-local capture in `output.py` — the
same plumbing that makes spool work). Threads can't be force-killed in
Python; instead, `jobs -k` calls the module's `stop()` if it exists
(cooperative), else refuses honestly.

## session.py — shells

`Session` wraps a socket: raw-tty interact (termios, Ctrl-] detach) with
line-mode fallback for pipes; `upgrade_to_pty` sends the python/`script`
pty spawn and marks the session, after which interact installs a SIGWINCH
handler pushing `stty rows/cols` on resize. `SessionManager` is
thread-safe (handler jobs add sessions from worker threads).

## store.py — the evidence layer

SQLite (stdlib), one file, `PRAGMA user_version` migrations. Tables:
`hosts`, `services`, `loot`, `creds` — all workspace-scoped, all upserting
on re-scan. Thread-safe via a lock (jobs write while you read). File loot
lives on disk in `~/.forge/loot/` with `file:<path>` in the row.

## lab.py — docker targets

Wraps `docker compose` via subprocess (no SDK): up/down/ps/clean per lab,
each a directory under `labs/`. `up` waits for *meaningful* readiness
(per-lab `READY` files: `http`/`banner`/`tcp` probes) because
docker-proxy accepts TCP before the app is serving. Console tracks
session-started labs and tears them down on exit; `lab clean` is the
janitor for strays (label-based removal even without the compose file).

## Supporting cast

- `output.py` — Terminal Workbench palette, `NO_COLOR`, thread-local
  capture, spool tee
- `brute.py` — bounded-queue credential engine (constant memory, early
  stop, race-free startup)
- `wordlists.py` — wordlist parsing, combo building, cred-option merging
- `dpapi.py` — DPAPI crypto shared by the dpapi_* modules (backup-key
  loot loading, domain masterkey unwrap, credential decrypt; imports
  are function-local so core stays stdlib-importable)
- `report.py` — workspace → Markdown/JSON rendering (pure functions)
- `config.py` — `config.toml` (tomllib) → workspace/color/setg
- `log.py` — rotating debug log
- `template.py` — module scaffolding

## Data flow example

`dir_buster` run: console `set` validates options → `run` → module probes
wildcard fingerprint → thread pool scans → hits print via output helpers
(→ spool + job capture) → findings written to store (services + loot) →
`report` renders them later from the same tables.
