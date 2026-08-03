# Console Commands

Full reference. Anything taking a module path or option name tab-completes;
file paths tab-complete in `set <option>`, `resource`, `spool`, `report`.

## Launch flags

| Flag | Effect |
|---|---|
| `-q` | No banner |
| `-x "cmd; cmd"` | Run commands, then interactive if on a tty |
| `-r file.rc` | Run a resource file at startup (like `msfconsole -r`) |
| `--no-color` | Disable colors (`NO_COLOR` env also respected) |

Environment: `FORGE_HOME` relocates (legacy `FRAMEWORK_HOME` also honored) `~/.forge`.

## Modules

| Command | What it does |
|---|---|
| `use <path>` | Load a module |
| `back` | Unload |
| `show options` | Option table for the loaded module |
| `show modules` / `exploits` / `auxiliary` / `payloads` | List modules |
| `show info` / `info [path]` | Metadata, description, options, requirements |
| `show errors` | Modules that failed to load, with tracebacks |
| `search <term>` | Search path/name/description |
| `template <type>/<category>/<name>` | Scaffold a new module (auxiliary/exploits/payloads) |
| `reload` | Re-scan module trees after edits |

## Options

| Command | What it does |
|---|---|
| `set <OPT> <val>` | Set on the loaded module (typed/validated immediately) |
| `unset <OPT>` | Back to default |
| `setg <OPT> <val>` | Global, visible to every module (e.g. `setg LHOST tun0`) |
| `unsetg <OPT>` | Remove a global |

Option types: `OptString`, `OptAddress`, `OptInt`, `OptFloat`, `OptPort`
(1–65535), `OptBool` (true/false/yes/no/1/0), `OptEnum` (fixed choices).

## Execution

| Command | What it does |
|---|---|
| `run` / `exploit` | Execute the loaded module |
| `run -j` | Execute as a background job |
| `check` | Exploit modules: safe, non-destructive vulnerability check |
| `generate` | Payload modules: print the payload |
| `jobs` | List jobs (id, module, status, runtime) |
| `jobs -o <id>` | Show a job's captured output |
| `jobs -k <id>` | Running: cooperative stop (module `stop()`). Finished: dismiss |

## Sessions

| Command | What it does |
|---|---|
| `sessions` | List sessions |
| `sessions -i <id>` | Interact. Raw tty mode: remote tab-complete/Ctrl-C work; **Ctrl-] detaches**. Piped stdin: line mode, `background` detaches |
| `sessions -u <id>` | Upgrade dumb shell → pty (python/`script` fallback, TERM, size sync), then interact |
| `sessions -k <id>` | Kill |

After a pty upgrade, resizing your window pushes `stty rows/cols` to the
remote live (SIGWINCH, Penelope-style).

## Data

| Command | What it does |
|---|---|
| `hosts` | Known hosts (current workspace) |
| `services [addr]` | Recorded services, optionally one host |
| `creds [host]` / `creds -d <id>` | Valid credentials; login modules try these first |
| `loot` / `-t <type>` | List findings |
| `loot -i <id>` | Show one entry (prints file contents for file loot) |
| `loot -a <type> <label> <text>` | Add a text note |
| `loot -f <type> <label> <path>` | Add a file (copied into `~/.forge/loot/`) |
| `loot -d <id>` | Delete (file loot: deletes the blob on disk too) |
| `workspace [name]` | List or switch/create workspaces (per-engagement data) |
| `report [file.md\|file.json]` | Export the workspace; no arg prints to screen |

## Labs

| Command | What it does |
|---|---|
| `lab` | List labs, state, target ports |
| `lab up <name>` | Build + start; waits for real readiness, prints targets |
| `lab down <name>` | Stop + remove |
| `lab status <name>` | Container state |
| `lab clean` | Tear down EVERY framework lab — asks `y/N` first |
| `lab purge <name>` | Destroy a lab fully: containers, volumes, images — reclaims disk (asks first) |

Labs you start are torn down automatically on `exit`. See [[Labs]].

## Misc

| Command | What it does |
|---|---|
| `resource <file>` | Run console commands from a file (`#` comments ok; nests 3 deep) |
| `serve <file> [port]` / `serve off` | Host a file over HTTP (staged alone behind a 404 page — no directory listing); prints linux + windows fetch lines |
| `debug [on\|off]` | Toggle verbose `[D]` debug output (also `FORGE_DEBUG=1` or `debug = true` in config) |
| `spool <file>` / `spool off` | Log all output (ANSI-stripped, append mode) — including session traffic |
| `!<cmd>` | Run a local shell command (captured into output/spool) |
| `help [cmd]` | Built-in help (every command above has a one-line docstring) |
| `exit` / `quit` / Ctrl-D | Quit (tears down session labs, saves history) |

History persists across sessions in `~/.forge/history`.
