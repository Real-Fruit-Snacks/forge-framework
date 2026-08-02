# Modules

Everything the framework does is a module. A module is one Python class in
one file; the file's location IS the module's path.

```
modules/auxiliary/scanner/dir_buster.py   →   auxiliary/scanner/dir_buster
~/.forge/modules/<same layout>        →   shadows bundled modules
```

## Types

| Type | Base class | Implements | For |
|---|---|---|---|
| auxiliary | `AuxiliaryModule` | `run()` | Scanners, enumeration, brute force |
| exploit | `ExploitModule` | `run()`, optional `check()` | Attacks; may yield sessions |
| payload | `PayloadModule` | `generate()` | One-liners, shellcode, encoders |

`check()` returns `True` (vulnerable), `False` (not), or `None` (unknown) —
it must be safe and non-destructive.

## Anatomy

```python
from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort

class SmbEnum(AuxiliaryModule):
    name = "SMB Enumerator"          # shown in listings
    description = """What it does, when to use it, what output to expect."""
    authors = ["you"]
    references = []                  # CVEs, URLs
    requirements = []                # third-party imports, e.g. ["impacket"]
    # ExploitModule also has: targets = ["Automatic"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True, description="Targets"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))

    def run(self):
        self.print_status(f"Running against {self.get_option('RHOSTS')}")
```

Rules of the road:

- **One class per file, defined in that file** (imported bases don't count).
- **Read options with `self.get_option("X")`** — module value first, then
  `setg` globals (which are plain strings).
- **Output only via `self.print_status/good/error/warning/line`** — job
  capture and spooling route through these; `print()` escapes both.
- **Typed options validate at `set` time** — use `OptPort` for ports,
  `OptBool` for flags, `OptEnum` for modes. See [[Console-Commands]].

## `self.framework`

| Handle | Use |
|---|---|
| `.sessions` | `add(sock, info)` → session object (exploits/handlers) |
| `.store` | `add_service`, `add_loot`, `add_cred`, `creds_for` — persist findings |
| `.global_options` | the `setg` dict |
| `.jobs`, `.registry`, `.lab_manager` | rarely needed from modules |

Guard optional use with `getattr(self.framework, "store", None)` so modules
stay testable without a console.

## requirements

Third-party deps are declared, then **imported lazily** so the file loads
without them:

```python
requirements = ["paramiko"]

try:
    import paramiko
except ImportError:
    paramiko = None
```

`use` warns, `run` is refused with an install hint, `info` marks them
missing. Installing: see [[Getting-Started#install]].

## The quality bar

What separates a professional module here (enforced in review and in the
`forge-module` skill):

1. **Pure helpers separated from the class** — parsing/filtering/decision
   logic as module-level functions taking plain values, testable without
   sockets. Exemplar: `modules/auxiliary/scanner/dir_buster.py`.
2. **Clean errors for user mistakes** — bad values, missing files,
   unreachable hosts → `print_error` + `return`. Tracebacks are for
   programmer bugs only (the console catches and shows those).
3. **Interruptible concurrency** — `ThreadPoolExecutor` +
   `cancel_futures=True` on `KeyboardInterrupt` (scanners); the bounded
   queue engine in `core/brute.py` (credential attacks).
4. **Persist findings** — services, loot, creds. Login modules try
   `store.creds_for(host, service)` before the wordlist.
5. **Shared logic lives in core** — `core/wordlists.py`, `core/brute.py`,
   `core/report.py`. Two modules needing it → core.
6. **Long-runners implement `stop()`** — polled event in the run loop;
   that's what makes `jobs -k` a cooperative stop (`exploits/multi/handler.py`
   is the reference).

## Writing one

```
forge > template auxiliary/scanner/smb_enum     # boilerplate
forge > reload
```

Edit the file, fill the TODOs, and test it — unit tests for helpers,
integration against a lab when one exists. See [[Testing]] and [[Labs]].
