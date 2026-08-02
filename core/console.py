"""The msfconsole-style REPL.

Module commands:   use, back, show, set, unset, setg, unsetg, run/exploit,
                   check, generate, search, info, template, reload
Job commands:      run -j (background), jobs, jobs -o <id>, jobs -k <id>
Session commands:  sessions, sessions -i <id>, sessions -u <id>, sessions -k <id>
Data commands:     hosts, services, loot, workspace
Lab commands:      lab, lab up|down|status <name>
Misc:              resource <file>, spool <file>|off
"""

import cmd
import glob
import os
import shlex
import textwrap
import traceback
from pathlib import Path
from typing import List, Optional

from core import log, output, template
from core.jobs import JobManager
from core.lab import LabError, LabManager
from core.module import BaseModule, ExploitModule, PayloadModule
from core.session import SessionManager
from core.store import Store

SHOW_TOPICS = ["options", "modules", "exploits", "auxiliary", "payloads", "info", "errors"]
MAX_RESOURCE_DEPTH = 3
DEFAULT_LABS_ROOT = Path(__file__).resolve().parent.parent / "labs"

BANNER = r"""
  _____ ___  ____   ____ _____
 |  ___/ _ \|  _ \ / ___| ____|
 | |_ | | | | |_) | |  _|  _|
 |  _|| |_| |  _ <| |_| | |___
 |_|   \___/|_| \_\\____|_____|
"""


class FrameworkConsole(cmd.Cmd):
    ruler = "-"

    def __init__(self, registry, store: Optional[Store] = None,
                 lab_manager: Optional[LabManager] = None,
                 history_file: Optional[Path] = None):
        super().__init__()
        self.registry = registry
        self.store = store if store is not None else Store(":memory:")
        self.lab_manager = lab_manager if lab_manager is not None \
            else LabManager(DEFAULT_LABS_ROOT)
        self.sessions = SessionManager()
        self.jobs = JobManager()
        self.global_options = {}  # setg datastore, keys uppercase, values strings
        self.module: Optional[BaseModule] = None
        self.module_path: Optional[str] = None
        self._resource_depth = 0
        self._spool_path: Optional[str] = None
        self._spool_file = None
        self._labs_started: set = set()  # labs started by THIS session
        self.history_file = history_file
        if history_file is not None:
            self._load_history()
        self._update_prompt()

    # ----------------------------------------------------------------- history
    def _load_history(self) -> None:
        try:
            import readline
        except ImportError:
            return
        try:
            readline.read_history_file(str(self.history_file))
        except (FileNotFoundError, OSError):
            pass
        readline.set_history_length(1000)

    def save_history(self) -> None:
        if self.history_file is None:
            return
        try:
            import readline
        except ImportError:
            return
        try:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            readline.write_history_file(str(self.history_file))
        except OSError:
            pass

    def print_banner(self) -> None:
        output.print_line(output.style(BANNER.rstrip("\n"), output.ACCENT, bold=True))
        output.print_line(output.style(
            "       forge v0.5 -- personal CTF/pentest framework",
            output.ACCENT, bold=True,
        ))
        output.print_line(output.style(
            f"+ -- --=[ {len(self.registry.modules)} modules loaded", output.TEXT_SOFT,
        ))
        if self.registry.errors:
            output.print_line(output.style(
                f"+ -- --=[ {len(self.registry.errors)} module(s) failed to load "
                "('show errors')",
                output.WARM,
            ))
        output.print_line()

    # ------------------------------------------------------------------ prompt
    def _update_prompt(self) -> None:
        if self.module_path:
            path = output.rl_style(self.module_path, output.ACCENT)
            self.prompt = f"forge ({path}) > "
        else:
            self.prompt = "forge > "

    def postcmd(self, stop: bool, line: str) -> bool:
        """Announce jobs that finished and sessions that opened."""
        for session in self.sessions.poll_new():
            output.print_good(
                f"Session {session.id} opened ({session.info})"
            )
        for job in self.jobs.poll_finished():
            if job.status == "done":
                output.print_good(
                    f"Job {job.id} finished: {job.name} ('jobs -o {job.id}' for output)"
                )
            else:
                output.print_error(
                    f"Job {job.id} failed: {job.name} ('jobs -o {job.id}' for traceback)"
                )
        return stop

    # ----------------------------------------------------------------- helpers
    def _require_module(self) -> bool:
        if self.module is None:
            output.print_error("No module selected. Use: use <module path>")
            return False
        return True

    def _check_requirements(self) -> bool:
        missing = self.module.missing_requirements()
        if missing:
            output.print_error("Missing dependencies: " + ", ".join(missing))
            output.print_status("Install with: pip install " + " ".join(missing))
            return False
        return True

    def _run_hook(self, func, label: str):
        try:
            return func()
        except Exception:
            output.print_error(f"{label} raised an exception:")
            traceback.print_exc()
            log.get().error("%s raised\n%s", label, traceback.format_exc())
            return None

    @staticmethod
    def _split(arg: str) -> Optional[List[str]]:
        try:
            return shlex.split(arg)
        except ValueError as e:
            output.print_error(str(e))
            return None

    def _print_table(self, headers: List[str], rows, indent: int = 2) -> None:
        rows = [[str(c) for c in row] for row in rows]
        cols = list(zip(headers, *rows)) if rows else [(h,) for h in headers]
        widths = [max(len(str(c)) for c in col) for col in cols]
        pad = " " * indent
        header = pad + "  ".join(h.ljust(w) for h, w in zip(headers, widths))
        rule = pad + "  ".join("-" * w for w in widths)
        output.print_line(output.style(header, output.TEXT_SOFT, bold=True))
        output.print_line(output.style(rule, output.TEXT_FAINT))
        for row in rows:
            output.print_line(pad + "  ".join(c.ljust(w) for c, w in zip(row, widths)))

    # ------------------------------------------------------ module: load/unload
    def do_use(self, arg: str) -> None:
        """Load a module: use auxiliary/scanner/port_scan"""
        path = arg.strip()
        if not path:
            output.print_error("Usage: use <module path>")
            return
        inst = self.registry.create(path)
        if inst is None:
            output.print_error(f"No such module: {path}")
            return
        inst.framework = self
        self.module = inst
        self.module_path = path
        self._update_prompt()
        missing = inst.missing_requirements()
        if missing:
            output.print_warning(
                "This module needs unavailable packages: " + ", ".join(missing)
            )

    def do_back(self, arg: str) -> None:
        """Unload the current module."""
        self.module = None
        self.module_path = None
        self._update_prompt()

    # ------------------------------------------------------------- show/search
    def do_show(self, arg: str) -> None:
        """show options | modules | exploits | auxiliary | payloads | info | errors"""
        what = arg.strip().lower() or "options"
        if what == "options":
            self._show_options(self.module)
        elif what in ("modules", "all"):
            self._list_modules(self.registry.paths())
        elif what == "exploits":
            self._list_modules(self.registry.paths("exploits"))
        elif what == "auxiliary":
            self._list_modules(self.registry.paths("auxiliary"))
        elif what == "payloads":
            self._list_modules(self.registry.paths("payloads"))
        elif what == "info":
            self.do_info("")
        elif what == "errors":
            if not self.registry.errors:
                output.print_line("No module load errors.")
            for path, err in self.registry.errors.items():
                output.print_error(path)
                output.print_line(textwrap.indent(err, "    "))
        else:
            output.print_error(f"Unknown topic. Try: show {' | '.join(SHOW_TOPICS)}")

    def _list_modules(self, paths: List[str]) -> None:
        if not paths:
            output.print_line("No modules found.")
            return
        rows = [(p, self.registry.get(p).name) for p in paths]
        self._print_table(["Module", "Name"], rows)

    def _show_options(self, module: Optional[BaseModule]) -> None:
        if module is None:
            output.print_error("No module selected.")
            return
        opts = module.options.options()
        if not opts:
            output.print_line("This module has no options.")
            return
        rows = [
            (o.name, o.display_value(), "yes" if o.required else "no", o.description)
            for o in opts
        ]
        self._print_table(["Name", "Current Setting", "Required", "Description"], rows)

    def do_search(self, arg: str) -> None:
        """Search modules by path, name, or description: search http"""
        term = arg.strip()
        if not term:
            output.print_error("Usage: search <term>")
            return
        results = self.registry.search(term)
        if not results:
            output.print_warning(f"No modules matching '{term}'")
            return
        self._list_modules(results)

    def do_info(self, arg: str) -> None:
        """Show module metadata: info [module path]"""
        path = arg.strip() or self.module_path
        if not path:
            output.print_error("No module selected. Usage: info [module path]")
            return
        inst = self.module if path == self.module_path else self.registry.create(path)
        if inst is None:
            output.print_error(f"No such module: {path}")
            return
        cls = type(inst)
        output.print_line()
        output.print_line(f"       Name: {cls.name}")
        output.print_line(f"     Module: {path}")
        output.print_line(f"       Type: {inst.type}")
        output.print_line(f"    Authors: {', '.join(cls.authors) if cls.authors else 'unknown'}")
        if isinstance(inst, ExploitModule) and cls.targets:
            output.print_line(f"    Targets: {', '.join(cls.targets)}")
        if cls.requirements:
            missing = inst.missing_requirements()
            req = ", ".join(
                r + (" (missing)" if r in missing else "") for r in cls.requirements
            )
            output.print_line(f"    Requires: {req}")
        if cls.references:
            output.print_line(" References:")
            for ref in cls.references:
                output.print_line(f"   - {ref}")
        output.print_line()
        output.print_line("Description:")
        desc = " ".join(cls.description.split())
        for line in textwrap.wrap(desc, 70) or [""]:
            output.print_line("  " + line)
        output.print_line()
        if inst.options.options():
            output.print_line("Options:")
            self._show_options(inst)

    # ------------------------------------------------------------ options: set
    def do_set(self, arg: str) -> None:
        """Set an option on the loaded module: set RHOSTS 10.10.10.10"""
        if not self._require_module():
            return
        parts = self._split(arg)
        if parts is None:
            return
        if len(parts) < 2:
            output.print_error("Usage: set <OPTION> <value>")
            return
        name, value = parts[0], " ".join(parts[1:])
        try:
            self.module[name] = value
        except KeyError:
            output.print_error(f"Unknown option: {name}")
            return
        except ValueError as e:
            output.print_error(str(e))
            return
        output.print_line(f"{name.upper()} => {value}")

    def do_unset(self, arg: str) -> None:
        """Clear an option on the loaded module: unset RHOSTS"""
        if not self._require_module():
            return
        name = arg.strip()
        if not name:
            output.print_error("Usage: unset <OPTION>")
            return
        try:
            self.module.options.unset(name)
        except KeyError:
            output.print_error(f"Unknown option: {name}")
            return
        output.print_line(f"Unset {name.upper()}")

    def do_setg(self, arg: str) -> None:
        """Set a global option visible to all modules: setg LHOST 10.10.14.5"""
        parts = self._split(arg)
        if parts is None:
            return
        if len(parts) < 2:
            output.print_error("Usage: setg <OPTION> <value>")
            return
        name, value = parts[0].upper(), " ".join(parts[1:])
        self.global_options[name] = value
        output.print_line(f"{name} => {value}")

    def do_unsetg(self, arg: str) -> None:
        """Remove a global option: unsetg LHOST"""
        name = arg.strip().upper()
        if not name:
            output.print_error("Usage: unsetg <OPTION>")
            return
        if self.global_options.pop(name, None) is None:
            output.print_error(f"Global option not set: {name}")
            return
        output.print_line(f"Unset {name}")

    # -------------------------------------------------------------- execution
    def do_run(self, arg: str) -> None:
        """Execute the loaded module. 'run -j' runs it as a background job."""
        if not self._require_module():
            return
        if not self.module.validate_options():
            return
        if not self._check_requirements():
            return
        parts = self._split(arg) if arg.strip() else []
        if parts is None:
            return
        if "-j" in parts:
            self._start_job()
        else:
            self._run_hook(self.module.run, "Module")

    do_exploit = do_run

    def _start_job(self) -> None:
        """Run a fresh copy of the current module in a background thread."""
        inst = self.registry.create(self.module_path)
        inst.framework = self
        for opt in self.module.options.options():
            if opt.value is not None:
                inst.options[opt.name] = opt.value
        job = self.jobs.start(self.module_path, inst.run, module=inst)
        output.print_status(f"Started job {job.id}: {self.module_path}")

    def do_check(self, arg: str) -> None:
        """Run an exploit module's safe vulnerability check."""
        if not self._require_module():
            return
        if not isinstance(self.module, ExploitModule):
            output.print_error("check is only supported by exploit modules")
            return
        if not self.module.validate_options():
            return
        if not self._check_requirements():
            return
        result = self._run_hook(self.module.check, "check()")
        if result is True:
            output.print_good("The target appears vulnerable")
        elif result is False:
            output.print_error("The target does not appear vulnerable")

    def do_generate(self, arg: str) -> None:
        """Generate output from a payload module."""
        if not self._require_module():
            return
        if not isinstance(self.module, PayloadModule):
            output.print_error("generate is only supported by payload modules")
            return
        if not self.module.validate_options():
            return
        if not self._check_requirements():
            return
        result = self._run_hook(self.module.generate, "generate()")
        if result is not None:
            output.print_line(result)

    # -------------------------------------------------------------------- jobs
    def do_jobs(self, arg: str) -> None:
        """Background jobs: jobs | jobs -o <id> (output) | jobs -k <id> (stop/dismiss)"""
        parts = self._split(arg)
        if parts is None:
            return
        if not parts or parts == ["-l"]:
            jobs = self.jobs.all()
            if not jobs:
                output.print_line("No jobs.")
                return
            rows = [
                (j.id, j.name, "running" if j.running else j.status, f"{j.runtime}s")
                for j in jobs
            ]
            self._print_table(["Id", "Module", "Status", "Runtime"], rows)
            return
        if len(parts) == 2 and parts[0] in ("-o", "-k"):
            try:
                jid = int(parts[1])
            except ValueError:
                output.print_error(f"Bad job id: {parts[1]}")
                return
            if parts[0] == "-o":
                job = self.jobs.get(jid)
                if job is None:
                    output.print_error(f"No job {jid}")
                    return
                text = job.output_text()
                output.print_line(text if text else "(no output yet)")
            else:
                job = self.jobs.get(jid)
                if job is None:
                    output.print_error(f"No job {jid}")
                elif job.running:
                    if job.request_stop():
                        output.print_status(f"Job {jid} stopping (cooperative)")
                    else:
                        output.print_error(
                            f"Job {jid} can't be stopped (module doesn't "
                            "implement stop()) — it runs to completion"
                        )
                elif self.jobs.dismiss(jid):
                    output.print_good(f"Dismissed job {jid}")
            return
        output.print_error("Usage: jobs [-l] | -o <id> | -k <id>")

    # ---------------------------------------------------------------- sessions
    def do_sessions(self, arg: str) -> None:
        """Manage sessions: -l list | -i <id> interact | -u <id> upgrade to pty | -k <id> kill"""
        parts = self._split(arg)
        if parts is None:
            return
        if not parts or parts == ["-l"]:
            sessions = self.sessions.all()
            if not sessions:
                output.print_line("No active sessions.")
                return
            rows = [
                (s.id, "shell", s.info, "alive" if s.alive else "dead")
                for s in sessions
            ]
            self._print_table(["Id", "Type", "Info", "Status"], rows)
            return
        if len(parts) == 2 and parts[0] in ("-i", "-u", "-k"):
            try:
                sid = int(parts[1])
            except ValueError:
                output.print_error(f"Bad session id: {parts[1]}")
                return
            if parts[0] in ("-i", "-u"):
                session = self.sessions.get(sid)
                if session is None:
                    output.print_error(f"No session {sid}")
                    return
                if parts[0] == "-u":
                    output.print_status(f"Upgrading session {sid} to a pty shell")
                    session.upgrade_to_pty()
                session.interact()
            else:
                if self.sessions.kill(sid):
                    output.print_good(f"Killed session {sid}")
                else:
                    output.print_error(f"No session {sid}")
            return
        output.print_error("Usage: sessions [-l] | -i <id> | -u <id> | -k <id>")

    # --------------------------------------------------------------- data store
    def do_hosts(self, arg: str) -> None:
        """List known hosts in the current workspace."""
        hosts = self.store.hosts()
        if not hosts:
            output.print_line("No hosts recorded yet.")
            return
        rows = [(h["address"], h["name"]) for h in hosts]
        self._print_table(["Address", "Name"], rows)

    def do_services(self, arg: str) -> None:
        """List recorded services: services [address]"""
        address = arg.strip() or None
        services = self.store.services(address)
        if not services:
            output.print_line("No services recorded yet.")
            return
        rows = [
            (s["address"], s["port"], s["proto"], s["name"], s["info"])
            for s in services
        ]
        self._print_table(["Host", "Port", "Proto", "Name", "Info"], rows)

    def do_report(self, arg: str) -> None:
        """Export the workspace: report [file.md | file.json] (no arg = print)"""
        from core import report as report_mod

        target = arg.strip()
        data = report_mod.collect(self.store)
        if target.endswith(".json"):
            text = report_mod.render_json(data)
        else:
            text = report_mod.render_markdown(data)
        if not target:
            output.print_line(text)
            return
        path = Path(target).expanduser()
        try:
            path.write_text(text + "\n", encoding="utf-8")
        except OSError as e:
            output.print_error(f"Cannot write {path}: {e}")
            return
        output.print_good(f"Report written to {path}")

    def do_creds(self, arg: str) -> None:
        """List stored credentials: creds [host] | creds -d <id>"""
        parts = self._split(arg)
        if parts is None:
            return
        if len(parts) == 2 and parts[0] == "-d":
            try:
                cid = int(parts[1])
            except ValueError:
                output.print_error(f"Bad cred id: {parts[1]}")
                return
            if self.store.delete_cred(cid):
                output.print_good(f"Deleted cred {cid}")
            else:
                output.print_error(f"No cred {cid} in this workspace")
            return
        address = parts[0] if parts else None
        entries = self.store.creds(address)
        if not entries:
            output.print_line("No credentials stored yet.")
            return
        rows = [
            (c["id"], c["address"], c["service"], c["username"], c["password"], c["source"])
            for c in entries
        ]
        self._print_table(
            ["Id", "Host", "Service", "Username", "Password", "Source"], rows
        )

    def do_loot(self, arg: str) -> None:
        """Loot: loot [-t type] | loot -i <id> | loot -a <type> <label> <text>"""
        parts = self._split(arg)
        if parts is None:
            return
        if not parts or (len(parts) == 2 and parts[0] == "-t"):
            type_filter = parts[1] if parts else None
            entries = self.store.loot(type_filter)
            if not entries:
                output.print_line("No loot recorded yet.")
                return
            rows = [
                (e["id"], e["type"], e["label"], e["address"]) for e in entries
            ]
            self._print_table(["Id", "Type", "Label", "Host"], rows)
            return
        if len(parts) == 2 and parts[0] == "-i":
            try:
                entry = self.store.loot_get(int(parts[1]))
            except ValueError:
                output.print_error(f"Bad loot id: {parts[1]}")
                return
            if entry is None:
                output.print_error(f"No loot {parts[1]} in this workspace")
                return
            content = entry["content"]
            if content.startswith("file:"):
                blob = Path(content[5:])
                output.print_status(f"File loot: {blob}")
                try:
                    output.print_line(
                        blob.read_bytes()[:65536].decode(errors="replace")
                    )
                except OSError as e:
                    output.print_error(f"Cannot read loot file: {e}")
            else:
                output.print_line(content)
            return
        if len(parts) == 4 and parts[0] == "-f":
            try:
                loot_id = self.store.add_loot_file(parts[1], parts[2], parts[3])
            except (ValueError, OSError) as e:
                output.print_error(str(e))
                return
            output.print_good(f"Saved file loot {loot_id}")
            return
        if len(parts) >= 4 and parts[0] == "-a":
            loot_id = self.store.add_loot(parts[1], parts[2], " ".join(parts[3:]))
            output.print_good(f"Saved loot {loot_id}")
            return
        if len(parts) == 2 and parts[0] == "-d":
            try:
                lid = int(parts[1])
            except ValueError:
                output.print_error(f"Bad loot id: {parts[1]}")
                return
            if self.store.delete_loot(lid):
                output.print_good(f"Deleted loot {lid}")
            else:
                output.print_error(f"No loot {lid} in this workspace")
            return
        output.print_error(
            "Usage: loot [-t type] | -i <id> | -d <id> | -a <type> <label> <text>"
        )

    def do_workspace(self, arg: str) -> None:
        """List workspaces, or switch: workspace [name]"""
        name = arg.strip()
        if not name:
            current = self.store.workspace
            for ws in self.store.workspaces():
                marker = "*" if ws == current else " "
                output.print_line(f"{marker} {ws}")
            return
        try:
            self.store.set_workspace(name)
        except ValueError as e:
            output.print_error(str(e))
            return
        output.print_status(f"Workspace: {name}")

    # -------------------------------------------------------------------- labs
    def do_lab(self, arg: str) -> None:
        """Manage test labs: lab | lab up|down|status <name> | lab clean"""
        parts = self._split(arg)
        if parts is None:
            return
        if not parts:
            labs = self.lab_manager.labs()
            if not labs:
                output.print_line(f"No labs found under {self.lab_manager.labs_root}")
                return
            rows = []
            for name in sorted(labs):
                running = self.lab_manager.is_running(name)
                state = "running" if running else ("unknown" if running is None else "stopped")
                targets = ", ".join(
                    f"127.0.0.1:{hp}->{cp}" for hp, cp in labs[name].targets
                )
                rows.append((name, state, targets))
            self._print_table(["Lab", "State", "Targets"], rows)
            return
        action, rest = parts[0], parts[1:]
        if action == "clean" and not rest:
            try:
                cleaned = self.lab_manager.clean()
            except LabError as e:
                output.print_error(str(e))
                return
            if not cleaned:
                output.print_line("No framework labs running.")
                return
            for name in cleaned:
                self._labs_started.discard(name)
                output.print_good(f"Tore down lab '{name}'")
            return
        if action in ("up", "down", "status") and len(rest) == 1:
            name = rest[0]
            try:
                if action == "up":
                    lab = self.lab_manager.up(name)
                    self._labs_started.add(name)
                    output.print_good(f"Lab '{name}' is up")
                    for host_port, container_port in lab.targets:
                        output.print_status(
                            f"  target: 127.0.0.1:{host_port} "
                            f"(container port {container_port})"
                        )
                    output.print_status("Point a module at it: set RHOSTS 127.0.0.1")
                elif action == "down":
                    self.lab_manager.down(name)
                    self._labs_started.discard(name)
                    output.print_good(f"Lab '{name}' is down")
                else:
                    running = self.lab_manager.is_running(name)
                    state = "running" if running else ("unknown" if running is None else "stopped")
                    output.print_line(f"{name}: {state}")
            except LabError as e:
                output.print_error(str(e))
            return
        output.print_error(
            "Usage: lab | lab up <name> | lab down <name> | lab status <name> | lab clean"
        )

    # ------------------------------------------------------------------- misc
    def do_resource(self, arg: str):
        """Run console commands from a file: resource <file>  ('#' comments ok)"""
        target = arg.strip()
        if not target:
            output.print_error("Usage: resource <file>")
            return
        path = Path(target).expanduser()
        if not path.is_file():
            output.print_error(f"No such file: {path}")
            return
        if self._resource_depth >= MAX_RESOURCE_DEPTH:
            output.print_error("Resource files nested too deep")
            return
        self._resource_depth += 1
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                output.print_line(output.style(f"resource> {line}", output.TEXT_FAINT))
                if self.onecmd(line):
                    return True  # an 'exit' inside the file exits the console
        finally:
            self._resource_depth -= 1

    def do_spool(self, arg: str) -> None:
        """Log all output to a file (append mode): spool <file> | spool off"""
        target = arg.strip()
        if not target:
            if output.spooling():
                output.print_status(f"Spooling to {self._spool_path}")
            else:
                output.print_line("Not spooling. Usage: spool <file> | spool off")
            return
        if target == "off":
            if not output.spooling():
                output.print_error("Not spooling")
                return
            output.print_status(f"Spool to {self._spool_path} stopped")
            self._close_spool()
            return
        path = Path(target).expanduser()
        try:
            fh = open(path, "a", encoding="utf-8")
        except OSError as e:
            output.print_error(f"Cannot open {path}: {e}")
            return
        self._close_spool()
        self._spool_file = fh
        self._spool_path = str(path)
        output.set_spool(fh)
        output.print_status(f"Spooling to {path} (append mode)")

    def _close_spool(self) -> None:
        output.set_spool(None)
        if self._spool_file is not None:
            self._spool_file.close()
            self._spool_file = None
            self._spool_path = None

    def do_template(self, arg: str) -> None:
        """Create a new module from a template: template auxiliary/scanner/my_scan"""
        path = arg.strip()
        if not path:
            output.print_error("Usage: template <type>/<category>/<name>")
            return
        try:
            written = template.create_template(self.registry.modules_root, path)
        except (ValueError, FileExistsError) as e:
            output.print_error(str(e))
            return
        output.print_good(f"Created {written}")
        output.print_status("Fill in the TODOs, then 'reload' to pick it up")

    def do_reload(self, arg: str) -> None:
        """Re-scan the module trees (picks up new and edited modules)."""
        self.registry.load()
        output.print_status(
            f"{len(self.registry.modules)} modules loaded, "
            f"{len(self.registry.errors)} failed"
        )

    def _shutdown_labs(self) -> None:
        """Tear down labs this session started. Idempotent; also runs via atexit."""
        for name in sorted(self._labs_started):
            try:
                self.lab_manager.down(name)
                output.print_status(f"Tore down lab '{name}'")
            except LabError as e:
                output.print_warning(f"Could not tear down lab '{name}': {e}")
        self._labs_started.clear()

    def do_exit(self, arg: str) -> bool:
        """Exit the framework."""
        running = self.jobs.running()
        if running:
            output.print_warning(
                f"{len(running)} job(s) still running; they will be abandoned"
            )
        self._shutdown_labs()
        self._close_spool()
        return True

    do_quit = do_exit

    def do_EOF(self, arg: str) -> bool:
        output.print_line()
        return self.do_exit(arg)

    # -------------------------------------------------------------- cmd plumbing
    def do_shell(self, arg: str) -> None:
        """Run a local shell command without leaving the console: !ls, !git status"""
        import subprocess

        if not arg.strip():
            output.print_error("Usage: !<command>")
            return
        # captured (not inherited stdio) so output lands in spool/job logs
        proc = subprocess.run(arg, shell=True, capture_output=True,
                              text=True, check=False)
        if proc.stdout:
            output.print_line(proc.stdout.rstrip("\n"))
        if proc.stderr:
            output.print_warning(proc.stderr.rstrip("\n"))
        if proc.returncode != 0:
            output.print_warning(f"exit code {proc.returncode}")

    def onecmd(self, line: str) -> bool:
        """Run one command, then fire job notifications.

        cmdloop() calls postcmd itself; poll_finished() reports each job
        only once, so the double call there is a no-op. Overriding here
        makes onecmd-driven flows (tests, -x scripts) see notifications too.
        """
        stop = super().onecmd(line)
        self.postcmd(stop, line)
        return stop

    def emptyline(self) -> None:
        pass

    def default(self, line: str) -> None:
        output.print_error(f"Unknown command: {line.split()[0] if line.split() else line}")

    # --------------------------------------------------------------- completion
    def complete_use(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return [p for p in self.registry.paths() if p.startswith(text)]

    complete_info = complete_use

    def complete_show(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return [t for t in SHOW_TOPICS if t.startswith(text)]

    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        words = line[:begidx].split()
        if len(words) <= 1:  # completing the option name
            return self._option_names(text)
        if len(words) == 2 and words[1].upper().endswith(("_FILE", "WORDLIST")):
            return self._path_complete(text)
        return []

    def complete_unset(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return self._option_names(text)

    def _path_complete(self, text: str) -> List[str]:
        """Glob-based file completion; dirs get a trailing slash."""
        expanded = os.path.expanduser(text or "")
        matches = []
        for match in sorted(glob.glob(expanded + "*")):
            if os.path.isdir(match):
                matches.append(match + "/")
            else:
                matches.append(match)
        return matches

    def complete_resource(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return self._path_complete(text)

    complete_spool = complete_resource
    complete_report = complete_resource

    def complete_workspace(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        return [w for w in self.store.workspaces() if w.startswith(text)]

    def complete_lab(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        if len(line[:begidx].split()) < 2:
            return [a for a in ("up", "down", "status", "clean") if a.startswith(text)]
        return [n for n in self.lab_manager.labs() if n.startswith(text)]

    def _option_names(self, text: str) -> List[str]:
        if self.module is None:
            return []
        return [
            o.name for o in self.module.options.options()
            if o.name.startswith(text.upper())
        ]
