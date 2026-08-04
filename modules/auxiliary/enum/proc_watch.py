"""Remote process-diff watcher over WinRM (ScheduledSpy's idea, remote).

Post-foothold privesc signal: short-lived SYSTEM spawns you can't see by
staring at a task list — a scheduled task firing every minute, a service
cycling, an installer kicking off as SYSTEM. The module polls
Win32_Process over WinRM, diffs each snapshot against the last, and
reports every NEW pid with a parent heuristic:

  parent services.exe        -> a service started
  parent svchost.exe/taskeng -> a scheduled task fired
  anything else              -> user/process spawn

Design notes: the poll is BOUNDED (DURATION seconds inline, or run -j
for a background job — no infinite loops), CommandLine degrades to
name-only when access is denied, and the CSV shape (not text scraping)
keeps parsing locale-proof.
"""

import csv
import io
import time

from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptPort, OptString

try:
    import winrm
except ImportError:
    winrm = None  # console gates run() on requirements

PS_SNAPSHOT = ("Get-CimInstance Win32_Process -Property "
               "ProcessId,ParentProcessId,Name,CommandLine | "
               "ConvertTo-Csv -NoTypeInformation")


def _b64_ps():
    import base64
    return base64.b64encode(PS_SNAPSHOT.encode("utf-16-le")).decode()


def parse_snapshot(csv_text):
    """ConvertTo-Csv output -> {pid: (name, ppid, cmdline)}."""
    out = {}
    reader = csv.DictReader(io.StringIO(csv_text.strip()))
    for row in reader:
        try:
            pid = int(row["ProcessId"])
            ppid = int(row["ParentProcessId"])
        except (KeyError, TypeError, ValueError):
            continue
        out[pid] = (row.get("Name") or "?",
                    ppid,
                    row.get("CommandLine") or "")
    return out


def annotate(name, parent_name):
    """One-line spawn classification from parent shape."""
    parent = (parent_name or "").lower()
    if parent == "services.exe":
        return "service started"
    if parent in ("svchost.exe", "taskeng.exe", "taskhostw.exe"):
        return "scheduled task fired"
    if parent in ("wmiprvse.exe",):
        return "wmi provider spawn"
    return "process spawn"


class ProcWatch(AuxiliaryModule):
    name = "Process Diff Watch (WinRM)"
    description = """
        Polls Win32_Process over WinRM and reports every new spawn with
        a parent heuristic (service / scheduled task / wmi / other) —
        the privesc signal of watching for short-lived SYSTEM cycles.
        Bounded: runs DURATION seconds inline, or `run -j` as a
        background watcher. CommandLine degrades to name-only when
        access is denied. Spawn list lands in loot.
    """
    authors = ["you"]
    requirements = ["winrm"]  # the pywinrm package; pip install pywinrm

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=5985, description="WinRM port"))
        self.options.add(OptString("SCHEME", default="http",
                                   description="http (5985) or https (5986)"))
        self.options.add(OptString("DOMAIN", default=".",
                                   description="Auth domain ('.' = local accounts)"))
        self.options.add(OptString("USERNAME", required=True, description="User"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))
        self.options.add(OptInt("INTERVAL", default=2,
                                description="Seconds between snapshots"))
        self.options.add(OptInt("DURATION", default=60,
                                description="Seconds to watch (bounded)"))
        self.options.add(OptString("EXCLUDE", default="",
                                   description="Process names to drop, "
                                               "comma-separated (noise diet)"))

    def run(self):
        user = str(self.get_option("USERNAME"))
        domain = str(self.get_option("DOMAIN") or ".")
        principal = user if domain in ("", ".") else f"{domain}\\{user}"
        timeout = max(int(self.get_option("INTERVAL")) * 3, 15)
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._watch(host, principal, timeout)

    def _session(self, host, principal, timeout):
        return winrm.Session(
            f"{self.get_option('SCHEME')}://{host}:{self.get_option('RPORT')}/wsman",
            auth=(principal, str(self.get_option("PASSWORD"))),
            transport="ntlm",
            server_cert_validation="ignore",
            operation_timeout_sec=timeout,
            read_timeout_sec=timeout + 1,
        )

    def _snapshots(self, session, host):
        """Yield Win32_Process snapshots forever, reusing ONE WinRM shell.

        pywinrm's run_ps opens a shell PER CALL — at 1s polls the guest's
        WinRM caps concurrent shells and starts rejecting with HTTP 400
        mid-watch (and each poll spawns winrshost/conhost noise into the
        very feed we're watching). One persistent shell + run_command
        fixes both."""
        protocol = session.protocol
        shell_id = protocol.open_shell()
        try:
            while True:
                command_id = protocol.run_command(shell_id, "powershell",
                                                  ["-EncodedCommand", _b64_ps()])
                stdout, stderr, status = protocol.get_command_output(
                    shell_id, command_id)
                protocol.cleanup_command(shell_id, command_id)
                if status != 0:
                    raise RuntimeError(
                        stderr.decode(errors="replace")[:120]
                        or f"command exited {status}")
                yield parse_snapshot(stdout.decode(errors="replace"))
        finally:
            protocol.close_shell(shell_id)

    def _watch(self, host, principal, timeout):
        interval = int(self.get_option("INTERVAL"))
        duration = int(self.get_option("DURATION"))
        exclude = {x.strip().lower() for x in
                   str(self.get_option("EXCLUDE") or "").split(",") if x.strip()}
        try:
            session = self._session(host, principal, timeout)
            snaps = self._snapshots(session, host)
            previous = next(snaps)
        except Exception as e:
            self.print_error(f"{host}: WinRM connect/snapshot failed - {e}")
            return
        self.print_status(f"{host}: watching {len(previous)} processes, "
                          f"{interval}s poll for {duration}s "
                          f"(run -j to background this)")

        seen_spawns = []
        failures = 0
        deadline = time.time() + duration
        while time.time() < deadline:
            time.sleep(interval)
            try:
                current = next(snaps)
            except StopIteration:
                self.print_error(f"{host}: WinRM shell closed by target")
                break
            except Exception as e:
                failures += 1
                self.print_debug(f"{host}: snapshot failed ({failures}): {e}")
                if failures >= 3:
                    self.print_error(f"{host}: 3 consecutive snapshot "
                                     f"failures — giving up ({e})")
                    break
                continue  # transient WinRM hiccup — keep watching
            failures = 0
            for pid in sorted(set(current) - set(previous)):
                name, ppid, cmdline = current[pid]
                if name.lower() in exclude:
                    continue
                parent = previous.get(ppid, current.get(ppid))
                parent_name = parent[0] if parent else "?"
                kind = annotate(name, parent_name)
                line = (f"{host}: [{kind}] {name} (pid {pid}, "
                        f"parent {parent_name} {ppid})")
                self.print_good(line)
                seen_spawns.append(line)
                if cmdline:
                    self.print_line(f"      {cmdline[:160]}")
                    seen_spawns.append(f"      {cmdline[:160]}")
            previous = current

        self.print_status(f"{host}: {len([s for s in seen_spawns if not s.startswith(' ')])} spawn(s) in {duration}s")
        store = getattr(self.framework, "store", None)
        if store is not None and seen_spawns:
            store.add_loot("proc-watch", f"spawns @ {host}",
                           "\n".join(seen_spawns), address=host)
