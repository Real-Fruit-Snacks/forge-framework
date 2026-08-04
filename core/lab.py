"""Lab infrastructure: spin up local throwaway targets with docker compose.

Each labs/<name>/compose.yml defines one target; labs bind to 127.0.0.1 only.
No docker SDK dependency — plain subprocess, with failures translated into
plain-language LabError messages the console can show directly.

Readiness: docker-proxy accepts TCP connections before the container's app
is actually serving, so a bare connect check lies. An optional labs/<name>/READY
file upgrades the check (one directive per line):
    http <port> <path>    poll GET until any HTTP response
    banner <port>         poll until the port sends bytes (e.g. sshd)
    tcp <port>            plain connect (the default for every mapped port)
"""

import http.client
import json
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core import output

# matches:  - "127.0.0.1:18080:8080"   (quoted or bare, optional /tcp /udp,
# trailing comment ok)
_PORT_RE = re.compile(
    r'^\s*-\s*"?127\.0\.0\.1:(\d+):(\d+)(?:/(?:tcp|udp))?"?\s*(?:#.*)?$'
)

# range mapping: 127.0.0.1:49152-49160:49152-49160 (docker-only lines used
# to be skipped — but preflight and down-release need to see them too)
_PORT_RANGE_RE = re.compile(
    r'^\s*-\s*"?127\.0\.0\.1:(\d+)-(\d+):(\d+)-(\d+)(?:/(?:tcp|udp))?"?\s*(?:#.*)?$'
)

_DAEMON_DOWN_HINTS = (
    "cannot connect to the docker daemon",
    "failed to connect to the docker api",
    "is the docker daemon running",
)


class LabError(Exception):
    """User-facing lab failure with a plain-language message."""


@dataclass
class Lab:
    name: str
    path: Path
    compose_file: Path
    targets: List[Tuple[int, int]]  # (host port, container port); host is 127.0.0.1


def _parse_targets(compose_file: Path) -> List[Tuple[int, int]]:
    """Pull the 127.0.0.1 port mappings out of a compose file.

    Understands 'ip:host:container' lines (the house format, documented in
    labs/README.md) and equal-length ranges ('ip:49152-49160:49152-49160',
    which the AD labs use for the pinned dynamic-RPC range — preflight and
    the down-release wait must see those ports too).
    """
    targets = []
    for line in compose_file.read_text(encoding="utf-8").splitlines():
        m = _PORT_RE.match(line)
        if m:
            targets.append((int(m.group(1)), int(m.group(2))))
            continue
        m = _PORT_RANGE_RE.match(line)
        if m:
            host_lo, host_hi = int(m.group(1)), int(m.group(2))
            cont_lo, cont_hi = int(m.group(3)), int(m.group(4))
            if host_hi - host_lo == cont_hi - cont_lo:
                targets.extend(
                    (host_lo + i, cont_lo + i)
                    for i in range(host_hi - host_lo + 1)
                )
    return targets


class LabManager:
    PROJECT_PREFIX = "forge-lab-"

    def __init__(self, labs_root):
        self.labs_root = Path(labs_root)
        self._compose: Optional[List[str]] = None

    # --------------------------------------------------------------- discovery
    def labs(self) -> Dict[str, Lab]:
        found = {}
        if self.labs_root.is_dir():
            for child in sorted(self.labs_root.iterdir()):
                compose = child / "compose.yml"
                if child.is_dir() and compose.is_file():
                    found[child.name] = Lab(
                        child.name, child, compose, _parse_targets(compose)
                    )
        return found

    def get(self, name: str) -> Lab:
        lab = self.labs().get(name)
        if lab is None:
            have = ", ".join(sorted(self.labs())) or "none"
            raise LabError(f"Unknown lab: {name} (available: {have})")
        return lab

    # ---------------------------------------------------------- compose plumbing
    def compose_cmd(self) -> List[str]:
        if self._compose is None:
            if shutil.which("docker"):
                self._compose = ["docker", "compose"]
            elif shutil.which("docker-compose"):
                self._compose = ["docker-compose"]
            else:
                raise LabError("Neither docker nor docker-compose is installed.")
        return self._compose

    def _run(self, cmd: List[str]) -> subprocess.CompletedProcess:
        output.print_debug(f"$ {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            raise LabError("docker is not installed (compose command not found)")
        except subprocess.TimeoutExpired:
            raise LabError(f"docker command timed out -- inspect: {' '.join(cmd)}")
        if proc.returncode != 0:
            combined = (proc.stdout + proc.stderr).lower()
            if any(hint in combined for hint in _DAEMON_DOWN_HINTS):
                raise LabError(
                    "Docker daemon is not running -- start it "
                    "(e.g. 'sudo systemctl start docker') and retry."
                )
            detail = (proc.stderr or proc.stdout).strip()
            raise LabError(f"docker command failed: {detail}")
        return proc

    def _compose_run(self, name: str, *args: str) -> subprocess.CompletedProcess:
        lab = self.get(name)
        cmd = self.compose_cmd() + [
            "-p", f"{self.PROJECT_PREFIX}{name}",
            "-f", str(lab.compose_file), *args,
        ]
        return self._run(cmd)

    # ---------------------------------------------------------------- lifecycle
    def up(self, name: str, ready_timeout: int = 30) -> Lab:
        lab = self.get(name)
        # only preflight when the lab isn't already running its own
        # ports — re-upping a live lab is a legitimate no-op
        if not self.is_running(name):
            self._check_ports_free(lab)
        self._compose_run(name, "up", "-d", "--build")
        checks, timeout = self._ready_checks(lab)
        self._wait_ready(lab, timeout or ready_timeout, checks)
        return lab

    @staticmethod
    def _check_ports_free(lab: Lab) -> None:
        """Fail fast when a host port the lab wants is already bound —
        the classic case is `ad` and `domain` both claiming 389/88/445,
        which otherwise dies mid-boot on docker's 'port is already
        allocated' with half the project running."""
        busy = []
        for host_port, _ in lab.targets:
            try:
                with socket.create_connection(("127.0.0.1", host_port),
                                              timeout=0.5):
                    busy.append(host_port)
            except OSError:
                continue
        if busy:
            ports = ", ".join(str(p) for p in busy)
            raise LabError(
                f"lab '{lab.name}' needs port(s) {ports} on 127.0.0.1 but "
                "they are in use — another lab running? (lab status / "
                "lab down <name> / lab clean)"
            )

    def _wait_ready(self, lab: Lab, timeout: int, checks) -> None:
        """Block until the lab's readiness checks all pass."""
        pending = list(checks)
        deadline = time.time() + timeout
        while pending and time.time() < deadline:
            pending = [c for c in pending if not self._check(*c)]
            if pending:
                time.sleep(0.25)
        if pending:
            raise LabError(
                f"lab '{lab.name}' started but readiness check(s) failed "
                f"-- check: docker compose -p {self.PROJECT_PREFIX}{lab.name} logs"
            )

    def _ready_checks(self, lab: Lab) -> Tuple[List[Tuple[str, int, str]], Optional[int]]:
        """Readiness checks from labs/<name>/READY, else TCP on every port.

        Directives: http <port> <path> | banner <port> | tcp <port> |
        timeout <seconds> (overrides the default for slow-booting labs,
        e.g. Windows installing on first start).
        """
        checks = []
        timeout = None
        ready_file = lab.path / "READY"
        if ready_file.is_file():
            for raw in ready_file.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 2)
                kind = parts[0]
                if kind == "timeout" and len(parts) == 2:
                    timeout = int(parts[1])
                elif kind == "http" and len(parts) == 3:
                    checks.append(("http", int(parts[1]), parts[2]))
                elif kind == "banner" and len(parts) == 2:
                    checks.append(("banner", int(parts[1]), ""))
                elif kind == "tcp" and len(parts) == 2:
                    checks.append(("tcp", int(parts[1]), ""))
                elif kind == "udp" and len(parts) == 2:
                    checks.append(("udp", int(parts[1]), ""))
        if not checks:
            checks = [("tcp", hp, "") for hp, _ in lab.targets]
        return checks, timeout

    @staticmethod
    def _check(kind: str, port: int, arg: str) -> bool:
        try:
            if kind == "tcp":
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return True
            if kind == "udp":
                # a UDP "connect" can't prove the app serves — it gates on
                # the proxy being bound. Real protocol readiness belongs
                # in tests (the snmp lab's README says the same).
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(1)
                    s.connect(("127.0.0.1", port))
                    s.send(b"\x00")
                    return True
            if kind == "banner":
                with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                    s.settimeout(2)
                    return bool(s.recv(64))
            if kind == "http":
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    conn.request("GET", arg or "/")
                    conn.getresponse().read()
                    return True
                finally:
                    conn.close()
        except (OSError, http.client.HTTPException):
            return False
        return False

    def down(self, name: str) -> None:
        lab = self.get(name)
        self._compose_run(name, "down", "--remove-orphans")
        self._wait_ports_released(lab)

    @staticmethod
    def _wait_ports_released(lab: Lab, timeout: float = 15.0) -> None:
        """Wait for docker-proxy to actually let go of the lab's host
        ports. `compose down` returns before the proxies unbind, and an
        immediate re-up (the test suite does exactly this between classes)
        dies on docker's 'address already in use'."""
        deadline = time.time() + timeout
        pending = {host_port for host_port, _ in lab.targets}
        while pending and time.time() < deadline:
            for host_port in list(pending):
                try:
                    with socket.create_connection(("127.0.0.1", host_port),
                                                  timeout=0.3):
                        pass  # still bound
                except OSError:
                    pending.discard(host_port)
            if pending:
                time.sleep(0.3)

    def purge(self, name: str) -> None:
        """Full reclaim: containers, networks, volumes AND images.

        Destroys everything the lab built or downloaded — the next `lab up`
        rebuilds from scratch (for windows: reinstalls Windows, ~20 min).
        """
        self.get(name)
        self._compose_run(name, "down", "--rmi", "all", "-v", "--remove-orphans")

    # -------------------------------------------------------------- janitor
    def running_projects(self) -> List[Tuple[str, str]]:
        """(project, config_file) for every running framework lab."""
        proc = self._run(self.compose_cmd() + ["ls", "--format", "json"])
        text = proc.stdout.strip()
        try:
            data = (
                json.loads(text) if text.startswith("[")
                else [json.loads(line) for line in text.splitlines() if line.strip()]
            )
        except json.JSONDecodeError:
            data = []
        projects = []
        for obj in data:
            name = obj.get("Name", "")
            if name.startswith(self.PROJECT_PREFIX):
                config = (obj.get("ConfigFiles") or "").split(",")[0]
                projects.append((name, config))
        return projects

    def clean(self) -> List[str]:
        """Tear down EVERY framework lab, even ones other sessions started.

        Returns the cleaned lab names. Orphaned projects (lab dir deleted)
        are removed via their compose labels instead of a config file.
        """
        cleaned = []
        for project, config in self.running_projects():
            if config and Path(config).is_file():
                self._run(self.compose_cmd() + [
                    "-p", project, "-f", config, "down", "--remove-orphans",
                ])
            else:
                self._remove_orphaned_project(project)
            cleaned.append(project[len(self.PROJECT_PREFIX):])
        return cleaned

    def _remove_orphaned_project(self, project: str) -> None:
        docker = shutil.which("docker")
        if docker is None:
            raise LabError("docker is not installed")
        label = f"com.docker.compose.project={project}"
        ps = self._run([docker, "ps", "-aq", "--filter", f"label={label}"])
        if ps.stdout.split():
            self._run([docker, "rm", "-f", *ps.stdout.split()])
        nets = self._run([docker, "network", "ls", "-q", "--filter", f"label={label}"])
        if nets.stdout.split():
            self._run([docker, "network", "rm", *nets.stdout.split()])

    def is_running(self, name: str) -> Optional[bool]:
        """True/False, or None when docker can't tell us (daemon down etc.)."""
        try:
            proc = self._compose_run(name, "ps", "--format", "json")
        except LabError:
            return None
        text = proc.stdout.strip()
        states: List[str] = []
        try:
            if text.startswith("["):
                data = json.loads(text)  # newer compose: one JSON array
            else:  # one JSON object per line
                data = [json.loads(line) for line in text.splitlines() if line.strip()]
            states = [
                str(obj.get("State") or obj.get("Status") or "").lower()
                for obj in data
            ]
        except (json.JSONDecodeError, TypeError, AttributeError):
            states = [text.lower()] if text else []
        return any("running" in s or s.startswith("up") for s in states)
