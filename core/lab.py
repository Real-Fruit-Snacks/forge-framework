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

# matches:  - "127.0.0.1:18080:8080"   (quoted or bare, optional /tcp /udp)
_PORT_RE = re.compile(r'^\s*-\s*"?127\.0\.0\.1:(\d+):(\d+)(?:/(?:tcp|udp))?"?\s*$')

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

    Deliberately simple: understands only 'ip:host:container' lines, which is
    the house format for labs (documented in labs/README.md).
    """
    targets = []
    for line in compose_file.read_text(encoding="utf-8").splitlines():
        m = _PORT_RE.match(line)
        if m:
            targets.append((int(m.group(1)), int(m.group(2))))
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
        self._compose_run(name, "up", "-d", "--build")
        self._wait_ready(lab, ready_timeout)
        return lab

    def _wait_ready(self, lab: Lab, timeout: int) -> None:
        """Block until the lab's readiness checks all pass."""
        checks = self._ready_checks(lab)
        pending = list(checks)
        deadline = time.time() + timeout
        while pending and time.time() < deadline:
            pending = [c for c in pending if not self._check(*c)]
            if pending:
                time.sleep(0.25)
        if pending:
            raise LabError(
                f"lab '{lab.name}' started but readiness check(s) failed "
                f"-- check: docker compose -p forge-lab-{lab.name} logs"
            )

    def _ready_checks(self, lab: Lab) -> List[Tuple[str, int, str]]:
        """Readiness checks from labs/<name>/READY, else TCP on every port."""
        checks = []
        ready_file = lab.path / "READY"
        if ready_file.is_file():
            for raw in ready_file.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 2)
                kind = parts[0]
                if kind == "http" and len(parts) == 3:
                    checks.append(("http", int(parts[1]), parts[2]))
                elif kind == "banner" and len(parts) == 2:
                    checks.append(("banner", int(parts[1]), ""))
                elif kind == "tcp" and len(parts) == 2:
                    checks.append(("tcp", int(parts[1]), ""))
        if not checks:
            checks = [("tcp", hp, "") for hp, _ in lab.targets]
        return checks

    @staticmethod
    def _check(kind: str, port: int, arg: str) -> bool:
        try:
            if kind == "tcp":
                with socket.create_connection(("127.0.0.1", port), timeout=1):
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
        self.get(name)
        self._compose_run(name, "down", "--remove-orphans")

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
