"""SQLite-backed persistence: workspaces, hosts, services, loot.

Modules record findings through `self.framework.store`; the console exposes
them via the `hosts`, `services`, `loot`, and `workspace` commands. Data
lives in $FRAMEWORK_HOME/framework.db (default ~/.framework/).

Thread-safe: job threads write while the console reads. Writes upsert, so
re-scanning a host enriches rows instead of duplicating them.
"""

import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import List, Optional, Union

# Schema versioning via PRAGMA user_version. Pre-version databases read as 0
# and run every migration in order. Migrations must be idempotent.
SCHEMA_VERSION = 1
MIGRATIONS = {
    1: """
CREATE TABLE IF NOT EXISTS hosts (
    id         INTEGER PRIMARY KEY,
    workspace  TEXT NOT NULL,
    address    TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    created    REAL NOT NULL,
    UNIQUE (workspace, address)
);
CREATE TABLE IF NOT EXISTS services (
    id         INTEGER PRIMARY KEY,
    workspace  TEXT NOT NULL,
    address    TEXT NOT NULL,
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL DEFAULT 'tcp',
    name       TEXT NOT NULL DEFAULT '',
    info       TEXT NOT NULL DEFAULT '',
    created    REAL NOT NULL,
    UNIQUE (workspace, address, port, proto)
);
CREATE TABLE IF NOT EXISTS loot (
    id         INTEGER PRIMARY KEY,
    workspace  TEXT NOT NULL,
    address    TEXT NOT NULL DEFAULT '',
    type       TEXT NOT NULL,
    label      TEXT NOT NULL,
    content    TEXT NOT NULL,
    created    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS creds (
    id         INTEGER PRIMARY KEY,
    workspace  TEXT NOT NULL,
    address    TEXT NOT NULL DEFAULT '',
    service    TEXT NOT NULL DEFAULT '',
    username   TEXT NOT NULL DEFAULT '',
    password   TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',
    created    REAL NOT NULL,
    UNIQUE (workspace, address, service, username, password)
);
""",
}
SCHEMA = MIGRATIONS[SCHEMA_VERSION]


class Store:
    def __init__(self, path: Union[str, Path], workspace: str = "default",
                 loot_dir: Optional[Union[str, Path]] = None):
        self.workspace = workspace
        self.loot_dir = Path(loot_dir) if loot_dir else None
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._migrate()

    def _migrate(self) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        while version < SCHEMA_VERSION:
            version += 1
            self._db.executescript(MIGRATIONS[version])
            self._db.execute(f"PRAGMA user_version = {version}")
        self._db.commit()

    # ------------------------------------------------------------ workspaces
    def workspaces(self) -> List[str]:
        rows = self._db.execute(
            "SELECT DISTINCT workspace FROM ("
            "  SELECT workspace FROM hosts"
            "  UNION SELECT workspace FROM services"
            "  UNION SELECT workspace FROM loot"
            ") ORDER BY workspace"
        ).fetchall()
        names = [r["workspace"] for r in rows]
        if self.workspace not in names:
            names.insert(0, self.workspace)
        return names

    def set_workspace(self, name: str) -> None:
        name = name.strip()
        if not name:
            raise ValueError("workspace name cannot be empty")
        self.workspace = name

    # ------------------------------------------------------------------ write
    def add_host(self, address: str, name: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO hosts (workspace, address, name, created)"
                " VALUES (?, ?, '', ?)",
                (self.workspace, address, time.time()),
            )
            if name:
                self._db.execute(
                    "UPDATE hosts SET name = ? WHERE workspace = ? AND address = ?",
                    (name, self.workspace, address),
                )
            self._db.commit()

    def add_service(self, address: str, port: int, proto: str = "tcp",
                    name: str = "", info: str = "") -> None:
        self.add_host(address)
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO services"
                " (workspace, address, port, proto, name, info, created)"
                " VALUES (?, ?, ?, ?, '', '', ?)",
                (self.workspace, address, int(port), proto, time.time()),
            )
            if name or info:
                self._db.execute(
                    "UPDATE services SET"
                    " name = CASE WHEN ? != '' THEN ? ELSE name END,"
                    " info = CASE WHEN ? != '' THEN ? ELSE info END"
                    " WHERE workspace = ? AND address = ? AND port = ? AND proto = ?",
                    (name, name, info, info,
                     self.workspace, address, int(port), proto),
                )
            self._db.commit()

    def add_loot(self, type: str, label: str, content: str,
                 address: str = "") -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO loot (workspace, address, type, label, content, created)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (self.workspace, address, type, label, content, time.time()),
            )
            self._db.commit()
            return cur.lastrowid

    def add_loot_file(self, type: str, label: str, source,
                      address: str = "") -> int:
        """Store a file as loot: copied to <loot_dir>/<id>-<label>.

        The row's content is 'file:<path>'. Raises ValueError when the
        store has no loot_dir, OSError when the source can't be read.
        """
        if self.loot_dir is None:
            raise ValueError("this store has no loot_dir for file storage")
        data = Path(source).read_bytes()
        loot_id = self.add_loot(type, label, "", address)
        safe = re.sub(r"[^\w.\-]", "_", label)[:40] or "loot"
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        dest = self.loot_dir / f"{loot_id}-{safe}"
        dest.write_bytes(data)
        with self._lock:
            self._db.execute(
                "UPDATE loot SET content = ? WHERE workspace = ? AND id = ?",
                (f"file:{dest}", self.workspace, loot_id),
            )
            self._db.commit()
        return loot_id

    def add_cred(self, address: str, service: str, username: str,
                 password: str, source: str = "") -> None:
        """Record a working credential (deduped per host/service/user/pass)."""
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO creds"
                " (workspace, address, service, username, password, source, created)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self.workspace, address, service, username, password,
                 source, time.time()),
            )
            self._db.commit()

    def creds_for(self, address: str, service: str) -> List[tuple]:
        """(username, password) pairs known-good for a host+service."""
        rows = self._db.execute(
            "SELECT username, password FROM creds"
            " WHERE workspace = ? AND address = ? AND service = ?",
            (self.workspace, address, service),
        ).fetchall()
        return [(r["username"], r["password"]) for r in rows]

    # ------------------------------------------------------------------- read
    def hosts(self) -> List[sqlite3.Row]:
        return self._db.execute(
            "SELECT * FROM hosts WHERE workspace = ? ORDER BY address",
            (self.workspace,),
        ).fetchall()

    def services(self, address: Optional[str] = None) -> List[sqlite3.Row]:
        if address is None:
            return self._db.execute(
                "SELECT * FROM services WHERE workspace = ?"
                " ORDER BY address, port",
                (self.workspace,),
            ).fetchall()
        return self._db.execute(
            "SELECT * FROM services WHERE workspace = ? AND address = ?"
            " ORDER BY port",
            (self.workspace, address),
        ).fetchall()

    def loot(self, type: Optional[str] = None) -> List[sqlite3.Row]:
        if type is None:
            return self._db.execute(
                "SELECT * FROM loot WHERE workspace = ? ORDER BY id",
                (self.workspace,),
            ).fetchall()
        return self._db.execute(
            "SELECT * FROM loot WHERE workspace = ? AND type = ? ORDER BY id",
            (self.workspace, type),
        ).fetchall()

    def creds(self, address: Optional[str] = None) -> List[sqlite3.Row]:
        if address is None:
            return self._db.execute(
                "SELECT * FROM creds WHERE workspace = ?"
                " ORDER BY address, service",
                (self.workspace,),
            ).fetchall()
        return self._db.execute(
            "SELECT * FROM creds WHERE workspace = ? AND address = ?"
            " ORDER BY service",
            (self.workspace, address),
        ).fetchall()

    def loot_get(self, loot_id: int) -> Optional[sqlite3.Row]:
        return self._db.execute(
            "SELECT * FROM loot WHERE workspace = ? AND id = ?",
            (self.workspace, int(loot_id)),
        ).fetchone()

    def delete_loot(self, loot_id: int) -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM loot WHERE workspace = ? AND id = ?",
                (self.workspace, int(loot_id)),
            )
            self._db.commit()
            return cur.rowcount > 0

    def delete_cred(self, cred_id: int) -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM creds WHERE workspace = ? AND id = ?",
                (self.workspace, int(cred_id)),
            )
            self._db.commit()
            return cur.rowcount > 0

    def delete_host(self, address: str) -> bool:
        """Delete a host and all its services from the current workspace."""
        with self._lock:
            self._db.execute(
                "DELETE FROM services WHERE workspace = ? AND address = ?",
                (self.workspace, address),
            )
            cur = self._db.execute(
                "DELETE FROM hosts WHERE workspace = ? AND address = ?",
                (self.workspace, address),
            )
            self._db.commit()
            return cur.rowcount > 0

    def delete_service(self, address: str, port: int,
                       proto: str = "tcp") -> bool:
        """Delete one service row from the current workspace."""
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM services WHERE workspace = ? AND address = ? "
                "AND port = ? AND proto = ?",
                (self.workspace, address, int(port), proto),
            )
            self._db.commit()
            return cur.rowcount > 0

    def clear_workspace(self) -> None:
        """Delete every host, service, loot, and cred in the current
        workspace."""
        with self._lock:
            for table in ("hosts", "services", "loot", "creds"):
                self._db.execute(
                    f"DELETE FROM {table} WHERE workspace = ?",
                    (self.workspace,),
                )
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()
