"""Session handling: wrap sockets as interactive shells.

Exploit modules hand a connected socket to SessionManager.add(); the user
interacts with it through the console's `sessions -i <id>` command.

Two interaction modes:
  - raw:  on a real tty, the terminal goes raw (termios) and bytes pass
          through untouched — remote tab completion, Ctrl-C, arrow keys,
          and curses apps all work. Detach with Ctrl-] (telnet style).
  - line: fallback for piped stdin — line buffered, detach with 'background'.
"""

import os
import select
import signal
import sys
import threading
import time
from typing import Dict, List, Optional, Set

from core import output

try:
    import termios
    import tty
    _HAS_TERMIOS = True
except ImportError:  # e.g. Windows
    _HAS_TERMIOS = False

DETACH_BYTE = b"\x1d"  # Ctrl-]

# Sent to a dumb shell to give it a pty. Tries python3, then python, then
# the ubiquitous `script` fallback.
UPGRADE_COMMAND = (
    "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
    " || python -c 'import pty;pty.spawn(\"/bin/bash\")'"
    " || script -qc /bin/bash /dev/null"
)


class Session:
    def __init__(self, sid: int, sock, info: str = ""):
        self.id = sid
        self.sock = sock
        self.info = info
        self.alive = True
        self.pty = False  # True once upgrade_to_pty() has run

    def send(self, data) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data)

    def recv(self, size: int = 4096) -> bytes:
        return self.sock.recv(size)

    def upgrade_to_pty(self) -> None:
        """Turn a dumb remote shell into a pty shell.

        Sends the classic python-pty spawn (with `script` fallback), exports
        a sane TERM, and syncs the remote tty size to the local one. After
        this, Ctrl-C, sudo prompts, and tab completion work on the far end,
        and interact() keeps the size synced on window resize (SIGWINCH).
        """
        commands = [UPGRADE_COMMAND, "export TERM=xterm-256color"]
        for command in commands:
            self.send(command + "\n")
            time.sleep(0.3)  # let each command take effect before the next
        self.pty = True
        self._sync_size()

    def _sync_size(self, size=None) -> None:
        """Push the local terminal size to the remote pty (Penelope-style).

        Leading space keeps the command out of bash history. Injection is
        only visible if the user is mid-line at the moment of resize.
        """
        if size is None:
            if not sys.stdout.isatty():
                return
            size = os.get_terminal_size()
        self.send(f" stty rows {size.lines} cols {size.columns}\n")

    # ------------------------------------------------------------ interaction
    def interact(self) -> None:
        if _HAS_TERMIOS and sys.stdin.isatty():
            self._interact_raw()
        else:
            self._interact_lines()

    def _interact_raw(self) -> None:
        output.print_status(
            f"Interacting with session {self.id} (Ctrl-] to detach)"
        )
        fd = sys.stdin.fileno()
        old_attrs = termios.tcgetattr(fd)
        self.sock.setblocking(False)
        remote_closed = False
        # Penelope-style: keep the remote pty size synced on window resize.
        old_winch = None
        if self.pty and threading.current_thread() is threading.main_thread():
            old_winch = signal.getsignal(signal.SIGWINCH)
            signal.signal(signal.SIGWINCH, lambda *_: self._sync_size())
        try:
            tty.setraw(fd)
            while self.alive:
                readable, _, _ = select.select([self.sock, fd], [], [])
                for src in readable:
                    if src is self.sock:
                        try:
                            data = self.sock.recv(4096)
                        except (BlockingIOError, InterruptedError):
                            continue
                        except OSError:
                            data = b""
                        if not data:
                            remote_closed = True
                            self.alive = False
                            break
                        os.write(sys.stdout.fileno(), data)
                        output.spool_write(data.decode(errors="replace"))
                    else:
                        data = os.read(fd, 4096)
                        if not data or DETACH_BYTE in data:
                            return
                        self.sock.sendall(data)
        finally:
            if old_winch is not None:
                signal.signal(signal.SIGWINCH, old_winch)
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
            self.sock.setblocking(True)
            output.print_line()
            if remote_closed:
                output.print_error(f"Session {self.id} closed")

    def _interact_lines(self) -> None:
        """Line-mode fallback for non-tty stdin (scripts, pipes)."""
        output.print_status(
            f"Interacting with session {self.id} ('background' to detach)"
        )
        self.sock.setblocking(False)
        try:
            while self.alive:
                readable, _, _ = select.select([self.sock, sys.stdin], [], [])
                for src in readable:
                    if src is self.sock:
                        try:
                            data = self.sock.recv(4096)
                        except (BlockingIOError, InterruptedError):
                            continue
                        except OSError:
                            data = b""
                        if not data:
                            output.print_error(f"Session {self.id} closed")
                            self.alive = False
                            break
                        sys.stdout.write(data.decode(errors="replace"))
                        sys.stdout.flush()
                        output.spool_write(data.decode(errors="replace"))
                    else:
                        line = sys.stdin.readline()
                        if not line or line.strip() == "background":
                            return
                        self.send(line)
        finally:
            self.sock.setblocking(True)

    def kill(self) -> None:
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass


class SessionManager:
    def __init__(self) -> None:
        self._sessions: Dict[int, Session] = {}
        self._next_id = 1
        self._announced: Set[int] = set()
        self._lock = threading.Lock()

    def add(self, sock, info: str = "") -> Session:
        with self._lock:
            session = Session(self._next_id, sock, info)
            self._sessions[session.id] = session
            self._next_id += 1
        return session

    def get(self, sid: int) -> Optional[Session]:
        return self._sessions.get(int(sid))

    def all(self) -> List[Session]:
        return [self._sessions[k] for k in sorted(self._sessions)]

    def poll_new(self) -> List[Session]:
        """Sessions added since the last call (for prompt announcements)."""
        with self._lock:
            new = [s for s in self._sessions.values()
                   if s.id not in self._announced]
            self._announced.update(s.id for s in new)
        return sorted(new, key=lambda s: s.id)

    def kill(self, sid: int) -> bool:
        with self._lock:
            session = self._sessions.pop(int(sid), None)
            self._announced.discard(int(sid))
        if session:
            session.kill()
            return True
        return False
