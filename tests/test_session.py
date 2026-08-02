"""Session tests, including a real pty upgrade against a live /bin/sh.

Run: python3 -m unittest discover -s tests
"""

import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.session import Session  # noqa: E402


def read_until(session, marker, timeout=5.0):
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline and marker.encode() not in buf:
        try:
            chunk = session.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace")


@unittest.skipUnless(shutil.which("sh"), "needs /bin/sh")
class TestPtyUpgrade(unittest.TestCase):
    def _shell_socket(self):
        """A socket with /bin/sh attached to the far end — a dumb shell."""
        local, remote = socket.socketpair()
        proc = subprocess.Popen(
            ["sh"],
            stdin=remote.fileno(), stdout=remote.fileno(), stderr=remote.fileno(),
            close_fds=True,
        )
        remote.close()
        return local, proc

    def test_upgrade_to_pty(self):
        sock, proc = self._shell_socket()
        try:
            sock.settimeout(5)
            session = Session(1, sock, "test")

            session.send("tty\n")
            before = read_until(session, "not a tty")
            self.assertIn("not a tty", before)

            session.upgrade_to_pty()
            time.sleep(0.5)  # let the pty spawn settle
            self.assertTrue(session.pty)

            session.send("tty\n")
            after = read_until(session, "/dev/pts")
            self.assertIn("/dev/pts", after)
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            sock.close()


class TestSyncSize(unittest.TestCase):
    def test_sync_size_sends_stty_command(self):
        local, remote = socket.socketpair()
        try:
            session = Session(1, local, "test")
            # os.terminal_size takes (columns, lines)
            session._sync_size(os.terminal_size((120, 40)))
            remote.settimeout(2)
            self.assertEqual(remote.recv(64).decode(), " stty rows 40 cols 120\n")
        finally:
            local.close()
            remote.close()


class TestInteractSpoolTee(unittest.TestCase):
    """Session traffic lands in the spool (line-mode interact, piped stdin)."""

    def test_line_interact_tees_remote_output(self):
        import io
        import contextlib
        from core import output

        local, remote = socket.socketpair()
        # piped stdin so interact sees line-mode and 'background' detaches
        stdin_r, stdin_w = os.pipe()
        real_stdin = sys.stdin
        spool = io.StringIO()
        try:
            session = Session(1, local, "test")
            output.set_spool(spool)
            remote.sendall(b"uid=0(root) shell-output\n")
            os.write(stdin_w, b"background\n")
            sys.stdin = os.fdopen(stdin_r)
            with contextlib.redirect_stdout(io.StringIO()):
                session._interact_lines()
        finally:
            sys.stdin = real_stdin
            output.set_spool(None)
            os.close(stdin_w)
            local.close()
            remote.close()
        self.assertIn("uid=0(root) shell-output", spool.getvalue())


if __name__ == "__main__":
    unittest.main()
