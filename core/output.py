"""Console output: msf-style tags in the Terminal Workbench palette.

Palette from https://github.com/Real-Fruit-Snacks/terminal-workbench-suite
(dark mode), emitted as 24-bit truecolor escapes. Philosophy per the
theme: color is spent only on signal.

Honors the NO_COLOR convention and --no-color (sets color_enabled=False).

Background jobs capture this module's output per-thread: inside
`with output.capture(buf):` on a worker thread, everything printed here
lands in `buf` (a list of lines) instead of the terminal.
"""

import os
import re
import sys
import threading
from contextlib import contextmanager
from typing import Iterator, List, Optional, TextIO

# Terminal Workbench (dark) palette
ACCENT = "#63f2ab"      # mint  -- success, active elements
ACCENT_ALT = "#6bdcff"  # cyan  -- status / info
WARM = "#f0c674"        # amber -- warnings
RED = "#ff6e7a"         # errors
TEXT = "#dce4df"        # normal text
TEXT_SOFT = "#b4c3bd"   # table headers
TEXT_FAINT = "#63736f"  # rules / separators

RESET = "\033[0m"
BOLD = "\033[1m"

color_enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ

# Per-thread capture buffer; set by capture() on job threads.
_local = threading.local()

# Spool: everything written to the terminal is also logged here, ANSI-free
# (exam-evidence friendly). Captured job output is NOT spooled at capture
# time — it gets spooled when the user actually views it via `jobs -o`.
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
# broader CSI (colors, cursor moves, erase) for raw byte streams like shells
_ANSI_CSI_RE = re.compile(r"\033\[[0-9;?]*[A-Za-z]")
_spool: Optional[TextIO] = None


def set_spool(fileobj: Optional[TextIO]) -> None:
    """Start/stop spooling output to a file object. None stops."""
    global _spool
    _spool = fileobj


def spooling() -> bool:
    return _spool is not None


def spool_write(text: str) -> None:
    """Write raw text straight to the spool (ANSI-stripped), bypassing the
    terminal — for byte streams like session traffic that never pass
    through the print_* helpers."""
    if _spool is not None:
        _spool.write(_ANSI_CSI_RE.sub("", text))
        _spool.flush()


def _write(text: str) -> None:
    buf: Optional[List[str]] = getattr(_local, "buffer", None)
    if buf is not None:
        buf.append(text)
    else:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        if _spool is not None:
            _spool.write(_ANSI_RE.sub("", text) + "\n")
            _spool.flush()


@contextmanager
def capture(buffer: List[str]) -> Iterator[None]:
    """Route this thread's output lines into `buffer` instead of stdout."""
    old = getattr(_local, "buffer", None)
    _local.buffer = buffer
    try:
        yield
    finally:
        _local.buffer = old


def _fg(hex_color: str) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"\033[38;2;{r};{g};{b}m"


def style(text: str, color: Optional[str] = None, bold: bool = False) -> str:
    """Wrap text in palette color/bold; returns text unchanged if no color."""
    if not color_enabled:
        return text
    prefix = (BOLD if bold else "") + (_fg(color) if color else "")
    return f"{prefix}{text}{RESET}" if prefix else text


def rl_style(text: str, color: str) -> str:
    """style() for readline prompts: escapes wrapped in \\001..\\002 so
    readline doesn't count them toward line width."""
    if not color_enabled:
        return text
    return f"\001{_fg(color)}\002{text}\001{RESET}\002"


def _emit(tag: str, color: str, msg: object) -> None:
    _write(f"{style(tag, color)} {msg}")


def print_status(msg: object) -> None:
    _emit("[*]", ACCENT_ALT, msg)


def print_good(msg: object) -> None:
    _emit("[+]", ACCENT, msg)


def print_error(msg: object) -> None:
    _emit("[-]", RED, msg)


def print_warning(msg: object) -> None:
    _emit("[!]", WARM, msg)


def print_line(msg: object = "") -> None:
    _write(str(msg))
