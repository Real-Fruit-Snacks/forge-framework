"""Debug logging to ~/.framework/logs/framework.log.

Separate from spool on purpose: spool is evidence you opt into; this is
the always-on black box for "why did my module die last Tuesday".
Registry load errors, job failures (with tracebacks), and console hook
exceptions land here. Nothing here is ever echoed to the terminal.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_logger = logging.getLogger("framework")
_logger.addHandler(logging.NullHandler())  # silent until setup()
_logger.propagate = False


def setup(home) -> None:
    """Point the logger at <home>/logs/framework.log (1MB x 3 rotations)."""
    log_dir = Path(home) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        log_dir / "framework.log", maxBytes=1024 * 1024, backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"
    ))
    _logger.addHandler(handler)
    _logger.setLevel(logging.DEBUG)  # file gets everything; console filters


def get() -> logging.Logger:
    return _logger
