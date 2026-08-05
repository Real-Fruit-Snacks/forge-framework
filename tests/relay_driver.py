"""In-container driver for the relay_smb e2e: runs the real module
through a FrameworkConsole on the lab network and prints everything.

Containers can't reach host sockets through the desktop firewall, so
the relay has to live IN the network like a real drop box would. This
runs in the forge-relay-test image (impacket installed), repo mounted
read-only at /forge. FORGE_RELAY_DEBUG=1 turns impacket's LOG on.

Usage: python /forge/tests/relay_driver.py <dc_ip> <source> <timeout>
"""

import io
import os
import sys

sys.path.insert(0, "/forge")

if os.environ.get("FORGE_RELAY_DEBUG"):
    import logging
    logging.basicConfig(level=logging.INFO,
                        format="%(name)s %(levelname)s %(message)s")

from core import output  # noqa: E402
from core.console import FrameworkConsole  # noqa: E402
from core.registry import ModuleRegistry  # noqa: E402
from core.store import Store  # noqa: E402
from pathlib import Path  # noqa: E402

output.color_enabled = False

dc_ip, source, timeout = sys.argv[1], sys.argv[2], sys.argv[3]

registry = ModuleRegistry(Path("/forge/modules"))
registry.load()
console = FrameworkConsole(registry, Store(":memory:"))
buf = io.StringIO()
import contextlib  # noqa: E402

with contextlib.redirect_stdout(buf):
    for command in (
        "use auxiliary/attack/relay_smb",
        f"set RHOSTS {dc_ip}",
        "set LPORT 445",
        f"set SOURCE {source}",
        f"set TIMEOUT {timeout}",
        "run",
    ):
        console.onecmd(command)
print(buf.getvalue(), flush=True)
console.store.close()
