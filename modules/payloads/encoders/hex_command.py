"""Hex-encode a shell command for delivery through byte-sensitive channels.

Like base64_command, but the alphabet is only [0-9a-f] plus the fixed
decoder wrapper. Useful when the target decoder is `xxd` or when the
command channel cannot tolerate the base64 alphabet.
"""

from core.module import PayloadModule
from core.options import OptString


def wrap_hex(command):
    """Wrap a shell command as echo <hex> | xxd -r -p | sh."""
    encoded = command.encode().hex()
    return f"echo {encoded} | xxd -r -p | sh"


class HexCommand(PayloadModule):
    name = "Hex Command Wrapper (sh)"
    description = """
        Wraps any shell command as echo <hex> | xxd -r -p | sh. The output
        uses only hex digits plus the fixed wrapper, so it survives channels
        that cannot carry the base64 alphabet (or that strip '+', '/', '=').
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptString("PAYLOAD", required=True,
                                   description="Shell command to wrap"))

    def generate(self):
        return wrap_hex(str(self.get_option("PAYLOAD")))
