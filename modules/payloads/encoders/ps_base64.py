"""PowerShell -EncodedCommand wrapper (UTF-16LE base64).

The Windows twin of the sh base64 wrapper: `powershell -enc <b64>` expects
UTF-16LE-encoded input, a classic both for living-off-the-land delivery and
for forgetting the encoding and staring at gibberish errors.
"""

import base64

from core.module import PayloadModule
from core.options import OptString


def wrap_ps(command):
    """Wrap a command as `powershell -enc <utf16le-b64>`."""
    encoded = base64.b64encode(command.encode("utf-16-le")).decode()
    return f"powershell -enc {encoded}"


class PsBase64(PayloadModule):
    name = "PowerShell -EncodedCommand Wrapper"
    description = """
        Wraps a command for powershell -enc (UTF-16LE base64). A standard
        living-off-the-land move on Windows: keeps special characters out
        of cmd.exe's parsing and keywords away from naive filters. Be
        clear-eyed about it, though: the encoding hides intent from
        strings-matching, not from Defender.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptString("PAYLOAD", required=True,
                                   description="PowerShell command to wrap"))

    def generate(self):
        return wrap_ps(str(self.get_option("PAYLOAD")))
