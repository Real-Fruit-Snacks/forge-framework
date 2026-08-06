"""Badchar-aware command encoder.

Takes a shell command and a set of forbidden bytes, then picks the first
of the built-in encodings whose complete output avoids every forbidden
byte. If none can satisfy the constraint, generation fails loudly instead
of emitting output that would break the target parser.

The BADCHARS option accepts literal characters and \\xNN hex escapes, so
null, newline, space, carriage return, etc. are easy to express:

    set BADCHARS "\\x00\\x0a\\x0d"
"""

import base64
import re
import urllib.parse

from core.module import PayloadModule
from core.options import OptString


def _parse_badchars(value):
    """Return a set of forbidden byte values from a BADCHARS string."""
    if value is None:
        return set()
    text = str(value)
    bad = set()
    pos = 0
    while pos < len(text):
        if text[pos] == "\\" and pos + 3 < len(text) and text[pos + 1] == "x":
            try:
                bad.add(int(text[pos + 2:pos + 4], 16))
                pos += 4
                continue
            except ValueError:
                pass
        bad.add(ord(text[pos]))
        pos += 1
    return bad


def _is_clean(text, bad):
    """True when no byte in text is in the forbidden set."""
    return all(byte not in bad for byte in text.encode())


def _base64_encode(payload):
    encoded = base64.b64encode(payload.encode()).decode()
    return f"echo {encoded} | base64 -d | sh"


def _hex_encode(payload):
    encoded = payload.encode().hex()
    return f"echo {encoded} | xxd -r -p | sh"


def _url_encode(payload):
    encoded = urllib.parse.quote(payload, safe="")
    return (
        f"python3 -c 'import sys,urllib.parse;"
        f'print(urllib.parse.unquote(sys.stdin.read()),end="")\' '
        f"<<'__EOF__'\n{encoded}\n__EOF__\n| sh"
    )


# Ordered by preference: fastest/shortest first, fallback later.
_ENCODERS = [
    ("base64", _base64_encode),
    ("hex", _hex_encode),
    ("urlencode", _url_encode),
]


class Badchar(PayloadModule):
    name = "Badchar-Aware Command Encoder"
    description = """
        Wraps a shell command in an encoding whose output avoids the bytes
        listed in BADCHARS. Tries base64, hex, and urlencode in order and
        returns the first clean command. Fails loudly if every encoding
        would emit a forbidden byte.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptString("PAYLOAD", required=True,
                                   description="Shell command to wrap"))
        self.options.add(OptString("BADCHARS", required=True,
                                   description="Forbidden bytes: literal "
                                               "chars and/or \\\\xNN escapes"))

    def generate(self):
        payload = str(self.get_option("PAYLOAD"))
        bad = _parse_badchars(self.get_option("BADCHARS"))
        if not bad:
            # Nothing forbidden; still encode so the output is channel-safe.
            return _base64_encode(payload)
        for name, encoder in _ENCODERS:
            candidate = encoder(payload)
            if _is_clean(candidate, bad):
                return candidate
        forbidden = " ".join(f"\\x{b:02x}" for b in sorted(bad))
        raise ValueError(
            f"No built-in encoding avoids these bytes: {forbidden}")
