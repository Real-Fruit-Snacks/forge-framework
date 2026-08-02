"""Boilerplate generation for new modules (`template` console command).

Uses string.Template so the generated code's f-strings/braces pass
through untouched. Placeholders: $class_name, $title.
"""

import re
from pathlib import Path
from string import Template

AUX_TEMPLATE = Template('''"""TODO: one-line summary of what this module does."""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString, OptInt, OptBool


class $class_name(AuxiliaryModule):
    name = "$title"
    description = """
        TODO: longer description -- what it does, when to use it, and what
        the output tells you.
    """
    authors = ["you"]
    # requirements = ["impacket"]  # third-party packages the console checks for

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        # self.options.add(OptInt("THREADS", default=10, description="..."))

    def run(self):
        rhosts = self.get_option("RHOSTS")
        self.print_status(f"Running against {rhosts}")
        # TODO: your logic here
        self.print_good("Done")
''')

EXPLOIT_TEMPLATE = Template('''"""TODO: one-line summary of the vulnerability this exploits."""

from core.module import ExploitModule
from core.options import OptAddress, OptPort


class $class_name(ExploitModule):
    name = "$title"
    description = """
        TODO: what this exploits, affected versions, and how it works.
    """
    authors = ["you"]
    # requirements = ["impacket"]  # third-party packages the console checks for
    references = []          # e.g. ["CVE-2024-1234", "https://..."]
    targets = ["Automatic"]

    def register_options(self):
        self.options.add(OptAddress("RHOST", required=True, description="Target host"))
        self.options.add(OptPort("RPORT", required=True, description="Target port"))

    def check(self):
        """Safe, non-destructive vulnerability check. Return True/False/None."""
        return None

    def run(self):
        rhost = self.get_option("RHOST")
        rport = self.get_option("RPORT")
        self.print_status(f"Exploiting {rhost}:{rport}")
        # TODO: exploitation logic
        # On success, hand the shell to the framework:
        #   session = self.framework.sessions.add(sock, info=f"{rhost}:{rport}")
        #   self.print_good(f"Session {session.id} opened")
        self.print_good("Done")
''')

PAYLOAD_TEMPLATE = Template('''"""TODO: one-line summary of the payload this generates."""

from core.module import PayloadModule
from core.options import OptAddress, OptPort


class $class_name(PayloadModule):
    name = "$title"
    description = """
        TODO: what the payload does and how to catch/deliver it.
    """
    authors = ["you"]
    # requirements = ["impacket"]  # third-party packages the console checks for

    def register_options(self):
        self.options.add(OptAddress("LHOST", required=True, description="Listen host"))
        self.options.add(OptPort("LPORT", default=4444, description="Listen port"))

    def generate(self):
        lhost = self.get_option("LHOST")
        lport = self.get_option("LPORT")
        # TODO: build and return the payload (string or bytes)
        return f"# payload for {lhost}:{lport}"
''')

TEMPLATES = {
    "auxiliary": AUX_TEMPLATE,
    "exploit": EXPLOIT_TEMPLATE,
    "payload": PAYLOAD_TEMPLATE,
}

_TYPE_DIRS = {"auxiliary": "auxiliary", "exploits": "exploit", "payloads": "payload"}


def _camelize(name):
    return "".join(part.capitalize() for part in re.split(r"[_\-\s]+", name) if part)


def create_template(modules_root, mod_path):
    """Write a boilerplate module file for mod_path like 'auxiliary/scanner/x'.

    Returns the Path written. Raises ValueError/FileExistsError on problems.
    """
    parts = mod_path.strip("/").split("/")
    if len(parts) < 2 or any(not p for p in parts):
        raise ValueError(
            "Path must look like <type>/<category>/<name>, "
            "e.g. auxiliary/scanner/my_scan"
        )
    raw_type = parts[0]
    if raw_type not in _TYPE_DIRS:
        raise ValueError(
            f"Unknown module type '{raw_type}' (use auxiliary, exploits, payloads)"
        )
    mtype = _TYPE_DIRS[raw_type]

    filename = parts[-1]
    if not re.fullmatch(r"[a-z0-9_]+", filename):
        raise ValueError("Module file name must be lowercase letters, digits, underscores")

    dest = Path(modules_root, *parts).with_suffix(".py")
    if dest.exists():
        raise FileExistsError(f"{dest} already exists")
    dest.parent.mkdir(parents=True, exist_ok=True)

    dest.write_text(TEMPLATES[mtype].substitute(
        class_name=_camelize(filename),
        title=filename.replace("_", " ").title(),
    ))
    return dest
