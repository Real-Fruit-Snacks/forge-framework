"""Share spidering: walk SMB shares for interesting files (Maelstrom's spider).

Bulk file-share triage. Every org has a share somewhere holding
unattend.xml (local admin password in cleartext), web.config (connection
strings with credentials), id_rsa, or someone's passwords.xlsx — and
nobody finds them by hand because nobody looks. The module enumerates
shares (or takes a list), walks each to a bounded depth, and flags
filenames matching the interesting-file patterns.

Listing only, no downloads — the point is a triage list, not exfil.
Matches are collated into the store (loot).
"""

import re

from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptPort, OptString

try:
    from impacket.dcerpc.v5 import srvs, transport
    from impacket.smbconnection import SMBConnection
except ImportError:
    srvs = transport = SMBConnection = None  # console gates run()

# the classics — connection strings, keys, passwords, deploy leftovers
INTERESTING = [
    r"^unattend.*\.xml$", r"^web\.config$", r"^wp-config\.php$",
    r"^id_rsa.*$", r"^id_ed25519.*$", r".*\.ppk$", r".*\.kdbx$",
    r"^passwords?.*$", r"^credentials?\..*$", r"^secrets?\..*$",
    r"^\.env.*$", r"^grafana\.ini$", r"^ntds\.dit$",
]
INTERESTING_RE = [re.compile(p, re.IGNORECASE) for p in INTERESTING]

SKIP_SHARES = {"IPC$", "print$", "NETLOGON", "SYSVOL"}


def is_interesting(filename):
    """Filename (no path) worth flagging during a spider walk."""
    return any(pattern.match(filename) for pattern in INTERESTING_RE)


def dce_rpc(smb_conn, pipe, uuid):
    """DCE/RPC over the existing SMB session (named pipe)."""
    rpc = transport.DCERPCTransportFactory(
        f"ncacn_np:{smb_conn.getRemoteHost()}[{pipe}]")
    rpc.set_smb_connection(smb_conn)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(uuid)
    return dce


class ShareSpider(AuxiliaryModule):
    name = "SMB Share Spider"
    description = """
        Walks SMB shares for interesting files (web.config, unattend.xml,
        id_rsa, passwords.*, .env, ...). Shares are enumerated via SRVSVC
        or given explicitly in SHARES. Listing only — a triage list,
        collated into the store (loot).
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username (blank = null session)"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
        self.options.add(OptString("DOMAIN", default="",
                                   description="Domain (blank = local account)"))
        self.options.add(OptString("SHARES", default="",
                                   description="Shares, comma-separated "
                                               "(blank = enumerate)"))
        self.options.add(OptInt("MAXDEPTH", default=3,
                                description="Directory recursion depth"))

    def run(self):
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        domain = str(self.get_option("DOMAIN") or "")
        shares = [s.strip() for s in str(self.get_option("SHARES") or "").split(",")
                  if s.strip()]
        port = int(self.get_option("RPORT"))
        depth = int(self.get_option("MAXDEPTH"))
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._spider(host, port, domain, user, password, shares, depth)

    def _spider(self, host, port, domain, user, password, shares, depth):
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=30)
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}:{port}: SMB login failed - {e}")
            return
        if not shares:
            shares = self._shares(conn, host)
        store = getattr(self.framework, "store", None)
        loot_lines = []
        for share in shares:
            if share in SKIP_SHARES:
                continue
            loot_lines.extend(self._walk(conn, host, share, "", 0, depth))
        if store is not None and loot_lines:
            store.add_loot("spider", f"interesting files @ {host}",
                           "\n".join(loot_lines), address=host)
        conn.close()

    def _shares(self, conn, host):
        try:
            dce = dce_rpc(conn, "\\pipe\\srvsvc", srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareEnum(dce, 1)
            return [entry['shi1_netname'].rstrip("\x00")
                    for entry in resp['InfoStruct']['ShareInfo']['Level1']['Buffer']]
        except Exception as e:
            self.print_error(f"{host}: share enum failed - {e}")
            return []

    def _walk(self, conn, host, share, path, level, depth):
        """Yield interesting-file lines, recursing to MAXDEPTH."""
        if level > depth:
            return
        try:
            entries = conn.listPath(share, f"{path}\\*" if path else "\\*")
        except Exception as e:
            self.print_debug(f"{host}: {share}:{path or '/'}: {e}")
            return
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            full = f"{path}\\{name}" if path else name
            if entry.is_directory():
                yield from self._walk(conn, host, share, full, level + 1, depth)
            elif is_interesting(name):
                line = f"{share}\\{full}"
                self.print_good(f"{host}: {line}")
                yield line
