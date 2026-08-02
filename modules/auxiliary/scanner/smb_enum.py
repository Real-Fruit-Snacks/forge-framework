"""SMB share and security enumeration via impacket.

What to look for and why (the point of running this by hand):

  - Server OS string: fingerprints the target family before you pick an
    exploit path.
  - Signing disabled: SMB without signing is relay-attack territory
    (ntlmrelayx) — one of the highest-value findings on a Windows network.
  - Null sessions (blank USERNAME/PASSWORD): if the server answers and
    lists shares with no creds, that's a finding on its own.
  - Readable shares: where the interesting files live. IPC$ is noise;
    everything else deserves a look.

Requires impacket (lazy import; console gates run on it). Test it against
the smb lab: lab up smb, RPORT 10445, try blank creds then labuser:labpass.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.smb3 import SMB2_DIALECT_21
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None  # console gates run() on requirements

NOISY_SHARES = {"IPC$", "ADMIN$", "C$"}


def server_signing_required(host, port, timeout=5):
    """Read the SERVER's signing policy from the SMB2 negotiate response.

    Gotcha worth knowing: impacket's isSigningRequired() on an SMB 3.1.1
    connection always returns True — impacket forces signing client-side
    for the pre-auth hash, which says nothing about server policy. So we
    negotiate 2.x dialects explicitly and read the server's SecurityMode.
    """
    conn = SMBConnection(host, host, sess_port=port, timeout=timeout,
                         preferredDialect=SMB2_DIALECT_21)
    try:
        return conn.isSigningRequired()
    finally:
        conn.close()


class SmbEnum(AuxiliaryModule):
    name = "SMB Share & Security Enumeration"
    description = """
        Enumerates an SMB server: OS string, whether signing is required
        (relay-attack surface), and the share list with per-share read
        access. Works with a null session (blank creds) or credentials.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username (blank = null session)"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
        self.options.add(OptString("DOMAIN", default="", description="Domain"))

    def run(self):
        port = self.get_option("RPORT")
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        domain = str(self.get_option("DOMAIN") or "")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._enum(host, port, user, password, domain)

    def _enum(self, host, port, user, password, domain):
        try:
            signing = server_signing_required(host, port)
        except Exception as e:
            self.print_error(f"{host}:{port} - {e}")
            return
        if signing:
            self.print_status(f"{host}: SMB signing required")
        else:
            self.print_good(
                f"{host}: SMB signing NOT required -- relay attacks possible"
            )

        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=5)
        except Exception as e:
            self.print_error(f"{host}:{port} - {e}")
            return

        try:
            os_info = conn.getServerOS() or "(OS string not reported)"
            self.print_good(f"{host}: {os_info}")

            who = user or "<null session>"
            try:
                conn.login(user, password, domain)
            except Exception as e:
                self.print_error(f"{host}: login as {who} failed - {e}")
                return
            self.print_status(f"{host}: authenticated as {who}")

            readable = []
            try:
                shares = conn.listShares()
            except Exception as e:
                self.print_error(f"{host}: share listing failed - {e}")
                return
            for share in shares:
                name = share["shi1_netname"][:-1]  # null-terminated
                access = self._read_access(conn, name)
                tag = "READ" if access else "    "
                noise = " (standard)" if name in NOISY_SHARES else ""
                self.print_line(f"    [{tag}] {name}{noise}")
                if access and name not in NOISY_SHARES:
                    readable.append(name)

            store = getattr(self.framework, "store", None)
            if store is not None:
                store.add_service(host, port, name="smb", info=os_info)
                if readable:
                    content = "\n".join(readable)
                    store.add_loot("smb-shares", f"readable shares {host}",
                                   content, address=host)
        finally:
            conn.close()

    @staticmethod
    def _read_access(conn, share):
        try:
            conn.connectTree(share)
            return True
        except Exception:
            return False
