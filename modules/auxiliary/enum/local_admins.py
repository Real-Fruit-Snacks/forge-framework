"""Local Administrators membership via SAMR (Maelstrom's local_groups).

The question that decides lateral movement: WHO is local admin here?
The answer lives in the target's own SAM database, in the Builtin
Administrators alias — readable over SAMR with sufficient rights
(usually admin, sometimes any authenticated user on lax builds).
Domain groups nested inside local admins are the real prize: they're
the org's admin model, and the accounts to phish first.

SIDs come back from the alias; they're resolved to names over the same
SAMR connection (against the local SAM and, for domain SIDs, the
domain). Collated into the store (loot).
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.dcerpc.v5 import samr, transport
    from impacket.smbconnection import SMBConnection
except ImportError:
    samr = transport = SMBConnection = None  # console gates run()

ADMINISTRATORS_RID = 544


def dce_rpc(smb_conn, pipe, uuid):
    """DCE/RPC over the existing SMB session (named pipe)."""
    rpc = transport.DCERPCTransportFactory(
        f"ncacn_np:{smb_conn.getRemoteHost()}[{pipe}]")
    rpc.set_smb_connection(smb_conn)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(uuid)
    return dce


class LocalAdmins(AuxiliaryModule):
    name = "Local Administrators via SAMR"
    description = """
        Lists the Builtin Administrators alias on a Windows host: direct
        members and nested domain groups — the org's admin model and the
        best phishing/lateral targets. Usually needs admin rights on the
        target; a clean error says so. Collated into the store (loot).
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Windows host(s), comma-separated"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Username (usually needs admin)"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))
        self.options.add(OptString("DOMAIN", default="",
                                   description="Domain (blank = local account)"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))

    def run(self):
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        domain = str(self.get_option("DOMAIN") or "")
        port = int(self.get_option("RPORT"))
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._enum(host, port, domain, user, password)

    def _enum(self, host, port, domain, user, password):
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=30)
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}:{port}: SMB login failed - {e}")
            return
        try:
            dce = dce_rpc(conn, "\\pipe\\samr", samr.MSRPC_UUID_SAMR)
            server_handle = samr.hSamrConnect(dce)['ServerHandle']
            builtin = samr.hSamrLookupDomainInSamServer(
                dce, server_handle, "Builtin")['DomainId']
            domain_handle = samr.hSamrOpenDomain(
                dce, server_handle, domainId=builtin)['DomainHandle']
            alias_handle = samr.hSamrOpenAlias(
                dce, domain_handle, aliasId=ADMINISTRATORS_RID)['AliasHandle']
            members = samr.hSamrGetMembersInAlias(dce, alias_handle)
            rids = members['Members']['Sids']
            names = self._resolve(dce, domain_handle, rids)
        except Exception as e:
            self.print_error(f"{host}: alias read failed "
                             "(needs local admin?) - " + str(e).split("\n")[0])
            conn.close()
            return
        conn.close()

        self.print_good(f"{host}: {len(names)} member(s) of local Administrators")
        store = getattr(self.framework, "store", None)
        for name in names:
            self.print_line(f"    {name}")
        if store is not None:
            store.add_loot("local-admins", f"Administrators @ {host}",
                           "\n".join(names), address=host)

    def _resolve(self, dce, domain_handle, rids):
        """Alias member SIDs -> display names, best effort per SID."""
        names = []
        for sid_record in rids:
            sid = sid_record['SidPointer']
            sid_str = sid.formatCanonical()
            try:
                # the alias itself is in Builtin; member SIDs resolve
                # against the machine's own domain handles
                resp = samr.hSamrLookupIdsInDomain(
                    dce, domain_handle, [sid_record['RelativeId']])
                names.append(resp['Names']['Names'][0]['Name'])
            except Exception:
                names.append(sid_str)
        return names
