"""WebClient (WebDAV) service check (Maelstrom's webdav).

The WebClient service is the quiet enabler of the nastiest relay
chains: when it's running, the machine will happily authenticate over
HTTP — and HTTP auth can be relayed to LDAP (no signing required) by
coercion attacks (PetitPotam, printer bug, and friends). WebClient is
off by default on servers, often ON on workstations, and every running
instance is a relay vector worth noting.

The check is a plain service query over svcctl (SCMR): exists?
running? Collated into the store (loot).
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.dcerpc.v5 import scmr, transport
    from impacket.smbconnection import SMBConnection
except ImportError:
    scmr = transport = SMBConnection = None  # console gates run()

SERVICE_NAME = "WebClient"
# scmr.hRQueryServiceStatus dwCurrentState values
STATES = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
          4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING",
          7: "PAUSED"}


def dce_rpc(smb_conn, pipe, uuid):
    """DCE/RPC over the existing SMB session (named pipe)."""
    rpc = transport.DCERPCTransportFactory(
        f"ncacn_np:{smb_conn.getRemoteHost()}[{pipe}]")
    rpc.set_smb_connection(smb_conn)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(uuid)
    return dce


class WebdavCheck(AuxiliaryModule):
    name = "WebClient (WebDAV) Service Check"
    description = """
        Queries the WebClient service via SCMR: running WebClient means
        the host will authenticate over HTTP, enabling NTLM relay to
        LDAP via coercion chains. Collated into the store (loot).
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Windows host(s), comma-separated"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Username (may need admin)"))
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
            self._check(host, port, domain, user, password)

    def _check(self, host, port, domain, user, password):
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=30)
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}:{port}: SMB login failed - {e}")
            return
        try:
            dce = dce_rpc(conn, "\\pipe\\svcctl", scmr.MSRPC_UUID_SCMR)
            manager = scmr.hROpenSCManagerW(dce)['lpScHandle']
            service = scmr.hROpenServiceW(dce, manager, SERVICE_NAME)['lpScHandle']
            status = scmr.hRQueryServiceStatus(dce, service)
            state = status['lpServiceStatus']['dwCurrentState']
            state_text = STATES.get(state, str(state))
        except Exception as e:
            self.print_error(f"{host}: service query failed "
                             "(needs admin? WebClient absent?) - "
                             + str(e).split("\n")[0])
            conn.close()
            return
        conn.close()

        if state_text == "RUNNING":
            self.print_good(f"{host}: WebClient RUNNING — relay-to-HTTP "
                            "vector present")
        else:
            self.print_status(f"{host}: WebClient {state_text}")
        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_loot("webdav", f"WebClient @ {host}", state_text,
                           address=host)
