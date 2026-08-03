"""Session and logon enumeration (Maelstrom's sessions + loggedon).

Who is on this box right now? Two views:
  - SMB sessions (SRVSVC NetrSessionEnum): remote users with an open
    session — where the admins are coming FROM, and whose machine is
    worth owning next.
  - Interactive logons (WKSSVC NetrWkstaUserEnum): users logged on at
    the console — whose creds might be in memory.

Both answers drive targeting: compromise the admin's SOURCE host, not
the server they're on. Both calls typically need local admin on modern
Windows — the module says so plainly instead of dying.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.dcerpc.v5 import srvs, transport, wkst
    from impacket.smbconnection import SMBConnection
except ImportError:
    srvs = transport = wkst = SMBConnection = None  # console gates run()


def dce_rpc(smb_conn, pipe, uuid):
    """DCE/RPC over the existing SMB session (named pipe)."""
    rpc = transport.DCERPCTransportFactory(
        f"ncacn_np:{smb_conn.getRemoteHost()}[{pipe}]")
    rpc.set_smb_connection(smb_conn)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(uuid)
    return dce


class HostSessions(AuxiliaryModule):
    name = "Windows Session + Logon Enumeration"
    description = """
        Lists active SMB sessions (NetrSessionEnum) and console logons
        (NetrWkstaUserEnum) on a Windows host: who's connected and from
        where. Usually needs local admin on the target — a clean error
        says so. Collated into the store (loot).
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
        store = getattr(self.framework, "store", None)
        loot_lines = []
        self._sessions(conn, host, loot_lines)
        self._logons(conn, host, loot_lines)
        if store is not None and loot_lines:
            store.add_loot("host-sessions", f"sessions @ {host}",
                           "\n".join(loot_lines), address=host)
        conn.close()

    def _sessions(self, conn, host, loot_lines):
        try:
            dce = dce_rpc(conn, "\\pipe\\srvsvc", srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrSessionEnum(dce, NULL_NAME, NULL_NAME, 10)
        except Exception as e:
            self.print_error(f"{host}: session enum failed "
                             "(needs local admin?) - " + str(e).split("\n")[0])
            return
        sessions = resp['InfoStruct']['SessionInfo10']['Buffer']
        if not sessions:
            self.print_status(f"{host}: no active SMB sessions")
            return
        self.print_good(f"{host}: {len(sessions)} SMB session(s)")
        for entry in sessions:
            line = f"    {entry['sesi10_username']} from {entry['sesi10_cname']}"
            self.print_line(line)
            loot_lines.append(line.strip())

    def _logons(self, conn, host, loot_lines):
        try:
            dce = dce_rpc(conn, "\\pipe\\wkssvc", wkst.MSRPC_UUID_WKST)
            resp = wkst.hNetrWkstaUserEnum(dce, 1)
        except Exception as e:
            self.print_error(f"{host}: logon enum failed "
                             "(needs local admin?) - " + str(e).split("\n")[0])
            return
        users = resp['UserInfo']['WkstaUserInfoLevel1']['Buffer']
        if not users:
            self.print_status(f"{host}: no console logons")
            return
        self.print_good(f"{host}: {len(users)} console logon(s)")
        for entry in users:
            line = (f"    {entry['wkui1_logon_domain']}\\{entry['wkui1_username']}"
                    f" (via {entry['wkui1_logon_server']})")
            self.print_line(line)
            loot_lines.append(line.strip())


# hNetrSessionEnum takes client/user filter names; NULL name = all
NULL_NAME = "\x00"
