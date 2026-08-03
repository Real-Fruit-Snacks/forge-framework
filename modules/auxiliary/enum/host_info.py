"""Host fingerprinting: OS version and disks (Maelstrom's os_info + disks).

First contact with a Windows host should answer two things: what is it
(exact OS build — tells you the patch level and which privescs apply)
and what's attached (disk letters — where to dig). OS version comes
free with any SMB session negotiation (no admin, not even a valid user
if null sessions live); the disk list is one SRVSVC call.

Lateral-movement hygiene note: OS strings and disk inventories are
exactly the kind of thing that ends up in engagement reports, so
they're collated into the store (loot), not just printed.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.dcerpc.v5 import srvs, transport
    from impacket.smbconnection import SMBConnection
except ImportError:
    srvs = transport = SMBConnection = None  # console gates run()


def dce_rpc(smb_conn, pipe, uuid):
    """DCE/RPC over the existing SMB session (named pipe)."""
    rpc = transport.DCERPCTransportFactory(
        f"ncacn_np:{smb_conn.getRemoteHost()}[{pipe}]")
    rpc.set_smb_connection(smb_conn)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(uuid)
    return dce


def os_version(conn):
    """'10.0.22621 build 22621' style version from the SMB negotiation."""
    major = conn.getServerOSMajor()
    minor = conn.getServerOSMinor()
    build = conn.getServerOSBuild()
    return f"{major}.{minor}.{build}" if major is not None else conn.getServerOS()


class HostInfo(AuxiliaryModule):
    name = "Windows Host Info (OS + disks)"
    description = """
        Fingerprints a Windows host over SMB: exact OS build (free with
        the session negotiation), machine/domain names, and attached
        disks via SRVSVC NetrServerDiskEnum. Collated into the store
        (loot).
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Windows host(s), comma-separated"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username (blank = null session)"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
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
            self._info(host, port, domain, user, password)

    def _info(self, host, port, domain, user, password):
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=30)
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}:{port}: SMB login failed - {e}")
            return

        store = getattr(self.framework, "store", None)
        version = os_version(conn)
        name = conn.getServerName()
        dns = conn.getServerDNSHostName()
        workgroup = conn.getServerDomain()
        self.print_good(f"{host}:{port}: {name} ({dns}) — Windows {version}, "
                        f"domain/workgroup {workgroup}")
        self.print_debug(f"{host}: OS string: {conn.getServerOS()}")
        if store is not None:
            store.add_service(host, port, name="smb",
                              info=f"Windows {version} {dns}")
            store.add_host(host, name=dns or name)

        try:
            dce = dce_rpc(conn, "\\pipe\\srvsvc", srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrServerDiskEnum(dce, 0)
            disks = [disk.rstrip("\x00") for disk in
                     resp['DiskInfoStruct']['Buffer'][0]['Disk']]
            self.print_status(f"{host}: disks: {', '.join(disks)}")
            if store is not None:
                store.add_loot("host-info", f"{name} @ {host}",
                               f"{name}\tWindows {version}\t{workgroup}\t"
                               f"disks: {', '.join(disks)}", address=host)
        except Exception as e:
            self.print_error(f"{host}: disk enum failed - {e}")
        conn.close()
