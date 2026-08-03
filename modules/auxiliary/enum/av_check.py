"""Antivirus product detection via service state (Maelstrom's av).

The canonical AV check is a WMI query (root\\SecurityCenter2), but WMI
is DCOM — 135 plus a dynamic RPC range, which is exactly what NAT'd
targets (like our docker labs) don't expose. The same recon answer —
"what's defending this box, and is it running?" — is available over
the transport we already have: svcctl service queries. Defender is
WinDefend; the common enterprise agents all have well-known service
names.

Running AV dictates the tradecraft budget for everything that follows
on that host. Findings are collated into the store (loot).
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.dcerpc.v5 import scmr, transport
    from impacket.smbconnection import SMBConnection
except ImportError:
    scmr = transport = SMBConnection = None  # console gates run()

# service name -> product
AV_SERVICES = {
    "WinDefend": "Microsoft Defender",
    "WdNisSvc": "Defender Network Inspection",
    "Sense": "Defender for Endpoint",
    "MBAMService": "Malwarebytes",
    "SentinelAgent": "SentinelOne",
    "CSFalconService": "CrowdStrike Falcon",
    "ekrn": "ESET",
    "AvastSvc": "Avast",
    "AVGSvc": "AVG",
    "SAVService": "Sophos",
    "cyserver": "Cybereason",
    "CylanceSvc": "Cylance",
    "TaniumClient": "Tanium",
    "cb": "Carbon Black",
}

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


class AvCheck(AuxiliaryModule):
    name = "AV Detection via Service State (SCMR)"
    description = """
        Identifies antivirus/EDR on a Windows host by querying
        well-known service names over SCMR (Defender, CrowdStrike,
        SentinelOne, ...). Works over SMB 445 — no DCOM/WMI needed, so
        it survives NAT'd targets. Collated into the store (loot).
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
        store = getattr(self.framework, "store", None)
        try:
            dce = dce_rpc(conn, "\\pipe\\svcctl", scmr.MSRPC_UUID_SCMR)
            manager = scmr.hROpenSCManagerW(
                dce, dwDesiredAccess=scmr.SC_MANAGER_ENUMERATE_SERVICE)['lpScHandle']
            # enumerate once and match names — opening a hardened AV
            # service directly gets refused even for admins (Defender's
            # DACL), and one denial shouldn't sink the whole check
            found = []
            services = scmr.hREnumServicesStatusW(dce, manager)
            for service in services:
                # impacket's reparsed WIDESTR keeps the null terminator
                name = service['lpServiceName'].rstrip('\x00')
                if name in AV_SERVICES:
                    state = service['ServiceStatus']['dwCurrentState']
                    found.append((AV_SERVICES[name],
                                  STATES.get(state, str(state))))
        except Exception as e:
            self.print_error(f"{host}: SCMR failed (needs admin?) - "
                             + str(e).split("\n")[0])
            conn.close()
            return
        conn.close()

        if not found:
            self.print_status(f"{host}: no known AV services found")
            return
        loot_lines = []
        for product, state in found:
            line = f"{product}: {state}"
            if state == "RUNNING":
                self.print_good(f"{host}: {line}")
            else:
                self.print_status(f"{host}: {line}")
            loot_lines.append(line)
        if store is not None:
            store.add_loot("av-check", f"AV services @ {host}",
                           "\n".join(loot_lines), address=host)
