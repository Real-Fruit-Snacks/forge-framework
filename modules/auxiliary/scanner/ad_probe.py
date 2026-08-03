"""Unauthenticated AD target profiler: one module, the whole first look.

Before any credential exists, a domain controller (or member) tells you
an astonishing amount. This module runs the full unauthenticated sweep
and collates it:

  SMB      — dialects (SMB1 alive?), signing required (relay surface),
             OS version, DNS domain + host names from the NTLM blob
  RPC      — endpoint-mapper dump (Windows) or per-interface ept_map
             probes (Samba refuses ept_lookup) annotated with the
             coercion table: PrinterBug (RPRN), PetitPotam (EFSR),
             ShadowCoerce (FSRVP), DFSCoerce (DFSNM), PrintNightmare
             (PAR); DRSUAPI presence = DCSync channel
  LDAP     — naming contexts, domain functionality level, SASL mechs,
             signing posture, and clock skew (rootDSE currentTime vs
             local — skew > 5 min breaks Kerberos)
  KERBEROS — one AS-REQ for a deliberately nonexistent principal: any
             KRB-ERROR proves the KDC. On Windows the error's realm
             field is authoritative (hintless discovery); Samba echoes
             your hint back, so there the probe CONFIRMS a hinted realm
             (C_PRINCIPAL_UNKNOWN = right realm) and discovery falls to
             the SMB/LDAP probes. No preauth sent — no account state
             touched
  ADCS     — GET /certsrv/: 401 with an NTLM challenge = web enrollment
             (ESC8 relay target); anonymous 200 is worse

Everything lands in loot as one profile per host.
"""

import datetime
import http.client
import socket
import time

from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptPort, OptString

try:
    from impacket.dcerpc.v5 import epm, transport
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import KRB_ERROR
    from impacket.krb5.kerberosv5 import KerberosError, sendReceive
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
    from impacket.smb import SMB_DIALECT
    from impacket.smb3structs import SMB2_DIALECT_21
    from impacket.smbconnection import SMBConnection
    from impacket.uuid import uuidtup_to_bin
    from pyasn1.codec.der import decoder
except ImportError:
    epm = None  # console gates run() on requirements

# well-known RPC interfaces: uuid -> (name, coercion hint, version)
WELL_KNOWN_RPC = {
    "12345778-1234-abcd-ef00-0123456789ac": ("SAMR", None, "1.0"),
    "12345778-1234-abcd-ef00-0123456789ab": ("LSARPC", None, "0.0"),
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2": ("DRSUAPI", "DCSync channel", "4.0"),
    "367abb81-9844-35f1-ad32-98f038001003": ("SCMR", "service exec", "2.0"),
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": ("SRVSVC", None, "3.0"),
    "6bffd098-a112-3610-9833-46c3f87e345a": ("WKSSVC", None, "1.0"),
    "12345678-1234-abcd-ef00-01234567cffb": ("NRPC", "netlogon", "1.0"),
    "338cd001-2244-31f1-aaaa-900038001003": ("RRP", "remote registry", "1.0"),
    "82273fdc-e32a-18c3-3f78-827929dc23ea": ("EVEN", "eventlog", "0.0"),
    "86d35949-83c9-4044-b424-db363231fd0c": ("TSCH", "task exec", "1.0"),
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": ("EPM", None, "3.0"),
    "12345678-1234-abcd-ef00-0123456789ab": ("RPRN", "PrinterBug", "1.0"),
    "c681d488-d850-11d0-8c52-00c04fd90f7e": ("EFSR", "PetitPotam", "0.0"),
    "df1941c5-fe89-4e79-bf10-463657acf44d": ("EFSR", "PetitPotam", "1.0"),
    "a8e0653c-2744-4389-a61d-7373df8b2292": ("FSRVP", "ShadowCoerce", "1.0"),
    "4fc742e0-4a10-11cf-8273-00aa004ae673": ("DFSNM", "DFSCoerce", "3.0"),
    "ae33069b-a2a8-46ee-a235-ddfd339be281": ("PAR", "PrintNightmare", "0.0"),
    "76f03f96-cdfd-44fc-a22c-64950a001209": ("PAR", "PrintNightmare", "0.0"),
}

DIALECT_NAMES = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0",
                 0x0302: "3.0.2", 0x0311: "3.1.1"}

# canonical named pipes per interface (DRSUAPI is TCP-only — no pipe)
CANONICAL_PIPES = {
    "12345778-1234-abcd-ef00-0123456789ac": r"\samr",
    "12345778-1234-abcd-ef00-0123456789ab": r"\lsarpc",
    "367abb81-9844-35f1-ad32-98f038001003": r"\svcctl",
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": r"\srvsvc",
    "6bffd098-a112-3610-9833-46c3f87e345a": r"\wkssvc",
    "12345678-1234-abcd-ef00-01234567cffb": r"\netlogon",
    "338cd001-2244-31f1-aaaa-900038001003": r"\winreg",
    "82273fdc-e32a-18c3-3f78-827929dc23ea": r"\eventlog",
    "86d35949-83c9-4044-b424-db363231fd0c": r"\atsvc",
    "12345678-1234-abcd-ef00-0123456789ab": r"\spoolss",
    "c681d488-d850-11d0-8c52-00c04fd90f7e": r"\efsrpc",
    "df1941c5-fe89-4e79-bf10-463657acf44d": r"\efsrpc",
    "a8e0653c-2744-4389-a61d-7373df8b2292": r"\FssagentRpc",
    "4fc742e0-4a10-11cf-8273-00aa004ae673": r"\netdfs",
    "ae33069b-a2a8-46ee-a235-ddfd339be281": r"\spoolss",
    "76f03f96-cdfd-44fc-a22c-64950a001209": r"\spoolss",
}

STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_ACCESS_DENIED = 0xC0000022

FUNC_LEVELS = {0: "2000", 1: "2003", 2: "2008", 3: "2008 R2",
               4: "2012", 5: "2012 R2", 6: "2016", 7: "2016/2019/2022"}


def annotate_rpc(uuid):
    """uuid -> 'NAME (hint)' or None when unknown."""
    entry = WELL_KNOWN_RPC.get(uuid.lower())
    if not entry:
        return None
    name, hint, _ver = entry
    return f"{name} ({hint})" if hint else name


class AdProbe(AuxiliaryModule):
    name = "AD Unauthenticated Profiler"
    description = """
        The full unauthenticated first look at an AD target: SMB dialects
        + signing + OS/domain names, RPC endpoint dump with coercion
        annotations (PrinterBug/PetitPotam/ShadowCoerce/DFSCoerce/
        PrintNightmare), LDAP posture + clock skew, KDC realm probe, and
        the /certsrv/ ESC8 check. No credentials needed; the KDC probe
        sends no preauth (zero account-state impact). Profile lands in
        loot.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))
        self.options.add(OptPort("RPC_PORT", default=135,
                                 description="Endpoint-mapper port"))
        self.options.add(OptString("DOMAIN", default="",
                                   description="Realm hint for the KDC probe AND "
                                               "auth domain for pipe binds "
                                               "(blank = local accounts)"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Creds for pipe-bind probing "
                                               "(hardened targets gate anonymous "
                                               "pipes)"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
        self.options.add(OptString("NTHASH", default="",
                                   description="NT hash, hex (overrides PASSWORD)"))
        self.options.add(OptInt("TIMEOUT", default=8, description="Per-probe timeout"))

    def run(self):
        port = int(self.get_option("RPORT"))
        timeout = int(self.get_option("TIMEOUT"))
        domain_hint = str(self.get_option("DOMAIN") or "").strip()
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            profile = {}
            profile.update(self._smb(host, port, timeout))
            profile.update(self._rpc(host, timeout))
            profile.update(self._ldap(host, timeout))
            profile.update(self._realm(host, domain_hint, timeout))
            profile.update(self._adcs(host, timeout))
            self._report(host, profile)

    # ------------------------------------------------------------- probes
    def _smb(self, host, port, timeout):
        out = {}
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=timeout,
                                 preferredDialect=SMB2_DIALECT_21)
            signing = conn.isSigningRequired()
            conn.close()
            out["signing"] = signing
        except Exception as e:
            self.print_debug(f"{host}: smb signing probe: {e}")
            out["signing"] = None
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
            # a session setup attempt populates the NTLM-derived fields
            # (OS version, DNS domain) — the result doesn't matter
            try:
                conn.login("", "")
            except Exception:
                pass
            parts = []
            os_name = conn.getServerOS()
            if os_name:
                parts.append(os_name)
            else:
                try:
                    major, minor, build = (conn.getServerOSMajor(),
                                           conn.getServerOSMinor(),
                                           conn.getServerOSBuild())
                    if major is not None:
                        parts.append(f"Windows {major}.{minor} build {build}")
                except Exception:
                    pass
            out["os"] = "; ".join(parts) or "?"
            out["dialect"] = DIALECT_NAMES.get(conn.getDialect(),
                                               f"0x{conn.getDialect():x}")
            out["dns_domain"] = conn.getServerDNSDomainName() or ""
            out["nb_name"] = conn.getServerName() or ""
            conn.close()
        except Exception as e:
            self.print_debug(f"{host}: smb fingerprint: {e}")
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=timeout,
                                 preferredDialect=SMB_DIALECT)
            try:
                conn.login("", "")
            except Exception:
                pass  # a failed SMB1 login still proves the dialect
            out["smb1"] = True
            conn.close()
        except Exception:
            out["smb1"] = False
        return out

    def _rpc(self, host, timeout):
        """Three tiers, honest about what each target allows:
        1. EPM dump (classic Windows)         — full interface list
        2. ept_map per-UUID (Samba: lookup    — presence per interface
           is unimplemented)
        3. direct UUID binds on canonical     — works on hardened 2022
           pipes (needs creds; EPM refuses      where the EPM itself
           our binds there)                    rejects the bind shape"""
        out = {"rpc": [], "rpc_mode": None, "rpc_gated": []}
        rpc_port = int(self.get_option("RPC_PORT"))
        try:
            rpctrans = transport.DCERPCTransportFactory(
                f"ncacn_ip_tcp:{host}[{rpc_port}]")
            dce = rpctrans.get_dce_rpc()
            dce.connect()
            dce.bind(epm.MSRPC_UUID_PORTMAP)
        except Exception as e:
            self.print_debug(f"{host}: epm bind failed ({e}) — "
                             f"skipping dump, trying direct binds")
            return self._rpc_bind_tier(host, timeout, out)
        try:
            entries = epm.hept_lookup(None, dce=dce)
            uuids = set()
            for entry in entries:
                try:
                    floor = entry["tower"]["Floors"][0]
                    uuids.add(str(floor["InterfaceUUID"]).lower())
                except Exception:
                    continue
            out["rpc"] = sorted(uuids)
            out["rpc_mode"] = "dump"
            dce.disconnect()
            return out
        except Exception as e:
            self.print_debug(f"{host}: ept_lookup refused ({e}) — "
                             f"falling back to ept_map probes")
        found = []
        for uuid, (_name, _hint, version) in WELL_KNOWN_RPC.items():
            try:
                epm.hept_map(host, uuidtup_to_bin((uuid, version)),
                             protocol="ncacn_np", dce=dce)
                found.append(uuid)
            except DCERPCException:
                continue
            except Exception as e:
                self.print_debug(f"{host}: ept_map {uuid}: {e}")
        dce.disconnect()
        if found:
            out["rpc"] = found
            out["rpc_mode"] = "map"
            return out
        return self._rpc_bind_tier(host, timeout, out)

    def _rpc_bind_tier(self, host, timeout, out):
        """Tier 3: bind each interface's UUID on its canonical pipe.
        Verdicts: bind ok = present; pipe missing = absent; access
        denied = present but auth-gated."""
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        nthash = str(self.get_option("NTHASH") or "").strip()
        domain = str(self.get_option("DOMAIN") or ".")
        smb_port = int(self.get_option("RPORT"))
        present, gated = [], []
        for uuid, pipe in CANONICAL_PIPES.items():
            _name, _hint, version = WELL_KNOWN_RPC[uuid]
            try:
                rpctrans = transport.SMBTransport(host, dstport=smb_port,
                                                  filename=pipe)
                rpctrans.set_credentials(user, password, domain, "", nthash)
                dce = rpctrans.get_dce_rpc()
                dce.connect()
                dce.bind(uuidtup_to_bin((uuid, version)))
                present.append(uuid)
                dce.disconnect()
            except Exception as e:
                code = None
                if hasattr(e, "getErrorCode"):
                    try:
                        code = int(e.getErrorCode())
                    except Exception:
                        code = None
                if code == STATUS_ACCESS_DENIED:
                    gated.append(uuid)
                self.print_debug(f"{host}: bind {uuid} on {pipe}: "
                                 f"{type(e).__name__} "
                                 f"{f'0x{code:08x}' if code else e}")
        out["rpc"] = present
        out["rpc_gated"] = gated
        out["rpc_mode"] = "bind"
        return out

    def _ldap(self, host, timeout):
        out = {}
        try:
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            packets = conn.search(
                searchBase="", scope=0,  # base object: the rootDSE
                searchFilter="(objectClass=*)",
                attributes=["defaultNamingContext", "domainFunctionality",
                            "supportedSASLMechanisms", "currentTime"])
            for packet in packets:
                if not isinstance(packet, ldapasn1.SearchResultEntry):
                    continue
                attrs = {str(a["type"]): [str(v) for v in a["vals"]]
                         for a in packet["attributes"]}
                out["base_dn"] = attrs.get("defaultNamingContext", [""])[0]
                level = attrs.get("domainFunctionality", [""])[0]
                out["func_level"] = FUNC_LEVELS.get(int(level), level) \
                    if level.isdigit() else level
                out["sasl"] = attrs.get("supportedSASLMechanisms", [])
                current = attrs.get("currentTime", [""])[0]
                if current:
                    server_time = datetime.datetime.strptime(
                        current, "%Y%m%d%H%M%S.0Z").replace(
                            tzinfo=datetime.timezone.utc)
                    skew = (server_time - datetime.datetime.now(
                        datetime.timezone.utc)).total_seconds()
                    out["skew"] = int(skew)
        except Exception as e:
            self.print_debug(f"{host}: ldap rootDSE: {e}")
        try:
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login("", "")
            out["ldap_signing"] = "not enforced (anonymous bind works)"
        except Exception as e:
            message = str(e).lower()
            if "strongerauthrequired" in message:
                out["ldap_signing"] = "REQUIRED"
            else:
                out["ldap_signing"] = f"not enforced ({e})"
        return out

    def _realm(self, host, domain_hint, timeout):
        # one AS-REQ for a nonexistent principal; any KRB-ERROR is a hit
        # and its realm field is authoritative (no preauth data sent)
        out = {}
        domain = domain_hint or "FORGE.INVALID"
        from impacket.krb5.asn1 import AS_REQ, seq_set, seq_set_iter
        from impacket.krb5.types import KerberosTime, Principal
        from pyasn1.codec.der import encoder
        import random

        as_req = AS_REQ()
        as_req["pvno"] = 5
        as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        req_body = seq_set(as_req, "req-body")
        req_body["kdc-options"] = constants.encodeFlags([
            constants.KDCOptions.forwardable.value])
        req_body["realm"] = domain
        name = Principal(f"probe-{random.getrandbits(16):x}",
                         type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        seq_set(req_body, "cname", name.components_to_asn1)
        server = Principal(f"krbtgt/{domain}",
                           type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(req_body, "sname", server.components_to_asn1)
        now = datetime.datetime.utcnow()
        req_body["till"] = KerberosTime.to_asn1(
            now + datetime.timedelta(days=1))
        req_body["rtime"] = KerberosTime.to_asn1(now)
        req_body["nonce"] = random.getrandbits(31)
        seq_set_iter(req_body, "etype",
                     (int(constants.EncryptionTypes.rc4_hmac.value),))
        try:
            sendReceive(encoder.encode(as_req), domain, host)
            out["realm"] = "KDC answered with a ticket?!"
        except KerberosError as e:
            # impacket hands us the KRB-ERROR two ways depending on where
            # it was raised: raw bytes, or an already-decoded structure
            try:
                packet = e.packet
                err = decoder.decode(packet, asn1Spec=KRB_ERROR())[0] \
                    if isinstance(packet, bytes) else packet
                out["realm"] = str(err["realm"])
                out["kdc_error"] = str(e).split("(")[0].replace(
                    "Kerberos SessionError: ", "")
            except Exception:
                out["realm"] = f"KDC answered ({e})"
        except OSError as e:
            self.print_debug(f"{host}: kdc probe: {e}")
        return out

    def _adcs(self, host, timeout):
        for scheme, port in (("http", 80), ("https", 443)):
            try:
                if scheme == "http":
                    conn = http.client.HTTPConnection(host, port,
                                                      timeout=timeout)
                else:
                    import ssl
                    conn = http.client.HTTPSConnection(
                        host, port, timeout=timeout,
                        context=ssl._create_unverified_context())
                conn.request("GET", "/certsrv/")
                resp = conn.getresponse()
                resp.read()
                conn.close()
                if resp.status == 401:
                    ntlm = "ntlm" in (resp.getheader("WWW-Authenticate")
                                      or "").lower()
                    return {"adcs": f"web enrollment on {scheme} "
                                    f"(401, NTLM challenge: {ntlm}) — "
                                    f"ESC8 relay target"}
                if resp.status == 200:
                    return {"adcs": f"ANONYMOUS web enrollment on {scheme} "
                                    f"— ESC8, no relay needed"}
            except (OSError, http.client.HTTPException):
                continue
        return {"adcs": None}

    # ------------------------------------------------------------- report
    def _report(self, host, profile):
        lines = [f"profile @ {host}"]
        if profile.get("os"):
            line = f"{host}: {profile['os']} (SMB {profile.get('dialect', '?')}"
            if profile.get("smb1"):
                line += ", SMB1 ENABLED"
            line += ")"
            self.print_good(line)
            lines.append(line)
        if profile.get("signing") is not None:
            if profile["signing"]:
                self.print_status(f"{host}: SMB signing required")
                lines.append("signing: required")
            else:
                self.print_good(f"{host}: SMB signing NOT required — "
                                f"relay attacks possible")
                lines.append("signing: NOT required (relayable)")
        if profile.get("dns_domain") or profile.get("nb_name"):
            line = (f"{host}: names: dns={profile.get('dns_domain', '?')} "
                    f"host={profile.get('nb_name', '?')}")
            self.print_line(f"[*] {line}")
            lines.append(line)
        if profile.get("rpc_mode") == "dump":
            self.print_status(f"{host}: RPC endpoint dump "
                              f"({len(profile['rpc'])} interfaces)")
        elif profile.get("rpc_mode") == "map":
            self.print_status(f"{host}: RPC interface probes "
                              f"({len(profile['rpc'])} present, ept_map mode)")
        elif profile.get("rpc_mode") == "bind":
            self.print_status(f"{host}: RPC interface binds "
                              f"({len(profile['rpc'])} present"
                              + (f", {len(profile['rpc_gated'])} auth-gated"
                                 if profile.get("rpc_gated") else "") + ")")
        for uuid in profile.get("rpc", []):
            note = annotate_rpc(uuid)
            if note:
                line = f"{host}:   rpc {note}"
                self.print_line(f"[*] {line}")
                lines.append(line)
        for uuid in profile.get("rpc_gated", []):
            note = annotate_rpc(uuid)
            if note:
                line = f"{host}:   rpc {note} (auth-gated)"
                self.print_line(f"[*] {line}")
                lines.append(line)
        if profile.get("base_dn"):
            line = (f"{host}: LDAP {profile['base_dn']} "
                    f"({profile.get('func_level', '?')}) "
                    f"signing={profile.get('ldap_signing', '?')}")
            self.print_line(f"[*] {line}")
            lines.append(line)
        if "skew" in profile:
            skew = profile["skew"]
            line = f"{host}: clock skew {skew:+d}s"
            if abs(skew) > 300:
                line += " (>5 min — Kerberos will fail)"
                self.print_warning(line)
            else:
                self.print_line(f"[*] {line}")
            lines.append(line)
        if profile.get("realm"):
            line = f"{host}: KDC realm {profile['realm']}"
            if profile.get("kdc_error"):
                line += f" ({profile['kdc_error']})"
            self.print_good(line)
            lines.append(line)
        if profile.get("adcs"):
            self.print_good(f"{host}: {profile['adcs']}")
            lines.append(profile["adcs"])

        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_loot("ad-probe", f"profile @ {host}",
                           "\n".join(lines), address=host)
