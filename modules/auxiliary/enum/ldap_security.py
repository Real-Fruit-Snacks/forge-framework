"""LDAP signing / channel-binding posture (Maelstrom's ldap_signing).

Two DC settings decide whether NTLM relay to LDAP(S) works:
  - LDAP signing: if the DC doesn't require it, an attacker can relay
    NTLM auth to LDAP and read/write the directory as the victim. If
    required, relayed binds die with strongerAuthRequired.
  - LDAPS channel binding: same question for LDAP over TLS — only
    meaningful when LDAPS is even exposed.

There's no honest remote registry read for these; the check is a live
probe instead: attempt a bind that offers no signing. Accepted =>
signing NOT required (relay-friendly). Rejected with
strongerAuthRequired => signing is enforced. That's exactly what the
DC does to a relayed credential, so the answer is ground truth.
"""

import socket

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

SIGNING_HINTS = ("strongerauthrequired", "stronger auth required",
                 "signing required")


def classify_bind_error(error_text):
    """Bind exception text -> 'required' when the DC demands signing,
    else 'error'."""
    text = error_text.lower()
    if any(hint in text for hint in SIGNING_HINTS):
        return "required"
    return "error"


class LdapSecurity(AuxiliaryModule):
    name = "LDAP Signing / Channel-Binding Posture"
    description = """
        Probes whether the DC requires LDAP signing (live bind without
        signing — the same thing a relayed credential gets) and whether
        LDAPS is exposed for channel binding to matter. Answers the
        NTLM-relay-to-LDAP question with ground truth, not registry
        guesses.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller(s), comma-separated"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Any domain user (the probe bind)"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._probe(host, domain, user, password)

    def _probe(self, host, domain, user, password):
        store = getattr(self.framework, "store", None)
        # 1. unsigned bind == what a relayed NTLM auth would attempt
        try:
            # impacket's LDAPConnection doesn't parse ports from URLs —
            # AD LDAP is 389 by definition, so the lab binds it 1:1.
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            verdict = classify_bind_error(str(e))
            if verdict == "required":
                self.print_good(f"{host}: LDAP signing REQUIRED "
                                "(relay to LDAP is dead)")
                self._loot(store, host, "signing required")
            else:
                self.print_error(f"{host}: bind failed - {e}")
            return
        self.print_good(f"{host}: LDAP signing NOT required "
                        "(relay to LDAP would work)")
        self._loot(store, host, "signing NOT required")

        # 2. channel binding only matters if LDAPS is even listening
        try:
            with socket.create_connection((host, 636), timeout=3):
                self.print_status(f"{host}: LDAPS exposed — channel binding "
                                  "is set server-side (not remotely readable)")
        except OSError:
            self.print_status(f"{host}: no LDAPS on 636 — channel binding n/a")

    def _loot(self, store, host, verdict):
        if store is not None:
            store.add_loot("ldap-security", f"ldap posture @ {host}",
                           verdict, address=host)
