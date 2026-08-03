"""User description harvester (Maelstrom's descriptions).

The description field is AD's junk drawer: admins stash passwords,
lockout hints, service notes, and ticket references in it because it
feels private — but ANY authenticated user can read every account's
description. One of the highest signal-to-effort checks in AD recon:
occasionally it's literally the password to the account it's on.

Entries whose descriptions smell like credentials get flagged; MATCH
narrows by description substring (classic: "pass"). Findings are
collated into the store (loot).
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

SEARCH_ATTRS = ["sAMAccountName", "description"]

# words that make a description interesting — the classics are temp
# passwords and rotation notes
SENSITIVE_WORDS = ("pass", "pwd", "cred", "secret", "key", "login", "temp")


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def entry_to_dict(entry):
    """SearchResultEntry -> {attribute: [string values]}."""
    out = {}
    for attr in entry["attributes"]:
        out[str(attr["type"])] = [str(v) for v in attr["vals"]]
    return out


def looks_sensitive(description):
    """True when the description mentions credential-ish words."""
    text = description.lower()
    return any(word in text for word in SENSITIVE_WORDS)


class AdDescriptions(AuxiliaryModule):
    name = "AD User Descriptions (LDAP)"
    description = """
        Dumps every user account's description field — where admins
        stash passwords, lockout hints, and service notes, readable by
        any authenticated user. Descriptions containing credential-ish
        words (pass/pwd/cred/...) are flagged. MATCH narrows by
        description substring. Collated into the store (loot).
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller(s), comma-separated"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Any domain user (read-only query)"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))
        self.options.add(OptString("MATCH", default="",
                                   description="Only descriptions containing this "
                                               "(case-insensitive)"))

    def run(self):
        base = domain_to_base(str(self.get_option("DOMAIN")))
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        match = str(self.get_option("MATCH") or "").strip().lower()
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._enum(host, base, user, password, match)

    def _enum(self, host, base, user, password, match):
        domain = str(self.get_option("DOMAIN"))
        try:
            # impacket's LDAPConnection doesn't parse ports from URLs —
            # AD LDAP is 389 by definition, so the lab binds it 1:1.
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind as {user} failed - {e}")
            return
        self.print_status(f"{host}: bound to {domain} as {user}")

        store = getattr(self.framework, "store", None)
        shown = 0
        loot_lines = []
        for packet in conn.search(searchBase=base,
                                  searchFilter="(&(objectClass=user)(description=*))",
                                  attributes=SEARCH_ATTRS):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue  # referrals / searchResDone
            attrs = entry_to_dict(packet)
            name = attrs.get("sAMAccountName", ["?"])[0]
            desc = attrs.get("description", [""])[0]
            if match and match not in desc.lower():
                continue
            shown += 1
            flag = "  <== CHECK THIS" if looks_sensitive(desc) else ""
            self.print_good(f"{name}: {desc}{flag}")
            loot_lines.append(f"{name}\t{desc}")
        if shown == 0:
            self.print_status(f"{host}: no descriptions matched")
        if store is not None and loot_lines:
            store.add_loot("ad-descriptions", f"descriptions @ {host}",
                           "\n".join(loot_lines), address=host)
