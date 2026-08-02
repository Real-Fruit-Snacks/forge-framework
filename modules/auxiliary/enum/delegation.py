"""Delegation enumeration via LDAP (impacket).

Kerberos delegation is the "who can impersonate whom" layer of AD, and
misconfigured delegation is a first-class privesc path:

  - unconstrained (TRUSTED_FOR_DELEGATION): the host keeps a copy of the
    user's TGT — compromise it, harvest TGTs of anyone who connects
    (printer-bug + this = domain admin).
  - constrained (msDS-AllowedToDelegateTo): the account may impersonate
    users to specific services. With protocol transition
    (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) it can mint those tickets
    from nothing — no user interaction needed.
  - RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity on the target): the
    resource itself names who may impersonate against it — the modern,
    attacker-favorite variant because the delegate list is writable by
    the resource's owner.

Detection is attribute-level, so this module just reads LDAP: one query
with a bitwise UAC match (LDAP matching rule 1.2.840.113556.1.4.803)
plus presence tests for the two delegation attributes.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

UF_TRUSTED_FOR_DELEGATION = 0x80000                 # 524288
UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000  # 16777216

SEARCH_ATTRS = [
    "sAMAccountName", "userAccountControl", "objectClass",
    "msDS-AllowedToDelegateTo",
]

# bit-test for unconstrained + presence test for constrained
SEARCH_FILTER = (
    "(&(objectClass=user)(|"
    f"(userAccountControl:1.2.840.113556.1.4.803:={UF_TRUSTED_FOR_DELEGATION})"
    "(msDS-AllowedToDelegateTo=*)"
    "))"
)

# RBCD is queried separately and BY PRESENCE ONLY: the attribute is a raw
# security descriptor and impacket's LDAP codec dies decoding it
# (PyAsn1UnicodeDecodeError). The filter answers "who has it" — the value
# itself never needs to cross the wire.
RBCD_FILTER = "(&(objectClass=user)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
RBCD_ATTRS = ["sAMAccountName", "objectClass"]


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def entry_to_dict(entry):
    """SearchResultEntry -> {attribute: [string values]}."""
    out = {}
    for attr in entry["attributes"]:
        out[str(attr["type"])] = [str(v) for v in attr["vals"]]
    return out


def uac_int(attrs):
    """userAccountControl as int; 0 when missing or unparsable."""
    try:
        return int(attrs.get("userAccountControl", ["0"])[0])
    except (ValueError, TypeError, IndexError):
        return 0


def is_computer(attrs):
    """Machine accounts end in $ and carry the computer class — DCs are
    trusted for delegation by default, so the caller tags these as such
    instead of screaming about them."""
    return "computer" in attrs.get("objectClass", [])


def delegation_kinds(attrs):
    """Classify one entry's delegation configuration.

    Returns a list drawn from: "unconstrained", "constrained",
    "constrained (protocol transition)", "rbcd-target". Empty for a
    healthy account.
    """
    kinds = []
    uac = uac_int(attrs)
    if uac & UF_TRUSTED_FOR_DELEGATION:
        kinds.append("unconstrained")
    if attrs.get("msDS-AllowedToDelegateTo"):
        if uac & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
            kinds.append("constrained (protocol transition)")
        else:
            kinds.append("constrained")
    if attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
        kinds.append("rbcd-target")
    return kinds


class DelegationEnum(AuxiliaryModule):
    name = "Delegation Enumeration (LDAP)"
    description = """
        Finds Kerberos delegation on a domain: unconstrained accounts,
        constrained delegation (with or without protocol transition), and
        resource-based constrained delegation targets. Machine accounts
        are tagged — DCs are trusted for delegation by default, that's not
        a finding on its own. Findings are collated into the store (loot).
        Works with any domain credential; read-only.
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

    def run(self):
        base = domain_to_base(str(self.get_option("DOMAIN")))
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._enum(host, base, user, password)

    def _enum(self, host, base, user, password):
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
        self.print_debug(f"{host}: filter={SEARCH_FILTER} base={base}")

        store = getattr(self.framework, "store", None)
        accounts = {}
        for packet in conn.search(searchBase=base, searchFilter=SEARCH_FILTER,
                                  attributes=SEARCH_ATTRS):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue  # referrals / searchResDone
            attrs = entry_to_dict(packet)
            accounts[attrs.get("sAMAccountName", ["?"])[0]] = attrs
        self.print_debug(f"{host}: {len(accounts)} account(s) with UAC/constrained")
        for packet in conn.search(searchBase=base, searchFilter=RBCD_FILTER,
                                  attributes=RBCD_ATTRS):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue
            attrs = entry_to_dict(packet)
            name = attrs.get("sAMAccountName", ["?"])[0]
            merged = accounts.setdefault(name, attrs)
            merged["msDS-AllowedToActOnBehalfOfOtherIdentity"] = ["<present>"]
        self.print_debug(f"{host}: {len(accounts)} account(s) after RBCD merge")

        found = 0
        for name, attrs in accounts.items():
            kinds = delegation_kinds(attrs)
            if not kinds:
                continue  # matched the filter but decoded empty — be safe
            found += 1
            machine = is_computer(attrs)
            tag = " (machine account)" if machine else ""
            self.print_good(f"{host}: {name}{tag}: {', '.join(kinds)}")
            targets = attrs.get("msDS-AllowedToDelegateTo", [])
            if targets:
                self.print_line(f"    delegates to: {', '.join(targets)}")
            self.print_debug(f"{host}: {name} uac={uac_int(attrs)}")
            if store is not None:
                detail = f"{name}\t{', '.join(kinds)}"
                if targets:
                    detail += f"\tdelegates to: {', '.join(targets)}"
                store.add_loot("delegation", f"{name} @ {host}", detail,
                               address=host)
        if found == 0:
            self.print_status(f"{host}: no delegation configured")
