"""adminCount=1 enumeration (Maelstrom's admin_count).

AdminSDHolder stamps adminCount=1 on every member of the protected
groups (Domain Admins, Enterprise Admins, Administrators, Account/
Backup/Print/Server Operators, ...) and — the interesting part — the
bit STAYS SET when the account leaves the group. So this query finds
both current privilege AND former admins whose accounts kept stale
rights and ACL grants ("orphaned adminCount"). Both are priority
targets; the second kind is the one nobody's watching.

Findings are collated into the store (loot). Read-only; any domain
credential works.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

SEARCH_ATTRS = ["sAMAccountName", "memberOf", "description"]

# group-name fragments that mark membership as privileged
PRIVILEGED_MARKERS = ("admin", "operators", "controllers")


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def entry_to_dict(entry):
    """SearchResultEntry -> {attribute: [string values]}."""
    out = {}
    for attr in entry["attributes"]:
        out[str(attr["type"])] = [str(v) for v in attr["vals"]]
    return out


def dn_to_cn(dn):
    """CN=Domain Admins,CN=Users,DC=forge,DC=local -> Domain Admins"""
    for part in dn.split(","):
        if part.upper().startswith("CN="):
            return part[3:]
    return dn


def privileged_groups(member_of):
    """CNs of the memberOf DNs that look privileged — empty list means
    orphaned adminCount (stamped in the past, no privileged group now)."""
    out = []
    for dn in member_of:
        cn = dn_to_cn(dn)
        if any(marker in cn.lower() for marker in PRIVILEGED_MARKERS):
            out.append(cn)
    return out


class AdPrivileged(AuxiliaryModule):
    name = "AD Privileged Accounts (adminCount)"
    description = """
        Finds accounts stamped adminCount=1 by AdminSDHolder: current
        members of the protected groups AND former members whose bit was
        never cleared (orphaned adminCount — stale rights nobody
        reviewed). Accounts with no privileged group left are flagged as
        orphaned. Collated into the store (loot).
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

        store = getattr(self.framework, "store", None)
        count = 0
        loot_lines = []
        for packet in conn.search(searchBase=base,
                                  searchFilter="(&(objectClass=user)(adminCount=1))",
                                  attributes=SEARCH_ATTRS):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue  # referrals / searchResDone
            count += 1
            attrs = entry_to_dict(packet)
            name = attrs.get("sAMAccountName", ["?"])[0]
            groups = privileged_groups(attrs.get("memberOf", []))
            if groups:
                self.print_good(f"{name}: {', '.join(sorted(groups))}")
                loot_lines.append(f"{name}\t{', '.join(sorted(groups))}")
            else:
                self.print_good(f"{name}: ORPHANED (adminCount set, "
                                "no privileged group)")
                loot_lines.append(f"{name}\tORPHANED")
        self.print_status(f"{host}: {count} adminCount=1 account(s)")
        if store is not None and loot_lines:
            store.add_loot("ad-privileged", f"adminCount=1 @ {host}",
                           "\n".join(loot_lines), address=host)
