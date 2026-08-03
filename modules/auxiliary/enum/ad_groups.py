"""Domain group enumeration via LDAP (Maelstrom's groups).

ad_enum tells you who the users are; this tells you how they're armed.
Every group in the domain with its membership, description, and type —
because privilege in AD lives in far more places than Domain Admins:
Backup Operators (DC file read = ntds.dit theft), Account Operators
(user/group control), Remote Desktop Users, DnsAdmins (DLL injection
as SYSTEM on the DC), and any custom group that grants shadow admin
rights nobody reviewed.

Security vs distribution matters: distribution groups carry no SID-based
rights, so they're noise for privesc — groupType's high bit (0x80000000)
marks security groups. Careful: LDAP returns groupType as a SIGNED
int32 string, so security groups read as negative numbers.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

SEARCH_ATTRS = ["sAMAccountName", "description", "member", "groupType"]
SECURITY_GROUP_BIT = 0x80000000


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def entry_to_dict(entry):
    """SearchResultEntry -> {attribute: [string values]}."""
    out = {}
    for attr in entry["attributes"]:
        out[str(attr["type"])] = [str(v) for v in attr["vals"]]
    return out


def group_type_int(attrs):
    """groupType as UNSIGNED int32 — LDAP serves it signed, so
    -2147483646 means 0x80000002 (global security group)."""
    try:
        raw = int(attrs.get("groupType", ["0"])[0])
    except (ValueError, TypeError, IndexError):
        return 0
    return raw & 0xFFFFFFFF


def is_security_group(attrs):
    return bool(group_type_int(attrs) & SECURITY_GROUP_BIT)


def dn_to_cn(dn):
    """CN=Ana Lyst,CN=Users,DC=forge,DC=local -> Ana Lyst"""
    for part in dn.split(","):
        if part.upper().startswith("CN="):
            return part[3:]
    return dn


class AdGroups(AuxiliaryModule):
    name = "AD Group Enumeration (LDAP)"
    description = """
        Enumerates domain groups with membership, description, and type
        (security groups are the ones that grant rights). MATCH narrows
        the list by name substring. Findings are collated into the store
        (loot). Works with any domain credential; read-only.
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
                                   description="Only groups whose name contains this "
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
        for packet in conn.search(searchBase=base, searchFilter="(objectClass=group)",
                                  attributes=SEARCH_ATTRS):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue  # referrals / searchResDone
            attrs = entry_to_dict(packet)
            name = attrs.get("sAMAccountName", ["?"])[0]
            if match and match not in name.lower():
                continue
            shown += 1
            members = [dn_to_cn(dn) for dn in attrs.get("member", [])]
            kind = "security" if is_security_group(attrs) else "distribution"
            desc = attrs.get("description", [""])[0]
            self.print_good(f"{name} ({kind}, {len(members)} members)"
                            f"{' - ' + desc if desc else ''}")
            for member in sorted(members):
                self.print_line(f"    {member}")
            self.print_debug(f"{host}: {name} groupType="
                             f"{attrs.get('groupType', ['?'])[0]} "
                             f"raw members={attrs.get('member', [])}")
            loot_lines.append(
                f"{name}\t{kind}\t{desc}\tmembers: {', '.join(sorted(members))}")
        if shown == 0:
            self.print_status(f"{host}: no groups matched")
        if store is not None and loot_lines:
            store.add_loot("ad-groups", f"groups @ {host}", "\n".join(loot_lines),
                           address=host)
