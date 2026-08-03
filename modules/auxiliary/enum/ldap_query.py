"""Arbitrary LDAP query runner (Maelstrom's custom_query).

The escape hatch: every engagement throws up one-off directory questions
this framework doesn't have a dedicated module for — "who hasn't rotated
their password in a year", "all servers in the domain", "accounts with
scriptPath set". Typing a raw filter beats writing a module every time,
and learning to write filters is a core AD skill.

Filters are RFC 4515: (&(objectClass=user)(adminCount=1)),
(|(cn=*svc*)(cn=*sql*)), (pwdLastSet<=133000000000000000).
Results are collated into the store (loot), not just printed.

Blank USERNAME/PASSWORD attempts an anonymous bind — whether the DC
answers searches anonymously is itself recon.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

DEFAULT_ATTRS = "sAMAccountName"


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def entry_to_dict(entry):
    """SearchResultEntry -> {attribute: [string values]}."""
    out = {}
    for attr in entry["attributes"]:
        out[str(attr["type"])] = [str(v) for v in attr["vals"]]
    return out


def validate_filter(query):
    """Reject obviously broken filters before they hit the wire.
    Returns an error string, or None when the filter looks sane."""
    if not query:
        return "empty filter"
    if not query.startswith("("):
        return "filter must start with '(' — e.g. (objectClass=user)"
    depth = 0
    for ch in query:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth < 0:
            return "unbalanced parentheses"
    if depth != 0:
        return "unbalanced parentheses"
    return None


def format_entry(attrs, show):
    """One display line from an entry dict for the requested attributes."""
    parts = []
    for name in show:
        values = attrs.get(name)
        if values:
            parts.append(f"{name}={';'.join(values)}")
    return "  ".join(parts) if parts else "(none of the requested attributes)"


class LdapQuery(AuxiliaryModule):
    name = "LDAP Query Runner"
    description = """
        Runs an arbitrary LDAP filter against a domain controller and
        prints the matching entries with the attributes you ask for
        (ATTRS). The one-off-question module: recon that doesn't fit a
        dedicated module. Results are collated into the store (loot).
        Works with valid creds or an anonymous bind where the DC allows it.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller(s), comma-separated"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username (blank = anonymous bind)"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
        self.options.add(OptString("QUERY", required=True,
                                   description="LDAP filter, e.g. (&(objectClass=user)(adminCount=1))"))
        self.options.add(OptString("ATTRS", default=DEFAULT_ATTRS,
                                   description="Attributes to display, comma-separated"))
        self.options.add(OptString("BASE", default="",
                                   description="Search base DN (blank = derived from DOMAIN)"))
        self.options.add(OptInt("LIMIT", default=100,
                                description="Max entries to return (0 = no limit)"))

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        query = str(self.get_option("QUERY") or "").strip()
        show = [a.strip() for a in str(self.get_option("ATTRS") or "").split(",")
                if a.strip()]
        base = str(self.get_option("BASE") or "").strip() or domain_to_base(domain)
        limit = int(self.get_option("LIMIT"))

        problem = validate_filter(query)
        if problem:
            self.print_error(f"Bad QUERY: {problem}")
            return

        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._query(host, domain, base, user, password, query, show, limit)

    def _query(self, host, domain, base, user, password, query, show, limit):
        who = user or "<anonymous>"
        try:
            # impacket's LDAPConnection doesn't parse ports from URLs —
            # AD LDAP is 389 by definition, so the lab binds it 1:1.
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind as {who} failed - {e}")
            return
        self.print_status(f"{host}: bound to {domain} as {who}")
        self.print_debug(f"{host}: base={base} filter={query} attrs={show} "
                         f"limit={limit}")

        store = getattr(self.framework, "store", None)
        lines = []
        count = 0
        try:
            for packet in conn.search(searchBase=base, searchFilter=query,
                                      attributes=show or None):
                if not isinstance(packet, ldapasn1.SearchResultEntry):
                    continue  # referrals / searchResDone
                if limit and count >= limit:
                    break
                count += 1
                attrs = entry_to_dict(packet)
                line = format_entry(attrs, show)
                self.print_line(f"    {line}")
                lines.append(line)
                self.print_debug(f"{host}: entry {count}: {attrs}")
        except Exception as e:
            self.print_error(f"{host}: search failed - {e}")
            return
        self.print_good(f"{host}: {count} entr{'y' if count == 1 else 'ies'}")
        if store is not None and lines:
            store.add_loot("ldap-query", f"{query} @ {host}",
                           "\n".join(lines), address=host)
