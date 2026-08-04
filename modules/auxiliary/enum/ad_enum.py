"""Active Directory enumeration via LDAP (impacket).

The AD recon loop, recreated natively: bind (credentialed or anonymous),
pull the domain's shape, and collate it into the store instead of stdout.

What each query is for:
  - domain object: password policy (min length, lockout) — tells you how
    hard you can spray later.
  - users with SPNs: kerberoastable accounts — ask for a service ticket,
    crack it offline. First-class AD finding.
  - Domain Admins membership: who you're ultimately after.
  - computers: the domain's machine inventory.

Blank USERNAME/PASSWORD attempts an anonymous bind — DCs that answer
searches anonymously are a finding on their own.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

POLICY_ATTRS = ["minPwdLength", "maxPwdAge", "lockoutThreshold"]
USER_ATTRS = ["sAMAccountName", "description", "servicePrincipalName", "objectClass"]
ADMIN_ATTRS = ["sAMAccountName"]
COMPUTER_ATTRS = ["dNSHostName", "operatingSystem"]


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def entry_to_dict(entry):
    """SearchResultEntry -> {attribute: [string values]}."""
    out = {}
    for attr in entry["attributes"]:
        out[str(attr["type"])] = [str(v) for v in attr["vals"]]
    return out


def is_kerberoastable(attrs):
    """User with an SPN — but not a machine account (computers inherit
    'person' in AD, so exclude them explicitly) and not krbtgt (every DC
    has SPNs on it; roasting it is pointless and tools skip it)."""
    if not attrs.get("servicePrincipalName"):
        return False
    classes = attrs.get("objectClass", [])
    if "computer" in classes or "person" not in classes:
        return False
    return attrs.get("sAMAccountName", [""])[0].lower() != "krbtgt"


def intervals_to_days(raw):
    """AD 100-ns interval attributes (negative) -> whole days."""
    try:
        return abs(int(raw)) // (10_000_000 * 86400)
    except (ValueError, TypeError):
        return 0


class AdEnum(AuxiliaryModule):
    name = "Active Directory Enumeration (LDAP)"
    description = """
        Enumerates an AD domain over LDAP: password policy, users,
        kerberoastable (SPN) accounts, Domain Admins, and computers.
        Findings are collated into the store (loot + creds), not just
        printed. Needs network access to a DC; works with valid creds or
        an anonymous bind where the DC allows it.
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

    # ------------------------------------------------------------------ search
    def _search(self, conn, base, search_filter, attributes):
        """Yield entry_to_dict rows for real entries (skips referrals/done)."""
        for packet in conn.search(searchBase=base, searchFilter=search_filter,
                                  attributes=attributes):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                yield entry_to_dict(packet)

    # -------------------------------------------------------------------- run
    def run(self):
        base = domain_to_base(str(self.get_option("DOMAIN")))
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._enum(host, base, user, password)

    def _enum(self, host, base, user, password):
        domain = str(self.get_option("DOMAIN"))
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
        self.print_debug(f"{host}: LDAP base={base}, url=ldap://{host}")

        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_service(host, 389, name="ldap", info=f"AD {domain}")
            if user:
                store.add_cred(host, "ldap", user, password, source="ad-enum")

        self._policy(conn, host, base, store)
        self._users(conn, host, base, store)
        self._domain_admins(conn, host, base)
        self._computers(conn, host, base, store)

    # ------------------------------------------------------------------ phases
    def _policy(self, conn, host, base, store):
        for attrs in self._search(conn, base, "(objectClass=domain)", POLICY_ATTRS):
            min_len = attrs.get("minPwdLength", ["?"])[0]
            lockout = attrs.get("lockoutThreshold", ["?"])[0]
            max_age = intervals_to_days(attrs.get("maxPwdAge", ["0"])[0])
            self.print_line(
                f"    policy: min length {min_len}, lockout after {lockout} "
                f"bad attempts, max age {max_age}d"
            )
            if store is not None:
                store.add_loot(
                    "ad-policy", f"password policy {host}",
                    f"minPwdLength={min_len} lockoutThreshold={lockout} "
                    f"maxPwdAgeDays={max_age}",
                    address=host,
                )

    def _users(self, conn, host, base, store):
        users = list(self._search(
            conn, base, "(&(objectClass=user)(!(objectClass=computer)))", USER_ATTRS
        ))
        # machine accounts by NAME marker too: Samba's SAMR creates them
        # user-class (no computer class to filter on), and the trailing $
        # is the canonical machine marker on any directory
        users = [a for a in users
                 if not a.get("sAMAccountName", [""])[0].endswith("$")]
        self.print_good(f"{host}: {len(users)} users")
        roast_count = sum(1 for a in users if is_kerberoastable(a))
        self.print_debug(f"{host}: {roast_count} kerberoastable of {len(users)}")
        lines = []
        for attrs in users:
            name = attrs.get("sAMAccountName", ["?"])[0]
            desc = attrs.get("description", [""])[0]
            roastable = is_kerberoastable(attrs)
            tag = "  <== KERBEROASTABLE" if roastable else ""
            self.print_line(f"    {name}{' (' + desc + ')' if desc else ''}{tag}")
            lines.append(f"{name}\t{desc}")
            if roastable and store is not None:
                spns = ",".join(attrs["servicePrincipalName"])
                store.add_loot("kerberoastable", f"{name} @ {host}",
                               f"{name}\tSPNs: {spns}", address=host)
        if store is not None and lines:
            store.add_loot("ad-users", f"users @ {host}", "\n".join(lines),
                           address=host)

    def _domain_admins(self, conn, host, base):
        admins = list(self._search(
            conn, base,
            f"(memberOf=CN=Domain Admins,CN=Users,{base})", ADMIN_ATTRS
        ))
        if admins:
            names = ", ".join(a.get("sAMAccountName", ["?"])[0] for a in admins)
            self.print_line(f"    Domain Admins: {names}")

    def _computers(self, conn, host, base, store):
        computers = list(self._search(conn, base, "(objectClass=computer)",
                                      COMPUTER_ATTRS))
        if computers:
            self.print_status(f"{host}: {len(computers)} computers")
            lines = []
            for attrs in computers:
                name = attrs.get("dNSHostName", ["?"])[0]
                os_info = attrs.get("operatingSystem", [""])[0]
                self.print_line(f"    {name}{' (' + os_info + ')' if os_info else ''}")
                lines.append(f"{name}\t{os_info}")
            if store is not None:
                store.add_loot("ad-computers", f"computers @ {host}",
                               "\n".join(lines), address=host)
