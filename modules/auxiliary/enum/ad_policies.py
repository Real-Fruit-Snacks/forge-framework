"""Password Settings Object enumeration (Maelstrom's pso).

The domain's default password policy is only the baseline — Password
Settings Objects (fine-grained password policies) override it per user
or group. Recon value is direct: a PSO with a short minimum length or
no lockout marks the accounts it applies to as the softest spray
targets in the domain, and the precedence value tells you which policy
wins when several apply.

ad_enum already prints the domain-wide default; this module finds the
exceptions. Findings are collated into the store (loot). Read-only; any
domain credential works.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

PSO_FILTER = "(objectClass=msDS-PasswordSettings)"
PSO_ATTRS = ["name", "msDS-PasswordSettingsPrecedence",
             "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
             "msDS-LockoutDuration", "msDS-PSOAppliesTo"]


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def entry_to_dict(entry):
    """SearchResultEntry -> {attribute: [string values]}."""
    out = {}
    for attr in entry["attributes"]:
        out[str(attr["type"])] = [str(v) for v in attr["vals"]]
    return out


def interval_to_minutes(raw):
    """AD duration attribute (negative 100-ns ticks, as a string) ->
    whole minutes. 0 on garbage; durations are stored negative."""
    try:
        return abs(int(raw)) // (10_000_000 * 60)
    except (ValueError, TypeError):
        return 0


def dn_to_cn(dn):
    """CN=Helpdesk,CN=Users,DC=forge,DC=local -> Helpdesk"""
    for part in dn.split(","):
        if part.upper().startswith("CN="):
            return part[3:]
    return dn


class AdPolicies(AuxiliaryModule):
    name = "AD Fine-Grained Password Policies (PSO)"
    description = """
        Enumerates Password Settings Objects: fine-grained password
        policies that override the domain default for specific users or
        groups. Shows precedence, minimum length, lockout threshold and
        duration, and who each PSO applies to. Weak PSOs mark the softest
        spray targets in the domain. Collated into the store (loot).
        On Windows any authenticated user can read PSOs; Samba's
        CN=System ACLs hide them from normal users, so against the lab
        you need a privileged account.
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
        for packet in conn.search(searchBase=base, searchFilter=PSO_FILTER,
                                  attributes=PSO_ATTRS):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue  # referrals / searchResDone
            count += 1
            attrs = entry_to_dict(packet)
            name = attrs.get("name", ["?"])[0]
            precedence = attrs.get("msDS-PasswordSettingsPrecedence", ["?"])[0]
            min_len = attrs.get("msDS-MinimumPasswordLength", ["?"])[0]
            lockout = attrs.get("msDS-LockoutThreshold", ["?"])[0]
            duration = interval_to_minutes(
                attrs.get("msDS-LockoutDuration", ["0"])[0])
            applies = [dn_to_cn(dn) for dn in attrs.get("msDS-PSOAppliesTo", [])]
            self.print_good(
                f"{name} (precedence {precedence}): min length {min_len}, "
                f"lockout {lockout} bad attempts for {duration}min"
                f" -> {', '.join(applies) or 'nobody'}")
            loot_lines.append(f"{name}\tprecedence {precedence}\tmin {min_len}\t"
                              f"lockout {lockout}/{duration}min\t"
                              f"{', '.join(applies)}")
        if count == 0:
            self.print_status(f"{host}: no fine-grained policies — domain "
                              "default applies everywhere")
        if store is not None and loot_lines:
            store.add_loot("ad-pso", f"password settings objects @ {host}",
                           "\n".join(loot_lines), address=host)
