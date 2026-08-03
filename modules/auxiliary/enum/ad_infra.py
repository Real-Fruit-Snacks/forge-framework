"""Domain infrastructure mapping: DCs, sites, subnets (dc_list + subnets).

The domain's shape beyond the user list: which machines are domain
controllers (the crown jewels' addresses), how the domain is carved
into AD sites, and which subnets belong to which site. Subnet objects
double as a free network map — every CIDR the org told AD about, no
scanning required. Site/DC layout also tells you where to point attacks
(local DC vs remote) and where new machine accounts will land.

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

# SERVER_TRUST_ACCOUNT — DC computer accounts carry this bit
UF_SERVER_TRUST_ACCOUNT = 0x2000  # 8192
DC_FILTER = ("(&(objectClass=computer)"
             f"(userAccountControl:1.2.840.113556.1.4.803:={UF_SERVER_TRUST_ACCOUNT}))")


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
    """CN=Default-First-Site-Name,CN=Sites,... -> Default-First-Site-Name"""
    for part in dn.split(","):
        if part.upper().startswith("CN="):
            return part[3:]
    return dn


class AdInfra(AuxiliaryModule):
    name = "AD Infrastructure Map (DCs, sites, subnets)"
    description = """
        Maps domain controllers (via the SERVER_TRUST_ACCOUNT bit), AD
        sites, and site-subnet assignments from the configuration
        partition. Subnets are a free network map: every CIDR the org
        registered with AD. Collated into the store (loot).
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
        domain = str(self.get_option("DOMAIN"))
        base = domain_to_base(domain)
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._enum(host, domain, base, user, password)

    def _enum(self, host, domain, base, user, password):
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
        loot_lines = []
        config = f"CN=Configuration,{base}"
        self._dcs(conn, host, base, loot_lines)
        self._sites(conn, host, config, loot_lines)
        self._subnets(conn, host, config, loot_lines)
        if store is not None and loot_lines:
            store.add_loot("ad-infra", f"infrastructure @ {host}",
                           "\n".join(loot_lines), address=host)

    def _search(self, conn, base, search_filter, attributes):
        for packet in conn.search(searchBase=base, searchFilter=search_filter,
                                  attributes=attributes):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                yield entry_to_dict(packet)

    def _dcs(self, conn, host, base, loot_lines):
        dcs = []
        for attrs in self._search(conn, base, DC_FILTER,
                                  ["dNSHostName", "operatingSystem"]):
            name = attrs.get("dNSHostName", ["?"])[0]
            os_info = attrs.get("operatingSystem", [""])[0]
            dcs.append(f"{name}{' (' + os_info + ')' if os_info else ''}")
        if dcs:
            self.print_good(f"domain controllers: {', '.join(dcs)}")
            loot_lines.append(f"DCs\t{', '.join(dcs)}")

    def _sites(self, conn, host, config, loot_lines):
        sites = [a.get("cn", ["?"])[0]
                 for a in self._search(conn, f"CN=Sites,{config}",
                                       "(objectClass=site)", ["cn"])]
        if sites:
            self.print_status(f"sites: {', '.join(sites)}")
            loot_lines.append(f"sites\t{', '.join(sites)}")

    def _subnets(self, conn, host, config, loot_lines):
        found = 0
        for attrs in self._search(conn, f"CN=Subnets,CN=Sites,{config}",
                                  "(objectClass=subnet)", ["cn", "siteObject"]):
            found += 1
            cidr = attrs.get("cn", ["?"])[0]
            site = dn_to_cn(attrs.get("siteObject", ["?"])[0])
            self.print_good(f"subnet {cidr} -> {site}")
            loot_lines.append(f"subnet\t{cidr}\t{site}")
        if found == 0:
            self.print_status("no site subnets registered")
