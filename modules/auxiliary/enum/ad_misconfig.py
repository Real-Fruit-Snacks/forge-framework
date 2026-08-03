"""Directory misconfiguration battery: MAQ, PASSWD_NOTREQD, pre-2k.

Three small checks that each punch above their weight:

  - MachineAccountQuota: how many computer accounts ANY domain user may
    create. Default is 10 — and "any user can spin a machine account"
    is the precondition for RBCD-based takeovers and half the relay
    tricks in the book. Zero means an admin closed it; anything else is
    a finding.
  - PASSWD_NOTREQD (UAC 0x20): accounts allowed to have an EMPTY
    password. Some actually do, and even when they don't, the flag says
    password policy doesn't apply to them.
  - Pre-Windows 2000 Compatible Access: members of this legacy group
    get anonymous-ish read over users and groups. Should be empty; if
    "Anonymous Logon" or "Everyone" is in it, the domain is leaking.

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

UF_PASSWD_NOTREQD = 0x20  # 32
NOTREQD_FILTER = ("(&(objectClass=user)"
                  f"(userAccountControl:1.2.840.113556.1.4.803:={UF_PASSWD_NOTREQD}))")
PRE2K_CN = "Pre-Windows 2000 Compatible Access"


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
    """CN=Anonymous Logon,S-1-5-7 -> Anonymous Logon"""
    for part in dn.split(","):
        if part.upper().startswith("CN="):
            return part[3:]
    return dn


class AdMisconfig(AuxiliaryModule):
    name = "AD Misconfiguration Battery (LDAP)"
    description = """
        Three classic directory misconfigurations in one pass:
        MachineAccountQuota (users can create machine accounts — RBCD
        and relay enabler), PASSWD_NOTREQD accounts (empty-password
        allowed), and Pre-Windows 2000 Compatible Access membership
        (legacy anonymous read). Collated into the store (loot).
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
        loot_lines = []
        self._maq(conn, host, base, loot_lines)
        self._notreqd(conn, host, base, loot_lines)
        self._pre2k(conn, host, base, loot_lines)
        if store is not None and loot_lines:
            store.add_loot("ad-misconfig", f"misconfig battery @ {host}",
                           "\n".join(loot_lines), address=host)

    def _search(self, conn, base, search_filter, attributes):
        for packet in conn.search(searchBase=base, searchFilter=search_filter,
                                  attributes=attributes):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                yield entry_to_dict(packet)

    def _maq(self, conn, host, base, loot_lines):
        for attrs in self._search(conn, base, "(objectClass=domain)",
                                  ["ms-DS-MachineAccountQuota"]):
            quota = attrs.get("ms-DS-MachineAccountQuota", ["?"])[0]
            if quota != "0":
                self.print_good(f"MachineAccountQuota = {quota} — any user "
                                "can create machine accounts")
            else:
                self.print_status("MachineAccountQuota = 0 (machine accounts "
                                  "restricted)")
            loot_lines.append(f"MachineAccountQuota\t{quota}")

    def _notreqd(self, conn, host, base, loot_lines):
        accounts = [a.get("sAMAccountName", ["?"])[0]
                    for a in self._search(conn, base, NOTREQD_FILTER,
                                          ["sAMAccountName"])]
        for name in accounts:
            self.print_good(f"PASSWD_NOTREQD: {name} (empty password allowed)")
            loot_lines.append(f"PASSWD_NOTREQD\t{name}")
        if not accounts:
            self.print_status("no PASSWD_NOTREQD accounts")

    def _pre2k(self, conn, host, base, loot_lines):
        for attrs in self._search(conn, base, f"(cn={PRE2K_CN})", ["member"]):
            members = [dn_to_cn(dn) for dn in attrs.get("member", [])]
            if members:
                self.print_good(f"{PRE2K_CN}: {', '.join(members)}")
                loot_lines.append(f"{PRE2K_CN}\t{', '.join(members)}")
            else:
                self.print_status(f"{PRE2K_CN} is empty")
