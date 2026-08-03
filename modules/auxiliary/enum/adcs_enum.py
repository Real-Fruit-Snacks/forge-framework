"""AD CS enumeration: CAs and dangerous certificate templates.

Enterprise CAs publish themselves under Public Key Services in the
configuration partition, and certificate templates sit beside them.
Most template analysis is pure LDAP — no CA access needed, which is
why this module works even on networks where you haven't found the CA
server yet.

The find that matters (ESC1): a template that lets the ENROLLEE supply
the subject name (msPKI-Certificate-Name-Flag bit ENROLLEE_SUPPLIES_SUBJECT
= 0x1) AND issues certificates usable for authentication. Ask for a cert
as "Administrator", get it, authenticate as Administrator. Domain admin
from a template misconfiguration — no password needed.

Templates are analyzed from their LDAP attributes alone, so the logic
is fully testable against planted template objects; a real CA is not
required for the enumeration half of AD CS work.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1

# EKUs that let a certificate AUTHENTICATE as its subject
AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2": "client auth",
    "1.3.6.1.5.2.3.4": "PKINIT client auth",
    "1.3.6.1.4.1.311.20.2.2": "smartcard logon",
    "2.5.29.37.0": "any purpose",
}

CA_ATTRS = ["cn", "dNSHostName", "certificateTemplates"]
TEMPLATE_ATTRS = ["cn", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage"]


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def entry_to_dict(entry):
    """SearchResultEntry -> {attribute: [string values]}."""
    out = {}
    for attr in entry["attributes"]:
        out[str(attr["type"])] = [str(v) for v in attr["vals"]]
    return out


def template_is_esc1(attrs):
    """Enrollee-supplied subject AND an authentication-capable EKU —
    request a cert as anyone, become anyone (ESC1)."""
    try:
        name_flag = int(attrs.get("msPKI-Certificate-Name-Flag", ["0"])[0])
    except (ValueError, TypeError, IndexError):
        name_flag = 0
    if not (name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT):
        return False
    ekus = set(attrs.get("pKIExtendedKeyUsage", []))
    return bool(ekus & set(AUTH_EKUS))


def auth_ekus_present(attrs):
    """Which authentication EKUs a template has, as friendly names."""
    return [name for oid, name in AUTH_EKUS.items()
            if oid in attrs.get("pKIExtendedKeyUsage", [])]


class AdcsEnum(AuxiliaryModule):
    name = "AD CS Enumeration (CAs + templates)"
    description = """
        Finds enterprise CAs (pKIEnrollmentService objects) and analyzes
        certificate templates from LDAP: enrollee-supplied-subject plus
        an authentication EKU is ESC1 (request a cert as Administrator,
        authenticate as Administrator). Works without touching the CA
        server — templates are just directory objects.
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

        pks = f"CN=Public Key Services,CN=Services,CN=Configuration,{base}"
        store = getattr(self.framework, "store", None)
        loot_lines = []

        cas = list(self._search(conn, pks, "(objectClass=pKIEnrollmentService)",
                                CA_ATTRS))
        if cas:
            for attrs in cas:
                name = attrs.get("cn", ["?"])[0]
                dns = attrs.get("dNSHostName", ["?"])[0]
                self.print_good(f"CA: {name} on {dns}")
                loot_lines.append(f"CA\t{name}\t{dns}")
        else:
            self.print_status(f"{host}: no enterprise CAs published")

        templates = list(self._search(conn, pks,
                                      "(objectClass=pKICertificateTemplate)",
                                      TEMPLATE_ATTRS))
        flagged = 0
        for attrs in templates:
            name = attrs.get("cn", ["?"])[0]
            if template_is_esc1(attrs):
                flagged += 1
                ekus = ", ".join(auth_ekus_present(attrs))
                self.print_good(f"{name}: ESC1 — enrollee supplies subject "
                                f"+ {ekus}")
                loot_lines.append(f"template\t{name}\tESC1 ({ekus})")
            else:
                self.print_debug(f"{host}: template {name} not ESC1-shaped")
        self.print_status(f"{host}: {len(templates)} template(s), "
                          f"{flagged} ESC1-shaped")
        if store is not None and loot_lines:
            store.add_loot("adcs", f"AD CS @ {host}", "\n".join(loot_lines),
                           address=host)

    def _search(self, conn, base, search_filter, attributes):
        for packet in conn.search(searchBase=base, searchFilter=search_filter,
                                  attributes=attributes):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                yield entry_to_dict(packet)
