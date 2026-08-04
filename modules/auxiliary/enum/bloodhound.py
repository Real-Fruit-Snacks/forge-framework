"""BloodHound collector: AD objects -> BloodHound CE JSON, straight from LDAP.

BloodHound answers "who can become whom" with a graph; this module
builds the graph's bones from plain authenticated LDAP reads — the
queries BloodHound.py makes, FORGE-shaped, no SharpHound, no ingestor
binary. Users, groups (with members resolved to SIDs), computers, and
the domain object land in loot as CE-format JSON files (type
'bloodhound'): drop them into BloodHound CE's import and the graph
lights up.

v1 scope, stated plainly: objects, memberships, delegation and roast
surface. The Aces arrays ship EMPTY — full ACL edge mapping (the deep
half of BloodHound) is its own project. What's here is still the
attack-surface skeleton: every principal, every group membership,
kerberoastable and unconstrained-delegation flags.

Object mapping notes:
  - users: samAccountType 805306368; IsEnabled from the UAC ADS_UF_
    ACCOUNTDISABLE bit; IsACLProtected from adminCount
  - computers: (objectClass=computer) OR (sAMAccountName=*$) — Samba's
    SAMR makes machine accounts user-class, the class filter alone
    misses them
  - group members: DN references resolved to SIDs via a second search
    (BloodHound keys members by SID, not DN)
"""

import json

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
    from impacket.ldap.ldaptypes import LDAP_SID
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

BH_VERSION = 5
UAC_DISABLED = 0x2
SAM_USER = 805306368  # samAccountType: normal user account


def sid_str(raw):
    return LDAP_SID(raw).formatCanonical()


def bh_name(sam, domain):
    return f"{sam}@{domain.upper()}".upper()


def bh_doc(kind, objects):
    return json.dumps({"meta": {"type": kind, "count": len(objects),
                                "version": BH_VERSION},
                       "data": objects}, indent=2)


def epoch_from_ad(raw):
    """AD's 100ns-since-1601 timestamp -> unix seconds (0 when unset)."""
    try:
        ticks = int(raw)
    except (TypeError, ValueError):
        return 0
    if ticks <= 0:
        return 0
    return max(0, (ticks - 116444736000000000) // 10_000_000)


class Bloodhound(AuxiliaryModule):
    name = "BloodHound Collector (CE JSON)"
    description = """
        Collects users, groups (+members), computers, and the domain
        object over LDAP and writes BloodHound CE JSON to loot (type
        'bloodhound', one blob per class). Import straight into
        BloodHound CE. Aces arrays ship empty in v1 — this is the
        graph skeleton, not the ACL edges.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller (LDAP)"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Any domain user"))
        self.options.add(OptString("PASSWORD", required=True,
                                   description="Password"))

    def run(self):
        host = str(self.get_option("RHOSTS")).split(",")[0].strip()
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        base = ",".join(f"DC={p}" for p in domain.split("."))
        try:
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind failed - {e}")
            return
        try:
            domain_sid = self._domain_sid(conn, base)
            if domain_sid is None:
                self.print_error(f"{host}: couldn't read the domain SID")
                return
            self.print_status(f"{host}: collecting into BloodHound CE "
                              f"JSON (domain SID {domain_sid})")
            store = getattr(self.framework, "store", None)
            self._loot(store, host, "users",
                       self._users(conn, base, domain))
            self._loot(store, host, "groups",
                       self._groups(conn, base, domain))
            self._loot(store, host, "computers",
                       self._computers(conn, base, domain))
            self._loot(store, host, "domains",
                       self._domain(base, domain, domain_sid))
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # -- collection ------------------------------------------------------

    def _search(self, conn, base, filter_, attributes):
        out = []
        for packet in conn.search(searchBase=base, searchFilter=filter_,
                                  attributes=attributes):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                attrs = {}
                for a in packet["attributes"]:
                    values = []
                    for v in a["vals"]:
                        # objectSid is ALWAYS binary — str() only throws
                        # when the bytes aren't UTF-8, and some SIDs are
                        if str(a["type"]) == "objectSid":
                            values.append(v.asOctets())
                            continue
                        try:
                            values.append(str(v))
                        except Exception:
                            values.append(v.asOctets())
                    attrs[str(a["type"])] = values
                out.append((str(packet["objectName"]), attrs))
        return out

    def _domain_sid(self, conn, base):
        for _dn, attrs in self._search(
                conn, base, "(objectClass=domainDNS)", ["objectSid"]):
            return sid_str(attrs["objectSid"][0])
        return None

    def _sid_for_dn(self, conn, dn):
        for _dn, attrs in self._search(conn, dn, "(objectClass=*)",
                                       ["objectSid"]):
            if "objectSid" in attrs:
                return sid_str(attrs["objectSid"][0])
        return None

    def _users(self, conn, base, domain):
        objects = []
        for dn, a in self._search(
                conn, base, f"(samAccountType={SAM_USER})",
                ["sAMAccountName", "objectSid", "userAccountControl",
                 "adminCount", "pwdLastSet", "lastLogon", "description",
                 "displayName", "servicePrincipalName", "primaryGroupID",
                 "msDS-AllowedToDelegateTo", "distinguishedName"]):
            sam = a.get("sAMAccountName", [""])[0]
            uac = int(a.get("userAccountControl", ["0"])[0])
            domain_sid = self._sid_prefix(a["objectSid"][0])
            objects.append({
                "ObjectIdentifier": sid_str(a["objectSid"][0]),
                "IsEnabled": not bool(uac & UAC_DISABLED),
                "IsACLProtected": a.get("adminCount", ["0"])[0] == "1",
                "Properties": {
                    "name": bh_name(sam, domain),
                    "distinguishedname": dn.upper(),
                    "samaccountname": sam,
                    "displayname": a.get("displayName", [""])[0],
                    "description": a.get("description", [""])[0],
                    "pwdlastset": epoch_from_ad(a.get("pwdLastSet", ["0"])[0]),
                    "lastlogon": epoch_from_ad(a.get("lastLogon", ["0"])[0]),
                    "serviceprincipalnames": a.get("servicePrincipalName", []),
                },
                "PrimaryGroupSID":
                    f"{domain_sid}-{a.get('primaryGroupID', ['513'])[0]}",
                "AllowedToDelegate": a.get("msDS-AllowedToDelegateTo", []),
                "HasSIDHistory": [],
                "ServicePrincipalNames": a.get("servicePrincipalName", []),
                "Aces": [],
                "IsDeleted": False,
            })
        self.print_status(f"users: {len(objects)}")
        return objects

    def _groups(self, conn, base, domain):
        objects = []
        for dn, a in self._search(
                conn, base, "(objectClass=group)",
                ["sAMAccountName", "objectSid", "description", "member",
                 "distinguishedName"]):
            sam = a.get("sAMAccountName", [""])[0]
            members = []
            for member_dn in a.get("member", []):
                sid = self._sid_for_dn(conn, member_dn)
                if sid:
                    members.append({"ObjectIdentifier": sid,
                                    "ObjectType": "User"})
            objects.append({
                "ObjectIdentifier": sid_str(a["objectSid"][0]),
                "Properties": {
                    "name": bh_name(sam, domain),
                    "distinguishedname": dn.upper(),
                    "samaccountname": sam,
                    "description": a.get("description", [""])[0],
                },
                "Members": members,
                "Aces": [],
                "IsDeleted": False,
            })
        self.print_status(f"groups: {len(objects)}")
        return objects

    def _computers(self, conn, base, domain):
        objects = []
        for dn, a in self._search(
                conn, base,
                "(|(objectClass=computer)(sAMAccountName=*$))",
                ["sAMAccountName", "objectSid", "userAccountControl",
                 "dNSHostName", "operatingSystem", "description",
                 "msDS-AllowedToDelegateTo", "distinguishedName"]):
            sam = a.get("sAMAccountName", [""])[0]
            uac = int(a.get("userAccountControl", ["0"])[0])
            dns = a.get("dNSHostName", [""])[0]
            objects.append({
                "ObjectIdentifier": sid_str(a["objectSid"][0]),
                "IsEnabled": not bool(uac & UAC_DISABLED),
                "IsACLProtected": False,
                "Properties": {
                    "name": (dns or sam.rstrip("$")).upper(),
                    "distinguishedname": dn.upper(),
                    "samaccountname": sam,
                    "dnshostname": dns,
                    "operatingsystem": a.get("operatingSystem", [""])[0],
                    "description": a.get("description", [""])[0],
                },
                "AllowedToDelegate": a.get("msDS-AllowedToDelegateTo", []),
                "Aces": [],
                "IsDeleted": False,
            })
        self.print_status(f"computers: {len(objects)}")
        return objects

    def _domain(self, base, domain, domain_sid):
        self.print_status("domain: 1")
        return [{
            "ObjectIdentifier": domain_sid,
            "Properties": {
                "name": domain.upper(),
                "distinguishedname": base.upper(),
            },
            "Trusts": [],
            "Aces": [],
            "ChildObjects": [],
            "IsDeleted": False,
        }]

    # -- helpers -----------------------------------------------------------

    def _sid_prefix(self, raw):
        return sid_str(raw).rsplit("-", 1)[0]

    def _loot(self, store, host, kind, objects):
        if store is None:
            return
        loot_id = store.add_loot("bloodhound",
                                 f"{kind}.json @ {host}",
                                 bh_doc(kind, objects), address=host)
        self.print_good(f"{kind}.json: {len(objects)} object(s) -> loot "
                        f"{loot_id}")